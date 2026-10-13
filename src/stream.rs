use crate::{invalid, unsupported};
use std::io;
use std::sync::{Arc, Mutex};
use virtdisk::ReadAt;

#[derive(Clone, Debug)]
pub(crate) struct Extent {
    pub start: u64,
    pub length: u64,
    pub physical: Option<u64>,
}
#[derive(Clone)]
pub(crate) struct LogicalStream {
    pub source: Arc<dyn ReadAt>,
    pub length: u64,
    pub initialized: u64,
    pub extents: Vec<Extent>,
    pub compression_unit: u64,
}
impl LogicalStream {
    fn raw_read(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let mut offset = offset;
        let mut output = output;
        while !output.is_empty() {
            if let Some(budget) = self.source.budget() {
                budget.work(1)?;
            }
            let index = self
                .extents
                .partition_point(|e| e.start <= offset)
                .checked_sub(1)
                .ok_or_else(|| invalid("missing stream extent"))?;
            let e = &self.extents[index];
            let within = offset - e.start;
            if within >= e.length {
                return Err(invalid("NTFS runlist contains a gap"));
            }
            let count = output.len().min((e.length - within) as usize);
            if let Some(physical) = e.physical {
                self.source
                    .read_exact_at(physical + within, &mut output[..count])?;
            } else {
                output[..count].fill(0);
            }
            output = &mut output[count..];
            offset += count as u64;
        }
        Ok(())
    }
    fn unit(&self, start: u64) -> io::Result<Vec<u8>> {
        if let Some(budget) = self.source.budget() {
            budget.decode(self.compression_unit)?;
        }
        let mut result = vec![0; self.compression_unit as usize];
        let end = start
            .checked_add(self.compression_unit)
            .ok_or_else(|| invalid("compression unit overflow"))?;
        let mut stored = Vec::new();
        let mut position = start;
        let mut sparse_seen = false;
        while position < end {
            if let Some(budget) = self.source.budget() {
                budget.work(1)?;
            }
            let index = self
                .extents
                .partition_point(|e| e.start <= position)
                .checked_sub(1)
                .ok_or_else(|| invalid("missing compressed extent"))?;
            let e = &self.extents[index];
            if position >= e.start + e.length {
                return Err(invalid("compressed runlist gap"));
            }
            let count = (end - position).min(e.start + e.length - position);
            match e.physical {
                Some(physical) => {
                    if sparse_seen {
                        return Err(invalid(
                            "allocated clusters follow sparse padding within compression unit",
                        ));
                    }
                    let old = stored.len();
                    stored.resize(old + count as usize, 0);
                    self.source
                        .read_exact_at(physical + position - e.start, &mut stored[old..])?;
                }
                None => sparse_seen = true,
            }
            position += count;
        }
        if stored.len() == result.len() {
            result.copy_from_slice(&stored);
        } else if !stored.is_empty() {
            // Allocated clusters can end in less than a full LZNT1 header. The
            // independently established unit size bounds the logical data;
            // padding is ignored only after all required chunks fully validate.
            let (produced, _) = ms_compress::lznt1::decompress_storage_unit(&stored, &mut result)
                .map_err(|e| invalid(format!("invalid LZNT1 stream: {e}")))?;
            let needed =
                (self.initialized.saturating_sub(start)).min(self.compression_unit) as usize;
            if produced < needed {
                return Err(invalid("LZNT1 unit shorter than initialized data"));
            }
        }
        Ok(result)
    }
}
impl ReadAt for LogicalStream {
    fn sparse_holes(&self) -> virtdisk::io::Result<Vec<(u64, u64)>> {
        let mut holes: Vec<(u64, u64)> = Vec::new();
        for extent in &self.extents {
            if let Some(budget) = self.budget() {
                budget.work(1)?;
            }
            if extent.physical.is_some() {
                continue;
            }
            let start = extent.start;
            let mut end = extent
                .start
                .checked_add(extent.length)
                .ok_or_else(|| invalid("sparse range overflow"))?;
            end = end.min(self.length);
            if start >= end {
                continue;
            }
            if let Some(last) = holes.last_mut().filter(|last| last.1 == start) {
                last.1 = end;
            } else {
                if let Some(budget) = self.budget() {
                    budget.metadata(16)?;
                }
                holes.push((start, end));
            }
        }
        if self.compression_unit != 0 {
            for hole in &mut holes {
                // Partial sparse units are compressed storage padding, not holes.
                hole.0 = hole
                    .0
                    .checked_add(self.compression_unit - 1)
                    .ok_or_else(|| invalid("sparse alignment overflow"))?
                    .checked_div(self.compression_unit)
                    .ok_or_else(|| invalid("zero compression unit"))?
                    * self.compression_unit;
                // A final all-sparse partial logical unit remains a hole; physical
                // runlists cover complete compression units beyond logical EOF.
                if hole.1 < self.length {
                    hole.1 = hole
                        .1
                        .checked_div(self.compression_unit)
                        .ok_or_else(|| invalid("zero compression unit"))?
                        * self.compression_unit;
                }
            }
            holes.retain(|hole| hole.0 < hole.1);
        }
        Ok(holes)
    }

    fn context(&self) -> virtdisk::ReadContext {
        self.source.context()
    }
    fn budget(&self) -> Option<virtdisk::ReadBudget> {
        self.source.budget()
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> virtdisk::io::Result<()> {
        let mut context = self.context();
        context.offset = Some(offset);
        (move || {
            if let Some(budget) = self.budget() {
                budget.work(1)?;
            }
            let output = output;
            if offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > self.length)
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NTFS stream read outside data size",
                ));
            }
            let initialized = output
                .len()
                .min(self.initialized.saturating_sub(offset) as usize);
            output[initialized..].fill(0);
            if initialized == 0 {
                return Ok(());
            }
            if self.compression_unit == 0 {
                return self.raw_read(offset, &mut output[..initialized]);
            }
            let mut position = offset;
            let mut destination = &mut output[..initialized];
            while !destination.is_empty() {
                let start = position / self.compression_unit * self.compression_unit;
                let unit = self.unit(start)?;
                let within = (position - start) as usize;
                let count = destination.len().min(unit.len() - within);
                destination[..count].copy_from_slice(&unit[within..within + count]);
                destination = &mut destination[count..];
                position += count as u64;
            }
            Ok(())
        })()
        .map_err(|e| context.error("read NTFS logical stream", e))
    }
}

pub(crate) struct Bytes(pub Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> virtdisk::io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| invalid("byte stream offset overflow"))?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| invalid("byte stream offset overflow"))?;
        let input = self.0.get(start..end).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "byte stream outside range")
        })?;
        output.copy_from_slice(input);
        Ok(())
    }
}

/// WOF FILE-provider data; an independently compressed chunk table.
type InputBatch = (u64, u64, Vec<u8>, Option<virtdisk::CacheReservation>);
type CachedChunk = (u64, Vec<u8>, Option<virtdisk::CacheReservation>);
pub(crate) struct Wof {
    data: Arc<dyn ReadAt>,
    length: u64,
    chunk: u64,
    algorithm: u32,
    offsets: Vec<u64>,
    cache: Mutex<Option<CachedChunk>>,
}
impl Wof {
    pub fn new(data: Arc<dyn ReadAt>, length: u64, algorithm: u32) -> io::Result<Self> {
        let chunk = match algorithm {
            0 => 4096,
            1 => 32768,
            2 => 8192,
            3 => 16384,
            _ => return Err(unsupported("unknown WOF FILE compression algorithm")),
        };
        let count = length.div_ceil(chunk);
        if count > 16_777_216 {
            return Err(unsupported("WOF chunk table exceeds capture safety limit"));
        }
        let width = if length > u64::from(u32::MAX) { 8 } else { 4 };
        let table_size = count
            .saturating_sub(1)
            .checked_mul(width)
            .ok_or_else(|| invalid("WOF table overflow"))?;
        if table_size > data.len() {
            return Err(invalid("WOF offset table truncated"));
        }
        if let Some(budget) = data.budget() {
            budget.metadata(table_size + (count + 1) * 8)?;
            budget.work(count)?;
        }
        let mut table = vec![0; table_size as usize];
        data.read_exact_at(0, &mut table)?;
        let mut offsets = vec![table_size];
        for entry in table.chunks_exact(width as usize) {
            let mut bytes = [0; 8];
            bytes[..entry.len()].copy_from_slice(entry);
            let relative = u64::from_le_bytes(bytes);
            let absolute = table_size
                .checked_add(relative)
                .ok_or_else(|| invalid("WOF chunk offset overflow"))?;
            if absolute
                < *offsets
                    .last()
                    .ok_or_else(|| invalid("WOF offsets missing"))?
                || absolute > data.len()
            {
                return Err(invalid("WOF chunk offsets are not ordered/bounded"));
            }
            offsets.push(absolute);
        }
        offsets.push(data.len());
        Ok(Self {
            data,
            length,
            chunk,
            algorithm,
            offsets,
            cache: Mutex::new(None),
        })
    }
    fn decode(&self, index: u64, input: &[u8]) -> io::Result<Vec<u8>> {
        let expected = (self.length - index * self.chunk).min(self.chunk) as usize;
        if input.len() as u64 > self.chunk {
            return Err(invalid("WOF compressed chunk exceeds logical chunk"));
        }
        if let Some(budget) = self.data.budget() {
            budget.decode(expected as u64)?;
        }
        if input.len() == expected {
            return Ok(input.to_vec());
        }
        let mut output = vec![0; expected];
        if self.algorithm == 1 {
            ms_compress::lzx::decompress_lzx(input, &mut output, self.chunk as usize)
                .map_err(|e| invalid(format!("WOF LZX: {e}")))?;
        } else {
            ms_compress::decompress_xpress(input, &mut output)
                .map_err(|e| invalid(format!("WOF XPRESS: {e}")))?;
        }
        Ok(output)
    }
}
impl ReadAt for Wof {
    fn context(&self) -> virtdisk::ReadContext {
        self.data.context()
    }
    fn budget(&self) -> Option<virtdisk::ReadBudget> {
        self.data.budget()
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> virtdisk::io::Result<()> {
        let mut context = self.context();
        context.offset = Some(offset);
        (move || {
            if let Some(budget) = self.budget() {
                budget.work(1)?;
            }
            let output = output;
            if offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > self.length)
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "WOF read outside range",
                ));
            }
            let mut position = offset;
            let mut output = output;
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("WOF cache poisoned"))?;
            let mut batch: Option<InputBatch> = None;
            while !output.is_empty() {
                let index = position / self.chunk;
                if cache.as_ref().is_none_or(|(cached, _, _)| *cached != index) {
                    *cache = None;
                    let reservation = self
                        .data
                        .budget()
                        .map(|b| b.cache(self.chunk))
                        .transpose()?;
                    if batch.as_ref().is_none_or(|b| index < b.0 || index > b.1) {
                        drop(batch.take()); // Release previous scratch lease before allocation.
                        let ceiling = self
                            .budget()
                            .map_or(65536, |b| b.limits().decompression_buffer_bytes.min(65536));
                        let count = (ceiling / self.chunk).max(1);
                        let last = ((position + output.len() as u64 - 1) / self.chunk)
                            .min(index + count - 1);
                        for chunk in index..=last {
                            if let Some(budget) = self.budget() {
                                budget.work(1)?;
                            }
                            if self.offsets[chunk as usize + 1] - self.offsets[chunk as usize]
                                > self.chunk
                            {
                                return Err(invalid("WOF compressed chunk exceeds logical chunk"));
                            }
                        }
                        let start = self.offsets[index as usize];
                        let size = self.offsets[last as usize + 1] - start;
                        if size > ceiling {
                            return Err(unsupported(
                                "WOF input batch exceeds configured decompression-buffer limit",
                            ));
                        }
                        let scratch = self.budget().map(|b| b.cache(size)).transpose()?;
                        let mut input = vec![0; size as usize];
                        self.data.read_exact_at(start, &mut input)?;
                        batch = Some((index, last, input, scratch));
                    }
                    let batch = batch
                        .as_ref()
                        .ok_or_else(|| invalid("WOF input batch missing"))?;
                    let base = self.offsets[batch.0 as usize];
                    let start = (self.offsets[index as usize] - base) as usize;
                    let end = (self.offsets[index as usize + 1] - base) as usize;
                    *cache = Some((
                        index,
                        self.decode(index, &batch.2[start..end])?,
                        reservation,
                    ));
                }
                let decoded = &cache
                    .as_ref()
                    .ok_or_else(|| invalid("WOF cache missing"))?
                    .1;
                let within = (position % self.chunk) as usize;
                let count = output.len().min(decoded.len() - within);
                output[..count].copy_from_slice(&decoded[within..within + count]);
                position += count as u64;
                output = &mut output[count..];
            }
            // Completed streams must not retain one decoded chunk each across
            // the whole manifest. Partial reads still reuse their current chunk.
            if position == self.length {
                *cache = None;
            }
            Ok(())
        })()
        .map_err(|e| context.error("read WOF logical stream", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_reads_zero_uninitialized_allocated_tail() {
        let source = Arc::new(Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]));
        let stream = LogicalStream {
            source,
            length: 12,
            initialized: 10,
            compression_unit: 0,
            extents: vec![
                Extent {
                    start: 0,
                    length: 4,
                    physical: Some(0),
                },
                Extent {
                    start: 4,
                    length: 4,
                    physical: None,
                },
                Extent {
                    start: 8,
                    length: 4,
                    physical: Some(4),
                },
            ],
        };
        let mut data = [255; 12];
        stream.read_exact_at(0, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4, 0, 0, 0, 0, 5, 6, 0, 0]);
        stream.read_exact_at(12, &mut []).unwrap();
        assert!(stream.read_exact_at(13, &mut []).is_err());
        assert!(stream.read_exact_at(u64::MAX, &mut [0]).is_err());
    }
    #[test]
    fn lznt1_units_decode_fragmented_storage_and_zero_final_tail() {
        let original = vec![b'A'; 8192];
        let mut compressed = ms_compress::lznt1::compress(&original).unwrap();
        let stored = compressed.len().div_ceil(512) * 512;
        compressed.resize(stored, 0);
        let stream = LogicalStream {
            source: Arc::new(Bytes(compressed)),
            length: 9000,
            initialized: 8192,
            compression_unit: 8192,
            extents: vec![
                Extent {
                    start: 0,
                    length: stored as u64,
                    physical: Some(0),
                },
                Extent {
                    start: stored as u64,
                    length: 8192 - stored as u64,
                    physical: None,
                },
                Extent {
                    start: 8192,
                    length: 8192,
                    physical: None,
                },
            ],
        };
        let mut data = vec![0; 9000];
        stream.read_exact_at(0, &mut data).unwrap();
        assert_eq!(&data[..8192], original);
        assert_eq!(&data[8192..], vec![0; 808]);
        let mut crossing = [0; 10];
        stream.read_exact_at(8187, &mut crossing).unwrap();
        assert_eq!(crossing, [b'A', b'A', b'A', b'A', b'A', 0, 0, 0, 0, 0]);
    }
    #[test]
    fn compressed_unit_rejects_allocated_clusters_after_sparse_padding() {
        let stream = LogicalStream {
            source: Arc::new(Bytes(vec![0; 4096])),
            length: 4096,
            initialized: 4096,
            compression_unit: 4096,
            extents: vec![
                Extent {
                    start: 0,
                    length: 2048,
                    physical: None,
                },
                Extent {
                    start: 2048,
                    length: 2048,
                    physical: Some(0),
                },
            ],
        };
        assert!(stream.read_exact_at(0, &mut [0]).is_err());
    }
    #[test]
    fn lznt1_complete_units_ignore_allocation_slack_without_relaxing_initialized_size() {
        let original = vec![b'A'; 8192];
        let encoded = ms_compress::lznt1::compress(&original).unwrap();
        for tail in [0, 0x7f] {
            let mut stored = encoded.clone();
            stored.push(tail);
            let stored_len = stored.len() as u64;
            let stream = LogicalStream {
                source: Arc::new(Bytes(stored)),
                length: 8192,
                initialized: 8192,
                compression_unit: 8192,
                extents: vec![
                    Extent {
                        start: 0,
                        length: stored_len,
                        physical: Some(0),
                    },
                    Extent {
                        start: stored_len,
                        length: 8192 - stored_len,
                        physical: None,
                    },
                ],
            };
            let mut output = vec![0; 8192];
            stream.read_exact_at(0, &mut output).unwrap();
            assert_eq!(output, original);
        }
        let short = ms_compress::lznt1::compress(&[b'A'; 4096]).unwrap();
        let stored_len = short.len() as u64;
        let stream = LogicalStream {
            source: Arc::new(Bytes(short)),
            length: 8192,
            initialized: 8192,
            compression_unit: 8192,
            extents: vec![
                Extent {
                    start: 0,
                    length: stored_len,
                    physical: Some(0),
                },
                Extent {
                    start: stored_len,
                    length: 8192 - stored_len,
                    physical: None,
                },
            ],
        };
        let error = stream.read_exact_at(0, &mut [0]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("shorter than initialized"));
    }

    #[test]
    #[ignore = "requires the independently Windows-decoded immutable unit14 fixture"]
    fn windows_lznt1_unit_matches_independent_output_with_odd_allocation_padding() {
        use sha2::{Digest, Sha256};
        let stored =
            std::fs::read(std::env::var("WINDOWS_NTFS_LZNT1_UNIT_FIXTURE").unwrap()).unwrap();
        assert_eq!(stored.len(), 24576);
        assert_eq!(
            format!("{:x}", Sha256::digest(&stored)),
            "7489c5576fd7d2137e87336b405089790fb385462524f9f66f05bba907e27588"
        );
        let stream = LogicalStream {
            source: Arc::new(Bytes(stored)),
            length: 65536,
            initialized: 65536,
            compression_unit: 65536,
            extents: vec![
                Extent {
                    start: 0,
                    length: 24576,
                    physical: Some(0),
                },
                Extent {
                    start: 24576,
                    length: 65536 - 24576,
                    physical: None,
                },
            ],
        };
        let mut output = vec![0; 65536];
        stream.read_exact_at(0, &mut output).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&output)),
            "d1407699c1edad31aa3c344ead414cd173079dd34feda57fd201bf77fe7aa3a0"
        );
    }
    #[test]
    fn wof_chunk_table_supports_verbatim_tail_and_cross_chunk_reads() {
        let mut data = 4096u32.to_le_bytes().to_vec();
        data.extend(vec![b'a'; 4096]);
        data.extend(b"tail");
        let wof = Wof::new(Arc::new(Bytes(data)), 4100, 0).unwrap();
        assert!(wof.sparse_holes().unwrap().is_empty());
        let mut crossing = [0; 8];
        wof.read_exact_at(4092, &mut crossing).unwrap();
        assert_eq!(&crossing, b"aaaatail");
        assert!(Wof::new(Arc::new(Bytes(9999u32.to_le_bytes().to_vec())), 4100, 0).is_err());
    }
    #[test]
    fn wof_actual_chunk_reads_enforce_cache_and_cumulative_decode_limits() {
        let mut data = 4096u32.to_le_bytes().to_vec();
        data.extend(vec![b'a'; 4096]);
        data.extend(b"tail");
        for (name, limits) in [
            (
                "cache",
                virtdisk::ParserLimits {
                    cache_bytes: 4095,
                    ..Default::default()
                },
            ),
            (
                "decoded output",
                virtdisk::ParserLimits {
                    decompressed_bytes: 4096,
                    ..Default::default()
                },
            ),
        ] {
            let budget = virtdisk::ReadBudget::new(limits).unwrap();
            let wof = Wof::new(budget.reader(Arc::new(Bytes(data.clone()))), 4100, 0).unwrap();
            let error = wof.read_exact_at(4092, &mut [0; 8]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(error.to_string().contains(name), "{error}");
        }
    }
    #[test]
    fn uninitialized_zero_reads_consume_work_without_physical_io() {
        let budget = virtdisk::ReadBudget::new(virtdisk::ParserLimits {
            work_items: 2,
            ..Default::default()
        })
        .unwrap();
        let stream = LogicalStream {
            source: budget.reader(Arc::new(Bytes(vec![]))),
            length: 4096,
            initialized: 0,
            extents: vec![],
            compression_unit: 0,
        };
        let mut bytes = [0xff; 16];
        stream.read_exact_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 16]);
        stream.read_exact_at(0, &mut bytes).unwrap();
        let error = stream.read_exact_at(0, &mut bytes).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("work"));
    }
    #[test]
    fn sparse_ranges_distinguish_compression_padding_and_clip_eof() {
        let make = |compression_unit| LogicalStream {
            source: Arc::new(Bytes(vec![0; 32])),
            length: 23,
            initialized: 23,
            extents: vec![
                Extent {
                    start: 0,
                    length: 4,
                    physical: Some(0),
                },
                Extent {
                    start: 4,
                    length: 20,
                    physical: None,
                },
            ],
            compression_unit,
        };
        assert_eq!(make(0).sparse_holes().unwrap(), vec![(4, 23)]);
        assert_eq!(make(8).sparse_holes().unwrap(), vec![(8, 23)]);
    }
    #[test]
    fn completed_wof_streams_release_shared_cache_reservations() {
        let budget = virtdisk::ReadBudget::new(virtdisk::ParserLimits {
            cache_bytes: 8192,
            ..Default::default()
        })
        .unwrap();
        let streams: Vec<_> = (0..4)
            .map(|_| Wof::new(budget.reader(Arc::new(Bytes(vec![42; 4096]))), 4096, 0).unwrap())
            .collect();
        let mut bytes = vec![0; 4096];
        for stream in &streams {
            stream.read_exact_at(0, &mut bytes).unwrap();
            assert_eq!(bytes, vec![42; 4096]);
            assert_eq!(budget.usage().cache_bytes, 0);
        }
        streams[0].read_exact_at(0, &mut bytes[..1]).unwrap();
        assert_eq!(budget.usage().cache_bytes, 4096);
        streams[0].read_exact_at(1, &mut bytes[1..]).unwrap();
        assert_eq!(budget.usage().cache_bytes, 0);
    }
    #[test]
    fn wof_batches_contiguous_chunks_and_preserves_random_partial_reads() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted {
            bytes: Vec<u8>,
            reads: Arc<AtomicUsize>,
        }
        impl ReadAt for Counted {
            fn len(&self) -> u64 {
                self.bytes.len() as u64
            }
            fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> virtdisk::io::Result<()> {
                self.reads.fetch_add(1, Ordering::Relaxed);
                Bytes(self.bytes.clone()).read_exact_at(offset, out)
            }
        }
        let logical: Vec<u8> = (0..(8 * 4096 + 37)).map(|i| (i % 251) as u8).collect();
        let chunks = logical.len().div_ceil(4096);
        let mut encoded = Vec::new();
        for i in 1..chunks {
            encoded.extend_from_slice(&((i * 4096) as u32).to_le_bytes());
        }
        encoded.extend_from_slice(&logical);
        let reads = Arc::new(AtomicUsize::new(0));
        let budget = virtdisk::ReadBudget::new(Default::default()).unwrap();
        let wof = Wof::new(
            budget.reader(Arc::new(Counted {
                bytes: encoded,
                reads: reads.clone(),
            })),
            logical.len() as u64,
            0,
        )
        .unwrap();
        let before = reads.load(Ordering::Relaxed);
        let mut full = vec![0; logical.len()];
        wof.read_exact_at(0, &mut full).unwrap();
        assert_eq!(full, logical);
        assert_eq!(reads.load(Ordering::Relaxed) - before, 1);
        assert_eq!(budget.usage().cache_bytes, 0);
        for (start, count) in [
            (1, 17),
            (4090, 19),
            (8000, 17000),
            (logical.len() - 37, 37),
            (0, 1),
        ] {
            let mut actual = vec![0; count];
            wof.read_exact_at(start as u64, &mut actual).unwrap();
            assert_eq!(actual, logical[start..start + count]);
        }
        let mut tail = vec![0; logical.len() - 1];
        wof.read_exact_at(1, &mut tail).unwrap();
        assert_eq!(tail, logical[1..]);
        assert_eq!(budget.usage().cache_bytes, 0);
    }
    #[test]
    fn batched_wof_xpress_matches_independent_c_oracle_bytes() {
        // The codec fixture retains upstream C-decoder expected bytes, not
        // expected output generated by the native decoder under test.
        let fixture = include_bytes!("../tests/fixtures/xpress-oracle.wxp");
        let count = u32::from_le_bytes(fixture[4..8].try_into().unwrap());
        let mut position = 8;
        let mut selected = Vec::new();
        for _ in 0..count {
            let n =
                u16::from_le_bytes(fixture[position..position + 2].try_into().unwrap()) as usize;
            position += 2;
            let name = &fixture[position..position + n];
            position += n;
            let input =
                u32::from_le_bytes(fixture[position..position + 4].try_into().unwrap()) as usize;
            let output = u32::from_le_bytes(fixture[position + 4..position + 8].try_into().unwrap())
                as usize;
            let success = fixture[position + 8] != 0;
            position += 9;
            let encoded = &fixture[position..position + input];
            position += input;
            if success {
                let expected = &fixture[position..position + output];
                position += output;
                if output == 4096 && name.starts_with(b"encoded-level-1-size-4096-") {
                    selected.push((encoded, expected));
                }
            }
        }
        assert_eq!(selected.len(), 4);
        let mut encoded = Vec::new();
        let mut relative = 0u32;
        for (input, _) in selected.iter().take(3) {
            relative += input.len() as u32;
            encoded.extend_from_slice(&relative.to_le_bytes());
        }
        let mut expected = Vec::new();
        for (input, output) in selected {
            encoded.extend_from_slice(input);
            expected.extend_from_slice(output);
        }
        let wof = Wof::new(Arc::new(Bytes(encoded)), expected.len() as u64, 0).unwrap();
        for (start, length) in [(0, 16384), (4000, 9000), (8190, 7), (16383, 1)] {
            let mut actual = vec![0; length];
            wof.read_exact_at(start as u64, &mut actual).unwrap();
            assert_eq!(actual, expected[start..start + length]);
        }
    }
}
