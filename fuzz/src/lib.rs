//! Sparse 32 MiB volume inputs keep complete NTFS metadata in compact corpora.
use disk_capture::Volume;
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use virtdisk::ReadAt;

const VOLUME_BYTES: u64 = 32 * 1024 * 1024;
const INPUT_BYTES: usize = 4 * 1024 * 1024;
const SECTOR_BYTES: usize = 512;
const RECORD_BYTES: usize = 4 + SECTOR_BYTES;
const READ_CALLS: usize = 4096;
const READ_BYTES: usize = 16 * 1024 * 1024;

struct SparseVolume {
    sectors: BTreeMap<u32, [u8; SECTOR_BYTES]>,
    calls: AtomicUsize,
    bytes: AtomicUsize,
}
impl ReadAt for SparseVolume {
    fn len(&self) -> u64 {
        VOLUME_BYTES
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> virtdisk::io::Result<()> {
        (|| -> io::Result<()> {
            if offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > self.len())
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fuzz volume bounds",
                ));
            }
            if output.len() > READ_BYTES
                || self.calls.fetch_add(1, Ordering::Relaxed) >= READ_CALLS
                || self.bytes.fetch_add(output.len(), Ordering::Relaxed) > READ_BYTES - output.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "fuzz read budget",
                ));
            }
            output.fill(0);
            let mut copied = 0;
            while copied < output.len() {
                let position = offset + copied as u64;
                let sector = (position / SECTOR_BYTES as u64) as u32;
                let within = (position % SECTOR_BYTES as u64) as usize;
                let count = (SECTOR_BYTES - within).min(output.len() - copied);
                if let Some(bytes) = self.sectors.get(&sector) {
                    output[copied..copied + count].copy_from_slice(&bytes[within..within + count]);
                }
                copied += count;
            }
            Ok(())
        })()
        .map_err(virtdisk::io::Error::from)
    }
}

/// Exercise native boot/MFT/security/index/attribute and logical stream parsing.
/// Input records are a little-endian sector index followed by 512 bytes;
/// absent sectors are zero and duplicate indices use the last complete record.
/// Input is capped at 4 MiB, reads at 4096 calls / 16 MiB, traversal at 64
/// entries and sampled logical payloads at 4 KiB per stream. Production parser
/// allocation ceilings still apply; this harness is not an exhaustive proof.
fn inspect(data: &[u8]) -> bool {
    if data.len() > INPUT_BYTES {
        return false;
    }
    let sectors = data
        .as_chunks::<RECORD_BYTES>()
        .0
        .iter()
        .filter_map(|record| {
            let sector = u32::from_le_bytes(record[..4].try_into().ok()?);
            if u64::from(sector) * SECTOR_BYTES as u64 >= VOLUME_BYTES {
                return None;
            }
            Some((sector, record[4..].try_into().ok()?))
        })
        .collect();
    let source: Arc<dyn ReadAt> = Arc::new(SparseVolume {
        sectors,
        calls: AtomicUsize::new(0),
        bytes: AtomicUsize::new(0),
    });
    let Ok(volume) = Volume::open(source) else {
        return false;
    };
    let mut entries = 0;
    if let Ok(manifest) = volume.capture_manifest_with_fallible_filter(|_| {
        entries += 1;
        if entries > 64 {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "fuzz traversal budget",
            ))
        } else {
            Ok(true)
        }
    }) {
        let mut buffer = [0; 4096];
        for node in manifest.nodes.iter().take(64) {
            for stream in node.streams.iter().take(16) {
                let count = stream.data.len().min(buffer.len() as u64) as usize;
                let _ = stream.data.read_exact_at(0, &mut buffer[..count]);
                let _ = stream.data.read_exact_at(
                    stream.data.len().saturating_sub(count as u64),
                    &mut buffer[..count],
                );
            }
        }
        return true;
    }
    false
}

pub fn ntfs(data: &[u8]) {
    let _ = inspect(data);
}

pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "ntfs" => ntfs(data),
        _ => return Err("unknown fuzz target"),
    }
    Ok(())
}

pub const TARGETS: &[&str] = &["ntfs"];
pub fn seeds(_target: &str) -> Vec<Vec<u8>> {
    vec![vec![], vec![0; 512], vec![0xff; 1024], b"header".to_vec()]
}

#[cfg(test)]
mod smoke {
    #[test]
    fn corpus_and_truncations_exercise_owned_harnesses() {
        for target in super::TARGETS {
            for seed in super::seeds(target) {
                super::run(target, &seed).unwrap();
                for end in [0, seed.len() / 2, seed.len().saturating_sub(1)] {
                    super::run(target, &seed[..end]).unwrap();
                }
                for offset in (0..seed.len()).step_by((seed.len() / 16).max(1)) {
                    let mut mutation = seed.clone();
                    mutation[offset] ^= 0xff;
                    super::run(target, &mutation).unwrap();
                }
            }
        }
    }
}
