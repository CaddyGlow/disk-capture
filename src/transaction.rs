//! Experimental building blocks for an offline alias writer.
//!
//! These primitives do not plan NTFS namespace/index changes or implement growth.
//! Inputs are opened read-only. A failed new output is retained as incomplete
//! evidence; only a returned receipt establishes successful verification.
//! Callers must keep inputs immutable and targets exclusively offline.

use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Experimental pure planning for selected resident DOS filename cache fields.
/// This does not locate records, write disks, or restore complete NTFS metadata.
pub mod filename_cache;

/// A fixed-size replacement in a complete, immutable raw image.
#[derive(Debug)]
pub struct Patch {
    /// Absolute byte offset in the raw input image, not a partition-relative offset.
    pub offset: u64,
    /// Exact bytes required at this location before replacement.
    pub expected: Vec<u8>,
    /// Same-length replacement bytes.
    pub replacement: Vec<u8>,
}

impl Patch {
    /// Build a whole protected FILE/INDX record replacement after USA validation.
    ///
    /// Record kind and USA geometry must remain unchanged. Attribute and index
    /// semantics require a separate planner and independent filesystem checks.
    pub fn protected_record(
        offset: u64,
        expected: Vec<u8>,
        replacement: Vec<u8>,
        sector_size: usize,
    ) -> io::Result<Self> {
        decode_usa(&expected, sector_size)?;
        decode_usa(&replacement, sector_size)?;
        if expected.len() != replacement.len() || expected[..8] != replacement[..8] {
            return Err(invalid("record kind or USA geometry changed"));
        }
        Ok(Self {
            offset,
            expected,
            replacement,
        })
    }
}

/// A complete plan bound to the whole raw input; not a filesystem transaction.
pub struct Plan {
    input_sha256: [u8; 32],
    input_size: u64,
    patches: Vec<Patch>,
}

/// Returned only after the new image and original input have been verified.
#[derive(Debug)]
pub struct Receipt {
    /// SHA-256 of the verified original input.
    pub input_sha256: [u8; 32],
    /// SHA-256 independently read back from the completed new output.
    pub output_sha256: [u8; 32],
    /// Unchanged image length.
    pub size: u64,
    /// Number of fixed-size patches verified.
    pub patches: usize,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hash(file: &mut File) -> io::Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        digest.update(&buffer[..count]);
    }
}

impl Plan {
    /// Check geometry, ordering, bounds and overlap before accepting a plan.
    ///
    /// Patches must already be sorted and nonempty; changing image length is
    /// unsupported. This does not establish semantic NTFS correctness.
    pub fn new(input_size: u64, input_sha256: [u8; 32], patches: Vec<Patch>) -> io::Result<Self> {
        let mut previous_end = 0;
        for patch in &patches {
            let length = u64::try_from(patch.expected.len())
                .map_err(|_| invalid("patch length overflow"))?;
            let end = patch
                .offset
                .checked_add(length)
                .ok_or_else(|| invalid("patch offset overflow"))?;
            if length == 0
                || patch.expected.len() != patch.replacement.len()
                || patch.offset < previous_end
                || end > input_size
            {
                return Err(invalid(
                    "empty, unequal, overlapping, unsorted or out-of-bounds patch",
                ));
            }
            previous_end = end;
        }
        Ok(Self {
            input_sha256,
            input_size,
            patches,
        })
    }

    fn validate_input(&self, input: &mut File) -> io::Result<()> {
        if !input.metadata()?.is_file()
            || input.metadata()?.len() != self.input_size
            || hash(input)? != self.input_sha256
        {
            return Err(invalid("input length or SHA-256 mismatch"));
        }
        for patch in &self.patches {
            input.seek(SeekFrom::Start(patch.offset))?;
            let mut actual = vec![0; patch.expected.len()];
            input.read_exact(&mut actual)?;
            if actual != patch.expected {
                return Err(invalid("patch expected-old-byte mismatch"));
            }
        }
        Ok(())
    }

    /// Validate all inputs before creating a new output, then flush and verify it.
    ///
    /// Never overwrites an existing path or opens the input for writing. On any
    /// error after creation, the incomplete output is retained and no receipt is
    /// returned. The caller must not publish such a file as complete. Input hash checks detect observed mismatches; they do not prevent
    /// concurrent writes or ABA changes. Exclusive immutability is still required.
    pub fn apply(&self, input_path: &Path, output_path: &Path) -> io::Result<Receipt> {
        let mut input = File::open(input_path)?;
        self.validate_input(&mut input)?;
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(output_path)?;
        input.seek(SeekFrom::Start(0))?;
        let copied = io::copy(&mut input, &mut output)?;
        if copied != self.input_size {
            return Err(invalid("input changed length while copying"));
        }
        for patch in &self.patches {
            output.seek(SeekFrom::Start(patch.offset))?;
            let mut actual = vec![0; patch.expected.len()];
            output.read_exact(&mut actual)?;
            if actual != patch.expected {
                return Err(invalid("copied patch old bytes changed"));
            }
            output.seek(SeekFrom::Start(patch.offset))?;
            output.write_all(&patch.replacement)?;
        }
        output.sync_all()?;
        self.validate_input(&mut input)?;
        // Compare every byte, including unpatched ranges, to the expected image.
        input.seek(SeekFrom::Start(0))?;
        output.seek(SeekFrom::Start(0))?;
        let mut offset = 0_u64;
        let mut expected = [0; 64 * 1024];
        let mut actual = [0; 64 * 1024];
        let mut digest = Sha256::new();
        let mut patch_index = 0;
        loop {
            let count = input.read(&mut expected)?;
            if count == 0 {
                break;
            }
            let end = offset + count as u64;
            while let Some(patch) = self.patches.get(patch_index) {
                if patch.offset >= end {
                    break;
                }
                let patch_end = patch.offset + patch.replacement.len() as u64;
                let start = offset.max(patch.offset);
                let stop = end.min(patch_end);
                if start < stop {
                    expected[(start - offset) as usize..(stop - offset) as usize].copy_from_slice(
                        &patch.replacement
                            [(start - patch.offset) as usize..(stop - patch.offset) as usize],
                    );
                }
                if patch_end > end {
                    break;
                }
                patch_index += 1;
            }
            output.read_exact(&mut actual[..count])?;
            if actual[..count] != expected[..count] {
                return Err(invalid("new output failed complete byte verification"));
            }
            digest.update(&actual[..count]);
            offset = end;
        }
        if output.metadata()?.len() != self.input_size || offset != self.input_size {
            return Err(invalid("new output length mismatch"));
        }
        self.validate_input(&mut input)?;
        Ok(Receipt {
            input_sha256: self.input_sha256,
            output_sha256: digest.finalize().into(),
            size: offset,
            patches: self.patches.len(),
        })
    }
}

fn usa_geometry(record: &[u8], sector_size: usize) -> io::Result<(usize, usize)> {
    if record.len() < 8
        || !matches!(&record[..4], b"FILE" | b"INDX")
        || sector_size < 512
        || !sector_size.is_power_of_two()
        || !record.len().is_multiple_of(sector_size)
    {
        return Err(invalid("unsupported FILE/INDX USA geometry"));
    }
    let offset = usize::from(u16::from_le_bytes([record[4], record[5]]));
    let count = usize::from(u16::from_le_bytes([record[6], record[7]]));
    let end = offset
        .checked_add(
            count
                .checked_mul(2)
                .ok_or_else(|| invalid("USA overflow"))?,
        )
        .ok_or_else(|| invalid("USA overflow"))?;
    let (minimum, first_content) = if &record[..4] == b"FILE" {
        (
            42,
            usize::from(u16::from_le_bytes([record[20], record[21]])),
        )
    } else {
        let entry_offset = u32::from_le_bytes([record[24], record[25], record[26], record[27]]);
        (
            40,
            24_usize
                .checked_add(entry_offset as usize)
                .ok_or_else(|| invalid("index offset overflow"))?,
        )
    };
    if count != record.len() / sector_size + 1
        || offset < minimum
        || first_content < minimum
        || first_content > record.len()
        || end > first_content
        || offset % 2 != 0
        || end > sector_size - 2
        || end > record.len()
    {
        return Err(invalid(
            "USA array is out of bounds or overlaps a sector trailer",
        ));
    }
    Ok((offset, count))
}

/// Validate on-disk update-sequence trailers and return the restored FILE/INDX bytes.
pub fn decode_usa(record: &[u8], sector_size: usize) -> io::Result<Vec<u8>> {
    let (offset, count) = usa_geometry(record, sector_size)?;
    let sequence = &record[offset..offset + 2];
    if sequence == [0, 0] || sequence == [255, 255] {
        return Err(invalid("invalid USA sequence"));
    }
    let mut decoded = record.to_vec();
    for index in 1..count {
        let trailer = index * sector_size - 2;
        if &record[trailer..trailer + 2] != sequence {
            return Err(invalid("torn FILE/INDX record"));
        }
        decoded[trailer..trailer + 2]
            .copy_from_slice(&record[offset + index * 2..offset + index * 2 + 2]);
    }
    Ok(decoded)
}

/// Protect decoded FILE/INDX bytes with a new non-reserved update-sequence number.
///
/// The caller must decode the old protected record first. This checks geometry,
/// not NTFS attribute/index semantics, and does not write any image.
pub fn encode_usa(decoded: &[u8], sector_size: usize, sequence: u16) -> io::Result<Vec<u8>> {
    let (offset, count) = usa_geometry(decoded, sector_size)?;
    if sequence == 0 || sequence == u16::MAX {
        return Err(invalid("invalid USA sequence"));
    }
    let mut protected = decoded.to_vec();
    protected[offset..offset + 2].copy_from_slice(&sequence.to_le_bytes());
    for index in 1..count {
        let trailer = index * sector_size - 2;
        protected[offset + index * 2..offset + index * 2 + 2]
            .copy_from_slice(&decoded[trailer..trailer + 2]);
        protected[trailer..trailer + 2].copy_from_slice(&sequence.to_le_bytes());
    }
    decode_usa(&protected, sector_size)?;
    Ok(protected)
}
