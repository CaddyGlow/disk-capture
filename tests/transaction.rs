//! Adversarial checks for experimental new-output transaction primitives.
use disk_capture::transaction::{Patch, Plan, decode_usa, encode_usa};
use sha2::{Digest, Sha256};
use std::fs;

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn record() -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..4].copy_from_slice(b"FILE");
    bytes[4..6].copy_from_slice(&48_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
    bytes[20..22].copy_from_slice(&64_u16.to_le_bytes());
    bytes[510..512].copy_from_slice(b"ab");
    bytes[1022..1024].copy_from_slice(b"cd");
    encode_usa(&bytes, 512, 7).unwrap()
}

#[test]
fn rejects_overlapping_unsorted_out_of_bounds_and_overflowing_plans() {
    let patch = |offset| Patch {
        offset,
        expected: vec![1, 2],
        replacement: vec![3, 4],
    };
    for patches in [
        vec![patch(1), patch(2)],
        vec![patch(3), patch(1)],
        vec![patch(9)],
        vec![patch(u64::MAX)],
    ] {
        assert!(Plan::new(10, [0; 32], patches).is_err());
    }
}

#[test]
fn rejects_length_changes_and_empty_patches() {
    for (expected, replacement) in [(vec![], vec![]), (vec![1], vec![1, 2])] {
        assert!(
            Plan::new(
                10,
                [0; 32],
                vec![Patch {
                    offset: 0,
                    expected,
                    replacement
                }]
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_stale_hash_before_creating_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"original").unwrap();
    assert!(
        Plan::new(8, sha(b"obsolete"), vec![])
            .unwrap()
            .apply(&input, &output)
            .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn validates_every_old_byte_before_creating_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"original").unwrap();
    let patches = vec![
        Patch {
            offset: 0,
            expected: b"o".to_vec(),
            replacement: b"O".to_vec(),
        },
        Patch {
            offset: 7,
            expected: b"X".to_vec(),
            replacement: b"L".to_vec(),
        },
    ];
    assert!(
        Plan::new(8, sha(b"original"), patches)
            .unwrap()
            .apply(&input, &output)
            .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn preserves_existing_output_and_input_when_create_new_fails() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"original").unwrap();
    fs::write(&output, b"existing").unwrap();
    let plan = Plan::new(8, sha(b"original"), vec![]).unwrap();
    assert!(plan.apply(&input, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"existing");
    assert!(plan.apply(&input, &input).is_err());
    assert_eq!(fs::read(&input).unwrap(), b"original");
}

#[test]
fn applies_cross_buffer_patch_and_verifies_every_unpatched_byte() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    let bytes = (0..150_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(&input, &bytes).unwrap();
    let patch = Patch {
        offset: 65530,
        expected: bytes[65530..65550].to_vec(),
        replacement: vec![99; 20],
    };
    let receipt = Plan::new(bytes.len() as u64, sha(&bytes), vec![patch])
        .unwrap()
        .apply(&input, &output)
        .unwrap();
    let mut expected = bytes.clone();
    expected[65530..65550].fill(99);
    assert_eq!(fs::read(&output).unwrap(), expected);
    assert_eq!(receipt.output_sha256, sha(&expected));
    assert_eq!(fs::read(&input).unwrap(), bytes);
}

#[test]
fn usa_roundtrip_retains_all_non_usa_bytes_and_sector_trailers() {
    let protected = record();
    let decoded = decode_usa(&protected, 512).unwrap();
    assert_eq!(&decoded[510..512], b"ab");
    assert_eq!(&decoded[1022..1024], b"cd");
    let reprotected = encode_usa(&decoded, 512, 8).unwrap();
    assert_eq!(decode_usa(&reprotected, 512).unwrap()[56..], decoded[56..]);
    Patch::protected_record(4096, protected, reprotected, 512).unwrap();
}

#[test]
fn rejects_torn_records_wrong_counts_trailer_overlap_and_reserved_sequence() {
    let original = record();
    let mut torn = original.clone();
    torn[510] ^= 1;
    assert!(decode_usa(&torn, 512).is_err());
    let mut wrong_count = original.clone();
    wrong_count[6] = 4;
    assert!(decode_usa(&wrong_count, 512).is_err());
    let mut overlap = original.clone();
    overlap[4..6].copy_from_slice(&508_u16.to_le_bytes());
    assert!(decode_usa(&overlap, 512).is_err());
    assert!(encode_usa(&original, 512, 0).is_err());
    assert!(Patch::protected_record(0, original, torn, 512).is_err());
}

#[test]
fn rejects_usa_overlapping_file_or_index_headers_and_content() {
    let original = record();
    for offset in [8_u16, 40, 62] {
        let mut bad = original.clone();
        bad[4..6].copy_from_slice(&offset.to_le_bytes());
        assert!(decode_usa(&bad, 512).is_err());
    }
    let mut index = original;
    index[..4].copy_from_slice(b"INDX");
    index[24..28].copy_from_slice(&40_u32.to_le_bytes());
    for offset in [8_u16, 38, 62] {
        let mut bad = index.clone();
        bad[4..6].copy_from_slice(&offset.to_le_bytes());
        if offset == 62 {
            bad[24..28].copy_from_slice(&40_u32.to_le_bytes());
        }
        assert!(decode_usa(&bad, 512).is_err());
    }
}

#[test]
#[ignore = "requires WINDOWS_NTFS_TRANSACTION_FIXTURE immutable raw NTFS image"]
fn reprotected_real_root_record_parses_independently_without_namespace_changes() {
    use std::io::{Read, Seek, SeekFrom};
    let path = std::env::var_os("WINDOWS_NTFS_TRANSACTION_FIXTURE").unwrap();
    let mut source = fs::File::open(&path).unwrap();
    let ntfs = ntfs::Ntfs::new(&mut source).unwrap();
    let root = ntfs.file(&mut source, 5).unwrap();
    let offset = root.position().value().unwrap().get();
    let mut protected = vec![0; ntfs.file_record_size() as usize];
    source.seek(SeekFrom::Start(offset)).unwrap();
    source.read_exact(&mut protected).unwrap();
    let sector_size = usize::from(ntfs.sector_size());
    let decoded = decode_usa(&protected, sector_size).unwrap();
    let sequence_offset = usize::from(u16::from_le_bytes([protected[4], protected[5]]));
    let old = u16::from_le_bytes([protected[sequence_offset], protected[sequence_offset + 1]]);
    let sequence = if old >= 65534 { 1 } else { old + 1 };
    let replacement = encode_usa(&decoded, sector_size, sequence).unwrap();
    let patch = Patch::protected_record(offset, protected, replacement, sector_size).unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = source.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    let source_hash: [u8; 32] = digest.finalize().into();
    let source_size = source.metadata().unwrap().len();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("candidate.ntfs");
    Plan::new(source_size, source_hash, vec![patch])
        .unwrap()
        .apply(std::path::Path::new(&path), &output)
        .unwrap();
    fn names(path: &std::path::Path) -> Vec<(Vec<u16>, String, String)> {
        let mut file = fs::File::open(path).unwrap();
        let parser = ntfs::Ntfs::new(&mut file).unwrap();
        let root = parser.file(&mut file, 5).unwrap();
        let index = root.directory_index(&mut file).unwrap();
        let mut entries = index.entries();
        let mut result = Vec::new();
        while let Some(entry) = entries.next(&mut file) {
            let entry = entry.unwrap();
            if let Some(key) = entry.key() {
                let key = key.unwrap();
                result.push((
                    key.name().u16_iter().collect(),
                    format!("{:?}", key.namespace()),
                    format!("{:?}", entry.file_reference()),
                ));
            }
        }
        result
    }
    let before = names(std::path::Path::new(&path));
    assert!(!before.is_empty());
    assert_eq!(before, names(&output));
}
