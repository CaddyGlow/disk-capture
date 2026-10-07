# Offline NTFS capture

`Volume` retains an immutable `Arc<dyn virtdisk::ReadAt>` partition. A
manifest preserves UTF-16 names, DOS aliases, file references/hard links, Win32
attributes, three Windows timestamps, raw self-relative security descriptors,
reparse buffers, extended attributes, object IDs, and deferred logical streams.
The WIM adapter lives in the `wim` crate's `disk-capture` feature.

Directory indexes and MFT resolution use `caddy-ntfs` 0.4.1, a fork of Colin Finck's `ntfs` 0.4.0 (MIT OR
Apache-2.0). Raw attribute decoding adds update-sequence validation, attribute
list reference checks, initialized-data zeroing, sparse extents, LZNT1 units,
`$Secure:$SDS` hash checks and `$SII` index cross-validation, and WOF FILE-provider XPRESS/LZX chunks. Compression
uses LGPL `ms-compress`; this crate's combined license records
that dependency. Object IDs resolve birth identifiers through `$Extend/$ObjId:$O`,
with file-reference and attribute cross-checks. No FFI or unsafe code is used.

The source must stay immutable through the deferred WIM write. Opening a file
read-only alone does not provide that guarantee. Capture rejects dirty or
unknown volume state, hibernation/fast startup, stale references, encrypted EFS
content, case-sensitive directories, unsupported reparse/data providers, and
malformed metadata. It does not repair a volume or replay the NTFS journal.

`capture_manifest_with_filter` admits paths before reading their attributes and
skips excluded directory trees. Hibernation checks run independently of that
filter. `read_file` opens logical streams by UTF-16 components with the source's
`$UpCase` mapping, without following intermediate reparse points.

NTFS internal records 0–15 are excluded. Recognized `$TXF_DATA` transaction state
and `$DSC` physical storage-tier hints are not portable WIM metadata and are
excluded; unknown logged utility streams fail. NTFS `INDEX_PRESENT` and
`VIEW_INDEX` and `EA_PRESENT` bits are removed from Win32 attributes; ordinary files without other flags
receive `FILE_ATTRIBUTE_NORMAL`. WOF FILE content is captured
as ordinary logical data, removing its storage reparse point and compression
stream. WOF WIM providers require a separate backing-resource resolver and are
rejected. Other recognized reparse points are preserved without traversal.

Validation commands:

```sh
cargo test --locked -p disk-capture
nix-shell -p ntfs3g --run 'cargo test --locked -p disk-capture --test ntfs3g -- --ignored captures_independently'
WINDOWS_NTFS_CASE_FIXTURE=/path/to/case-sensitive.ntfs cargo test --locked -p disk-capture --test ntfs3g -- --ignored rejects_empty
cargo run --release --locked -p disk-capture --example inspect -- /path/to/image.qcow2 3 --verify-data
```

The independent ntfs-3g fixture covers resident/nonresident content, ADS,
case-insensitive lookup, exclusions, and 512-byte clusters with 1024-byte MFT
records, and hibernation rejection even with exclusions. A Windows-created empty case-sensitive directory is rejected; its
ordinary control directory is captured with attributes `0x10`. The case flag
was identified in the `$STANDARD_INFORMATION` version-number field, bit zero,
by comparing retained Windows fixture records 38 and 39 and querying Windows.

On 2026-10-05 the immutable `win11-secure` base's OS partition produced 169,141
entries and 136,720 streams. All 27,506,812,428 logical bytes (counting hard-link
aliases) were read to EOF. This exercises a real Windows tree but is not, by
itself, independent byte equality, a complete installation gate, or a claim
that unsupported NTFS features have become supported. See the repository's
QCOW2 conversion evidence for the WIM and installation results.

A finalized Windows-created fixture independently matched all nine entries and
331 logical streams against Windows APIs: names, short names, attributes, three
timestamps, source file identities, security descriptor semantics, reparse
targets, extended attributes, full object IDs, stream sizes, and SHA-256 hashes.
`tests/compare_windows_fixture.py` records the comparison policy and differences.
The retained case-sensitive fixture also exercises dirty/unknown volume flags
and a deliberately corrupted `$SII` key.

Primary format references:

- [NTFS parser source](https://github.com/ColinFinck/ntfs)
- [Microsoft case-sensitive directory API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_case_sensitive_information)
- [Microsoft LZNT1 specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/124d9696-a69c-409a-a055-2562fbe255f9)
- [WOF FILE provider format and decoder reference](https://github.com/ebiggers/ntfs-3g-system-compression)
- [NTFS extended attribute representation](https://github.com/tuxera/ntfs-3g/wiki/Using-Extended-Attributes)

## Releases

CI checks formatting, Clippy and tests on Linux and Windows. A matching version tag runs validation, verifies and publishes the crate to crates.io, then creates its GitHub Release with the crate and SHA-256 checksums.
For source builds, clone `virtdisk`, `partmgr`, `caddy-ntfs` and `ms-compress` beside this repository. CI also generates and captures independent ntfs-3g fixtures.
