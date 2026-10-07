//! Bounded, pure planning for a scratch record's resident DOS `$FILE_NAME` cache.
//!
//! The caller must independently establish a contiguous physical MFT mapping,
//! partition bounds, immutable image identity, and complete index/cache invariants.
//! No parser-provided starting position alone establishes a whole-record mapping.
//! This module performs no I/O and does not authorize applying its proposed patch.

use super::{Patch, decode_usa, encode_usa, invalid};
use std::io;

/// Exact identity and complete old value for one resident DOS filename attribute.
pub struct Selection<'a> {
    /// File record number and sequence, encoded as the complete NTFS reference.
    pub file_reference: u64,
    /// Exact resident attribute instance identifier within this record.
    pub attribute_id: u16,
    /// Complete parent record number and sequence reference.
    pub parent_reference: u64,
    /// Exact UTF-16 units; no Unicode normalization or lossy string conversion.
    pub name: &'a [u16],
    /// Complete old resident `$FILE_NAME` value, including all cached fields.
    pub expected_value: &'a [u8],
    /// Expected old cached ChangeTime, in NTFS ticks.
    pub expected_change_time: u64,
    /// Proposed replacement cached ChangeTime, in NTFS ticks.
    pub replacement_change_time: u64,
}

fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(
                offset
                    ..offset
                        .checked_add(2)
                        .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated u16"))?
            .try_into()
            .map_err(|_| invalid("truncated u16"))?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(
                offset
                    ..offset
                        .checked_add(4)
                        .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated u32"))?
            .try_into()
            .map_err(|_| invalid("truncated u32"))?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(
                offset
                    ..offset
                        .checked_add(8)
                        .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated u64"))?
            .try_into()
            .map_err(|_| invalid("truncated u64"))?,
    ))
}

/// Propose a whole protected FILE record with exactly one logical 8-byte change.
///
/// `raw_offset` is an externally verified absolute raw-image position. This pure
/// planner cannot establish that mapping or bind the enclosing image hash. It
/// rejects extensions, attribute lists, nonresident/named filename attributes,
/// ambiguous selectors, stale references, malformed bounds, and torn USA records.
/// It preserves the original USA sequence; a field crossing a sector trailer is
/// encoded through the corresponding USA saved word. Only decoded ChangeTime
/// bytes may change. No filename, namespace, INDEX entry, or size is changed.
pub fn plan_dos_cached_change_time(
    raw_offset: u64,
    protected: &[u8],
    sector_size: usize,
    selection: &Selection<'_>,
) -> io::Result<Patch> {
    if !(512..=65536).contains(&protected.len())
        || selection.name.is_empty()
        || selection.name.len() > 255
        || selection.file_reference >> 48 == 0
        || selection.parent_reference >> 48 == 0
        || selection.file_reference & 0x0000_ffff_ffff_ffff < 16
        || selection.expected_change_time == selection.replacement_change_time
        || raw_offset.checked_add(protected.len() as u64).is_none()
    {
        return Err(invalid("invalid bounded scratch cache selection"));
    }
    let mut decoded = decode_usa(protected, sector_size)?;
    if &decoded[..4] != b"FILE"
        || u16_at(&decoded, 4)? < 48
        || u16_at(&decoded, 16)? != (selection.file_reference >> 48) as u16
        || u16_at(&decoded, 22)? != 1
        || u64_at(&decoded, 32)? != 0
        || u32_at(&decoded, 44)? as u64 != selection.file_reference & 0x0000_ffff_ffff_ffff
        || u32_at(&decoded, 28)? as usize != decoded.len()
    {
        return Err(invalid("stale, extended, non-file or unbound FILE record"));
    }
    let used = u32_at(&decoded, 24)? as usize;
    let mut position = usize::from(u16_at(&decoded, 20)?);
    let usa_end = usize::from(u16_at(&decoded, 4)?)
        .checked_add(
            usize::from(u16_at(&decoded, 6)?)
                .checked_mul(2)
                .ok_or_else(|| invalid("USA extent overflow"))?,
        )
        .ok_or_else(|| invalid("USA extent overflow"))?;
    if position < 48
        || position < usa_end
        || !position.is_multiple_of(8)
        || used > decoded.len()
        || used < position + 4
    {
        return Err(invalid("invalid FILE attribute bounds"));
    }
    let mut selected_offset = None;
    let mut instances = std::collections::HashSet::new();
    loop {
        let kind = u32_at(&decoded[..used], position)?;
        if kind == u32::MAX {
            if !position.is_multiple_of(8) || position.checked_add(4).is_none_or(|end| end > used) {
                return Err(invalid("unaligned or truncated attribute terminator"));
            }
            break;
        }
        if kind == 0 || kind == 0x20 {
            return Err(invalid("invalid type or unsupported attribute-list record"));
        }
        let length = u32_at(&decoded[..used], position + 4)? as usize;
        let end = position
            .checked_add(length)
            .ok_or_else(|| invalid("attribute extent overflow"))?;
        if length < 24 || !length.is_multiple_of(8) || end > used || end <= position {
            return Err(invalid("invalid attribute extent"));
        }
        let attribute = &decoded[position..end];
        if !instances.insert(u16_at(attribute, 14)?) {
            return Err(invalid("duplicate attribute instance identifier"));
        }
        if attribute[8] > 1 || (attribute[8] == 1 && length < 64) {
            return Err(invalid("invalid resident/nonresident attribute header"));
        }
        if kind == 0x30 {
            if attribute[8] != 0 || attribute[9] != 0 || u16_at(attribute, 12)? != 0 {
                return Err(invalid("filename attribute must be unnamed plain resident"));
            }
            let value_offset = usize::from(u16_at(attribute, 20)?);
            let value_length = u32_at(attribute, 16)? as usize;
            let value_end = value_offset
                .checked_add(value_length)
                .ok_or_else(|| invalid("filename value overflow"))?;
            if value_offset < 24 || value_length < 66 || value_end > attribute.len() {
                return Err(invalid("invalid filename value bounds"));
            }
            let value = &attribute[value_offset..value_end];
            if value.len() != 66 + usize::from(value[64]) * 2 || value[65] > 3 {
                return Err(invalid("invalid filename name/namespace extent"));
            }
            let identity = value[65] == 2
                && u64_at(value, 0)? == selection.parent_reference
                && value[66..]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .eq(selection.name.iter().copied());
            if identity {
                if selected_offset.is_some()
                    || u16_at(attribute, 14)? != selection.attribute_id
                    || value != selection.expected_value
                    || u64_at(value, 24)? != selection.expected_change_time
                {
                    return Err(invalid(
                        "ambiguous filename or expected identity/value mismatch",
                    ));
                }
                selected_offset = Some(position + value_offset + 24);
            }
        }
        position = end;
    }
    let offset = selected_offset.ok_or_else(|| invalid("exact DOS filename not found"))?;
    let before = decoded.clone();
    decoded[offset..offset + 8].copy_from_slice(&selection.replacement_change_time.to_le_bytes());
    if decoded[..offset] != before[..offset] || decoded[offset + 8..] != before[offset + 8..] {
        return Err(invalid("unexpected decoded record change"));
    }
    let sequence = u16_at(&before, usize::from(u16_at(&before, 4)?))?;
    let replacement = encode_usa(&decoded, sector_size, sequence)?;
    // Saved USA words are derived trailer storage, not independent cached metadata.
    // Re-encoding a changed trailer also changes its saved word in the decoded view.
    let mut normalized = decoded.clone();
    let usa_offset = usize::from(u16_at(&decoded, 4)?);
    let usa_count = usize::from(u16_at(&decoded, 6)?);
    for index in 1..usa_count {
        let trailer = index * sector_size - 2;
        normalized[usa_offset + index * 2..usa_offset + index * 2 + 2]
            .copy_from_slice(&decoded[trailer..trailer + 2]);
    }
    if decode_usa(&replacement, sector_size)? != normalized {
        return Err(invalid("USA replacement does not round-trip"));
    }
    Patch::protected_record(raw_offset, protected.to_vec(), replacement, sector_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE: u64 = (1 << 48) | 37;
    const PARENT: u64 = (1 << 48) | 36;
    const BEFORE: u64 = 134357212052222843;
    const AFTER: u64 = 134357207029815463;

    fn value(name: &[u16], namespace: u8) -> Vec<u8> {
        let mut b = vec![0; 66];
        b[..8].copy_from_slice(&PARENT.to_le_bytes());
        for offset in [8, 16, 24, 32] {
            b[offset..offset + 8].copy_from_slice(&BEFORE.to_le_bytes());
        }
        b[64] = name.len() as u8;
        b[65] = namespace;
        b.extend(name.iter().flat_map(|n| n.to_le_bytes()));
        b
    }

    fn record(first: usize, values: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x42; 1024];
        b[..64].fill(0);
        b[..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&48u16.to_le_bytes());
        b[6..8].copy_from_slice(&3u16.to_le_bytes());
        b[16..18].copy_from_slice(&1u16.to_le_bytes());
        b[20..22].copy_from_slice(&(first as u16).to_le_bytes());
        b[22..24].copy_from_slice(&1u16.to_le_bytes());
        b[28..32].copy_from_slice(&1024u32.to_le_bytes());
        b[44..48].copy_from_slice(&37u32.to_le_bytes());
        let mut position = first;
        for (id, v) in values.iter().enumerate() {
            let size = (24 + v.len()).next_multiple_of(8);
            b[position..position + size].fill(0);
            b[position..position + 4].copy_from_slice(&0x30u32.to_le_bytes());
            b[position + 4..position + 8].copy_from_slice(&(size as u32).to_le_bytes());
            b[position + 14..position + 16].copy_from_slice(&(id as u16).to_le_bytes());
            b[position + 16..position + 20].copy_from_slice(&(v.len() as u32).to_le_bytes());
            b[position + 20..position + 22].copy_from_slice(&24u16.to_le_bytes());
            b[position + 24..position + 24 + v.len()].copy_from_slice(v);
            position += size;
        }
        b[position..position + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        b[24..28].copy_from_slice(&((position + 4) as u32).to_le_bytes());
        encode_usa(&b, 512, 7).unwrap()
    }

    fn selection<'a>(name: &'a [u16], expected: &'a [u8]) -> Selection<'a> {
        Selection {
            file_reference: REFERENCE,
            attribute_id: 0,
            parent_reference: PARENT,
            name,
            expected_value: expected,
            expected_change_time: BEFORE,
            replacement_change_time: AFTER,
        }
    }

    #[test]
    fn only_selected_dos_cache_changes_with_exact_parent_name_and_instance() {
        let name = "ALPHAB~1.BIN".encode_utf16().collect::<Vec<_>>();
        let dos = value(&name, 2);
        let long = value(&"LongAlpha.bin".encode_utf16().collect::<Vec<_>>(), 1);
        let raw = record(80, &[dos.clone(), long]);
        let patch = plan_dos_cached_change_time(4096, &raw, 512, &selection(&name, &dos)).unwrap();
        assert_eq!(patch.expected, raw);
        assert_eq!(patch.offset, 4096);
        let mut expected = decode_usa(&raw, 512).unwrap();
        expected[128..136].copy_from_slice(&AFTER.to_le_bytes());
        assert_eq!(decode_usa(&patch.replacement, 512).unwrap(), expected);
        assert_eq!(&patch.replacement[..128], &raw[..128]);
        assert_eq!(&patch.replacement[136..], &raw[136..]);
    }

    #[test]
    fn cache_field_crossing_sector_trailer_updates_saved_usa_word_only() {
        let name = [0xd800, 0x41]; // Preserve raw UTF-16, including an unpaired unit.
        let v = value(&name, 2);
        let raw = record(456, std::slice::from_ref(&v)); // ChangeTime is at 504..512.
        let mut selected = selection(&name, &v);
        // Exercise saved-word changes even though the observed real times share these bits.
        selected.replacement_change_time ^= 1 << 56;
        let patch = plan_dos_cached_change_time(8192, &raw, 512, &selected).unwrap();
        let mut expected = decode_usa(&raw, 512).unwrap();
        expected[504..512].copy_from_slice(&selected.replacement_change_time.to_le_bytes());
        let saved = [expected[510], expected[511]];
        expected[50..52].copy_from_slice(&saved);
        assert_eq!(decode_usa(&patch.replacement, 512).unwrap(), expected);
        assert_eq!(&patch.replacement[510..512], &raw[510..512]);
        assert_ne!(&patch.replacement[50..52], &raw[50..52]);
    }

    #[test]
    fn stale_file_or_parent_sequence_and_wrong_instance_are_rejected() {
        let name = [0x41];
        let v = value(&name, 2);
        let raw = record(80, std::slice::from_ref(&v));
        for case in 0..3 {
            let mut s = selection(&name, &v);
            match case {
                0 => s.file_reference ^= 1 << 48,
                1 => s.parent_reference ^= 1 << 48,
                _ => s.attribute_id = 1,
            }
            assert!(plan_dos_cached_change_time(0, &raw, 512, &s).is_err());
        }
    }

    #[test]
    fn different_namespace_case_or_any_old_payload_byte_is_rejected() {
        let name = [0x41];
        let v = value(&name, 2);
        for namespace in [0, 1, 3] {
            let raw = record(80, &[value(&name, namespace)]);
            assert!(plan_dos_cached_change_time(0, &raw, 512, &selection(&name, &v)).is_err());
        }
        let raw = record(80, std::slice::from_ref(&v));
        assert!(plan_dos_cached_change_time(0, &raw, 512, &selection(&[0x61], &v)).is_err());
        let mut wrong = v.clone();
        wrong[40] = 1;
        assert!(plan_dos_cached_change_time(0, &raw, 512, &selection(&name, &wrong)).is_err());
    }

    #[test]
    fn duplicate_matching_names_and_duplicate_instance_ids_are_rejected() {
        let name = [0x41];
        let v = value(&name, 2);
        let raw = record(80, &[v.clone(), v.clone()]);
        assert!(plan_dos_cached_change_time(0, &raw, 512, &selection(&name, &v)).is_err());
        let mut decoded = decode_usa(&raw, 512).unwrap();
        let second = 80 + 96;
        decoded[second + 14..second + 16].fill(0);
        let raw = encode_usa(&decoded, 512, 7).unwrap();
        assert!(plan_dos_cached_change_time(0, &raw, 512, &selection(&name, &v)).is_err());
    }

    #[test]
    fn torn_usa_extension_attribute_list_and_bad_extent_are_rejected() {
        let name = [0x41];
        let v = value(&name, 2);
        let raw = record(80, std::slice::from_ref(&v));
        let mut torn = raw.clone();
        torn[510] ^= 1;
        assert!(plan_dos_cached_change_time(0, &torn, 512, &selection(&name, &v)).is_err());
        for case in 0..4 {
            let mut decoded = decode_usa(&raw, 512).unwrap();
            match case {
                0 => decoded[32] = 1,
                1 => decoded[80..84].copy_from_slice(&0x20u32.to_le_bytes()),
                2 => decoded[84..88].copy_from_slice(&4096u32.to_le_bytes()),
                _ => decoded[80 + 20..80 + 22].copy_from_slice(&1024u16.to_le_bytes()),
            }
            let bad = encode_usa(&decoded, 512, 7).unwrap();
            assert!(plan_dos_cached_change_time(0, &bad, 512, &selection(&name, &v)).is_err());
        }
        assert!(plan_dos_cached_change_time(u64::MAX, &raw, 512, &selection(&name, &v)).is_err());
    }

    #[test]
    fn attribute_start_inside_usa_and_truncated_terminator_are_rejected() {
        let name = [0x41];
        let v = value(&name, 2);
        let raw = record(80, std::slice::from_ref(&v));
        // Both remain protected records with intact sector trailer signatures.
        let mut overlapping = raw.clone();
        overlapping[20..22].copy_from_slice(&48u16.to_le_bytes());
        assert!(plan_dos_cached_change_time(0, &overlapping, 512, &selection(&name, &v)).is_err());
        let mut decoded = decode_usa(&raw, 512).unwrap();
        let used = u32_at(&decoded, 24).unwrap() - 1;
        decoded[24..28].copy_from_slice(&used.to_le_bytes());
        let truncated = encode_usa(&decoded, 512, 7).unwrap();
        assert!(plan_dos_cached_change_time(0, &truncated, 512, &selection(&name, &v)).is_err());
    }
}
