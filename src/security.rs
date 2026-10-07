use crate::attributes::{u16_at, u32_at, u64_at};
use crate::invalid;
use std::collections::HashMap;
use std::io;
use virtdisk::ReadAt;

pub(crate) fn validate_descriptor(sd: &[u8]) -> io::Result<()> {
    if sd.len() < 20 || !sd.len().is_multiple_of(4) || sd[0] != 1 || u16_at(sd, 2)? & 0x8000 == 0 {
        return Err(invalid(
            "security descriptor is not revision1 self-relative",
        ));
    }
    for field in [4, 8] {
        let offset = u32_at(sd, field)? as usize;
        if offset == 0 {
            continue;
        }
        if offset < 20 || !offset.is_multiple_of(4) {
            return Err(invalid("unaligned/header-overlapping security component"));
        }
        let header = sd
            .get(offset..offset + 8)
            .ok_or_else(|| invalid("security SID offset outside descriptor"))?;
        let length = 8 + usize::from(header[1]) * 4;
        if header[0] != 1 || header[1] > 15 || sd.get(offset..offset + length).is_none() {
            return Err(invalid("invalid security SID"));
        }
    }
    for field in [12, 16] {
        let offset = u32_at(sd, field)? as usize;
        if offset == 0 {
            continue;
        }
        if offset < 20 || !offset.is_multiple_of(4) {
            return Err(invalid("unaligned/header-overlapping security component"));
        }
        let header = sd
            .get(offset..offset + 8)
            .ok_or_else(|| invalid("ACL offset outside descriptor"))?;
        let present = if field == 12 { 0x10 } else { 4 };
        if u16_at(sd, 2)? & present == 0 || ![2, 4].contains(&header[0]) {
            return Err(invalid("ACL revision/presence is invalid"));
        }
        let length = u16_at(header, 2)? as usize;
        if !length.is_multiple_of(4) || length < 8 || sd.get(offset..offset + length).is_none() {
            return Err(invalid("ACL outside descriptor"));
        }
        let mut cursor = offset + 8;
        for _ in 0..u16_at(header, 4)? {
            let size = u16_at(sd, cursor + 2)? as usize;
            if !size.is_multiple_of(4)
                || size < 4
                || cursor
                    .checked_add(size)
                    .is_none_or(|end| end > offset + length)
            {
                return Err(invalid("invalid ACE extent"));
            }
            cursor += size;
        }
    }
    Ok(())
}
fn hash(sd: &[u8]) -> u32 {
    let mut value = 0u32;
    for chunk in sd.chunks(4) {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        value = value.rotate_left(3).wrapping_add(u32::from_le_bytes(word));
    }
    value
}
pub(crate) fn read_sds(source: &dyn ReadAt) -> io::Result<HashMap<u32, Vec<u8>>> {
    if source.len() > 256 * 1024 * 1024 {
        return Err(crate::unsupported("$Secure:$SDS exceeds safety limit"));
    }
    if let Some(budget) = source.budget() {
        budget.metadata(source.len())?;
    }
    let mut data = vec![0; source.len() as usize];
    source.read_exact_at(0, &mut data)?;
    let mut result = HashMap::new();
    let mut offset = 0usize;
    while offset + 20 <= data.len() {
        if let Some(budget) = source.budget() {
            budget.work(1)?;
        }
        // Every 256KiB primary segment is followed by its redundant copy.
        if offset & 0x40000 != 0 {
            offset = (offset + 0x40000) & !0x3ffff;
            continue;
        }
        let size = u32_at(&data, offset + 16)? as usize;
        if size == 0 {
            offset = (offset + 0x40000) & !0x3ffff;
            continue;
        }
        if !size.is_multiple_of(4)
            || size < 40
            || offset
                .checked_add(size)
                .is_none_or(|end| end > data.len() || end > (offset & !0x3ffff) + 0x40000)
        {
            return Err(invalid("invalid $SDS record length"));
        }
        let id = u32_at(&data, offset + 4)?;
        if u64_at(&data, offset + 8)? != offset as u64 {
            return Err(invalid("$SDS descriptor offset mismatch"));
        }
        let sd = &data[offset + 20..offset + size];
        if let Some(budget) = source.budget() {
            budget.metadata(sd.len() as u64)?;
        }
        validate_descriptor(sd)?;
        if hash(sd) != u32_at(&data, offset)? {
            return Err(invalid("$SDS descriptor hash mismatch"));
        }
        if let Some(previous) = result.insert(id, sd.to_vec())
            && previous != sd
        {
            return Err(invalid("duplicate security ID with different descriptors"));
        }
        offset = (offset + size + 15) & !15;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_relative_descriptor_preserves_null_acl_semantics_and_rejects_bad_offsets() {
        let mut descriptor = vec![0; 20];
        descriptor[0] = 1;
        descriptor[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        validate_descriptor(&descriptor).unwrap();
        descriptor[16..20].copy_from_slice(&20u32.to_le_bytes());
        assert!(validate_descriptor(&descriptor).is_err());
        descriptor.extend([2, 0, 8, 0, 0, 0, 0, 0]);
        validate_descriptor(&descriptor).unwrap();
        descriptor[24] = 1;
        assert!(validate_descriptor(&descriptor).is_err());
    }
}

#[derive(Clone, Debug)]
struct SecurityIndex;
#[derive(Debug)]
struct SecurityKey(u32);
#[derive(Debug)]
struct SecurityEntry([u8; 20]);
impl ntfs::indexes::NtfsIndexEntryType for SecurityIndex {
    type KeyType = SecurityKey;
}
impl ntfs::indexes::NtfsIndexEntryHasData for SecurityIndex {
    type DataType = SecurityEntry;
}
impl ntfs::indexes::NtfsIndexEntryKey for SecurityKey {
    fn key_from_slice(
        slice: &[u8],
        _position: ntfs::types::NtfsPosition,
    ) -> Result<Self, ntfs::NtfsError> {
        if slice.len() != 4 {
            return Err(ntfs::NtfsError::Io(invalid("invalid $SII key length")));
        }
        Ok(Self(u32::from_le_bytes(slice.try_into().map_err(
            |_| ntfs::NtfsError::Io(invalid("invalid $SII key")),
        )?)))
    }
}
impl ntfs::indexes::NtfsIndexEntryData for SecurityEntry {
    fn data_from_slice(
        slice: &[u8],
        _position: ntfs::types::NtfsPosition,
    ) -> Result<Self, ntfs::NtfsError> {
        Ok(Self(slice.try_into().map_err(|_| {
            ntfs::NtfsError::Io(invalid("invalid $SII data length"))
        })?))
    }
}

pub(crate) fn validate_sii(
    _ntfs: &ntfs::Ntfs,
    secure: &ntfs::NtfsFile<'_>,
    cursor: &mut crate::Cursor,
    sds: &dyn ReadAt,
    descriptors: &HashMap<u32, Vec<u8>>,
) -> io::Result<()> {
    let mut attributes = secure.attributes();
    let mut root = None;
    let mut allocation = None;
    while let Some(item) = attributes.next(cursor) {
        let item = item.map_err(crate::ntfs_error)?;
        let attribute = item.to_attribute().map_err(crate::ntfs_error)?;
        if !attribute
            .name()
            .map_err(crate::ntfs_error)?
            .u16_iter()
            .eq("$SII".encode_utf16())
        {
            continue;
        }
        match attribute.ty().map_err(crate::ntfs_error)? {
            ntfs::NtfsAttributeType::IndexRoot => root = Some(item),
            ntfs::NtfsAttributeType::IndexAllocation => allocation = Some(item),
            _ => {}
        }
    }
    let index = ntfs::NtfsIndex::<SecurityIndex>::new(
        root.ok_or_else(|| invalid("$Secure:$SII root missing"))?,
        allocation,
    )
    .map_err(crate::ntfs_error)?;
    let mut entries = index.entries();
    let mut seen = std::collections::HashSet::new();
    let mut last = None;
    while let Some(entry) = entries.next(cursor) {
        let entry = entry.map_err(crate::ntfs_error)?;
        let key = entry
            .key()
            .ok_or_else(|| invalid("$SII key missing"))?
            .map_err(crate::ntfs_error)?
            .0;
        let header = entry
            .data()
            .ok_or_else(|| invalid("$SII data missing"))?
            .map_err(crate::ntfs_error)?
            .0;
        if last.is_some_and(|previous| previous >= key) || !seen.insert(key) {
            return Err(invalid("$SII index keys not strictly ordered"));
        }
        last = Some(key);
        if seen.len() > descriptors.len() || u32_at(&header, 4)? != key {
            return Err(invalid("$SII descriptor identity mismatch"));
        }
        let descriptor = descriptors
            .get(&key)
            .ok_or_else(|| invalid("$SII references missing descriptor"))?;
        if u32_at(&header, 0)? != hash(descriptor)
            || u32_at(&header, 16)? as usize != descriptor.len() + 20
        {
            return Err(invalid("$SII descriptor hash/length mismatch"));
        }
        let mut disk_header = [0; 20];
        sds.read_exact_at(u64_at(&header, 8)?, &mut disk_header)?;
        if disk_header != header {
            return Err(invalid("$SII and $SDS entry headers disagree"));
        }
    }
    if seen.len() != descriptors.len() {
        return Err(invalid("$SDS descriptor missing from $SII"));
    }
    Ok(())
}
