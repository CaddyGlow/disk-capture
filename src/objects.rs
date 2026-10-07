use crate::attributes::u64_at;
use crate::{Cursor, invalid, ntfs_error};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsIndex};
use std::{collections::HashMap, io};

#[derive(Clone, Debug)]
struct ObjectIndex;
#[derive(Debug)]
struct ObjectKey([u8; 16]);
#[derive(Debug)]
struct ObjectEntry([u8; 56]);
impl ntfs::indexes::NtfsIndexEntryType for ObjectIndex {
    type KeyType = ObjectKey;
}
impl ntfs::indexes::NtfsIndexEntryHasData for ObjectIndex {
    type DataType = ObjectEntry;
}
impl ntfs::indexes::NtfsIndexEntryKey for ObjectKey {
    fn key_from_slice(
        slice: &[u8],
        _position: ntfs::types::NtfsPosition,
    ) -> Result<Self, ntfs::NtfsError> {
        Ok(Self(slice.try_into().map_err(|_| {
            ntfs::NtfsError::Io(invalid("invalid $ObjId key length"))
        })?))
    }
}
impl ntfs::indexes::NtfsIndexEntryData for ObjectEntry {
    fn data_from_slice(
        slice: &[u8],
        _position: ntfs::types::NtfsPosition,
    ) -> Result<Self, ntfs::NtfsError> {
        Ok(Self(slice.try_into().map_err(|_| {
            ntfs::NtfsError::Io(invalid("invalid $ObjId data length"))
        })?))
    }
}
/// Per-volume $ObjId index values: full file reference followed by birth IDs.
pub(crate) type ObjectMap = HashMap<[u8; 16], (u64, [u8; 48])>;
pub(crate) fn read(
    ntfs: &Ntfs,
    cursor: &mut Cursor,
) -> io::Result<(ObjectMap, Vec<virtdisk::CacheReservation>)> {
    let extend = ntfs.file(cursor, 11).map_err(ntfs_error)?;
    crate::attributes::read(
        ntfs,
        cursor.source.clone(),
        crate::attributes::Geometry::new(ntfs)?,
        &extend,
        cursor,
    )?;
    let index = extend.directory_index(cursor).map_err(ntfs_error)?;
    let mut entries = index.entries();
    let mut object_file: Option<NtfsFile<'_>> = None;
    while let Some(entry) = entries.next(cursor) {
        if let Some(budget) = cursor.source.budget() {
            budget.work(1)?;
            budget.metadata(128)?;
        }
        let entry = entry.map_err(ntfs_error)?;
        let name = entry
            .key()
            .ok_or_else(|| invalid("$Extend filename missing"))?
            .map_err(ntfs_error)?;
        if name.name().u16_iter().eq("$ObjId".encode_utf16()) {
            let file = entry.to_file(ntfs, cursor).map_err(ntfs_error)?;
            if file.sequence_number() != entry.file_reference().sequence_number() {
                return Err(invalid("stale $ObjId index reference"));
            }
            if object_file.replace(file).is_some() {
                return Err(invalid("duplicate $ObjId file"));
            }
        }
    }
    let Some(file) = object_file else {
        return Ok((HashMap::new(), Vec::new()));
    };
    crate::attributes::read(
        ntfs,
        cursor.source.clone(),
        crate::attributes::Geometry::new(ntfs)?,
        &file,
        cursor,
    )?;
    let mut attributes = file.attributes();
    let mut root = None;
    let mut allocation = None;
    while let Some(item) = attributes.next(cursor) {
        let item = item.map_err(ntfs_error)?;
        let attribute = item.to_attribute().map_err(ntfs_error)?;
        if !attribute
            .name()
            .map_err(ntfs_error)?
            .u16_iter()
            .eq("$O".encode_utf16())
        {
            continue;
        }
        match attribute.ty().map_err(ntfs_error)? {
            NtfsAttributeType::IndexRoot => root = Some(item),
            NtfsAttributeType::IndexAllocation => allocation = Some(item),
            _ => {}
        }
    }
    let index = NtfsIndex::<ObjectIndex>::new(
        root.ok_or_else(|| invalid("$ObjId:$O root missing"))?,
        allocation,
    )
    .map_err(ntfs_error)?;
    let mut entries = index.entries();
    let mut result = HashMap::new();
    let mut reservations = Vec::new();
    while let Some(entry) = entries.next(cursor) {
        if result.len() > 1_000_000 {
            return Err(crate::unsupported("object ID index exceeds capture limit"));
        }
        let entry = entry.map_err(ntfs_error)?;
        let key = entry
            .key()
            .ok_or_else(|| invalid("$ObjId key missing"))?
            .map_err(ntfs_error)?
            .0;
        let data = entry
            .data()
            .ok_or_else(|| invalid("$ObjId data missing"))?
            .map_err(ntfs_error)?
            .0;
        let reference = u64_at(&data, 0)?;
        let births = data[8..]
            .try_into()
            .map_err(|_| invalid("invalid birth ID length"))?;
        if let Some(budget) = cursor.source.budget() {
            reservations.push(budget.cache(256)?);
        }
        if result.insert(key, (reference, births)).is_some() {
            return Err(invalid("duplicate object ID index key"));
        }
    }
    Ok((result, reservations))
}
