use crate::stream::{Bytes, Extent, LogicalStream, Wof};
use crate::{Cursor, Stream, invalid, ntfs_error, unsupported};
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;
use virtdisk::ReadAt;

pub(crate) fn u16_at(data: &[u8], offset: usize) -> io::Result<u16> {
    let b = data
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated NTFS u16"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
pub(crate) fn u32_at(data: &[u8], offset: usize) -> io::Result<u32> {
    let b = data
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("truncated NTFS u32"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub(crate) fn u64_at(data: &[u8], offset: usize) -> io::Result<u64> {
    let b = data
        .get(offset..offset + 8)
        .ok_or_else(|| invalid("truncated NTFS u64"))?;
    Ok(u64::from_le_bytes(
        b.try_into().map_err(|_| invalid("NTFS u64"))?,
    ))
}
fn utf16(data: &[u8]) -> io::Result<Vec<u16>> {
    if !data.len().is_multiple_of(2) {
        return Err(invalid("odd UTF16 length"));
    }
    Ok(data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect())
}
pub(crate) fn validate_name(name: &[u16]) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name.iter().any(|c| [0, 47, 92].contains(c))
        || name == [46]
        || name == [46, 46]
    {
        return Err(invalid("invalid NTFS directory name"));
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub(crate) struct Geometry {
    sector: usize,
    record: usize,
    cluster: u64,
}
impl Geometry {
    pub fn new(ntfs: &Ntfs) -> io::Result<Self> {
        let geometry = Self {
            sector: ntfs.sector_size() as usize,
            record: ntfs.file_record_size() as usize,
            cluster: u64::from(ntfs.cluster_size()),
        };
        if geometry.record > 65536
            || geometry.sector < 256
            || !geometry.record.is_multiple_of(geometry.sector)
        {
            return Err(invalid("invalid MFT/sector geometry"));
        }
        Ok(geometry)
    }
}
#[derive(Clone)]
pub(crate) struct Attributes {
    pub cached_stream_bytes: u64,
    pub storage_class: Option<u32>,
    pub attributes: u32,
    pub creation_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub security_id: u32,
    pub security_descriptor: Option<Vec<u8>>,
    pub reparse_data: Vec<u8>,
    pub extended_attributes: Vec<u8>,
    pub object_id: Vec<u8>,
    pub streams: Vec<Stream>,
}
#[derive(Clone)]
struct RawAttribute {
    ty: u32,
    name: Vec<u16>,
    instance: u16,
    flags: u16,
    lowest: u64,
    highest: u64,
    length: u64,
    initialized: u64,
    compression: u8,
    resident: Option<Vec<u8>>,
    runs: Vec<u8>,
}
fn record(
    ntfs: &Ntfs,
    source: &dyn ReadAt,
    file: &NtfsFile<'_>,
    geometry: Geometry,
    cursor: &mut Cursor,
) -> io::Result<Vec<RawAttribute>> {
    let mut context = source.context();
    context.record = Some(file.file_record_number() | (u64::from(file.sequence_number()) << 48));
    record_inner(ntfs, source, file, geometry, cursor)
        .map_err(|e| context.error("parse NTFS record", e))
}
fn record_inner(
    ntfs: &Ntfs,
    source: &dyn ReadAt,
    file: &NtfsFile<'_>,
    geometry: Geometry,
    cursor: &mut Cursor,
) -> io::Result<Vec<RawAttribute>> {
    let position = file
        .position()
        .value()
        .ok_or_else(|| invalid("MFT record has no physical location"))?
        .get();
    if let Some(budget) = source.budget() {
        budget.metadata(geometry.record as u64)?;
    }
    let mut data = vec![0; geometry.record];
    if geometry.record as u64 <= geometry.cluster {
        source.read_exact_at(position, &mut data)?;
    } else {
        let mft = ntfs.file(cursor, 0).map_err(ntfs_error)?;
        let item = mft
            .data(cursor, "")
            .ok_or_else(|| invalid("MFT data missing"))?
            .map_err(ntfs_error)?;
        let attribute = item.to_attribute().map_err(ntfs_error)?;
        let mut value = attribute.value(cursor).map_err(ntfs_error)?;
        let offset = file
            .file_record_number()
            .checked_mul(geometry.record as u64)
            .ok_or_else(|| invalid("MFT record offset overflow"))?;
        value
            .seek(cursor, std::io::SeekFrom::Start(offset))
            .map_err(ntfs_error)?;
        std::io::Read::read_exact(&mut value.attach(cursor), &mut data)?;
    }
    if data.get(..4) != Some(b"FILE") {
        return Err(invalid("invalid MFT magic"));
    }
    let usa = u16_at(&data, 4)? as usize;
    let count = u16_at(&data, 6)? as usize;
    if count != geometry.record / geometry.sector + 1
        || usa
            .checked_add(count * 2)
            .is_none_or(|end| end > data.len())
    {
        return Err(invalid("invalid MFT update sequence array"));
    }
    let signature = u16_at(&data, usa)?;
    for i in 1..count {
        let tail = i * geometry.sector - 2;
        if u16_at(&data, tail)? != signature {
            return Err(invalid("torn MFT update sequence"));
        }
        let original = u16_at(&data, usa + i * 2)?.to_le_bytes();
        data[tail..tail + 2].copy_from_slice(&original);
    }
    if u16_at(&data, 16)? != file.sequence_number() || u16_at(&data, 22)? & 1 == 0 {
        return Err(invalid("stale or deleted MFT record"));
    }
    let used = u32_at(&data, 24)? as usize;
    if used > data.len() {
        return Err(invalid("MFT used size exceeds record"));
    }
    let mut offset = u16_at(&data, 20)? as usize;
    let mut attributes = Vec::new();
    while offset + 4 <= used {
        if let Some(budget) = source.budget() {
            budget.work(1)?;
        }
        let ty = u32_at(&data, offset)?;
        if ty == u32::MAX {
            return Ok(attributes);
        }
        let size = u32_at(&data, offset + 4)? as usize;
        if size < 24
            || !size.is_multiple_of(8)
            || offset.checked_add(size).is_none_or(|end| end > used)
        {
            return Err(invalid("invalid raw MFT attribute size"));
        }
        if let Some(budget) = source.budget() {
            budget.metadata(std::mem::size_of::<RawAttribute>() as u64 + size as u64 * 2)?;
        }
        let a = &data[offset..offset + size];
        let nonresident = a[8];
        if nonresident > 1 {
            return Err(invalid("invalid attribute residency"));
        }
        let name_start = u16_at(a, 10)? as usize;
        let name_size = usize::from(a[9]) * 2;
        let name = if name_size == 0 {
            Vec::new()
        } else {
            utf16(
                a.get(name_start..name_start + name_size)
                    .ok_or_else(|| invalid("attribute name outside extent"))?,
            )?
        };
        if name.iter().any(|c| [0, 47, 58, 92].contains(c)) {
            return Err(invalid("invalid NTFS attribute name"));
        }
        let flags = u16_at(a, 12)?;
        let instance = u16_at(a, 14)?;
        let mut raw = RawAttribute {
            ty,
            name,
            instance,
            flags,
            lowest: 0,
            highest: 0,
            length: 0,
            initialized: 0,
            compression: 0,
            resident: None,
            runs: Vec::new(),
        };
        if nonresident == 0 {
            let length = u32_at(a, 16)? as usize;
            let start = u16_at(a, 20)? as usize;
            let bytes = a
                .get(start..start + length)
                .ok_or_else(|| invalid("resident value outside attribute"))?;
            raw.resident = Some(bytes.to_vec());
            raw.length = length as u64;
            raw.initialized = raw.length;
        } else {
            if size < 64 {
                return Err(invalid("nonresident header truncated"));
            }
            raw.lowest = u64_at(a, 16)?;
            raw.highest = u64_at(a, 24)?;
            raw.length = u64_at(a, 48)?;
            raw.initialized = u64_at(a, 56)?;
            raw.compression = a[34];
            let start = u16_at(a, 32)? as usize;
            if start < 64 || start >= size {
                return Err(invalid("runlist outside attribute"));
            }
            raw.runs = a[start..].to_vec();
        }
        attributes.push(raw);
        offset += size;
    }
    Err(invalid("MFT attribute end marker missing"))
}
fn runlist(a: &RawAttribute, geometry: Geometry, source: &dyn ReadAt) -> io::Result<Vec<Extent>> {
    let mut cursor = 0;
    let mut logical = a
        .lowest
        .checked_mul(geometry.cluster)
        .ok_or_else(|| invalid("VCN overflow"))?;
    let mut lcn = 0i64;
    let mut extents = Vec::new();
    while cursor < a.runs.len() {
        if let Some(budget) = source.budget() {
            budget.work(1)?;
        }
        let header = a.runs[cursor];
        cursor += 1;
        if header == 0 {
            break;
        }
        let n = usize::from(header & 15);
        let m = usize::from(header >> 4);
        if n == 0 || n > 8 || m > 8 || cursor + n + m > a.runs.len() {
            return Err(invalid("invalid runlist widths"));
        }
        let mut count = [0; 8];
        count[..n].copy_from_slice(&a.runs[cursor..cursor + n]);
        cursor += n;
        let length = u64::from_le_bytes(count)
            .checked_mul(geometry.cluster)
            .ok_or_else(|| invalid("run length overflow"))?;
        if length == 0 {
            return Err(invalid("zero-length NTFS run"));
        }
        let physical = if m == 0 {
            None
        } else {
            let sign = a.runs[cursor + m - 1] & 128 != 0;
            let mut delta = [if sign { 255 } else { 0 }; 8];
            delta[..m].copy_from_slice(&a.runs[cursor..cursor + m]);
            lcn = lcn
                .checked_add(i64::from_le_bytes(delta))
                .ok_or_else(|| invalid("LCN delta overflow"))?;
            let value = u64::try_from(lcn)
                .map_err(|_| invalid("negative LCN"))?
                .checked_mul(geometry.cluster)
                .ok_or_else(|| invalid("LCN overflow"))?;
            if value
                .checked_add(length)
                .is_none_or(|end| end > source.len())
            {
                return Err(invalid("NTFS run exceeds partition"));
            }
            Some(value)
        };
        cursor += m;
        extents.push(Extent {
            start: logical,
            length,
            physical,
        });
        logical = logical
            .checked_add(length)
            .ok_or_else(|| invalid("VCN end overflow"))?;
    }
    if a.length == 0 && extents.is_empty() && a.lowest == 0 && [0, u64::MAX].contains(&a.highest) {
        return Ok(extents);
    }
    let expected = a
        .highest
        .checked_add(1)
        .and_then(|v| v.checked_mul(geometry.cluster))
        .ok_or_else(|| invalid("highest VCN overflow"))?;
    if a.length != 0 && logical != expected {
        return Err(invalid("runlist does not match declared VCN range"));
    }
    Ok(extents)
}
fn build(
    parts: &[RawAttribute],
    source: Arc<dyn ReadAt>,
    geometry: Geometry,
) -> io::Result<Arc<dyn ReadAt>> {
    let context = source.context();
    if let Some(budget) = source.budget() {
        budget.metadata(parts.iter().map(|a| a.runs.len() as u64 * 32).sum())?;
    }
    build_inner(parts, source, geometry).map_err(|e| context.error("decode NTFS attribute", e))
}
fn build_inner(
    parts: &[RawAttribute],
    source: Arc<dyn ReadAt>,
    geometry: Geometry,
) -> io::Result<Arc<dyn ReadAt>> {
    let first = parts
        .first()
        .ok_or_else(|| invalid("empty attribute group"))?;
    if first.flags & 0x4000 != 0 {
        return Err(unsupported(
            "EFS encrypted attribute requires raw EFS capture",
        ));
    }
    if let Some(bytes) = &first.resident {
        if parts.len() != 1 {
            return Err(invalid("duplicate resident attribute"));
        }
        if let Some(budget) = source.budget() {
            if bytes.len() as u64 > budget.limits().attribute_bytes {
                return Err(unsupported(
                    "resident attribute exceeds configured attribute limit",
                ));
            }
            budget.metadata(bytes.len() as u64)?;
            return Ok(virtdisk::contextual_reader(
                budget.reader(Arc::new(Bytes(bytes.clone()))),
                source.context(),
            ));
        }
        return Ok(Arc::new(Bytes(bytes.clone())));
    }
    if first.lowest != 0 || first.initialized > first.length {
        return Err(invalid("invalid initial attribute extent"));
    }
    let compression = if first.flags & 1 != 0 {
        if first.compression != 4 {
            return Err(unsupported("unsupported NTFS compression-unit exponent"));
        }
        geometry
            .cluster
            .checked_mul(16)
            .filter(|n| *n <= 1024 * 1024)
            .ok_or_else(|| unsupported("NTFS compression unit exceeds limit"))?
    } else {
        0
    };
    let mut extents = Vec::new();
    let mut end = 0;
    for part in parts {
        if part.resident.is_some()
            || part.flags != first.flags
            || part.lowest.checked_mul(geometry.cluster) != Some(end)
        {
            return Err(invalid("discontinuous or inconsistent attribute extents"));
        }
        let decoded = runlist(part, geometry, source.as_ref())?;
        for extent in decoded {
            end = extent
                .start
                .checked_add(extent.length)
                .ok_or_else(|| invalid("run extent overflow"))?;
            extents.push(extent);
        }
    }
    if end < first.length {
        return Err(invalid("runlist shorter than attribute data"));
    }
    Ok(Arc::new(LogicalStream {
        source,
        length: first.length,
        initialized: first.initialized,
        extents,
        compression_unit: compression,
    }))
}
fn bytes(data: &dyn ReadAt, maximum: usize) -> io::Result<Vec<u8>> {
    bytes_inner(data, maximum).map_err(|e| data.context().error("materialize NTFS attribute", e))
}
fn bytes_inner(data: &dyn ReadAt, maximum: usize) -> io::Result<Vec<u8>> {
    let maximum = data.budget().map_or(maximum as u64, |b| {
        b.limits().attribute_bytes.min(maximum as u64)
    });
    if data.len() > maximum {
        return Err(unsupported("metadata attribute exceeds safety limit"));
    }
    if let Some(budget) = data.budget() {
        budget.metadata(data.len())?;
    }
    let mut result = vec![0; data.len() as usize];
    data.read_exact_at(0, &mut result)?;
    Ok(result)
}

pub(crate) fn read(
    ntfs: &Ntfs,
    source: Arc<dyn ReadAt>,
    geometry: Geometry,
    file: &NtfsFile<'_>,
    cursor: &mut Cursor,
) -> io::Result<Attributes> {
    let mut raw = record(ntfs, source.as_ref(), file, geometry, cursor)?;
    let lists = raw
        .iter()
        .filter(|a| a.ty == 0x20)
        .cloned()
        .collect::<Vec<_>>();
    if lists.len() > 1 {
        return Err(invalid("duplicate ATTRIBUTE_LIST"));
    }
    if let Some(list) = lists.first() {
        let mut context = source.context();
        context.record =
            Some(file.file_record_number() | (u64::from(file.sequence_number()) << 48));
        context.attribute = Some(0x20);
        context.stream = Some(list.name.clone());
        let list_source = virtdisk::contextual_reader(source.clone(), context);
        let value = build(std::slice::from_ref(list), list_source.clone(), geometry)?;
        let data = bytes(value.as_ref(), 64 * 1024 * 1024)?;
        let mut offset = 0;
        let mut records = std::collections::HashMap::new();
        records.insert(file.file_record_number(), raw.clone());
        let mut selected = Vec::new();
        let mut seen = HashSet::new();
        while offset + 26 <= data.len() {
            if let Some(budget) = source.budget() {
                budget.work(1)?;
            }
            let ty = u32_at(&data, offset)?;
            if ty == 0 || ty == u32::MAX {
                break;
            }
            let size = u16_at(&data, offset + 4)? as usize;
            if size < 26 || offset + size > data.len() {
                return Err(invalid("invalid ATTRIBUTE_LIST entry"));
            }
            let entry = &data[offset..offset + size];
            let name_length = usize::from(entry[6]) * 2;
            let name_offset = usize::from(entry[7]);
            let name = if name_length == 0 {
                Vec::new()
            } else {
                utf16(
                    entry
                        .get(name_offset..name_offset + name_length)
                        .ok_or_else(|| invalid("ATTRIBUTE_LIST name out of bounds"))?,
                )?
            };
            let lowest = u64_at(entry, 8)?;
            let reference = u64_at(entry, 16)?;
            let number = reference & 0xffff_ffff_ffff;
            let sequence = (reference >> 48) as u16;
            let instance = u16_at(entry, 24)?;
            if !records.contains_key(&number) {
                if records.len().saturating_sub(1) as u64
                    >= source
                        .budget()
                        .map_or(65536, |b| b.limits().attribute_list_records)
                {
                    return Err(list_source.context().error(
                        "expand NTFS attribute list",
                        unsupported("too many ATTRIBUTE_LIST records"),
                    ));
                }
                let extra = ntfs.file(cursor, number).map_err(ntfs_error)?;
                if extra.sequence_number() != sequence {
                    return Err(invalid("stale ATTRIBUTE_LIST file reference"));
                }
                let location = extra
                    .position()
                    .value()
                    .ok_or_else(|| invalid("extension record location missing"))?
                    .get();
                let mut base = [0; 8];
                source.read_exact_at(location + 32, &mut base)?;
                let expected =
                    file.file_record_number() | (u64::from(file.sequence_number()) << 48);
                if u64::from_le_bytes(base) != expected {
                    return Err(invalid("ATTRIBUTE_LIST extension belongs to another file"));
                }
                records.insert(
                    number,
                    record(ntfs, source.as_ref(), &extra, geometry, cursor)?,
                );
            } else if number == file.file_record_number() && sequence != file.sequence_number() {
                return Err(invalid("stale base ATTRIBUTE_LIST reference"));
            }
            let candidate = records
                .get(&number)
                .and_then(|attrs| {
                    attrs.iter().find(|a| {
                        a.instance == instance && a.ty == ty && a.name == name && a.lowest == lowest
                    })
                })
                .ok_or_else(|| invalid("ATTRIBUTE_LIST target attribute mismatch"))?;
            if !seen.insert((number, instance)) {
                return Err(invalid("duplicate ATTRIBUTE_LIST target"));
            }
            selected.push(candidate.clone());
            offset += size;
        }
        // Attributes absent from the list must not be silently discarded.
        for attribute in &raw {
            if attribute.ty != 0x20
                && !seen.contains(&(file.file_record_number(), attribute.instance))
            {
                return Err(invalid("base attribute missing from ATTRIBUTE_LIST"));
            }
        }
        raw = selected;
    }
    let mut grouped: BTreeMap<(u32, Vec<u16>), Vec<RawAttribute>> = BTreeMap::new();
    for a in raw {
        if a.ty != 0x30 && a.ty != 0x20 {
            grouped.entry((a.ty, a.name.clone())).or_default().push(a);
        }
    }
    for parts in grouped.values_mut() {
        parts.sort_by_key(|a| a.lowest);
    }
    let standard = grouped
        .remove(&(0x10, Vec::new()))
        .ok_or_else(|| invalid("STANDARD_INFORMATION missing"))?;
    let value = build(&standard, source.clone(), geometry)?;
    let info = bytes(value.as_ref(), 4096)?;
    if info.len() < 48 {
        return Err(invalid("STANDARD_INFORMATION shorter than legacy header"));
    }
    // Windows stores its per-directory case flag in the formerly reserved
    // version-number field. Confirmed against an empty Windows-created case
    // directory and its control; WIM has no restoration field for this state.
    if file.is_directory() && u32_at(&info, 40)? & 1 != 0 {
        return Err(unsupported(
            "case-sensitive NTFS directories are not representable in WIM",
        ));
    }
    let cached_stream_bytes = grouped
        .values()
        .flatten()
        .map(|a| {
            std::mem::size_of::<RawAttribute>() as u64
                + a.name.len() as u64 * 2
                + a.resident.as_ref().map_or(0, |b| b.len() as u64)
                + a.runs.len() as u64 * 32
        })
        .sum();
    let mut result = Attributes {
        cached_stream_bytes,
        storage_class: None,
        // INDEX_PRESENT, VIEW_INDEX and EA_PRESENT are internal NTFS flags, not Win32
        // FILE_ATTRIBUTE bits returned by Windows filesystem queries.
        attributes: u32_at(&info, 32)? & !0x30040000,
        creation_time: u64_at(&info, 0)?,
        write_time: u64_at(&info, 8)?,
        access_time: u64_at(&info, 24)?,
        security_id: if info.len() >= 56 {
            u32_at(&info, 52)?
        } else {
            0
        },
        security_descriptor: None,
        reparse_data: Vec::new(),
        extended_attributes: Vec::new(),
        object_id: Vec::new(),
        streams: Vec::new(),
    };
    if result.attributes & 0x4000 != 0 {
        return Err(unsupported("EFS encrypted file is unsupported offline"));
    }
    for ((ty, name), parts) in grouped {
        let mut context = source.context();
        context.record =
            Some(file.file_record_number() | (u64::from(file.sequence_number()) << 48));
        context.attribute = Some(ty);
        context.stream = Some(name.clone());
        let source = virtdisk::contextual_reader(source.clone(), context);
        let context = source.context();
        (|| -> io::Result<()> {
            match ty {
                0x80 => result.streams.push(Stream {
                    name,
                    data: build(&parts, source.clone(), geometry)?,
                }),
                0x50 => {
                    result.security_descriptor = Some(bytes(
                        build(&parts, source.clone(), geometry)?.as_ref(),
                        1024 * 1024,
                    )?)
                }
                0xc0 => {
                    result.reparse_data =
                        bytes(build(&parts, source.clone(), geometry)?.as_ref(), 16384)?
                }
                0xe0 => {
                    result.extended_attributes =
                        bytes(build(&parts, source.clone(), geometry)?.as_ref(), 65536)?
                }
                0x40 => {
                    result.object_id =
                        bytes(build(&parts, source.clone(), geometry)?.as_ref(), 64)?;
                    if ![16, 32, 48, 64].contains(&result.object_id.len()) {
                        return Err(invalid("invalid OBJECT_ID size"));
                    }
                }
                0xd0 => {} // EA_INFORMATION is derived from the complete EA list.
                0x90 => {
                    // Validate the third-party index reader's allocation size before
                    // constructing its index-record buffers.
                    let root = bytes(build(&parts, source.clone(), geometry)?.as_ref(), 65536)?;
                    if root.len() < 32 {
                        return Err(invalid("INDEX_ROOT header is truncated"));
                    }
                    let size = u32_at(&root, 8)?;
                    if size < geometry.sector as u32
                        || size > 65536
                        || !size.is_multiple_of(geometry.sector as u32)
                    {
                        return Err(unsupported(
                            "INDEX_ROOT allocation record exceeds bounded geometry",
                        ));
                    }
                }
                0xa0 | 0xb0 | 0x60 | 0x70 => {} // Filesystem indexes, bitmaps and volume labels.
                0x100 => {
                    if name.iter().copied().eq("$DSC".encode_utf16()) {
                        let dsc = bytes(build(&parts, source.clone(), geometry)?.as_ref(), 8)?;
                        result.storage_class = Some(storage_class(&dsc)?);
                    }
                    // TxF bookkeeping is filesystem transaction state, excluded by
                    // native Windows backup and WIM capture; it is not a data stream.
                    if !name.iter().copied().eq("$TXF_DATA".encode_utf16())
                        && !name.iter().copied().eq("$DSC".encode_utf16())
                    {
                        return Err(unsupported(format!(
                            "unknown logged utility stream {:?} on record {}",
                            name,
                            file.file_record_number()
                        )));
                    }
                }
                _ => return Err(unsupported(format!("unsupported NTFS attribute {ty:#x}"))),
            }
            Ok(())
        })()
        .map_err(|e| context.error("capture NTFS attribute", e))?;
    }
    normalize_ea(&mut result.extended_attributes)?;
    if !result.reparse_data.is_empty() {
        let tag = u32_at(&result.reparse_data, 0)?;
        let length = u16_at(&result.reparse_data, 4)? as usize;
        if length + 8 != result.reparse_data.len() {
            return Err(invalid("reparse length mismatch"));
        }
        if tag == 0x80000017 {
            if u32_at(&result.reparse_data, 8)? != 1
                || u32_at(&result.reparse_data, 12)? != 2
                || u32_at(&result.reparse_data, 16)? != 1
            {
                return Err(unsupported("WOF WIM/detached provider is unsupported"));
            }
            let algorithm = u32_at(&result.reparse_data, 20)?;
            let unnamed = result
                .streams
                .iter()
                .position(|s| s.name.is_empty())
                .ok_or_else(|| invalid("WOF unnamed stream missing"))?;
            let compressed = result
                .streams
                .iter()
                .position(|s| {
                    s.name
                        .iter()
                        .copied()
                        .eq("WofCompressedData".encode_utf16())
                })
                .ok_or_else(|| invalid("WOF compressed stream missing"))?;
            let logical = Arc::new(Wof::new(
                result.streams[compressed].data.clone(),
                result.streams[unnamed].data.len(),
                algorithm,
            )?);
            result.streams[unnamed].data = logical;
            result.streams.remove(compressed);
            result.reparse_data.clear();
            result.attributes &= !(0x400 | 0x200);
        } else if ![0xa0000003, 0xa000000c, 0x8000001b].contains(&tag) {
            return Err(unsupported(format!(
                "unsupported reparse provider {tag:#x}"
            )));
        }
    }
    if result.attributes & 0x400 != 0 && result.reparse_data.is_empty() {
        return Err(invalid("reparse attribute without reparse data"));
    }
    Ok(result)
}
fn normalize_ea(ea: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < ea.len() {
        let next = u32_at(ea, offset)? as usize;
        let name = *ea
            .get(offset + 5)
            .ok_or_else(|| invalid("EA header truncated"))? as usize;
        let value = u16_at(ea, offset + 6)? as usize;
        let size = 8 + name + 1 + value;
        if offset + size > ea.len() || ea[offset + 8 + name] != 0 {
            return Err(invalid("EA value/name truncated"));
        }
        if next == 0 || offset + next >= ea.len() {
            if next != 0 && next < size {
                return Err(invalid("invalid final EA offset"));
            }
            ea[offset..offset + 4].fill(0);
            return Ok(());
        }
        if next < size || !next.is_multiple_of(4) {
            return Err(invalid("invalid EA next offset"));
        }
        offset += next;
    }
    Ok(())
}

pub(crate) fn volume_flags(
    ntfs: &Ntfs,
    source: &dyn ReadAt,
    geometry: Geometry,
    cursor: &mut Cursor,
) -> io::Result<u16> {
    let volume = ntfs.file(cursor, 3).map_err(ntfs_error)?;
    let attributes = record(ntfs, source, &volume, geometry, cursor)?;
    let information = attributes
        .iter()
        .find(|a| a.ty == 0x70 && a.name.is_empty())
        .ok_or_else(|| invalid("VOLUME_INFORMATION missing"))?;
    let data = information
        .resident
        .as_ref()
        .ok_or_else(|| invalid("VOLUME_INFORMATION must be resident"))?;
    u16_at(data, 10)
}

fn storage_class(dsc: &[u8]) -> io::Result<u32> {
    if dsc.len() != 8 || u32_at(dsc, 4)? != 0 {
        return Err(unsupported(
            "invalid or unsupported $DSC storage class flags",
        ));
    }
    u32_at(dsc, 0)
}
#[cfg(test)]
mod storage_class_tests {
    #[test]
    fn preserves_native_dsc_class_and_rejects_unknown_flags_or_sizes() {
        assert_eq!(super::storage_class(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(), 2);
        for bytes in [&[2, 0, 0, 0][..], &[2, 0, 0, 0, 1, 0, 0, 0][..]] {
            assert_eq!(
                super::storage_class(bytes).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
    }
}
