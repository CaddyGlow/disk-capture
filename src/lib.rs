//! Read-only offline NTFS capture for immutable disk images.
//!
//! Directory indexes are read using the MIT/Apache `ntfs` parser. Raw attributes
//! are independently decoded to retain metadata and logical initialized-data
//! boundaries. The source must remain immutable until all deferred reads finish.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use virtdisk::ReadAt;

mod attributes;
mod objects;
mod security;
mod stream;
/// Experimental offline transaction primitives; not an NTFS alias writer.
pub mod transaction;
use attributes::{Attributes, Geometry};

/// Validate self-relative descriptor, SID, ACL and ACE extent bounds.
///
/// ACE payloads remain opaque; this does not validate access semantics or prove
/// that Windows can restore reserved security information.
pub fn validate_security_descriptor(descriptor: &[u8]) -> io::Result<()> {
    security::validate_descriptor(descriptor)
}

/// Captured tree; node zero is the volume root.
pub struct Manifest {
    /// Parent-before-child directory entries.
    pub nodes: Vec<Node>,
    /// Source NTFS volume serial number.
    pub volume_serial: u64,
}
/// One directory entry. Hard links share `file_id` and streams.
pub struct Node {
    /// Parent node index; absent only for node zero.
    pub parent: Option<usize>,
    /// Original UTF-16 name, including unpaired surrogates.
    pub name: Vec<u16>,
    /// DOS namespace alias, if present.
    pub short_name: Vec<u16>,
    /// MFT record number and sequence number combined as an NTFS file reference.
    pub file_id: u64,
    /// Windows FILE_ATTRIBUTE flags.
    pub attributes: u32,
    /// Creation time in Windows 100ns ticks.
    pub creation_time: u64,
    /// Last access time in Windows 100ns ticks.
    pub access_time: u64,
    /// Last write time in Windows 100ns ticks.
    pub write_time: u64,
    /// Exact self-relative security descriptor.
    pub security_descriptor: Vec<u8>,
    /// REPARSE_DATA_BUFFER including its tag and length header.
    pub reparse_data: Vec<u8>,
    /// Packed FILE_FULL_EA_INFORMATION entries.
    pub extended_attributes: Vec<u8>,
    /// Raw NTFS object identifier, including optional birth identifiers.
    pub object_id: Vec<u8>,
    /// Validated desired storage class from the NTFS $DSC utility attribute.
    pub storage_class: Option<u32>,
    /// Unnamed and named logical data streams.
    pub streams: Vec<Stream>,
}
/// A deferred logical data stream retaining the immutable source.
#[derive(Clone)]
pub struct Stream {
    /// UTF-16 stream name; empty for unnamed data.
    pub name: Vec<u16>,
    /// Bounded positional logical reader.
    pub data: Arc<dyn ReadAt>,
}

/// An NTFS volume opened without writes or journal replay.
pub struct Volume {
    source: Arc<dyn ReadAt>,
    ntfs: Ntfs,
    geometry: Geometry,
    security: HashMap<u32, Vec<u8>>,
    upcase: Vec<u16>,
    object_ids: objects::ObjectMap,
    cached_attributes: Mutex<HashMap<u64, CachedAttributes>>,
    cache_reservations: Vec<virtdisk::CacheReservation>,
}

struct CachedAttributes {
    attributes: Attributes,
    _reservation: virtdisk::CacheReservation,
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
pub(crate) fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
pub(crate) fn ntfs_error(error: ntfs::NtfsError) -> io::Error {
    use ntfs::NtfsError::*;
    let error = match error {
        Io(error) => return error,
        error => error,
    };
    let kind = match &error {
        AttributeNotFound { .. } => io::ErrorKind::NotFound,
        NotADirectory { .. } => io::ErrorKind::NotADirectory,
        AttributeOfDifferentType { .. }
        | BufferTooSmall { .. }
        | InvalidFileRecordNumber { .. }
        | UnexpectedAttributeListAttribute { .. }
        | UnexpectedNonResidentAttribute { .. }
        | UnexpectedResidentAttribute { .. }
        | InvalidTime => io::ErrorKind::InvalidInput,
        UnsupportedAttributeType { .. }
        | UnsupportedClusterSize { .. }
        | UnsupportedFileNamespace { .. }
        | UnsupportedSectorSize { .. } => io::ErrorKind::Unsupported,
        // These variants identify invalid on-disk structures, bounds or references.
        InvalidAttributeLength { .. }
        | InvalidAttributeNameLength { .. }
        | InvalidAttributeNameOffset { .. }
        | InvalidByteCountInDataRunHeader { .. }
        | InvalidClusterCountInDataRunHeader { .. }
        | InvalidFileAllocatedSize { .. }
        | InvalidFileSignature { .. }
        | InvalidFileUsedSize { .. }
        | InvalidIndexAllocatedSize { .. }
        | InvalidIndexEntryDataRange { .. }
        | InvalidIndexEntrySize { .. }
        | InvalidIndexRootEntriesOffset { .. }
        | InvalidIndexRootUsedSize { .. }
        | InvalidIndexSignature { .. }
        | InvalidIndexUsedSize { .. }
        | InvalidNonResidentValueDataRange { .. }
        | InvalidResidentAttributeValueLength { .. }
        | InvalidResidentAttributeValueOffset { .. }
        | InvalidRecordSizeInfo { .. }
        | InvalidSectorsPerCluster { .. }
        | InvalidStructuredValueSize { .. }
        | InvalidTwoByteSignature { .. }
        | InvalidUpcaseTableSize { .. }
        | InvalidUpdateSequenceCount { .. }
        | InvalidUpdateSequenceNumberRange { .. }
        | InvalidVcnInDataRunHeader { .. }
        | LcnTooBig { .. }
        | MissingIndexAllocation { .. }
        | TotalSectorsTooBig { .. }
        | UpdateSequenceArrayExceedsRecordSize { .. }
        | UpdateSequenceNumberMismatch { .. }
        | VcnMismatchInIndexAllocation { .. }
        | VcnOutOfBoundsInIndexAllocation { .. }
        | VcnTooBig { .. }
        | InvalidMftLcn => io::ErrorKind::InvalidData,
        // NtfsError is non-exhaustive; future API/request variants need review.
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

/// A private seek cursor over a positional reader; cursors do not interfere.
struct Cursor {
    source: Arc<dyn ReadAt>,
    position: u64,
}
impl Cursor {
    fn new(source: Arc<dyn ReadAt>) -> Self {
        Self {
            source,
            position: 0,
        }
    }
}
impl Read for Cursor {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let count = destination
            .len()
            .min(self.source.len().saturating_sub(self.position) as usize);
        if count != 0 {
            if let Some(budget) = self.source.budget() {
                budget.metadata(count as u64)?;
            }
            self.source
                .read_exact_at(self.position, &mut destination[..count])?;
        }
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for Cursor {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        let position = match offset {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => self.source.len().checked_add_signed(n),
        }
        .ok_or_else(|| invalid("negative or overflowing NTFS cursor seek"))?;
        self.position = position;
        Ok(position)
    }
}

impl Volume {
    /// Open a clean NTFS 3.x volume. Dirty/unsupported state fails closed.
    pub fn open(source: Arc<dyn ReadAt>) -> io::Result<Self> {
        Self::open_with_limits(source, virtdisk::ParserLimits::default())
    }

    /// Open with caller-tightened metadata, work, traversal and decoding limits.
    pub fn open_with_limits(
        source: Arc<dyn ReadAt>,
        limits: virtdisk::ParserLimits,
    ) -> io::Result<Self> {
        let context = source.context();
        limits.validate()?;
        let budget = source
            .budget()
            .filter(|b| b.limits() == limits)
            .map_or_else(|| virtdisk::ReadBudget::new(limits), Ok)?;
        let source = budget.reader(source);
        Self::open_inner(source)
            .map_err(|e| context.error("open NTFS volume", e))
            .map_err(io::Error::from)
    }

    fn open_inner(source: Arc<dyn ReadAt>) -> io::Result<Self> {
        if source.len() >= 11 {
            let mut oem = [0; 8];
            source.read_exact_at(3, &mut oem)?;
            if &oem == b"-FVE-FS-" {
                return Err(unsupported(
                    "BitLocker-encrypted volume: decrypt the volume before offline capture; locked/encrypted NTFS is not supported",
                ));
            }
        }
        let mut boot = [0; 512];
        source.read_exact_at(0, &mut boot)?;
        let ntfs = Ntfs::new(&mut std::io::Cursor::new(boot)).map_err(ntfs_error)?;
        let mut cursor = Cursor::new(source.clone());
        if ntfs.size() > source.len() {
            return Err(invalid("NTFS volume exceeds partition"));
        }
        let geometry = Geometry::new(&ntfs)?;
        let info = ntfs.volume_info(&mut cursor).map_err(ntfs_error)?;
        if info.major_version() != 3 {
            return Err(unsupported("only NTFS 3.x is supported"));
        }
        let flags = attributes::volume_flags(&ntfs, source.as_ref(), geometry, &mut cursor)?;
        // Historical NT4 and modern short-name policy bits are not recovery state.
        // The 0x80 policy is present on the clean Windows-formatted fixture.
        if flags & !(8 | 0x80) != 0 {
            return Err(unsupported(format!(
                "NTFS volume requires recovery or has unknown state: flags {flags:#x}"
            )));
        }
        let mut volume = Self {
            source,
            ntfs,
            geometry,
            security: HashMap::new(),
            upcase: Vec::new(),
            object_ids: HashMap::new(),
            cached_attributes: Mutex::new(HashMap::new()),
            cache_reservations: Vec::new(),
        };
        let secure = volume.ntfs.file(&mut cursor, 9).map_err(ntfs_error)?;
        let attributes = volume.read_attributes(&secure, &mut cursor)?;
        let sds = attributes
            .streams
            .iter()
            .find(|s| s.name == "$SDS".encode_utf16().collect::<Vec<_>>())
            .ok_or_else(|| invalid("$Secure:$SDS missing"))?;
        volume.cache_reservations.push(
            volume
                .source
                .budget()
                .ok_or_else(|| invalid("missing NTFS parser budget"))?
                .cache(
                    sds.data
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| unsupported("SDS cache size overflow"))?,
                )?,
        );
        volume.security = security::read_sds(sds.data.as_ref())?;
        security::validate_sii(
            &volume.ntfs,
            &secure,
            &mut cursor,
            sds.data.as_ref(),
            &volume.security,
        )
        .map_err(|error| {
            volume
                .source
                .context()
                .error("validate $Secure:$SII", error)
        })?;
        let upcase = volume.ntfs.file(&mut cursor, 10).map_err(ntfs_error)?;
        let attrs = volume.read_attributes(&upcase, &mut cursor)?;
        let data = attrs
            .streams
            .iter()
            .find(|s| s.name.is_empty())
            .ok_or_else(|| invalid("$UpCase data missing"))?;
        if data.data.len() != 131072 {
            return Err(invalid("invalid $UpCase table size"));
        }
        volume.cache_reservations.push(
            volume
                .source
                .budget()
                .ok_or_else(|| invalid("missing NTFS parser budget"))?
                .cache(131072)?,
        );
        let mut table = vec![0; 131072];
        data.data.read_exact_at(0, &mut table)?;
        volume.upcase = table
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let (object_ids, reservations) = objects::read(&volume.ntfs, &mut cursor)?;
        volume.object_ids = object_ids;
        volume.cache_reservations.extend(reservations);
        Ok(volume)
    }

    fn read_attributes(&self, file: &NtfsFile<'_>, cursor: &mut Cursor) -> io::Result<Attributes> {
        let id = file.file_record_number() | (u64::from(file.sequence_number()) << 48);
        let mut cache = self
            .cached_attributes
            .lock()
            .map_err(|_| io::Error::other("NTFS attribute cache poisoned"))?;
        if let Some(attributes) = cache.get(&id) {
            if let Some(budget) = self.source.budget() {
                budget.metadata(
                    attributes.attributes.reparse_data.len() as u64
                        + attributes.attributes.extended_attributes.len() as u64
                        + attributes.attributes.object_id.len() as u64
                        + attributes
                            .attributes
                            .streams
                            .iter()
                            .map(|s| s.name.len() as u64 * 2 + std::mem::size_of::<Stream>() as u64)
                            .sum::<u64>(),
                )?;
            }
            return Ok(attributes.attributes.clone());
        }
        let mut context = self.source.context();
        context.record = Some(id);
        let attributes =
            attributes::read(&self.ntfs, self.source.clone(), self.geometry, file, cursor)
                .map_err(|e| context.error("read NTFS attributes", e))
                .map_err(io::Error::from)?;
        // Include conservative map, Arc, contextual-reader and per-stream overhead.
        let bytes = (1024
            + attributes.streams.len() * 1024
            + std::mem::size_of::<Attributes>()
            + attributes.security_descriptor.as_ref().map_or(0, Vec::len)
            + attributes.reparse_data.len()
            + attributes.extended_attributes.len()
            + attributes.object_id.len()
            + attributes
                .streams
                .iter()
                .map(|s| std::mem::size_of::<Stream>() + s.name.len() * 2)
                .sum::<usize>()) as u64;
        let bytes = bytes
            .checked_add(attributes.cached_stream_bytes)
            .ok_or_else(|| unsupported("attribute cache size overflow"))?;
        let reservation = self
            .source
            .budget()
            .ok_or_else(|| invalid("missing NTFS parser budget"))?
            .cache(bytes)?;
        cache.insert(
            id,
            CachedAttributes {
                attributes: attributes.clone(),
                _reservation: reservation,
            },
        );
        Ok(attributes)
    }

    /// Capture every user directory entry with complete supported metadata.
    ///
    /// NTFS internal records 0..15 are excluded. Unsupported data providers,
    /// encryption, case-sensitive directories, and inconsistent references fail.
    pub fn capture_manifest(&self) -> io::Result<Manifest> {
        self.capture_manifest_with_filter(|_| true)
    }

    /// Capture entries admitted by a path policy before reading their metadata.
    /// The predicate receives original UTF-16 components relative to the root.
    /// Rejecting a directory excludes its entire subtree. The root is retained.
    /// Hibernation safety is checked independently of user exclusions.
    pub fn capture_manifest_with_filter(
        &self,
        mut include: impl FnMut(&[Vec<u16>]) -> bool,
    ) -> io::Result<Manifest> {
        self.capture_manifest_with_fallible_filter(|path| Ok(include(path)))
    }

    /// Capture with a fallible pre-attribute filter for cancellation and budgets.
    /// Rejected directories skip their subtree; errors abort without a manifest.
    pub fn capture_manifest_with_fallible_filter(
        &self,
        include: impl FnMut(&[Vec<u16>]) -> io::Result<bool>,
    ) -> io::Result<Manifest> {
        self.capture_manifest_inner(include)
            .map_err(|e| self.source.context().error("capture NTFS tree", e))
            .map_err(io::Error::from)
    }
    fn capture_manifest_inner(
        &self,
        mut include: impl FnMut(&[Vec<u16>]) -> io::Result<bool>,
    ) -> io::Result<Manifest> {
        self.check_hibernation()?;
        let mut cursor = Cursor::new(self.source.clone());
        let root = self.ntfs.root_directory(&mut cursor).map_err(ntfs_error)?;
        let root_attributes = self.read_attributes(&root, &mut cursor)?;
        let mut nodes = vec![self.node(&root, root_attributes, None, Vec::new(), Vec::new())?];
        let mut pending = vec![(
            0,
            root.file_record_number(),
            root.sequence_number(),
            Vec::<Vec<u16>>::new(),
        )];
        let mut directories = HashSet::new();
        directories.insert(root.file_record_number());
        while let Some((parent, number, sequence, parent_path)) = pending.pop() {
            let directory = self.ntfs.file(&mut cursor, number).map_err(ntfs_error)?;
            if directory.sequence_number() != sequence {
                return Err(invalid("stale directory reference"));
            }
            let index = directory.directory_index(&mut cursor).map_err(ntfs_error)?;
            let mut entries = index.entries();
            let mut children = Vec::new();
            let mut aliases: HashMap<u64, Vec<Vec<u16>>> = HashMap::new();
            while let Some(entry) = entries.next(&mut cursor) {
                if let Some(budget) = self.source.budget() {
                    budget.work(1)?;
                    budget.metadata(256)?;
                }
                let entry = entry.map_err(ntfs_error)?;
                let filename = entry
                    .key()
                    .ok_or_else(|| invalid("directory index has no filename"))?
                    .map_err(ntfs_error)?;
                let file = entry.to_file(&self.ntfs, &mut cursor).map_err(ntfs_error)?;
                if file.file_record_number() < 16 || file.file_record_number() == 5 {
                    continue;
                }
                let parent_reference = filename.parent_directory_reference();
                if parent_reference.file_record_number() != number
                    || parent_reference.sequence_number() != sequence
                {
                    return Err(invalid(
                        "directory index filename has a stale/wrong parent reference",
                    ));
                }
                let reference = entry.file_reference();
                if reference.sequence_number() != file.sequence_number() {
                    return Err(invalid("stale NTFS index file reference"));
                }
                if let Some(budget) = self.source.budget() {
                    budget.metadata(filename.name().u16_iter().count() as u64 * 2)?;
                }
                let name = filename.name().u16_iter().collect::<Vec<_>>();
                attributes::validate_name(&name)?;
                if filename.namespace() == NtfsFileNamespace::Dos {
                    aliases
                        .entry(file.file_record_number())
                        .or_default()
                        .push(name);
                    continue;
                }
                children.push((file, name, filename.namespace()));
            }
            // Only Win32 namespace entries own separate DOS names. Hard links
            // created in the POSIX namespace must not inherit another link's
            // alias. Count before exclusions to preserve ambiguous Win32 pairs.
            let mut long_names_per_file = HashMap::<u64, usize>::new();
            for (file, _, namespace) in &children {
                if *namespace == NtfsFileNamespace::Win32 {
                    *long_names_per_file
                        .entry(file.file_record_number())
                        .or_default() += 1;
                }
            }
            let mut names = HashSet::new();
            for (file, name, namespace) in children {
                if let Some(budget) = self.source.budget() {
                    if parent_path.len() as u64 >= budget.limits().recursion_depth {
                        return Err(unsupported(
                            "NTFS traversal exceeds configured recursion limit",
                        ));
                    }
                    budget.metadata(
                        (name.len() * 2 + parent_path.iter().map(|p| p.len() * 2).sum::<usize>())
                            as u64,
                    )?;
                }
                let mut path = parent_path.clone();
                path.push(name.clone());
                if !include(&path)? {
                    continue;
                }
                if !names.insert(name.clone()) {
                    return Err(invalid("duplicate NTFS directory filename"));
                }
                let short = dos_short_name(
                    namespace,
                    &name,
                    aliases
                        .get(&file.file_record_number())
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                    long_names_per_file
                        .get(&file.file_record_number())
                        .copied()
                        .unwrap_or_default(),
                )?;
                let mut context = self.source.context();
                context.record =
                    Some(file.file_record_number() | (u64::from(file.sequence_number()) << 48));
                context.path = Some(path.clone());
                let attrs = self
                    .read_attributes(&file, &mut cursor)
                    .map_err(|e| context.clone().error("capture NTFS entry", e))
                    .map_err(io::Error::from)?;
                let id = nodes.len();
                let node = self
                    .node(&file, attrs, Some(parent), name, short)
                    .map_err(|e| context.error("capture NTFS metadata", e))
                    .map_err(io::Error::from)?;
                if file.is_directory() && node.reparse_data.is_empty() {
                    if !directories.insert(file.file_record_number()) {
                        return Err(invalid("NTFS directory cycle or alias"));
                    }
                    pending.push((id, file.file_record_number(), file.sequence_number(), path));
                }
                nodes.push(node);
            }
        }
        Ok(Manifest {
            nodes,
            volume_serial: self.ntfs.serial_number(),
        })
    }

    fn fold(&self, name: &[u16]) -> Vec<u16> {
        name.iter().map(|c| self.upcase[usize::from(*c)]).collect()
    }
    fn check_hibernation(&self) -> io::Result<()> {
        let path = vec!["hiberfil.sys".encode_utf16().collect()];
        match self.read_file(&path, &[]) {
            Ok(data) => {
                let mut signature = [0; 4];
                if data.len() >= 4 {
                    data.read_exact_at(0, &mut signature)?;
                }
                if signature != [0; 4] {
                    return Err(unsupported("hibernated or fast-startup NTFS volume"));
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Open logical data by UTF-16 components with NTFS `$UpCase` matching.
    /// Intermediate reparse points are never followed.
    pub fn read_file(&self, path: &[Vec<u16>], stream_name: &[u16]) -> io::Result<Arc<dyn ReadAt>> {
        let mut context = self.source.context();
        context.path = Some(path.to_vec());
        context.stream = Some(stream_name.to_vec());
        self.read_file_inner(path, stream_name)
            .map_err(|e| context.error("locate NTFS stream", e))
            .map_err(io::Error::from)
    }
    fn read_file_inner(
        &self,
        path: &[Vec<u16>],
        stream_name: &[u16],
    ) -> io::Result<Arc<dyn ReadAt>> {
        if let Some(budget) = self.source.budget()
            && path.len() as u64 > budget.limits().recursion_depth
        {
            return Err(unsupported("NTFS path exceeds configured recursion limit"));
        }
        let mut cursor = Cursor::new(self.source.clone());
        let mut file = self.ntfs.root_directory(&mut cursor).map_err(ntfs_error)?;
        for component in path {
            attributes::validate_name(component)?;
            let attrs = self.read_attributes(&file, &mut cursor)?;
            if !file.is_directory() || !attrs.reparse_data.is_empty() {
                return Err(unsupported(
                    "offline path crosses a non-directory or reparse point",
                ));
            }
            let index = file.directory_index(&mut cursor).map_err(ntfs_error)?;
            let mut entries = index.entries();
            let wanted = self.fold(component);
            let mut found: Option<NtfsFile<'_>> = None;
            while let Some(entry) = entries.next(&mut cursor) {
                let entry = entry.map_err(ntfs_error)?;
                let name = entry
                    .key()
                    .ok_or_else(|| invalid("index name missing"))?
                    .map_err(ntfs_error)?;
                if self.fold(&name.name().u16_iter().collect::<Vec<_>>()) == wanted {
                    let candidate = entry.to_file(&self.ntfs, &mut cursor).map_err(ntfs_error)?;
                    if entry.file_reference().sequence_number() != candidate.sequence_number() {
                        return Err(invalid("stale path file reference"));
                    }
                    if let Some(existing) = &found
                        && existing.file_record_number() != candidate.file_record_number()
                    {
                        return Err(unsupported("ambiguous case-sensitive path"));
                    }
                    found = Some(candidate);
                }
            }
            file = found.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "offline NTFS path missing")
            })?;
        }
        let attrs = self.read_attributes(&file, &mut cursor)?;
        attrs
            .streams
            .into_iter()
            .find(|s| self.fold(&s.name) == self.fold(stream_name))
            .map(|s| s.data)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "offline NTFS data stream missing")
            })
    }

    fn node(
        &self,
        file: &NtfsFile<'_>,
        attrs: Attributes,
        parent: Option<usize>,
        name: Vec<u16>,
        short_name: Vec<u16>,
    ) -> io::Result<Node> {
        if let Some(budget) = self.source.budget() {
            budget.metadata(attrs.security_descriptor.as_ref().map_or_else(
                || {
                    self.security
                        .get(&attrs.security_id)
                        .map_or(0, |sd| sd.len())
                },
                Vec::len,
            ) as u64)?;
        }
        let descriptor = if let Some(sd) = attrs.security_descriptor {
            sd
        } else {
            self.security
                .get(&attrs.security_id)
                .cloned()
                .ok_or_else(|| invalid(format!("missing NTFS security ID {}", attrs.security_id)))?
        };
        security::validate_descriptor(&descriptor)?;
        let attributes = win32_attributes(attrs.attributes, file.is_directory());
        let reference = file.file_record_number() | (u64::from(file.sequence_number()) << 48);
        let mut object_id = attrs.object_id;
        if !object_id.is_empty() {
            let key = <[u8; 16]>::try_from(&object_id[..16])
                .map_err(|_| invalid("object ID shorter than GUID"))?;
            let (indexed_reference, births) = self
                .object_ids
                .get(&key)
                .ok_or_else(|| invalid("file object ID missing from $ObjId index"))?;
            if *indexed_reference != reference {
                return Err(invalid("object ID index points at a different file"));
            }
            let existing = object_id.len() - 16;
            if object_id[16..] != births[..existing] {
                return Err(invalid("object ID birth fields disagree with index"));
            }
            object_id.extend(&births[existing..]);
        }
        Ok(Node {
            parent,
            name,
            short_name,
            file_id: file.file_record_number() | (u64::from(file.sequence_number()) << 48),
            attributes,
            creation_time: attrs.creation_time,
            access_time: attrs.access_time,
            write_time: attrs.write_time,
            security_descriptor: descriptor,
            reparse_data: attrs.reparse_data,
            extended_attributes: attrs.extended_attributes,
            object_id,
            storage_class: attrs.storage_class,
            streams: attrs.streams,
        })
    }
}

fn dos_short_name(
    namespace: NtfsFileNamespace,
    name: &[u16],
    aliases: &[Vec<u16>],
    win32_names: usize,
) -> io::Result<Vec<u16>> {
    match namespace {
        NtfsFileNamespace::Win32AndDos => Ok(name.to_vec()),
        NtfsFileNamespace::Posix => Ok(Vec::new()),
        NtfsFileNamespace::Win32 => {
            if aliases.len() > 1 || (!aliases.is_empty() && win32_names != 1) {
                return Err(unsupported(
                    "ambiguous DOS aliases for hard links in one directory",
                ));
            }
            Ok(aliases.first().cloned().unwrap_or_default())
        }
        NtfsFileNamespace::Dos => Err(invalid("DOS entry used as a long filename")),
    }
}

fn win32_attributes(mut attributes: u32, directory: bool) -> u32 {
    if directory {
        attributes |= 0x10;
    } else {
        attributes &= !0x10;
    }
    if attributes == 0 { 0x80 } else { attributes }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dos_alias_pairing_respects_file_name_namespace() {
        use super::*;
        let long = "FaceProcessor.dll".encode_utf16().collect::<Vec<_>>();
        let aliases = vec!["FACEPR~1.DLL".encode_utf16().collect::<Vec<_>>()];
        assert_eq!(
            dos_short_name(NtfsFileNamespace::Win32, &long, &aliases, 1).unwrap(),
            aliases[0]
        );
        assert!(
            dos_short_name(NtfsFileNamespace::Posix, &long, &aliases, 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            dos_short_name(NtfsFileNamespace::Win32AndDos, &long, &aliases, 1).unwrap(),
            long
        );
    }

    #[test]
    fn multiple_win32_names_or_dos_aliases_remain_ambiguous_before_filtering() {
        use super::*;
        let long = "FaceProcessor.dll".encode_utf16().collect::<Vec<_>>();
        let alias = "FACEPR~1.DLL".encode_utf16().collect::<Vec<_>>();
        for (aliases, count) in [(vec![alias.clone()], 2), (vec![alias.clone(), alias], 1)] {
            let error =
                dos_short_name(NtfsFileNamespace::Win32, &long, &aliases, count).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(error.to_string().contains("ambiguous DOS aliases"));
        }
    }
    use super::{ntfs_error, win32_attributes};

    #[test]
    fn out_of_bounds_index_child_is_invalid_data_and_retains_typed_cause() {
        let error = ntfs_error(ntfs::NtfsError::VcnOutOfBoundsInIndexAllocation {
            position: ntfs::types::NtfsPosition::from(None::<std::num::NonZeroU64>),
            vcn: ntfs::types::Vcn::from(0xfffffffe_i64),
        });
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref::<ntfs::NtfsError>(),
            Some(ntfs::NtfsError::VcnOutOfBoundsInIndexAllocation { .. })
        ));
    }

    #[test]
    fn wrapped_storage_and_policy_errors_preserve_their_kind() {
        for kind in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::Unsupported,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let error = ntfs_error(ntfs::NtfsError::Io(std::io::Error::new(kind, "reader")));
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "reader");
        }
    }

    #[test]
    fn unsupported_cluster_size_is_not_misclassified_as_corruption() {
        let error = ntfs_error(ntfs::NtfsError::UnsupportedClusterSize {
            min: 512,
            max: 65536,
            actual: 131072,
        });
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn logical_ntfs_requests_are_not_misclassified_as_disk_corruption() {
        let position = ntfs::types::NtfsPosition::from(None::<std::num::NonZeroU64>);
        let cases = [
            (
                ntfs::NtfsError::AttributeNotFound {
                    position,
                    ty: ntfs::NtfsAttributeType::Data,
                },
                std::io::ErrorKind::NotFound,
            ),
            (
                ntfs::NtfsError::BufferTooSmall {
                    expected: 64,
                    actual: 16,
                },
                std::io::ErrorKind::InvalidInput,
            ),
            (
                ntfs::NtfsError::AttributeOfDifferentType {
                    position,
                    expected: ntfs::NtfsAttributeType::Data,
                    actual: ntfs::NtfsAttributeType::FileName,
                },
                std::io::ErrorKind::InvalidInput,
            ),
            (
                ntfs::NtfsError::NotADirectory { position },
                std::io::ErrorKind::NotADirectory,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(ntfs_error(error).kind(), expected);
        }
    }

    #[test]
    fn synthesizes_normal_only_for_files_without_attributes() {
        assert_eq!(win32_attributes(0, false), 0x80);
        assert_eq!(win32_attributes(0, true), 0x10);
        assert_eq!(win32_attributes(0x20, false), 0x20);
        assert_eq!(win32_attributes(0x10, false), 0x80);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    struct Image(Vec<u8>);
    impl ReadAt for Image {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> virtdisk::io::Result<()> {
            (|| -> io::Result<()> {
                let bytes = self
                    .0
                    .get(offset as usize..offset as usize + output.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                output.copy_from_slice(bytes);
                Ok(())
            })()
            .map_err(virtdisk::io::Error::from)
        }
    }
    #[test]
    fn bitlocker_is_rejected_before_ntfs_parsing_with_decryption_guidance() {
        let mut bytes = vec![0; 512];
        bytes[3..11].copy_from_slice(b"-FVE-FS-");
        let error = Volume::open(Arc::new(Image(bytes))).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("BitLocker"));
        assert!(error.to_string().contains("decrypt"));
        assert!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<virtdisk::io::Error>()
                .unwrap()
                .get_ref()
                .unwrap()
                .is::<virtdisk::ReadError>()
        );
    }
}
