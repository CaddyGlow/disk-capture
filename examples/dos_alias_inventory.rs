//! Preserve actual immutable source DOS aliases and verify their native index references.
use partmgr::PartitionTable;
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::Arc,
};
use virtdisk::{Qcow2, ReadAt};
struct Cursor {
    source: Arc<dyn ReadAt>,
    position: u64,
}
impl Read for Cursor {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = bytes
            .len()
            .min(self.source.len().saturating_sub(self.position) as usize);
        if count != 0 {
            self.source
                .read_exact_at(self.position, &mut bytes[..count])?;
        }
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for Cursor {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => self.source.len().checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::other("cursor overflow"))?;
        Ok(self.position)
    }
}
fn hex(name: &[u16]) -> String {
    name.iter()
        .flat_map(|v| v.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn include(path: &[Vec<u16>]) -> bool {
    let names: Vec<_> = path
        .iter()
        .map(|v| String::from_utf16_lossy(v).to_lowercase())
        .collect();
    if matches!(
        names[0].as_str(),
        "pagefile.sys"
            | "swapfile.sys"
            | "hiberfil.sys"
            | "system volume information"
            | "$recycle.bin"
            | "windows.old"
    ) {
        return false;
    }
    if names.len() >= 2 && names[0] == "windows" && names[1] == "csc" {
        return false;
    }
    !(names.len() == 3
        && names[0] == "windows"
        && names[1] == "panther"
        && matches!(names[2].as_str(), "unattend.xml" | "unattend-original.xml"))
}
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        return Err(io::Error::other(
            "usage: dos_alias_inventory IMAGE PARTITION NEW_OUTPUT [BACKING...]",
        ));
    }
    let disk = Qcow2::open_chain(
        &args[0],
        &args[3..].iter().map(PathBuf::from).collect::<Vec<_>>(),
    )?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let partition: Arc<dyn ReadAt> =
        Arc::new(table.select(args[1].parse().map_err(io::Error::other)?)?);
    let volume = disk_capture::Volume::open(partition.clone())?;
    let manifest = volume.capture_manifest_with_filter(include)?;
    let mut cursor = Cursor {
        source: partition,
        position: 0,
    };
    let ntfs = ntfs::Ntfs::new(&mut cursor).map_err(io::Error::other)?;
    let mut paths: Vec<Vec<u16>> = vec![Vec::new(); manifest.nodes.len()];
    let mut rows = Vec::new();
    let mut parents = std::collections::BTreeMap::<usize, Vec<usize>>::new();
    for (index, node) in manifest.nodes.iter().enumerate().skip(1) {
        let parent = node
            .parent
            .ok_or_else(|| io::Error::other("missing parent"))?;
        let mut path = paths[parent].clone();
        path.push(b'/' as u16);
        path.extend(&node.name);
        paths[index] = path.clone();
        if node.short_name.is_empty() {
            continue;
        }
        // The native names remain raw UTF16; only equality classification uses valid Unicode.
        let same = match (
            String::from_utf16(&node.name),
            String::from_utf16(&node.short_name),
        ) {
            (Ok(a), Ok(b)) => a.to_lowercase() == b.to_lowercase(),
            _ => node.name == node.short_name,
        };
        if same {
            continue;
        }
        parents.entry(parent).or_default().push(index);
    }
    let directory_scans = parents.len();
    for (parent, children) in parents {
        let mut wanted = std::collections::HashMap::<Vec<u16>, u64>::new();
        for index in &children {
            let node = &manifest.nodes[*index];
            for name in [&node.name, &node.short_name] {
                if let Some(existing) = wanted.insert(name.clone(), node.file_id)
                    && existing != node.file_id
                {
                    return Err(io::Error::other("ambiguous alias selector"));
                }
            }
        }
        let directory = ntfs
            .file(
                &mut cursor,
                manifest.nodes[parent].file_id & 0x0000ffffffffffff,
            )
            .map_err(io::Error::other)?;
        if directory.sequence_number() != (manifest.nodes[parent].file_id >> 48) as u16 {
            return Err(io::Error::other("stale parent"));
        }
        let index = directory
            .directory_index(&mut cursor)
            .map_err(io::Error::other)?;
        let mut entries = index.entries();
        let mut found = std::collections::HashMap::<Vec<u16>, u64>::new();
        while let Some(entry) = entries.next(&mut cursor) {
            let entry = entry.map_err(io::Error::other)?;
            let name = entry
                .key()
                .ok_or_else(|| io::Error::other("index key absent"))?
                .map_err(io::Error::other)?;
            let raw: Vec<u16> = name.name().u16_iter().collect();
            if let Some(expected) = wanted.get(&raw) {
                let file = entry
                    .to_file(&ntfs, &mut cursor)
                    .map_err(io::Error::other)?;
                if entry.file_reference().sequence_number() != file.sequence_number() {
                    return Err(io::Error::other("stale alias reference"));
                }
                let id = file.file_record_number() | (u64::from(file.sequence_number()) << 48);
                if *expected != id || found.insert(raw, id).is_some() {
                    return Err(io::Error::other(
                        "ambiguous or changed native alias reference",
                    ));
                }
            }
        }
        for index in children {
            let node = &manifest.nodes[index];
            if found.get(&node.name) != Some(&node.file_id)
                || found.get(&node.short_name) != Some(&node.file_id)
            {
                return Err(io::Error::other(format!(
                    "DOS alias reference missing {}",
                    String::from_utf16_lossy(&paths[index])
                )));
            }
            rows.push(serde_json::json!({"path_utf16_le":hex(&paths[index]),"alias_utf16_le":hex(&node.short_name),"parent_path_utf16_le":hex(&paths[parent]),"file_id":node.file_id,"long_reference":node.file_id,"short_reference":node.file_id,"attributes":node.attributes}));
        }
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    serde_json::to_writer(
        file,
        &serde_json::json!({"schema":1,"source":args[0],"nodes":manifest.nodes.len(),"volume_serial":manifest.volume_serial,"aliases":rows,"count":rows.len(),"all_native_index_references_exact":true,"directory_scans":directory_scans}),
    )?;
    println!(
        "nodes={} distinct_aliases={} exact={}",
        manifest.nodes.len(),
        rows.len(),
        rows.len()
    );
    Ok(())
}
