//! Read selected offline entry security descriptors for an independent trust-label inventory.
//! Input paths are arrays of original UTF-16 code units, with a leading slash.
//! Output identity is canonical little-endian UTF-16 hex; display text is lossy only.
use partmgr::partition::PartitionTable;
use std::{collections::HashSet, fs, io, path::PathBuf, sync::Arc};
use virtdisk::{Qcow2, RawDisk, ReadAt};
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err(io::Error::other(
            "usage: trust_inventory IMAGE BACKING_OR_- PARTITION PATHS_UTF16_JSON OUTPUT_JSON",
        ));
    }
    let paths: Vec<Vec<u16>> =
        serde_json::from_slice(&fs::read(&args[4])?).map_err(io::Error::other)?;
    let mut prefixes = HashSet::new();
    for path in &paths {
        let mut prefix = Vec::new();
        let components = path
            .strip_prefix(&[u16::from(b'/')])
            .ok_or_else(|| io::Error::other("canonical path must begin with slash"))?;
        if components.is_empty() {
            continue;
        }
        for component in components.split(|unit| *unit == u16::from(b'/')) {
            if component.is_empty() || component.contains(&0) {
                return Err(io::Error::other("empty or NUL path component"));
            }
            prefix.push(component.to_vec());
            prefixes.insert(prefix.clone());
        }
    }
    let raw: Arc<dyn ReadAt> = Arc::new(RawDisk::open(&args[1])?);
    let mut magic = [0; 4];
    raw.read_exact_at(0, &mut magic)?;
    let disk: Arc<dyn ReadAt> = if magic == *b"QFI\xfb" {
        let backings = if args[2] == "-" {
            Vec::new()
        } else {
            vec![PathBuf::from(&args[2])]
        };
        Arc::new(Qcow2::open_chain(&args[1], &backings)?)
    } else {
        if args[2] != "-" {
            return Err(io::Error::other("raw image requires '-' backing argument"));
        }
        raw
    };
    let table = PartitionTable::read(disk, 512)?;
    let volume = disk_capture::Volume::open(Arc::new(
        table.select(args[3].parse().map_err(io::Error::other)?)?,
    ))?;
    let manifest = volume.capture_manifest_with_filter(|path| prefixes.contains(path))?;
    let selected = paths.len();
    let mut names = vec![Vec::<u16>::new(); manifest.nodes.len()];
    let mut entries = Vec::new();
    for (index, node) in manifest.nodes.iter().enumerate() {
        let path = if index == 0 {
            vec![u16::from(b'/')]
        } else {
            let parent = node
                .parent
                .ok_or_else(|| io::Error::other("missing parent"))?;
            names[index] = names[parent].clone();
            names[index].push(u16::from(b'/'));
            names[index].extend_from_slice(&node.name);
            names[index].clone()
        };
        let canonical = path
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        entries.push(serde_json::json!({"path_utf16_le":canonical,"display_path":String::from_utf16_lossy(&path),"file_id":node.file_id,"security":node.security_descriptor.iter().map(|b|format!("{b:02x}")).collect::<String>()}));
    }
    fs::write(
        &args[5],
        serde_json::to_vec(&entries).map_err(io::Error::other)?,
    )?;
    println!("selected={} found={}", selected, entries.len());
    Ok(())
}
