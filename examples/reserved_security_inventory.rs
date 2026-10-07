//! Independently inventory every reserved SACL ACE on an immutable Windows volume.
use partmgr::PartitionTable;
use serde_json::json;
use std::{io, path::PathBuf, sync::Arc};
use virtdisk::Qcow2;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn aces(sd: &[u8]) -> io::Result<Vec<String>> {
    if sd.len() < 20 {
        return Err(io::Error::other("short descriptor"));
    }
    let offset = u32::from_le_bytes(sd[12..16].try_into().unwrap()) as usize;
    if offset == 0 {
        return Ok(Vec::new());
    }
    if offset + 8 > sd.len() {
        return Err(io::Error::other("SACL bounds"));
    }
    let end = offset + u16::from_le_bytes(sd[offset + 2..offset + 4].try_into().unwrap()) as usize;
    if end > sd.len() {
        return Err(io::Error::other("SACL length"));
    }
    let count = u16::from_le_bytes(sd[offset + 4..offset + 6].try_into().unwrap());
    let mut cursor = offset + 8;
    let mut selected = Vec::new();
    for _ in 0..count {
        if cursor + 4 > end {
            return Err(io::Error::other("ACE bounds"));
        }
        let size = u16::from_le_bytes(sd[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        if size < 4 || cursor + size > end {
            return Err(io::Error::other("ACE length"));
        }
        if matches!(sd[cursor], 18 | 20) {
            selected.push(hex(&sd[cursor..cursor + size]));
        }
        cursor += size;
    }
    Ok(selected)
}
fn include(path: &[Vec<u16>]) -> bool {
    let names: Vec<String> = path
        .iter()
        .map(|s| String::from_utf16_lossy(s).to_lowercase())
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        return Err(io::Error::other(
            "usage: reserved_security_inventory IMAGE PARTITION NEW_OUTPUT [BACKING ...]",
        ));
    }
    let mut backing_args = args[3..].iter();
    let paths_output = backing_args
        .clone()
        .find_map(|arg| arg.strip_prefix("--paths-output="));
    let backings: Vec<PathBuf> = backing_args
        .by_ref()
        .filter(|arg| !arg.starts_with("--paths-output="))
        .map(PathBuf::from)
        .collect();
    let disk = Qcow2::open_chain(&args[0], &backings)?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let volume = disk_capture::Volume::open(Arc::new(
        table.select(args[1].parse().map_err(io::Error::other)?)?,
    ))?;
    let manifest = volume.capture_manifest_with_filter(include)?;
    let mut paths: Vec<Vec<u16>> = vec![Vec::new(); manifest.nodes.len()];
    let mut rows = Vec::new();
    let mut all_paths = Vec::new();
    let (mut trust, mut resource) = (0, 0);
    for (index, node) in manifest.nodes.iter().enumerate() {
        let mut path = node
            .parent
            .map_or_else(Vec::new, |parent| paths[parent].clone());
        path.push(b'/' as u16);
        path.extend(&node.name);
        paths[index] = if index == 0 { Vec::new() } else { path.clone() };
        if paths_output.is_some() {
            all_paths.push(json!({"path_utf16_le":hex(&path.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<_>>()),"attributes":node.attributes,"file_id":node.file_id}));
        }
        let selected = aces(&node.security_descriptor)?;
        if selected.is_empty() {
            continue;
        }
        if selected.iter().any(|ace| ace.starts_with("14")) {
            trust += 1;
        }
        if selected.iter().any(|ace| ace.starts_with("12")) {
            resource += 1;
        }
        let bytes: Vec<u8> = path.iter().flat_map(|n| n.to_le_bytes()).collect();
        rows.push(json!({"path_utf16_le":hex(&bytes),"path_utf16":path,"display_path":String::from_utf16_lossy(&path),"attributes":node.attributes,"file_id":node.file_id,"security":hex(&node.security_descriptor),"reserved_aces":selected}));
    }
    rows.sort_by(|a, b| {
        a["path_utf16_le"]
            .as_str()
            .cmp(&b["path_utf16_le"].as_str())
    });
    let report = json!({"schema":1,"kind":"offline-reserved-sacl-inventory","source":args[0],"nodes":manifest.nodes.len(),"process_trust_paths":trust,"resource_attribute_paths":resource,"rows":rows});
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    serde_json::to_writer(file, &report)?;
    if let Some(output) = paths_output {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        serde_json::to_writer(file, &all_paths)?;
    }
    println!(
        "{}",
        json!({"nodes":manifest.nodes.len(),"process_trust_paths":trust,"resource_attribute_paths":resource})
    );
    Ok(())
}
