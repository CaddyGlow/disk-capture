//! Inventory an immutable Windows source without reading its payload streams.
use disk_capture::Volume;
use partmgr::partition::PartitionTable;
use serde_json::json;
use std::{collections::BTreeMap, fs, io, path::PathBuf, sync::Arc};
use virtdisk::Qcow2;
fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err(io::Error::other(
            "usage: manifest_diagnostics IMAGE BACKING PARTITION OUTPUT",
        ));
    }
    let disk = Qcow2::open_chain(&args[1], &[PathBuf::from(&args[2])])?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let volume = Volume::open(Arc::new(
        table.select(args[3].parse().map_err(io::Error::other)?)?,
    ))?;
    let manifest = volume.capture_manifest_with_filter(|path| {
        let root = String::from_utf16_lossy(&path[0]).to_lowercase();
        if [
            "pagefile.sys",
            "swapfile.sys",
            "hiberfil.sys",
            "system volume information",
            "$recycle.bin",
        ]
        .contains(&root.as_str())
        {
            return false;
        }
        !(root == "windows"
            && path
                .get(1)
                .is_some_and(|p| String::from_utf16_lossy(p).eq_ignore_ascii_case("CSC")))
    })?;
    let mut paths = Vec::<String>::with_capacity(manifest.nodes.len());
    let mut reparses = Vec::new();
    let mut identities = BTreeMap::<u64, Vec<String>>::new();
    let mut attribute_counts = BTreeMap::<u32, usize>::new();
    for node in &manifest.nodes {
        let name = String::from_utf16_lossy(&node.name);
        let path = node
            .parent
            .map_or_else(String::new, |parent| format!("{}/{}", paths[parent], name));
        *attribute_counts.entry(node.attributes).or_default() += 1;
        if node.attributes & 0x410 != 0 {
            identities
                .entry(node.file_id)
                .or_default()
                .push(path.clone());
        }
        if !node.reparse_data.is_empty() {
            let tag = u32::from_le_bytes(node.reparse_data[..4].try_into().unwrap());
            let raw = node
                .reparse_data
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            reparses.push(
                json!({"path":path,"tag":format!("{tag:08x}"),"raw":raw,"identity":node.file_id}),
            );
        }
        paths.push(path);
    }
    identities.retain(|_, paths| paths.len() > 1);
    fs::write(&args[4], serde_json::to_vec_pretty(&json!({"entries":manifest.nodes.len(),"reparses":reparses,"repeated_directory_or_reparse_ids":identities,"attribute_counts":attribute_counts})).map_err(io::Error::other)?)?;
    eprintln!(
        "{} entries, {} reparses",
        manifest.nodes.len(),
        reparses.len()
    );
    Ok(())
}
