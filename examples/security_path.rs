//! Read a single offline NTFS entry's security descriptor without opening its data.
use partmgr::partition::PartitionTable;
use std::{io, path::PathBuf, sync::Arc};
use virtdisk::Qcow2;
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(io::Error::other(
            "usage: security_path QCOW2 BACKING PARTITION PATH",
        ));
    }
    let wanted: Vec<Vec<u16>> = args[4]
        .split('/')
        .map(|s| s.encode_utf16().collect())
        .collect();
    let disk = Qcow2::open_chain(&args[1], &[PathBuf::from(&args[2])])?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let volume = disk_capture::Volume::open(Arc::new(
        table.select(args[3].parse().map_err(io::Error::other)?)?,
    ))?;
    let manifest = volume.capture_manifest_with_filter(|path| {
        path.len() <= wanted.len() && path.iter().zip(&wanted).all(|(a, b)| a == b)
    })?;
    let node = manifest
        .nodes
        .iter()
        .find(|node| node.name == *wanted.last().unwrap())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "selected entry absent"))?;
    println!(
        "path={} file_id={:016x} security={}",
        args[4],
        node.file_id,
        node.security_descriptor
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(())
}
