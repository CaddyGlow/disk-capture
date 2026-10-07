//! Extract one offline file through native disk and NTFS readers without writes.
use partmgr::PartitionTable;
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};
use virtdisk::Qcow2;
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        return Err(io::Error::other(
            "usage: read_file IMAGE PARTITION RELATIVE_PATH NEW_OUTPUT [BACKING ...]",
        ));
    }
    let backing: Vec<_> = args[4..].iter().map(PathBuf::from).collect();
    let disk = Qcow2::open_chain(&args[0], &backing)?;
    disk.validate_active_mapping_and_compressed_payloads()?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let volume = disk_capture::Volume::open(Arc::new(
        table.select(args[1].parse().map_err(io::Error::other)?)?,
    ))?;
    let path: Vec<_> = args[2]
        .split('/')
        .map(|s| s.encode_utf16().collect())
        .collect();
    let stream = volume.read_file(&path, &[])?;
    if stream.len() > 256 * 1024 * 1024 {
        return Err(io::Error::other("diagnostic file exceeds 256 MiB bound"));
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < stream.len() {
        let count = buffer.len().min((stream.len() - offset) as usize);
        stream.read_exact_at(offset, &mut buffer[..count])?;
        output.write_all(&buffer[..count])?;
        offset += count as u64;
    }
    output.sync_all()
}
