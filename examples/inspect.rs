use partmgr::partition::PartitionTable;
use std::{io, sync::Arc};
use virtdisk::{Qcow2, RawDisk, ReadAt};
fn main() -> io::Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    let path = arguments
        .get(1)
        .ok_or_else(|| io::Error::other("usage: inspect IMAGE PARTITION"))?;
    let partition = arguments
        .get(2)
        .ok_or_else(|| io::Error::other("missing partition"))?
        .parse::<u32>()
        .map_err(io::Error::other)?;
    let raw: Arc<dyn ReadAt> = Arc::new(RawDisk::open(path)?);
    let disk: Arc<dyn ReadAt> = Arc::new(Qcow2::open(raw)?);
    let table = PartitionTable::read(disk, 512)?;
    for p in table.partitions() {
        eprintln!(
            "partition {} lba{} sectors{}",
            p.index, p.first_lba, p.sectors
        );
    }
    let volume = disk_capture::Volume::open(Arc::new(table.select(partition)?))?;
    let tree = volume.capture_manifest()?;
    eprintln!("nodes {}", tree.nodes.len());
    let mut files = 0;
    let mut bytes = 0;
    for node in &tree.nodes {
        files += node.streams.len();
        bytes += node.streams.iter().map(|s| s.data.len()).sum::<u64>();
        if arguments.get(3).is_some_and(|s| s == "--verify-data") {
            for stream in &node.streams {
                let mut position = 0;
                let mut buffer = vec![0; 1024 * 1024];
                while position < stream.data.len() {
                    let count = buffer.len().min((stream.data.len() - position) as usize);
                    stream.data.read_exact_at(position, &mut buffer[..count])?;
                    position += count as u64;
                }
            }
        }
    }
    eprintln!("streams {files} logicalbytes {bytes}");
    Ok(())
}
