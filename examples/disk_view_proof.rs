//! Retain GPT boundary bytes and a complete immutable Windows partition digest.
use partmgr::partition::PartitionTable;
use sha2::{Digest, Sha256};
use std::{fs, io, path::PathBuf, sync::Arc};
use virtdisk::{Qcow2, ReadAt};
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err(io::Error::other(
            "usage: disk_view_proof IMAGE NEW_OUTPUT_DIRECTORY [BACKING ...]",
        ));
    }
    let backing: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
    let disk: Arc<dyn ReadAt> = Arc::new(Qcow2::open_chain(&args[1], &backing)?);
    let table = PartitionTable::read(disk.clone(), 512)?;
    let partition = table.select(3)?;
    let output = PathBuf::from(&args[2]);
    fs::create_dir(&output)?;
    let mut prefix = vec![0; 34 * 512];
    let mut tail = vec![0; 33 * 512];
    disk.read_exact_at(0, &mut prefix)?;
    disk.read_exact_at(disk.len() - tail.len() as u64, &mut tail)?;
    fs::write(output.join("disk-prefix.bin"), prefix)?;
    fs::write(output.join("disk-tail.bin"), tail)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 4 * 1024 * 1024];
    let mut offset = 0;
    while offset < partition.len() {
        let count = buffer.len().min((partition.len() - offset) as usize);
        partition.read_exact_at(offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    let digest = hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let proof = serde_json::json!({"image":args[1],"backings":backing,"virtual_bytes":disk.len(),"windows_partition":3,"partition_bytes":partition.len(),"partition_sha256":digest});
    fs::write(
        output.join("proof.json"),
        serde_json::to_vec_pretty(&proof).map_err(io::Error::other)?,
    )?;
    println!("{proof}");
    Ok(())
}
