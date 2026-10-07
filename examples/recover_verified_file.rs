//! Recover one explicitly bounded file from a preserved disk; never relax capture policy.
use partmgr::PartitionTable;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};
use virtdisk::Qcow2;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 6 {
        return Err(io::Error::other(
            "usage: recover_verified_file IMAGE PARTITION PATH NEW_OUTPUT EXPECTED_BYTES EXPECTED_SHA256 [BACKING ...]",
        ));
    }
    let expected: u64 = args[4].parse().map_err(io::Error::other)?;
    if expected == 0 || expected > 16 * 1024 * 1024 * 1024 {
        return Err(io::Error::other(
            "explicit recovery length outside 1..16GiB",
        ));
    }
    let expected_hash = &args[5];
    if expected_hash.len() != 64
        || !expected_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::other(
            "expected SHA256 must be canonical lowercase hex",
        ));
    }
    let backings: Vec<PathBuf> = args[6..].iter().map(PathBuf::from).collect();
    let disk = Qcow2::open_chain(&args[0], &backings)?;
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let volume = disk_capture::Volume::open(Arc::new(
        table.select(args[1].parse().map_err(io::Error::other)?)?,
    ))?;
    let path: Vec<Vec<u16>> = args[2]
        .split('/')
        .map(|s| s.encode_utf16().collect())
        .collect();
    let stream = volume.read_file(&path, &[])?;
    if stream.len() != expected {
        return Err(io::Error::other(format!(
            "recovery source length {}, expected {expected}",
            stream.len()
        )));
    }
    let mut destination = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[3])?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut digest = Sha256::new();
    let mut offset = 0;
    while offset < expected {
        let count = buffer.len().min((expected - offset) as usize);
        stream.read_exact_at(offset, &mut buffer[..count])?;
        digest.update(&buffer[..count]);
        destination.write_all(&buffer[..count])?;
        offset += count as u64;
    }
    destination.sync_all()?;
    let actual = format!("{:x}", digest.finalize());
    if &actual != expected_hash {
        return Err(io::Error::other(format!(
            "recovery SHA256 mismatch {actual}; failed output retained"
        )));
    }
    println!("{{\"bytes\":{expected},\"sha256\":\"{actual}\",\"expected_exact\":true}}");
    Ok(())
}
