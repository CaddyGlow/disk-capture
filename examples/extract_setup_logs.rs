//! Read-only diagnostics for a shut-down failed installation. Never replays NTFS.
use partmgr::PartitionTable;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};
use virtdisk::Qcow2;

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 2 {
        return Err(io::Error::other(
            "usage: extract_setup_logs IMAGE NEW_OUTPUT_DIR [AUTHORIZED_BACKING ...] (source must be shut down)",
        ));
    }
    let image = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let backing: Vec<_> = args[2..].iter().map(PathBuf::from).collect();
    fs::create_dir(&output)?;
    let disk = Qcow2::open_chain(&image, &backing)?;
    eprintln!(
        "QCOW validation: {:?}",
        disk.validate_active_mapping_and_compressed_payloads()?
    );
    let table = PartitionTable::read(Arc::new(disk), 512)?;
    let candidates = [
        "$WINDOWS.~BT/Sources/Panther/setupact.log",
        "$WINDOWS.~BT/Sources/Panther/setuperr.log",
        "$WINDOWS.~BT/Sources/Rollback/setupact.log",
        "$WINDOWS.~BT/Sources/Rollback/setuperr.log",
        "Windows/Panther/setupact.log",
        "Windows/Panther/setuperr.log",
        "Windows/Panther/UnattendGC/setupact.log",
        "Windows/Panther/UnattendGC/setuperr.log",
        "Windows/Logs/DISM/dism.log",
        "Windows/Logs/CBS/CBS.log",
    ];
    let mut report = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("extraction.txt"))?;
    writeln!(
        report,
        "source={}\nbacking={backing:?}\nread-only; no journal replay; clean NTFS required",
        image.display()
    )?;
    for partition in table.partitions() {
        let volume = match disk_capture::Volume::open(Arc::new(table.select(partition.index)?)) {
            Ok(volume) => volume,
            Err(error) => {
                writeln!(
                    report,
                    "partition {}: unavailable: {error}",
                    partition.index
                )?;
                continue;
            }
        };
        match volume.capture_manifest_with_filter(|path| {
            path.first().is_none_or(|component| {
                String::from_utf16_lossy(component).eq_ignore_ascii_case("qcow2-failure")
            })
        }) {
            Ok(manifest) => {
                let mut paths = vec![PathBuf::new(); manifest.nodes.len()];
                for (index, node) in manifest.nodes.iter().enumerate().skip(1) {
                    let component = String::from_utf16(&node.name).map_err(io::Error::other)?;
                    if component.contains(['/', '\\']) || matches!(component.as_str(), "." | "..") {
                        return Err(io::Error::other("unsafe diagnostic filename"));
                    }
                    let parent = node
                        .parent
                        .ok_or_else(|| io::Error::other("missing parent"))?;
                    paths[index] = paths[parent].join(component);
                    if let Some(stream) = node.streams.iter().find(|s| s.name.is_empty()) {
                        if node.attributes & 0x10 != 0 || stream.data.len() > 256 * 1024 * 1024 {
                            continue;
                        }
                        let target = output
                            .join(format!("partition-{}", partition.index))
                            .join(&paths[index]);
                        fs::create_dir_all(
                            target
                                .parent()
                                .ok_or_else(|| io::Error::other("missing parent"))?,
                        )?;
                        let mut file = fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(target)?;
                        let mut offset = 0;
                        let mut buffer = vec![0; 1024 * 1024];
                        while offset < stream.data.len() {
                            let count = buffer.len().min((stream.data.len() - offset) as usize);
                            stream.data.read_exact_at(offset, &mut buffer[..count])?;
                            file.write_all(&buffer[..count])?;
                            offset += count as u64;
                        }
                        file.sync_all()?;
                        writeln!(
                            report,
                            "partition {} {}: extracted {} bytes",
                            partition.index,
                            paths[index].display(),
                            stream.data.len()
                        )?;
                    }
                }
            }
            Err(error) => writeln!(
                report,
                "partition {} qcow2-failure manifest: {error}",
                partition.index
            )?,
        }
        for path in candidates {
            let components: Vec<Vec<u16>> = path
                .split('/')
                .map(|s| s.encode_utf16().collect())
                .collect();
            let stream = match volume.read_file(&components, &[]) {
                Ok(stream) => stream,
                Err(error) => {
                    writeln!(report, "partition {} {path}: {error}", partition.index)?;
                    continue;
                }
            };
            if stream.len() > 256 * 1024 * 1024 {
                writeln!(
                    report,
                    "partition {} {path}: exceeds diagnostic 256 MiB bound",
                    partition.index
                )?;
                continue;
            }
            let target = output
                .join(format!("partition-{}", partition.index))
                .join(path);
            fs::create_dir_all(
                target
                    .parent()
                    .ok_or_else(|| io::Error::other("missing output parent"))?,
            )?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            let mut offset = 0;
            let mut buffer = vec![0; 1024 * 1024];
            while offset < stream.len() {
                let count = buffer.len().min((stream.len() - offset) as usize);
                stream.read_exact_at(offset, &mut buffer[..count])?;
                file.write_all(&buffer[..count])?;
                offset += count as u64;
            }
            file.sync_all()?;
            writeln!(
                report,
                "partition {} {path}: extracted {} bytes",
                partition.index,
                stream.len()
            )?;
        }
    }
    report.sync_all()
}
