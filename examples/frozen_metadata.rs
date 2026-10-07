//! Capture a small immutable offline subtree for independent Windows comparison.
use disk_capture::Volume;
use partmgr::partition::PartitionTable;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io, path::PathBuf, sync::Arc};
use virtdisk::{Qcow2, ReadAt};
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(source: &dyn ReadAt) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = vec![0; 1024 * 1024];
    while offset < source.len() {
        let count = buffer.len().min((source.len() - offset) as usize);
        source.read_exact_at(offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(hex(&hash.finalize()))
}
fn utf16(data: &[u16]) -> io::Result<String> {
    String::from_utf16(data).map_err(io::Error::other)
}
fn read(source: &dyn ReadAt) -> io::Result<Vec<u8>> {
    let count = usize::try_from(source.len()).map_err(io::Error::other)?;
    if count > 64 * 1024 * 1024 {
        return Err(io::Error::other("diagnostic log size exceeds limit"));
    }
    let mut bytes = vec![0; count];
    source.read_exact_at(0, &mut bytes)?;
    Ok(bytes)
}
fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 7 {
        return Err(io::Error::other(
            "usage: frozen_metadata IMAGE PARTITION BACKING ROOT OUTPUT_JSON LOG_DIR [EXTRA_BACKING ...]",
        ));
    }
    let mut backings = if args[3] == "-" {
        Vec::new()
    } else {
        vec![PathBuf::from(&args[3])]
    };
    backings.extend(args[7..].iter().map(PathBuf::from));
    let image = Qcow2::open_chain(&args[1], &backings)?;
    let table = PartitionTable::read(Arc::new(image), 512)?;
    let volume = Volume::open(Arc::new(
        table.select(args[2].parse().map_err(io::Error::other)?)?,
    ))?;
    let wanted = args[4].to_lowercase();
    let manifest = volume.capture_manifest_with_filter(|path| {
        String::from_utf16_lossy(&path[0]).to_lowercase() == wanted
    })?;
    let mut paths = vec![String::new(); manifest.nodes.len()];
    let mut entries = Vec::<Value>::new();
    for (index, node) in manifest.nodes.iter().enumerate().skip(1) {
        let parent = node
            .parent
            .ok_or_else(|| io::Error::other("child has no parent"))?;
        let name = utf16(&node.name)?;
        paths[index] = if parent == 0 {
            String::new()
        } else {
            format!("{}\\{name}", paths[parent])
        };
        let streams=node.streams.iter().map(|stream|Ok(json!({"Name":utf16(&stream.name)?,"Length":stream.data.len(),"Hash":if stream.data.is_empty() {String::new()}else{hash(stream.data.as_ref())?}}))).collect::<io::Result<Vec<_>>>()?;
        entries.push(json!({"Path":paths[index],"Info":{"Attributes":node.attributes,"Creation":node.creation_time,"Access":node.access_time,"Write":node.write_time,"Identity":format!("{:016X}",node.file_id)},"SecurityRaw":hex(&node.security_descriptor),"Short":utf16(&node.short_name)?,"Streams":streams,"ReparseRaw":hex(&node.reparse_data),"EaRaw":hex(&node.extended_attributes),"ObjectIdRaw":hex(&node.object_id)}));
    }
    fs::write(
        &args[5],
        serde_json::to_vec_pretty(
            &json!({"volume_serial":manifest.volume_serial,"entries":entries}),
        )
        .map_err(io::Error::other)?,
    )?;
    fs::create_dir_all(&args[6])?;
    for path in [
        "Windows/System32/Sysprep/Panther/setupact.log",
        "Windows/System32/Sysprep/Panther/setuperr.log",
        "Windows/Panther/setupact.log",
        "Windows/Panther/setuperr.log",
    ] {
        let components = path
            .split('/')
            .map(|c| c.encode_utf16().collect())
            .collect::<Vec<_>>();
        match volume.read_file(&components, &[]) {
            Ok(data) => {
                let name = path.replace('/', "_");
                fs::write(PathBuf::from(&args[6]).join(name), read(data.as_ref())?)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut recovery = Vec::new();
    for path in [
        "Windows/System32/Recovery/Winre.wim",
        "Recovery/WindowsRE/Winre.wim",
    ] {
        let components = path
            .split('/')
            .map(|c| c.encode_utf16().collect())
            .collect::<Vec<_>>();
        match volume.read_file(&components, &[]) {
            Ok(data) => recovery.push(
                json!({"partition":3,"path":path,"size":data.len(),"sha256":hash(data.as_ref())?}),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if table
        .partitions()
        .iter()
        .any(|partition| partition.index == 4)
    {
        let recovery_volume = Volume::open(Arc::new(table.select(4)?))?;
        for path in [
            "Recovery/WindowsRE/Winre.wim",
            "Windows/System32/Recovery/Winre.wim",
        ] {
            let components = path
                .split('/')
                .map(|c| c.encode_utf16().collect())
                .collect::<Vec<_>>();
            match recovery_volume.read_file(&components, &[]) {
            Ok(data) => recovery.push(
                json!({"partition":4,"path":path,"size":data.len(),"sha256":hash(data.as_ref())?}),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        }
    }
    fs::write(
        PathBuf::from(&args[6]).join("winre-locations.json"),
        serde_json::to_vec_pretty(&recovery).map_err(io::Error::other)?,
    )?;
    eprintln!("fixture entries {}", entries.len());
    Ok(())
}
