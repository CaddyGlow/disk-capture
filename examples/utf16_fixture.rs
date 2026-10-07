//! Verify an immutable, clean scratch volume against a Windows-created fixture.
use partmgr::partition::PartitionTable;
use std::{io, sync::Arc};
use virtdisk::{Qcow2, RawDisk, ReadAt};
fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if !(3..=4).contains(&args.len()) {
        return Err(io::Error::other(
            "usage: utf16_fixture IMAGE OUTPUT_JSON [PARTITION]",
        ));
    }
    let raw: Arc<dyn ReadAt> = Arc::new(RawDisk::open(&args[1])?);
    let mut magic = [0; 4];
    raw.read_exact_at(0, &mut magic)?;
    let qcow2 = magic == *b"QFI\xfb";
    let disk: Arc<dyn ReadAt> = if qcow2 {
        Arc::new(Qcow2::open(raw)?)
    } else {
        raw
    };
    let table = PartitionTable::read(disk, 512)?;
    let partition = args
        .get(3)
        .map(|value| value.parse::<u32>().map_err(io::Error::other))
        .transpose()?
        .unwrap_or(if qcow2 { 2 } else { 1 });
    let volume = disk_capture::Volume::open(Arc::new(table.select(partition)?))?;
    let wanted: Vec<u16> = "OddFixture".encode_utf16().collect();
    let manifest = volume.capture_manifest_with_filter(|path| path[0] == wanted)?;
    let mut unpaired: Vec<u16> = "unpaired-".encode_utf16().collect();
    unpaired.push(0xd800);
    unpaired.extend(".bin".encode_utf16());
    let odd = manifest
        .nodes
        .iter()
        .find(|node| node.name == unpaired)
        .ok_or_else(|| io::Error::other("unpaired UTF16 filename not preserved"))?;
    let stream = odd
        .streams
        .iter()
        .find(|stream| stream.name.is_empty())
        .ok_or_else(|| io::Error::other("unpaired file has no data"))?;
    let mut byte = [0u8; 1];
    stream.data.read_exact_at(0, &mut byte)?;
    if stream.data.len() != 1 || byte != [42] {
        return Err(io::Error::other("unpaired file payload mismatch"));
    }
    let many_name: Vec<u16> = "many-ads.bin".encode_utf16().collect();
    let many = manifest
        .nodes
        .iter()
        .find(|node| node.name == many_name)
        .ok_or_else(|| io::Error::other("many ADS file missing"))?;
    if many.streams.len() != 161 {
        return Err(io::Error::other("attribute-list streams missing"));
    }
    for i in 0u16..160 {
        let name: Vec<u16> = format!("stream-{i}").encode_utf16().collect();
        let stream = many
            .streams
            .iter()
            .find(|stream| stream.name == name)
            .ok_or_else(|| io::Error::other("named attribute-list stream missing"))?;
        stream.data.read_exact_at(0, &mut byte)?;
        if stream.data.len() != 1 || byte != [i as u8] {
            return Err(io::Error::other("named stream payload mismatch"));
        }
    }
    let result = serde_json::json!({"unpaired_name_utf16": odd.name,
        "unpaired_payload":42,"many_ads_file_id":format!("{:016x}",many.file_id),
        "verified_named_streams":160,"many_ads_total_streams":161,"nodes":manifest.nodes.len()});
    std::fs::write(
        &args[2],
        serde_json::to_vec_pretty(&result).map_err(io::Error::other)?,
    )?;
    eprintln!("unpaired UTF16 exact name/data and 160 extension-record ADS verified");
    Ok(())
}
