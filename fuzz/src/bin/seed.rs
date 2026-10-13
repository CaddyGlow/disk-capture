fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("usage: seed TARGET DIRECTORY")?;
    let output = std::path::PathBuf::from(args.next().ok_or("missing corpus directory")?);
    std::fs::create_dir_all(&output)?;
    for (index, seed) in disk_capture_fuzz::seeds(&target).iter().enumerate() {
        std::fs::write(output.join(format!("seed-{index}")), seed)?;
    }
    Ok(())
}
