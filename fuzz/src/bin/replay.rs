fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("usage: replay TARGET FILE...")?;
    for file in args {
        disk_capture_fuzz::run(&target, &std::fs::read(file)?)?;
    }
    Ok(())
}
