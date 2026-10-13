fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            disk_capture_fuzz::ntfs(data);
        });
    }
}
