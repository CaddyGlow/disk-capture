# Repository guidelines

Rust 2024 crate `disk-capture`. Read-only offline NTFS metadata and logical-stream capture.
Sibling checkouts required for path dependencies: `virtdisk`, `caddy-ntfs`, `ms-compress`, `partmgr`.
Use `cargo fmt -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo test --all-features --locked`.
Host tests do not establish Windows servicing or capture correctness.
