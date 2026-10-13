# Independent disk-capture fuzzing

Owned targets: ntfs. Harnesses have input/read/output budgets and do not depend on another project’s fuzz package. Malformed input is expected; panics and oracle mismatches are findings. Seeds include structural inputs and regression fixtures where available. Production defaults remain unchanged.

Run `cargo test --manifest-path fuzz/Cargo.toml --locked` and `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings`. Install honggfuzz 0.5.62 plus GCC/binutils/libunwind/liblzma development libraries, then run `python3 scripts/fuzz-campaign.py --iterations 10000`. Replay with `cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- TARGET FILE`.

The weekly/manual workflow instruments code and retains seed/source hashes, tool versions, raw logs, summary counts, and findings even on failure. Each case has a five-second timeout. Bounded smoke campaigns do not establish absence of bugs or replace sustained sanitizer campaigns. Fuzzing operates only on memory or temporary files created by the harness; no input-supplied host paths are opened.
