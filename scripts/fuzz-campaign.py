#!/usr/bin/env python3
"""Run independent instrumented campaigns and retain seeds, logs and findings."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, re, subprocess
ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--iterations", type=int, default=10000)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if args.iterations < 1:
    parser.error("iterations must be positive")
config = json.loads((ROOT / "fuzz/targets.json").read_text())
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
output = (args.output or ROOT / "target/fuzz-runs" / f"{stamp}-{os.getpid()}").resolve()
output.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, RUSTC_WRAPPER="", CARGO_INCREMENTAL="0", CC="gcc", NIX_HARDENING_ENABLE="", HFUZZ_BUILD_ARGS="--locked", HFUZZ_WORKSPACE=str(output / "workspace"), CARGO_TARGET_DIR=str(ROOT / "target/honggfuzz"))
receipt = {"iterations_requested": args.iterations, "targets": {}, "scope": "bounded coverage-guided smoke; not security qualification"}
for tool in [["rustc", "--version"], ["cargo", "hfuzz", "version"]]:
    receipt[" ".join(tool)] = subprocess.check_output(tool, text=True).strip()
receipt["source_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "fuzz/src").rglob("*.rs"))}
for target, limit in config.items():
    corpus = ROOT / "fuzz/corpus" / target
    corpus.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "run", "--manifest-path", str(ROOT / "fuzz/Cargo.toml"), "--locked", "--bin", "seed", "--", target, str(corpus)], cwd=ROOT, check=True)
    receipt["targets"][target] = {"seeds": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(corpus.iterdir()) if p.is_file()}}
    run_args = f"-n 1 -t 5 -N {args.iterations} -F {limit} --exit_upon_crash"
    with (output / f"{target}.log").open("w") as log:
        result = subprocess.run(["cargo", "hfuzz", "run", target], cwd=ROOT / "fuzz", env=dict(env, HFUZZ_INPUT=str(corpus), HFUZZ_RUN_ARGS=run_args), stdout=log, stderr=subprocess.STDOUT)
    summaries = re.findall(r"Summary iterations:(\d+) .*?crashes_count:(\d+) timeout_count:(\d+)[^\n]*", (output / f"{target}.log").read_text(errors="replace"))
    row = receipt["targets"][target]
    row.update(exit_code=result.returncode, arguments=run_args, passed=False)
    if summaries:
        iterations, crashes, timeouts = map(int, summaries[-1])
        row.update(iterations=iterations, crashes=crashes, timeouts=timeouts, passed=result.returncode == 0 and iterations >= args.iterations and crashes == timeouts == 0)
    (output / "summary.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not row["passed"]:
        raise SystemExit(f"Fuzz campaign failed; retained evidence: {output}")
print(output)
