#!/usr/bin/env python3
"""Encode a read-only 32 MiB NTFS fixture as indexed nonzero 512-byte sectors."""
import argparse
import pathlib
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("volume", type=pathlib.Path)
parser.add_argument("output", type=pathlib.Path)
args = parser.parse_args()
if args.volume.stat().st_size != 32 * 1024 * 1024:
    parser.error("volume must be exactly 32 MiB")
records = bytearray()
with args.volume.open("rb") as source:
    index = 0
    while sector := source.read(512):
        if any(sector):
            records.extend(struct.pack("<I", index))
            records.extend(sector)
        index += 1
if len(records) > 4 * 1024 * 1024:
    parser.error("nonzero sector corpus exceeds harness 4 MiB input limit")
with args.output.open("xb") as output:
    output.write(records)
print(f"{len(records) // 516} sectors, {len(records)} bytes")
