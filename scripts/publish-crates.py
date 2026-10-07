#!/usr/bin/env python3
"""Publish workspace crates in dependency order, skipping versions already uploaded."""
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], text=True))
packages = {p["name"]: p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]
            and p["publish"] != []}
selected = set(sys.argv[1:]) if len(sys.argv) > 1 else set(packages)
if selected - packages.keys():
    raise SystemExit(f"Unknown publishable packages: {selected - packages.keys()}")

def exists(package):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{package['name']}/{package['version']}",
        headers={"User-Agent": "CaddyGlow-release-workflow"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=30):
                return True
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return False
            if error.code not in (429, 500, 502, 503, 504) or attempt == 3:
                raise
        except urllib.error.URLError:
            if attempt == 3:
                raise
        time.sleep(2 ** attempt)

while selected:
    ready = sorted(name for name in selected if not any(
        dep["name"] in selected for dep in packages[name]["dependencies"] if dep["kind"] != "dev"))
    if not ready:
        raise SystemExit("Workspace publication dependency cycle")
    for name in ready:
        package = packages[name]
        if exists(package):
            print(f"Already published: {name} {package['version']}", flush=True)
        else:
            command = ["cargo", "publish", "--locked", "-p", name]
            for attempt in range(8):
                result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)
                print(result.stdout, end="", flush=True)
                if result.returncode == 0:
                    break
                retry = re.search(r"Please try again after (.+? GMT)", result.stdout)
                if "429 Too Many Requests" not in result.stdout or not retry or attempt == 7:
                    raise subprocess.CalledProcessError(result.returncode, command)
                delay = max(1, parsedate_to_datetime(retry[1]).timestamp() - time.time() + 5)
                print(f"Registry rate limit: retrying {name} in {delay:.0f} seconds", flush=True)
                time.sleep(delay)
        selected.remove(name)
