#!/usr/bin/env python3
"""Check publication hashes and sizes, missing files, and unexpected files."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "docs/PROVENANCE_MANIFEST.json"
IGNORED_DIRS = {".git", "target", "run", ".toolchain", "__pycache__"}


def publication_files():
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        build_bin = (rel.parts[0] == "bin" or
                     (len(rel.parts) > 1 and rel.parts[0] in {"identity", "zk-component", "pq-identity"} and rel.parts[1] == "bin"))
        if path.is_file() and not build_bin and not any(p in IGNORED_DIRS for p in rel.parts):
            if rel.as_posix() != MANIFEST:
                yield rel.as_posix(), path


def main():
    manifest = json.loads((ROOT / MANIFEST).read_text())
    entries = manifest["entries"]
    names = [e["published_path"] for e in entries]
    duplicate = len(names) != len(set(names))
    actual = dict(publication_files())
    bad, missing = [], []
    for entry in entries:
        name = entry["published_path"]
        path = actual.get(name)
        if path is None:
            missing.append(name)
            continue
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            bad.append(name)
    extra = sorted(actual.keys() - set(names))
    print(f"entries={len(entries)} mismatches={len(bad)} missing={len(missing)} "
          f"unlisted={len(extra)} duplicate_entries={duplicate}")
    for label, paths in [("MISMATCH", bad), ("MISSING", missing), ("UNLISTED", extra)]:
        for path in paths[:20]:
            print(label, path)
    return 1 if duplicate or bad or missing or extra else 0


if __name__ == "__main__":
    sys.exit(main())
