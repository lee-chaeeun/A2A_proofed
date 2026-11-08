#!/usr/bin/env python3
"""Rewrite docs/PROVENANCE_MANIFEST.json: path, SHA-256 and size of every published file."""
from datetime import datetime, timezone
import hashlib
import json
from verify_manifest import ROOT, MANIFEST, publication_files


def main():
    entries = []
    for name, path in publication_files():
        data = path.read_bytes()
        entries.append({"published_path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    (ROOT / MANIFEST).write_text(json.dumps({
        "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "every published file except this manifest",
        "files": len(entries), "bytes": sum(e["bytes"] for e in entries),
        "entries": entries,
    }, indent=1) + "\n")
    print(f"Inventoried {len(entries)} files.")


if __name__ == "__main__":
    main()
