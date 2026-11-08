#!/usr/bin/env python3
"""Refresh the reviewed publication inventory, without changing experimental data."""
from datetime import datetime, timezone
import hashlib
import json
from verify_manifest import ROOT, MANIFEST, publication_files


def main():
    target = ROOT / MANIFEST
    old = json.loads(target.read_text()) if target.exists() else {"entries": []}
    previous = {e["published_path"]: e for e in old["entries"]}
    entries = []
    for name, path in publication_files():
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        entry = dict(previous.get(name, {}))
        if not entry:
            entry = {"published_path": name,
                     "origin": "publication documentation or packaging tool"}
        elif entry["sha256"] != digest:
            entry.setdefault("original_source_sha256", entry["sha256"])
            entry["origin"] = "publication-edited file; earlier source hash retained"
        entry.update(sha256=digest, bytes=len(data))
        entries.append(entry)
    target.write_text(json.dumps({
        "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "final source, selected evidence and publication documents; inventory excludes itself",
        "files": len(entries), "bytes": sum(e["bytes"] for e in entries),
        "entries": entries,
    }, indent=1) + "\n")
    print(f"Inventoried {len(entries)} files; review diff before committing.")


if __name__ == "__main__":
    main()
