#!/usr/bin/env python3
"""Verify every file of the publication copy against docs/PROVENANCE_MANIFEST.json
(sha256 and size) and report files present in the tree but absent from the manifest.
Run from the repository root: python3 docs/packaging/verify_manifest.py"""
import hashlib, json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parents[2]
man = json.loads((root / 'docs' / 'PROVENANCE_MANIFEST.json').read_text())
bad, missing = [], []
listed = set()
for e in man['entries']:
    p = root / e['published_path']
    listed.add(e['published_path'])
    if not p.exists():
        missing.append(e['published_path']); continue
    if hashlib.sha256(p.read_bytes()).hexdigest() != e['sha256']:
        bad.append(e['published_path'])
extra = []
for p in root.rglob('*'):
    if p.is_file() and not any(part in ('.git', 'bin', 'target') for part in p.parts):
        r = p.relative_to(root).as_posix()
        if r not in listed and not r.startswith('docs/') and r not in ('.gitignore', 'README.md', 'LICENSE', 'NOTICE', 'paper/README-BUILD.txt', 'paper/main.tex'):
            extra.append(r)
print('manifest entries: %d; hash mismatches: %d; missing: %d; unlisted files outside docs/: %d' % (len(man['entries']), len(bad), len(missing), len(extra)))
for x in bad[:20]: print('  MISMATCH', x)
for x in missing[:20]: print('  MISSING', x)
for x in extra[:20]: print('  UNLISTED', x)
sys.exit(1 if bad or missing else 0)
