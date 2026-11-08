#!/usr/bin/env python3
"""Build the curated publication copy from an explicit allowlist (8 Nov 2026).

Nothing is copied by directory default: every file must match an allowlist entry below.
Evidence files are copied byte-identical; the manifest records sha256, source path and
the originating snapshot/run so each copy can be checked against the research trees.
Excluded by construction: run/ (lab CA and TLS private keys, emulator state, pids),
.toolchain/, zk/target/, bin/, zk/proof-cache entries, copied-run control trees, source
tarballs and binaries inside snapshot directories, task prompts, historical paper copies.
"""
import fnmatch, hashlib, json, os, shutil, sys, time
from pathlib import Path

WS = Path('/home/bitchae/aisafety/swarmalign')
OUT = WS / 'a2a-proof-binding-public'
ID, ZK, PAPER = WS / 'a2a-identity', WS / 'a2a-identity-zkp', WS / 'paper' / 'a2a-identity'

def files_under(root, rel, include=('*',), exclude=()):
    base = root / rel
    out = []
    for p in sorted(base.rglob('*')):
        if not p.is_file():
            continue
        r = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(r, e) or fnmatch.fnmatch(p.name, e) for e in exclude):
            continue
        if any(fnmatch.fnmatch(r, i) or fnmatch.fnmatch(p.name, i) for i in include):
            out.append(r)
    return out

def top_files(root, rel, include=('*',)):
    base = root / rel
    return [p.relative_to(root).as_posix() for p in sorted(base.iterdir()) if p.is_file() and any(fnmatch.fnmatch(p.name, i) for i in include)]

SRC_EXCL = ('*/testdata/*.tar.gz',)
ident = []
ident += ['README.md', 'REPORT.md', 'RESULTS_V2.md', 'RESULTS_V3.md', 'RESULTS_V3_FINAL.md', 'RESULTS_V3_CORRECTIONS.md', 'SCOPE_AND_LIMITATIONS.md', 'BASELINE_V3_PLAN.md', 'V3_FINALIZATION_PLAN.md', 'CORRECTION_PLAN_V3.md', 'go.mod', 'go.sum']
ident += files_under(ID, 'cmd') + files_under(ID, 'internal') + files_under(ID, 'fixtures') + files_under(ID, 'scripts')
# evidence (identity): final corrected run complete; compact copies of the others
ident += files_under(ID, 'results/v3-final/20261108-004047')
ident += top_files(ID, 'results/v3-final/20261108-000017') + files_under(ID, 'results/v3-final/20261108-000017/continuity', include=('*summary*', '*.md'))
ident += top_files(ID, 'results/v3-final/20261107-235740') + top_files(ID, 'results/v3-final/20261107-235908')
ident += top_files(ID, 'results/v2/20261107-194025')
ident += files_under(ID, 'results/v3-repro/20261107-202528') + files_under(ID, 'results/v3/20261107-203206')
ident += files_under(ID, 'results/audit/20261107T225036Z-v2-continuity-historical', exclude=('*.tar.gz',))
ident += files_under(ID, 'results/audit/20261107T233054Z-checker-falseclean-before') + files_under(ID, 'results/audit/20261107T234220Z-checker-falseclean-after')
ident += files_under(ID, 'results/audit/20261107T234220Z-checker-v2-over-run-20261108-000017', include=('*.md', '*.json', '*.txt'))
ident += files_under(ID, 'results/audit/20261107T234045Z-v3final-snapshot', exclude=('*.tar.gz', 'a2aid*'))
ident += files_under(ID, 'results/audit/20261107T233054Z-v3corr-prefix', exclude=('*.tar.gz', 'a2aid*'))
ident += files_under(ID, 'results/reviewer-v3-final', exclude=('*.tar.gz',))

zk = []
zk += ['README.md', 'RESULTS_ZK.md', 'RESULTS_ZK_CORRECTIONS.md', 'ZK_COMPONENT_PLAN.md', 'ZK_CORRECTION_PLAN.md', 'go.mod', 'go.sum']
zk += files_under(ZK, 'cmd') + files_under(ZK, 'internal') + files_under(ZK, 'fixtures') + files_under(ZK, 'scripts')
zk += ['zk/Cargo.toml', 'zk/Cargo.lock', 'zk/image-id.txt', 'zk/image-id.json', 'zk/proof-cache/README.md']
zk += files_under(ZK, 'zk/host') + files_under(ZK, 'zk/methods', exclude=('*/target/*',))
zk += files_under(ZK, 'results/zk/20261108-111817') + files_under(ZK, 'results/zk-integration/20261108-112143')
zk += files_under(ZK, 'results/zk/20261108-002724', exclude=('results/zk/20261108-002724/oracle-controls/*/*',))
zk += top_files(ZK, 'results/zk-integration/20261108-003306') + files_under(ZK, 'results/zk-integration/20261108-003306/receipts')
zk += top_files(ZK, 'results/zk/20261108-002012') + top_files(ZK, 'results/zk/20261108-002316')
zk += files_under(ZK, 'results/zk/feasibility') + ['results/zk/PLAN.sha256', 'results/zk/zk-integration-test.log', 'results/zk/zk-integration-test-corrected.log']
for d in ('results/audit/20261108T105605Z-zk-before-fix', 'results/audit/20261108T111037Z-zk-oracle-controls-after-legacyview', 'results/audit/20261108T112131Z-zk-oracle-controls-after-schema2'):
    zk += files_under(ZK, d, include=('controls.json', 'cli.log', 'oracle-summary.json', 'oracle.md', 'oracle.jsonl', '*.log', 'README.txt'))
zk += files_under(ZK, 'results/audit/20261108T112526Z-zk-legacy-view-20261108-002724') + files_under(ZK, 'results/audit/20261108T112527Z-zk-legacy-view-20261108-003306')
for d in ('results/audit/20261108T105409Z-zkcorr-prefix', 'results/audit/20261108T111816Z-zkcorr-snapshot', 'results/audit/20261108T112430Z-zkcorr-final-snapshot', 'results/audit/20261108T003236Z-zk-snapshot'):
    zk += files_under(ZK, d, exclude=('*.tar.gz', 'a2aid*'))
zk += files_under(ZK, 'results/reviewer-zk/20261108T103550Z', include=('*.json', '*.log', '*.py', '*.go.txt'), exclude=('results/reviewer-zk/20261108T103550Z/*/*',))

paper = ['paper-draft.md', 'md2tex.py', 'latexmkrc', 'a2a-identity-latex.zip', 'output/pdf/a2a-identity-paper.pdf', 'output/pdf/SHA256SUMS', 'CLAIM_EVIDENCE_TABLE.md', 'PAPER_CORRECTIONS_PENDING.md']
reviews = ['REVIEW.md', 'BASELINE_V2_REVIEW.md', 'BASELINE_V3_REVIEW.md', 'REVIEW_V3_FINAL.md', 'REVIEW_V3_CORRECTIONS.md', 'REVIEW_ZK_COMPONENT.md']

manifest = []
def copy(src_root, rel, dst_rel, origin):
    src = src_root / rel
    dst = OUT / dst_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    h = hashlib.sha256(src.read_bytes()).hexdigest()
    manifest.append({'published_path': dst_rel, 'source_path': str(src.relative_to(WS)), 'sha256': h, 'bytes': src.stat().st_size, 'origin': origin})

# Re-runnable: component and paper trees are rebuilt from the allowlist; hand-written
# files (README.md, .gitignore, docs/*.md, docs/packaging/) are never touched; docs/reviews
# and the manifest are regenerated.
if OUT.exists():
    for child in ('identity', 'zk-component', 'paper'):
        if (OUT / child).exists():
            shutil.rmtree(OUT / child)
    if (OUT / 'docs' / 'reviews').exists():
        shutil.rmtree(OUT / 'docs' / 'reviews')

def origin_for(rel):
    if rel.startswith('results/'):
        return 'retained run or audit directory (byte-identical copy)'
    return 'source/doc as of the final snapshot (byte-identical copy)'
for rel in dict.fromkeys(ident):
    copy(ID, rel, 'identity/' + rel, 'a2a-identity: ' + origin_for(rel))
for rel in dict.fromkeys(zk):
    copy(ZK, rel, 'zk-component/' + rel, 'a2a-identity-zkp: ' + origin_for(rel))
for rel in paper:
    copy(PAPER, rel, 'paper/' + Path(rel).name, 'paper folder, final 8 Nov 2026')
for rel in reviews:
    copy(PAPER, rel, 'docs/reviews/' + rel, 'paper folder (review history)')
# paper: self-contained TeX (fonts inside) is the ZIP variant
tex = (PAPER / 'main.tex').read_text().replace('Path           = ../fonts/,', 'Path           = fonts/,')
(OUT / 'paper' / 'main.tex').write_text(tex)
manifest.append({'published_path': 'paper/main.tex', 'source_path': 'paper/a2a-identity/main.tex', 'sha256': hashlib.sha256(tex.encode()).hexdigest(), 'bytes': len(tex.encode()), 'origin': 'paper folder; packaging-only change: font path ../fonts/ -> fonts/ (source sha256 ' + hashlib.sha256((PAPER / 'main.tex').read_bytes()).hexdigest() + ')'})
for f in sorted((WS / 'paper' / 'fonts').glob('OldStandardTT-*.ttf')):
    copy(WS / 'paper', 'fonts/' + f.name, 'paper/fonts/' + f.name, 'template fonts (SIL OFL)')
(OUT / 'paper' / 'README-BUILD.txt').write_text('Build with LuaLaTeX, twice: lualatex main.tex && lualatex main.tex\nmain.tex is generated from paper-draft.md by md2tex.py (pandoc >= 3; the script reads the preamble from the existing main.tex).\nFonts: Old Standard TT (SIL Open Font License) in fonts/.\n')
manifest.sort(key=lambda m: m['published_path'])
(OUT / 'docs' / 'PROVENANCE_MANIFEST.json').write_text(json.dumps({'built_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'files': len(manifest), 'bytes': sum(m['bytes'] for m in manifest), 'entries': manifest}, indent=1) + '\n')
tot = sum(m['bytes'] for m in manifest)
print('copied %d files, %.1f MB' % (len(manifest), tot / 1e6))
for top in ('identity', 'zk-component', 'paper', 'docs'):
    n = sum(1 for m in manifest if m['published_path'].startswith(top + '/')); b = sum(m['bytes'] for m in manifest if m['published_path'].startswith(top + '/'))
    print('  %-13s %5d files %6.1f MB' % (top, n, b / 1e6))
big = [m for m in manifest if m['bytes'] > 2_000_000]
print('files > 2 MB:', [(m['published_path'], m['bytes']) for m in big])
