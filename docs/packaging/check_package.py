#!/usr/bin/env python3
"""Check source completeness, source-map coverage, documentation links and obvious secrets."""
import argparse
from pathlib import Path
import re
import subprocess
import tomllib
from verify_manifest import ROOT, publication_files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true', help='Check declared Rust binaries and Git visibility only')
    args=parser.parse_args()
    failures=[]
    declared=[]
    for component in ['zk-component','pq-identity']:
        manifest=ROOT/component/'zk/host/Cargo.toml'
        data=tomllib.loads(manifest.read_text())
        for binary in data.get('bin',[]):
            source=manifest.parent/binary['path']
            rel=source.relative_to(ROOT).as_posix()
            declared.append(rel)
            if not source.is_file():
                failures.append(f'missing declared Rust executable source: {rel}')
            if (ROOT/'.git').exists():
                result=subprocess.run(['git','check-ignore','--no-index','-q',rel],cwd=ROOT)
                if result.returncode==0:
                    failures.append(f'Git ignores declared Rust source: {rel}')
                elif result.returncode!=1:
                    failures.append(f'could not check Git visibility: {rel}')
    included=dict(publication_files())
    for rel in declared:
        if rel not in included:
            failures.append(f'manifest inventory omits declared Rust source: {rel}')
    if not args.source_only:
        guide=(ROOT/'docs/CODE_MAP.md').read_text()
        # Every source directory (or script) of the three modules must be described in the
        # code map once; module prefixes are omitted there because the modules share layout.
        for name in included:
            parts=Path(name).parts
            if parts[0] in {'identity','zk-component','pq-identity'} and 'results' not in parts and 'fixtures' not in parts:
                if Path(name).suffix in {'.go','.rs','.c','.h','.sh','.py'}:
                    rel=Path(*parts[1:])
                    key=rel.as_posix() if rel.parts[0]=='scripts' else rel.parent.as_posix()
                    candidates={key}
                    if rel.parts[0]=='zk':  # zk/host/src/bin, zk/methods/guest/src -> described as zk/host, zk/methods/guest
                        candidates|={'/'.join(rel.parts[:i]) for i in range(2,len(rel.parts))}
                    if not any(f'`{c}`' in guide or f'`{c},' in guide or f', `{c}`' in guide for c in candidates):
                        failures.append(f'source directory missing from CODE_MAP: {key} ({name})')
        docs=[ROOT/'README.md',*sorted((ROOT/'docs').glob('*.md')),
              *[ROOT/c/'README.md' for c in ['identity','zk-component','pq-identity']]]
        for path in docs:
            for target in re.findall(r'\]\(([^)]+)\)',path.read_text()):
                target=target.split('#',1)[0]
                if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:',target):
                    continue
                if not (path.parent/target).exists():
                    failures.append(f'broken link in {path.relative_to(ROOT)}: {target}')
        secret=re.compile(rb'-----BEGIN (?:EC |RSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|(?:sk-ant-api\w*-|sk-proj-)[A-Za-z0-9_-]{20,}')
        for name,path in included.items():
            if name==Path(__file__).relative_to(ROOT).as_posix():
                continue
            if secret.search(path.read_bytes()):
                failures.append(f'private-key/token pattern in {name}')
    for failure in failures:
        print('FAIL:',failure)
    print(f'Package checks: {len(declared)} declared Rust binaries; {len(failures)} failure(s)')
    return bool(failures)


if __name__=='__main__':
    raise SystemExit(main())
