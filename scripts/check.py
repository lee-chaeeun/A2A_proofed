#!/usr/bin/env python3
"""Run tests and retained-evidence checks without changing published evidence."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RUNS = {'pq': ('pq-identity', 'results/pq/20261108-153049'),
        'identity': ('identity', 'results/v3-final/20261108-004047'),
        'zk': ('zk-component', 'results/zk/20261108-111817')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=['pq', 'identity', 'zk', 'all'], default='pq')
    parser.add_argument('--evidence-only', action='store_true', help='Build and audit, without running Go tests')
    parser.add_argument('--zk-verifier', type=Path, help='Built zkverify executable; required to reverify ZK receipts')
    parser.add_argument('--out', type=Path, help='New output directory; defaults to a fresh temporary directory')
    args = parser.parse_args()
    out = args.out.resolve() if args.out else Path(tempfile.mkdtemp(prefix='a2a-proofed-check-'))
    if args.out:
        out.mkdir(parents=True, exist_ok=False)
    zkver = args.zk_verifier.resolve() if args.zk_verifier else None
    if zkver and not zkver.is_file():
        parser.error('--zk-verifier must be an existing executable')
    records = []
    def run(label, cmd, cwd, env=None):
        print(f'\n{label}: {" ".join(map(str, cmd))}', flush=True)
        result = subprocess.run(list(map(str, cmd)), cwd=cwd, env=env)
        records.append({'check': label, 'exit': result.returncode})
        (out/'checks.json').write_text(json.dumps(records, indent=2)+'\n')
        if result.returncode:
            raise SystemExit(f'{label} failed (exit {result.returncode}); reports: {out}')
    components = list(RUNS) if args.component == 'all' else [args.component]
    for name in components:
        folder, retained = RUNS[name]
        cwd = ROOT/folder
        binary = out/f'a2aid-{name}'
        run(f'{name} build', ['go', 'build', '-o', binary, './cmd/a2aid'], cwd)
        if not args.evidence_only:
            run(f'{name} Go race tests', ['go', 'test', '-race', '-count=1', './...'], cwd)
        if name == 'pq':
            for suffix, path in [('final',retained), ('rerun','results/pq-integration/20261108-164204')]:
                run(f'PQ {suffix} audit', [binary, 'audit-pq', '--results', path, '--out',out/f'pq-{suffix}'], cwd)
            run('PQ mutation controls', ['python3','-I','scripts/pq_audit_controls.py','--bin',binary,'--run',retained,'--out',out/'pq-controls'], cwd)
            env = dict(os.environ, A2AID_RUNNER_TEST_BIN=str(binary))
            run('PQ runner failure injection', ['bash','scripts/test_pq_runner.sh'],cwd,env)
        elif name == 'identity':
            copied=out/'identity-evidence'
            shutil.copytree(cwd/retained,copied)
            run('Identity release audit',[binary,'audit-release','--results',copied],cwd)
        elif zkver:
            run('ZK receipt oracle',[binary,'zk-oracle','--results',retained,'--verify-bin',zkver,'--out',out/'zk-oracle'],cwd)
        else:
            print('SKIP: retained ZK receipt verification requires --zk-verifier; Go tests are not a substitute.',flush=True)
            records.append({'check':'retained ZK receipt verification','status':'skipped: no --zk-verifier'})
    (out/'checks.json').write_text(json.dumps(records,indent=2)+'\n')
    print(f'\nRequested checks finished. Reports: {out}')


if __name__ == '__main__':
    main()
