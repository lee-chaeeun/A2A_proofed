#!/usr/bin/env python3
"""Actual-CLI mutation controls for `a2aid audit-pq` on COPIES of a PQ matrix run.

usage: pq_audit_controls.py --bin BIN --run RUN --out OUT [--expected fixtures/pq-audit-controls-expected.json]

Each case copies the run, applies one mutation, runs the audit CLI and records the
exit code and summary. The expected exit code of every case is read from the frozen
expectation table; the script ASSERTS them: it exits 1 if any case returns another
code (including an unexpectedly clean mutation) and 2 if the expectation table does
not cover a case. The original run directory is never modified.

Ten proof/schema controls plus seven release-evidence controls R1–R7 (events,
connection continuity, dispatch context, issued sessions, typed appraisal time, receipt
multiplicity and joins).
"""
import argparse, base64, hashlib, json, shutil, subprocess, sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--bin', required=True); ap.add_argument('--run', required=True); ap.add_argument('--out', required=True)
ap.add_argument('--expected', default=str(Path(__file__).resolve().parent.parent / 'fixtures' / 'pq-audit-controls-expected.json'))
a = ap.parse_args()
run, out = Path(a.run), Path(a.out); out.mkdir(parents=True, exist_ok=True)
expected = json.loads(Path(a.expected).read_text())['expected_exit']

CELL = 'P1_PQ-device+cb'  # accepted bound delivery used by the release-invariant controls

def dec(d, cell):
    p = d / 'cells' / cell / 'decision.json'; return p, json.loads(p.read_text())
def save(p, j): p.write_text(json.dumps(j, indent=1))
def events_path(d, cell): return d / 'cells' / cell / 'controller-events.jsonl'
def read_events(d, cell): return [json.loads(l) for l in events_path(d, cell).read_text().splitlines() if l.strip()]
def write_events(d, cell, evs): events_path(d, cell).write_text(''.join(json.dumps(e) + '\n' for e in evs))

# ---- proof and schema controls ----
def c_unmodified(d): pass
def c_remove_cell(d): shutil.rmtree(d / 'cells' / CELL)
def c_duplicate_decision(d):
    p, j = dec(d, 'P1_PQ-env+cb'); j['decisions'].append(j['decisions'][0]); save(p, j)
def c_alter_context(d):
    p, j = dec(d, CELL); pv = j['decisions'][0]['raw_evidence']['proof_v4']
    b = bytearray(base64.b64decode(pv['context'])); b[-1] ^= 1; pv['context'] = base64.b64encode(bytes(b)).decode(); save(p, j)
def c_alter_signature(d):
    p, j = dec(d, 'P1_PQ-env+tls'); pv = j['decisions'][0]['raw_evidence']['proof_v4']
    b = bytearray(base64.b64decode(pv['signature'])); b[100] ^= 1; pv['signature'] = base64.b64encode(bytes(b)).decode(); save(p, j)
def c_substitute_registry_key(d):
    p = d / 'enrollment-registry.json'; r = json.loads(p.read_text())
    r['deployments']['A']['v4_keys']['PQ-device']['public_b64'] = r['deployments']['B']['v4_keys']['PQ-device']['public_b64']; p.write_text(json.dumps(r, indent=1))
def c_remove_proof_keep_accept(d):
    p, j = dec(d, 'P1_EC-env+cb'); del j['decisions'][0]['raw_evidence']['proof_v4']; save(p, j)
def c_unknown_alg(d):
    p, j = dec(d, 'P1_PQ-env+cb'); j['decisions'][0]['raw_evidence']['proof_v4']['alg'] = 'ML-DSA-87'; save(p, j)
def c_policy_downgrade(d):
    p, j = dec(d, 'P8_PQ-env+cb'); j['decisions'][0]['policy'] = 'PQ-env+tls'; save(p, j)
def c_flip_accept(d):
    p, j = dec(d, 'P8_PQ-env+cb'); x = j['decisions'][0]; x['accept'] = True
    for k in ('signature_valid_under_pinned_key', 'context_matches_expected', 'expiry_ok'): x['proof_v4'][k] = True
    save(p, j)

# ---- release-evidence invariants ----
def r1_missing_requester_events(d):
    p, j = dec(d, CELL); j['decisions'][0]['requester_events'] = []; save(p, j)
def r2_dispatch_connection_swap(d):
    p, j = dec(d, CELL); x = j['decisions'][0]; x['dispatch_conn_id'] = 999; x['job_reused_proof_connection'] = False; save(p, j)
def r3_dispatch_context_action(d):
    p, j = dec(d, CELL); j['decisions'][0]['dispatch_context']['action'] = 'release-something-else'; save(p, j)
def r4_missing_issued_sessions(d):
    p, j = dec(d, CELL); j.pop('sessions', None); save(p, j)
def r5_invalid_appraisal_time(d):
    p, j = dec(d, CELL); j['decisions'][0]['appraised_at'] = 'not-a-time'; save(p, j)
def r6_duplicate_receipt(d):
    evs = read_events(d, CELL); rec = [e for e in evs if e.get('kind') == 'job_received']; assert rec, 'no receipt to duplicate'
    evs.append(json.loads(json.dumps(rec[0]))); write_events(d, CELL, evs)
def r7_receipt_id_token_exporter(d):
    evs = read_events(d, CELL)
    for e in evs:
        if e.get('kind') == 'job_received':
            e['data']['decision_id'] = 'ffffffffffffffff'; e['data']['token'] = 'deadbeefdeadbeefdeadbeef'; e['data']['exporter_hex'] = '00' * 32
    write_events(d, CELL, evs)

cases = [('unmodified', c_unmodified), ('removed-cell-P1_PQ-device+cb', c_remove_cell), ('duplicate-decision-P1_PQ-env+cb', c_duplicate_decision),
         ('altered-context-bytes-P1_PQ-device+cb', c_alter_context), ('changed-signature-P1_PQ-env+tls', c_alter_signature),
         ('substituted-registry-key-PQ-device', c_substitute_registry_key), ('proof-removed-accept-kept-P1_EC-env+cb', c_remove_proof_keep_accept),
         ('unknown-algorithm-label-P1_PQ-env+cb', c_unknown_alg), ('policy-downgrade-P8_PQ-env+cb', c_policy_downgrade),
         ('accept-flag-forged-P8_PQ-env+cb', c_flip_accept),
         ('R1-missing-requester-events-P1_PQ-device+cb', r1_missing_requester_events),
         ('R2-dispatch-connection-swap-P1_PQ-device+cb', r2_dispatch_connection_swap),
         ('R3-dispatch-context-action-P1_PQ-device+cb', r3_dispatch_context_action),
         ('R4-missing-issued-sessions-P1_PQ-device+cb', r4_missing_issued_sessions),
         ('R5-invalid-appraisal-time-P1_PQ-device+cb', r5_invalid_appraisal_time),
         ('R6-duplicate-receipt-P1_PQ-device+cb', r6_duplicate_receipt),
         ('R7-receipt-id-token-exporter-P1_PQ-device+cb', r7_receipt_id_token_exporter)]
results, mismatches, uncovered = [], [], []
for name, fn in cases:
    d = out / name
    if d.exists(): shutil.rmtree(d)
    shutil.copytree(run, d, ignore=shutil.ignore_patterns('process-logs', 'boot', 'pq-audit*', 'release-audit*'))
    fn(d)
    p = subprocess.run([a.bin, 'audit-pq', '--results', str(d), '--out', str(d / 'audit-out')], capture_output=True, text=True)
    (d / 'cli.log').write_text(p.stdout + p.stderr)
    summ = {}
    sp = d / 'audit-out' / 'pq-audit-summary.json'
    if sp.exists(): summ = json.loads(sp.read_text())
    exp = expected.get(name)
    item = {'control': name, 'exit': p.returncode, 'expected_exit': exp, 'as_expected': exp == p.returncode,
            **{k: summ.get(k) for k in ('cells_declared', 'cells_found', 'agree', 'disagree', 'violations', 'incomplete', 'malformed', 'unsupported', 'orphan_receipts')}}
    if exp is None: uncovered.append(name)
    elif exp != p.returncode: mismatches.append(name)
    results.append(item); print(json.dumps(item))
status = 2 if uncovered else (1 if mismatches else 0)
(out / 'controls.json').write_text(json.dumps({'bin': a.bin, 'bin_sha256': hashlib.sha256(Path(a.bin).read_bytes()).hexdigest(), 'run': str(run),
    'expected_table': a.expected, 'expected_table_sha256': hashlib.sha256(Path(a.expected).read_bytes()).hexdigest(),
    'results': results, 'mismatches': mismatches, 'uncovered': uncovered, 'status': status}, indent=1) + '\n')
if uncovered: print('UNCOVERED controls (no expectation):', uncovered, file=sys.stderr)
if mismatches: print('MISMATCHED controls:', mismatches, file=sys.stderr)
print(f'controls: {len(results)} cases, {len(mismatches)} mismatches, {len(uncovered)} uncovered, status {status}')
sys.exit(status)
