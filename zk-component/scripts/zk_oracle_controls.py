#!/usr/bin/env python3
"""Actual-CLI oracle controls on COPIES of a ZK run (never in place).

usage: zk_oracle_controls.py --bin BIN --run RUN --out OUT [--legacy-inventory FILE]
                             [--verify-bin ZKVERIFY] [--cases before|after]

Each case copies the run, applies one mutation, runs `BIN zk-oracle` and records the
exit code and summary. "before" runs the four reviewer cases only (for the pre-edit
binary, which has no inventory/verifier flags); "after" runs the full declared set.
"""
import argparse, base64, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--bin', required=True); ap.add_argument('--run', required=True); ap.add_argument('--out', required=True)
ap.add_argument('--legacy-inventory'); ap.add_argument('--verify-bin'); ap.add_argument('--openings', default='fixtures/zk/openings.json')
ap.add_argument('--cases', default='after', choices=['before', 'after'])
a = ap.parse_args()
run, out = Path(a.run), Path(a.out)
out.mkdir(parents=True, exist_ok=True)

def rows(d): return [json.loads(l) for l in (d / 'decisions.jsonl').read_text().splitlines() if l.strip()]
def wrows(d, rs): (d / 'decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rs))
def events(d): return [json.loads(l) for l in (d / 'events.jsonl').read_text().splitlines() if l.strip()]
def wevents(d, es): (d / 'events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in es))
def reseq(es):
    for i, e in enumerate(es): e['seq'] = i + 1
    return es
def first(d, fx, pol):
    for r in rows(d):
        if r['fixture'] == fx and r['policy'] == pol: return r
def mutate_row(d, fx, pol, fn):
    rs = rows(d)
    for r in rs:
        if r['fixture'] == fx and r['policy'] == pol: fn(r)
    wrows(d, rs)
def approval_of(es, req, pol):
    for e in es:
        if e['kind'] == 'approval_inserted' and e['fields'].get('request_id') == req and e['fields'].get('policy') == pol: return e

def c_unmodified(d): pass
def c_remove_z4(d): wrows(d, [r for r in rows(d) if r['fixture'] != 'Z4'])
def c_duplicate_row(d): rs = rows(d); wrows(d, rs + [rs[0]])
def c_corrupt_receipts(d):
    for p in (d / 'receipts').glob('*.bin'): p.write_bytes(b'not-a-receipt')
def neutralize(e):
    # keep the sequence number (so row<->event links and the gap-free chain stay intact) but
    # remove the insert itself: the event becomes an inert known kind
    return {'seq': e['seq'], 'kind': 'zk_reuse', 'at': e['at'], 'fields': {'note': 'control: event neutralized'}}
def c_remove_all_approval_events(d): wevents(d, [neutralize(e) if e['kind'] == 'approval_inserted' else e for e in events(d)])
# §4 receipt binding
def c_remove_one_receipt(d): (d / 'receipts' / (first(d, 'Z1', 'V0')['receipt_sha256'] + '.bin')).unlink()
def c_row_hash_to_other_receipt(d):
    other = first(d, 'Z6', 'V0')['receipt_sha256']
    mutate_row(d, 'Z1', 'V0', lambda r: r.__setitem__('receipt_sha256', other))
def c_row_journal_altered(d):
    def f(r):
        j = bytearray.fromhex(r['verified_journal_hex']); j[4] ^= 1; r['verified_journal_hex'] = j.hex()
    mutate_row(d, 'Z1', 'VTI', f)
def c_false_valid_z9a(d): mutate_row(d, 'Z9a', 'V0', lambda r: (r.__setitem__('proof_valid', True), r.__setitem__('verified_journal_hex', first(d, 'Z1', 'V0')['verified_journal_hex'])))
def c_false_invalid_z1(d): mutate_row(d, 'Z1', 'VI', lambda r: (r.__setitem__('proof_valid', False), r.__setitem__('verified_journal_hex', '')))
def c_row_image_changed(d):
    pinned = first(d, 'Z1', 'V0')['expected_image_id_hex']
    mutate_row(d, 'Z9b', 'V0', lambda r: r.__setitem__('expected_image_id_hex', pinned))
# §5 ledger
def c_remove_one_approval_event(d):
    es = events(d); e = approval_of(es, 'Z1', 'VTI'); es[es.index(e)] = neutralize(e); wevents(d, es)
def c_orphan_approval(d):
    es = events(d); e = dict(approval_of(es, 'Z1', 'V0')); e = json.loads(json.dumps(e)); e['fields']['request_id'] = 'Z2'; e['fields']['policy'] = 'V0'
    if 'evaluation_id' in e['fields']: e['fields']['evaluation_id'] = 'Z2/V0'
    es.append(e); wevents(d, reseq(es))
def c_duplicate_approval(d):
    es = events(d); e = approval_of(es, 'Z1', 'V0'); i = es.index(e); es.insert(i + 1, json.loads(json.dumps(e))); wevents(d, reseq(es))
def c_approval_fields_changed(d):
    es = events(d); e = approval_of(es, 'Z1', 'VT'); e['fields']['receipt_sha256'] = first(d, 'Z6', 'V0')['receipt_sha256']; wevents(d, es)
def c_prior_approval_removed_for_duplicate(d):
    es = events(d); e = approval_of(es, 'Z1', 'V0'); es[es.index(e)] = neutralize(e); wevents(d, es)
    mutate_row(d, 'Z1', 'V0', lambda r: (r.__setitem__('approval_inserted', False), r.__setitem__('approval_count_after', 0), r.__setitem__('approval_seq', 0)))
def c_approval_flag_flipped_only(d): mutate_row(d, 'Z4', 'VTI', lambda r: r.__setitem__('approval_inserted', True))
# §3 structure
def c_truncated_events(d):
    s = (d / 'events.jsonl').read_text(); (d / 'events.jsonl').write_text(s[: len(s) - 40])
def c_seq_gap(d):
    es = events(d)
    for e in es:
        if e['seq'] >= 10: e['seq'] += 1
    wevents(d, es)
def c_seq_duplicate(d):
    es = events(d); es[5]['seq'] = es[4]['seq']; wevents(d, es)
def c_unknown_policy(d): mutate_row(d, 'Z2', 'VT', lambda r: r.__setitem__('policy', 'VX'))
def c_null_request(d):
    p = d / 'requests.json'; rq = json.loads(p.read_text()); rq[0] = None; p.write_text(json.dumps(rq))
def c_bad_challenge_hex(d):
    p = d / 'requests.json'; rq = json.loads(p.read_text()); rq[1]['challenge_hex'] = rq[1]['challenge_hex'][:-2]; p.write_text(json.dumps(rq))
def c_missing_marker(d):
    es = [neutralize(e) if (e['kind'] == 'zk_decision' and e['fields'].get('request_id') == 'Z6' and e['fields'].get('policy') == 'V0') else e for e in events(d)]
    wevents(d, es)
def c_malformed_row(d):
    p = d / 'decisions.jsonl'; p.write_text(p.read_text() + '{not json\n')

before = [('unmodified', c_unmodified), ('remove-all-Z4-rows', c_remove_z4), ('duplicate-first-row', c_duplicate_row),
          ('all-receipts-replaced-same-filename', c_corrupt_receipts), ('all-approval-events-neutralized', c_remove_all_approval_events)]
after = before + [
    ('one-receipt-file-removed', c_remove_one_receipt), ('row-receipt-hash-points-to-other-receipt', c_row_hash_to_other_receipt),
    ('row-verified-journal-altered', c_row_journal_altered), ('proof_valid-true-on-corrupted-Z9a', c_false_valid_z9a),
    ('proof_valid-false-on-genuine-Z1', c_false_invalid_z1), ('row-expected-image-id-changed-Z9b', c_row_image_changed),
    ('one-approval-event-neutralized-Z1-VTI', c_remove_one_approval_event), ('orphan-approval-event-Z2-V0', c_orphan_approval),
    ('approval-event-duplicated-Z1-V0', c_duplicate_approval), ('approval-event-receipt-changed-Z1-VT', c_approval_fields_changed),
    ('prior-approval-removed-before-duplicate-delivery', c_prior_approval_removed_for_duplicate), ('approval-flag-flipped-only-Z4-VTI', c_approval_flag_flipped_only),
    ('events-truncated-mid-line', c_truncated_events), ('sequence-gap', c_seq_gap), ('sequence-duplicate', c_seq_duplicate),
    ('unknown-policy-string', c_unknown_policy), ('null-request-record', c_null_request), ('short-challenge-hex', c_bad_challenge_hex),
    ('decision-marker-neutralized-Z6-V0', c_missing_marker), ('malformed-decision-row', c_malformed_row)]

results = []
for name, fn in (before if a.cases == 'before' else after):
    d = out / name
    if d.exists(): shutil.rmtree(d)
    shutil.copytree(run, d, ignore=shutil.ignore_patterns('oracle-controls', 'process-logs', 'boot', 'oracle*.json*', 'oracle.md'))
    fn(d)
    cmd = [a.bin, 'zk-oracle', '--results', str(d), '--openings', a.openings]
    if a.legacy_inventory: cmd += ['--legacy-inventory', a.legacy_inventory]
    if a.verify_bin: cmd += ['--verify-bin', a.verify_bin]
    p = subprocess.run(cmd, capture_output=True, text=True)
    (d / 'cli.log').write_text(p.stdout + p.stderr)
    summ = {}
    sp = d / 'oracle-summary.json'
    if sp.exists(): summ = json.loads(sp.read_text())
    item = {'control': name, 'exit': p.returncode, 'stdout': p.stdout.strip()[-400:], 'stderr': p.stderr.strip()[-300:]}
    for k in ('rows', 'scored', 'incomplete', 'malformed', 'violations', 'observed_vs_policy_semantics_disagreements', 'disagreements', 'evidence_mismatches', 'expected_attack_successes'):
        if k in summ: item[k] = summ[k]
    results.append(item); print(json.dumps(item))
(out / 'controls.json').write_text(json.dumps({'bin': a.bin, 'bin_sha256': hashlib.sha256(Path(a.bin).read_bytes()).hexdigest(), 'run': str(run), 'legacy_inventory': a.legacy_inventory, 'verify_bin': a.verify_bin, 'cases': a.cases, 'results': results}, indent=1) + '\n')
