# Results map: which artifact supports which claim

Paths are relative to this repository. Full reports: `identity/RESULTS_V3_FINAL.md`,
`identity/RESULTS_V3_CORRECTIONS.md`, `identity/RESULTS_V2.md`, `zk-component/RESULTS_ZK.md`,
`zk-component/RESULTS_ZK_CORRECTIONS.md`; the paper's own table is `paper/CLAIM_EVIDENCE_TABLE.md`.

## Identity component (`identity/`)
| claim (paper section) | artifact | note |
|---|---|---|
| Endpoint/TLS controls stop copy, replay, different-address and credential-less hijack; stolen TLS credentials defeat +tls (§4.1, Table 1, App. C) | `identity/results/v2/20261107-194025/matrix.csv`, `appraisals.*`, `provenance.json`, `predictions-frozen.md` | 231 cells, 201 applicable, 199/201 predicted; per-cell traces of this run are not in the copy |
| Channel binding rejects the stolen-TLS relay identically for S-env and T; 24/24 agreement incl. 8 attacker deliveries; receipts 10 TLS (5 A, 5 B) + 4 HTTP (§4.2, Table 2) | `identity/results/v3-final/20261108-004047/matrix.csv`, `release-audit.md`, `release-audit-summary.json`, `cells/*` | checker v2 exit 0: 6 verified dispatches, 10 verified non-dispatches, 8 fixture-expected violations |
| Pre-fix binding downgrade and cross-policy oracle deliver to the relay (§4.3) | `identity/results/v3-repro/20261107-202528/matrix.csv` | archived v2 binary; 17 matches / 7 misses against post-fix predictions |
| Pre-fix dispatch to a replacement connection (§4.3) | `identity/results/audit/20261107T225036Z-v2-continuity-historical/go-test-output.txt` (line "RESULT: B RECEIVED THE JOB") | adapted test on an isolated extraction of the archived v2 source; logs rather than asserts |
| Post-fix continuity cases and churn (§4.4) | `identity/results/v3-final/20261108-004047/continuity/`, `continuity-test-summary.txt`, `churn.txt` | T+cb 30/30/0; S-env+cb 28 refused + 2 client-unknown, 30 A receipts, 0 B |
| Checker v1 false-cleans and v2 classifications (§4.5) | `identity/results/audit/20261107T233054Z-checker-falseclean-before/`, `…234220Z-checker-falseclean-after/`, `identity/results/reviewer-v3-final/` | exits 2,2,1,1,1 after |
| swtpm clone + PCR re-extend impersonates A under T/P (§4.1 F19/F21) | `identity/results/v2/20261107-194025/matrix.csv` rows F19, F21 | software emulator only |
| Superseded first final run (schema 1, checker v1) and two failed attempts | `identity/results/v3-final/20261108-000017/` (top level), `20261107-235740/`, `20261107-235908/` | kept deliberately; not validation evidence |

## Computation component (`zk-component/`)
| claim (paper section) | artifact | note |
|---|---|---|
| Genuine proofs; 12 min to first proof; 22.1–23.6 s per proof; 223,348-byte receipts (§5.1) | `zk-component/results/zk/feasibility/feasibility.json`, `results/zk/20261108-111817/exchanges.jsonl`, `receipts/` | one CPU host; 7 timings |
| 52/52 cells; Z6/Z7 Pinned vs Current; Z4 obsolete input with fresh challenge; Z3 replay (§5.2, Table 3) | `zk-component/results/zk/20261108-111817/decisions.jsonl`, `summary.md`, `ledgers.json`, `run-inventory.json` | inventory declared before execution; 9 exchanges, 7 new proofs, 0 cache hits (`run-stats.json`) |
| Oracle v2 agreement, 10 receipt/image pairs re-verified (7 valid, 3 rejected), 7 expected weak-policy successes (§5.3) | `zk-component/results/zk/20261108-111817/oracle-summary.json`, `oracle.md` | re-runnable: `bin/a2aid zk-oracle --results … --verify-bin zk/target/release/zkverify --out <dir>` |
| Oracle v1 false-cleans; v2 rejects 24 mutations (§5.3) | `zk-component/results/audit/20261108T105605Z-zk-before-fix/oracle-controls-pre-edit/controls.json`, `…111037Z-zk-oracle-controls-after-legacyview/controls.json`, `…112131Z-…-after-schema2/controls.json` | per-case `cli.log` and `oracle-summary.json` kept; mutated run copies omitted |
| Unsigned-card task delivery before the transport repair; rejected after (§5.3) | `…105605Z-zk-before-fix/unsigned-card-characterization-pre-edit.log`, `…112430Z-zkcorr-final-snapshot/unsigned-card-characterization-post-fix.log`, `zk-component/internal/zk/transport_test.go` | reviewer evidence in `results/reviewer-zk/20261108T103550Z/` |
| First run (superseded as validation) and its legacy replay view | `zk-component/results/zk/20261108-002724/`, `results/audit/20261108T112526Z-zk-legacy-view-20261108-002724/` | same 52 outcomes; scored by oracle v1 at the time |
| Independent second executions | `zk-component/results/zk-integration/20261108-112143/`, `20261108-003306/` | integration test logs `results/zk/zk-integration-test*.log` |
| Pre-specification and timestamp disclosure (§5.3, App. B) | `zk-component/results/zk/PLAN.sha256` (00:06:31Z), `results/zk/20261108-002012/predictions-frozen.json` (byte-identical to `fixtures/zk/predictions.json`) | `frozen_at` string in the JSON is a mislabeled local time |

## Metrics as printed in the paper
Identity v2: 55/140 attacker-endpoint cells delivered to B (per policy in §4.1); honest 0/22 rejected.
Identity final: 24/24 decision and recipient agreement; 14 receipts (10 TLS: 5 A, 5 B; 4 HTTP).
ZK final: 52/52; wrong-context accepted 3/8; unsafe approvals 5/12; legitimate denied 0/12.
