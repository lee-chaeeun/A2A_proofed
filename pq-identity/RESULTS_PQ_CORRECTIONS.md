# PQ identity corrections — before/after (8 November 2026, 14:11–15:50 UTC)

Scope: `paper/a2a-identity/REVIEW_PQ_IDENTITY.md` (two P1 findings, the P2 wording
findings) plus the runner defect. Plan frozen before editing: `PQ_CORRECTION_PLAN.md`
(sha256 `cc5c7efd…`, recorded 14:11Z in `results/audit/20261108T141124Z-pqcorr-prefix/`
with the pre-edit source hashes, the pre-edit binary `4a7b1634…` and the reproductions
below). The native emulator ML-DSA demonstration (`results/audit/20261108T130125Z-pq-gate/`)
is untouched. Predictions (`fixtures/predictions-pq.md` `e53f992b…`) and the manifest
(`190281fa…`) are unchanged. Earlier reports: `RESULTS_PQ_IDENTITY.md` (pre-correction
state, dated pointer at its top), `PQ_IDENTITY_PLAN.md`.

## 1. Reproduced before editing (pre-edit source and binary)

| finding | reproduction | record |
|---|---|---|
| ZK requester sends the task on a replacement connection after a valid bound proof | reviewer overlay test `TestReviewerPQZK_ReconnectDelivery` against the research `internal/zk`: PASS = the task POST arrived on a second TLS connection (proof 127.0.0.1:53158, task :53172) | `…pqcorr-prefix/reproduction/transport-characterization-pre-edit.log` |
| `audit-pq` v1 accepts seven evidence mutations as clean | all seven reviewer copies re-audited with the pre-edit binary: exit 0, 128 agree, 0 violations each | `…pqcorr-prefix/reproduction/<mutation>/pq-audit-summary.json` |
| `audit-release` v2 cannot stand in | unmodified copy of `results/pq/20261108-142717`: exit 2, 32 `unsupported_historical_schema` (P2/P7 early rejections without typed context, P11 hand-built decisions) | `…pqcorr-prefix/reproduction/baseline-release/release-audit-summary.json` |
| runner suppresses the audit | `scripts/pq_matrix.sh` had `audit-pq … \|\| true`; the control script printed but never asserted | pre-edit tarball `source-pre-correction.tar.gz` |

## 2. Corrections

**ZK transport continuity (`internal/verifier`, `internal/zk/requester.go`).** The
release guard of the identity requester (single-use authorization per issued session,
typed authorization/dispatch contexts, transport seal, pre-send check that the one
recorded connection is the proof connection, refusal of any new dial, classification of
a written-but-unanswered request as *unknown*) was extracted into `GuardedSend`, used by
the synthetic-job `Release` and by the ZK requester for `PQ-device+cb`. The ZK task is
the only message sent (no synthetic job). Errors keep their chain: `ErrDeliveryRefused`
(nothing sent) and `ErrDeliveryUnknown` (written, no response; resolve from the worker's
record). Recovery is a new `Dispatch` (new connection, nonce, proof, decision). The
`C+tls` baseline keeps its documented semantics. The exchange record now carries the
identity decision's bounded record (decision id, proof/pinned/dispatch connection ids,
token, dials refused, requester events, connections) and a `delivery_outcome`.

Regression tests (`internal/zk/pq_transport_test.go`, real HTTPS a2a-go servers,
software ML-DSA test key enrolled under the device policy base, stub receipt, server
counters; these test transport, not custody or computation):

| case | server counters | requester record |
|---|---|---|
| honest | 1 proof, 1 task, 1 TLS connection; task on the proof connection | delivered; pinned = dispatch = proof connection 1; events challenge_sent…sealed…sent |
| proof connection closed, replacement with same certificate and no signer (reviewer scenario) | **0 tasks** | refused before any byte; `refused_reconnect`; `ErrDeliveryRefused` |
| server would sign again on a new connection | 1 handshake, 0 tasks | the dial is refused by the seal and counted (`tls_dials_refused ≥ 1`) |
| fresh decision after refusal | 2 proofs, 2 handshakes, 1 task on the second proof connection | new decision id, nonce and token |
| server reads the task and closes without responding | 1 task, 1 handshake | `unknown` (sent, no response), no second connection |
| wrong key under the enrolled key id | 0 tasks | rejected at the proof stage, no authorization event |

Genuine-receipt smoke test over the lab (`results/zk-pq-smoke/20261108-154419/`): honest
PQ-device+cb task delivered through the guard (connection 1 for proof and dispatch),
fresh proof 18.9 s, receipt verified under the pinned image id, four approvals under
Pinned; impostor (A's TLS credentials, own keys under A's kids) rejected, zero
`zk_task_served` at B. One smoke test, not a new 52-cell matrix.

**Composite audit (`audit-pq` v2, `internal/pqaudit`, structural checker 2.1 in
`internal/audit`).** Per declared cell: strict loading (inventory, decision record,
sessions, controller events; any parse error is malformed, never ignored); the
structural release invariants of checker v2 (contiguous events, no duplicate critical
event, path-specific ordering and terminals, typed context equality across decision,
authorization and dispatch, issued-session join and token, pinned = proof connection,
exactly one connection, job written to the pinned connection, receipt joins by decision
id, token and exporter, one receipt per dispatch, release cardinality, orphan receipts,
duplicate decision ids); proof re-verification (algorithm/kid pin, strict context
decode, expected context rebuilt from the issued session, typed `appraised_at` inside the
session validity, expiry window, signature); agreement with the declared inventory.
Checker 2.1 differs from 2 in two rules only: session checks apply once a nonce was
issued (an early rejection has no session), and the per-decision entry points are
exported. Records lacking schema-2 fields are `unsupported`, never upgraded; the old
final run `…142717` therefore audits as exit 2 with 24 unsupported cells (P2, P7, P11)
under the new audit, which is why fresh records were collected.

Producer changes so that every path yields a full schema-2 record (`producer_revision`
= `2026-11-08-pq-corrections`, written into each decision and the run inventory): the
typed decision context exists from the first event; `connect_failed` is emitted for
endpoint-equality and TLS-name failures, not only for card-fetch failures; the
concurrent-delivery and nonce-burn drivers use the same lifecycle helpers as `Run`
(`Challenge`, `AppraiseRecord`) and card-only legs issue no nonce.

**Controls.** `scripts/pq_audit_controls.py` now asserts every exit code against the
frozen table `fixtures/pq-audit-controls-expected.json` (sha256 `620bb735…`) and exits
non-zero on any mismatch or uncovered case. Seventeen cases: the ten original ones and
R1–R7 from the review. `internal/pqaudit/pqaudit_test.go` applies the same mutations to
a six-cell fixture copied from the retained run (`fixtures/testdata/pq-mini-run`) and
also drives the real CLI.

**Runner.** `scripts/pq_matrix.sh` fails at the first failing stage (build, setup,
matrix, audit, controls, tests), validates the run-path handoff (exit 3 when the path
is empty or has no inventory) and removes its temp file by trap. `scripts/test_pq_runner.sh`
injects failures with stubs: audit exit 1 and 2, a control that unexpectedly exits clean
(stub audit always 0 against the real table), matrix failure, bad run path, setup
failure, test failure, and one all-real case; nine cases, all as expected.

## 3. Frozen control expectations vs. observed (final run, `results/audit/20261108T143109Z-pq-audit-controls/`)

| control | frozen | observed |
|---|---|---|
| unmodified | 0 | 0 |
| removed cell | 2 | 2 |
| duplicate decision record | 1 | 1 (*) |
| altered context bytes | 1 | 1 |
| changed signature | 1 | 1 |
| substituted registry public key | 1 | 1 |
| proof removed, accept kept | 1 | 1 |
| unknown algorithm label | 2 | 2 |
| policy downgrade in a decision | 1 | 1 |
| forged accept flag | 1 | 1 |
| R1 requester events removed | 2 | 2 |
| R2 dispatch connection 999, reused=false | 1 | 1 |
| R3 dispatch-context action changed | 1 | 1 |
| R4 issued sessions removed | 2 | 2 (**) |
| R5 appraisal time `not-a-time` | 2 | 2 |
| R6 duplicated receipt | 1 | 1 |
| R7 receipt id/token/exporter changed | 1 | 1 (orphan receipt + sent dispatch without receipt) |

(*) Prediction miss, corrected before the evidence run: the first composite
implementation returned 2 (the cell failed its declared count before decision ids were
compared). Duplicate-id registration was moved before the cardinality gate on the test
fixture at 14:27Z; the run and controls above were executed after that change.
(**) The reviewer's variant of R4 (sessions set to an empty list rather than removed)
classifies as a violation (exit 1: "issued session exists" fails); both are non-clean.

## 4. Corrected evidence

| item | value |
|---|---|
| source snapshots | `results/audit/20261108T142748Z-pqcorr-snapshot` (attempt 1), `…143034Z-pqcorr-snapshot-2` (final; `files-changed-since-snapshot-1.txt`: audit.go, matrix.go, verifier.go) |
| attempt 1 (retained, superseded) | `results/pq/20261108-152809`, binary `8d047e2e…`: 128/128 predictions, composite audit exit 1 (24 structural violations), runner stopped at the audit gate; causes and the re-audit with the corrected checker in `ATTEMPT-NOTE.md` / `…142748Z-pqcorr-snapshot/attempt-1-recheck/` |
| **final run** | `results/pq/20261108-153049`, binary `15b7717f…`: **128/128**, audit exit 0 (16 verified dispatches, 95 verified non-dispatches, 25 declared attacker deliveries, 35 proofs valid / 84 invalid as recorded, 0 orphan receipts, 0 duplicate ids); controls 17/17 as frozen; `go test -race ./...` passed inside the runner (`…snapshot-2/matrix-attempt-2.log`) |
| integration rerun | `results/pq-integration/20261108-164204`, same binary: 128/128, audit exit 0, identical structural counts |
| retries | one (attempt 1 → 2) of the declared budget of two |
| public-copy emulator build | `results/audit/20261108T141020Z-public-toolchain-build/`: first attempt failed at a script defect (`options.h` is generated in the wolfTPM source tree at commit `1362e1e5`; the script looked only in the build tree; fixed in both trees); rerun from the public copy: wolfSSL `0ac786e0`, wolfTPM `1362e1e5`, `libwolfssl.a` `b763e2ff…` and `libwolftpm.a` `7ee6c94e…` byte-identical to the research build, `pqtpm` `b69d5dc7…` identical, `fwtpm_server` `b38b243b…` (research `65ae8f1b…`; same sources, different embedded build paths); opt-in device test against that backend on port 2371: PASS (create, sign, CIRCL verification, tampered message/context/signature rejected, wrong auth `TPM_RC_BAD_AUTH`, restart persistence, evict) |
| signed-context lengths (honest cells, final run) | EC-env 271/303 B (+tls/+cb), PQ-env 275/307, PQ-file 309, PQ-device 278/310; the microbenchmark message is a fixed 306-byte context |
| challenge→proof latency (honest cells, two executions) | ECDSA 1.4–2.6 ms, software ML-DSA 1.9–2.6 ms, device 3.8–4.9 ms; connect→appraised 2.1–2.9 ms (C+tls) to 6.7–7.5 ms (PQ-device) |

Matrix outcomes are unchanged from the pre-correction report (same 128 recipients; P8,
P6, P12, X1–X4 readings as before). The `Version` field of the registry is a label: what
the verifier enforces is the pinned algorithm, key id and public key; X4 changed the
enrolled key id (and the label) for PQ-file and the copied volume's key was rejected at
the key-id stage. No rotation or revocation protocol is claimed.

## 5. Checks executed and skips

Executed from the research tree: `go vet`, `go test -race -count=1 ./...` (all packages,
twice: standalone and inside the runner), `scripts/test_pq_runner.sh` (9/9),
`scripts/pq_audit_controls.py` on the fixture and on the final run, the composite audit
on the final run, the rerun and the old runs, the opt-in device test (research backend
and public-copy backend), the opt-in genuine-receipt smoke test (twice; the second after a
wording change of the test). Not run: a new 52-cell ZK matrix, the bench (unchanged
code), physical hardware. Default `go test` skips the device test, the ZK integration /
oracle tests and the smoke test unless opted in; they were run explicitly as listed.

## 6. Remaining limitations

Emulator state and authorization material are files; physical non-exportability was not
measured. Agent Card JWS, TLS 1.3, the lab CA and the swtpm quote are classical; the
classical-compromise fixture is a capability model. The audit validates the consistency
of trusted, cooperative observations with shared verification libraries; it does not
establish that logs describe reality. The ZK component proves the pinned computation,
not the prover's identity, input trustworthiness or PQ security. 128/128 is agreement
with declared outcomes including 25 declared attacker deliveries.
