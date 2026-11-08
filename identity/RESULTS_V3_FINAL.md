# RESULTS v3-final — closing the V3 evidence gaps (8 Nov 2026)

Declared plan: `V3_FINALIZATION_PLAN.md` (sha256 `bb4218f5…`, recorded before
execution in `results/audit/20261107T223952Z-v3final-prefix/PLAN.sha256`). Everything
earlier is preserved unchanged: v1, v2, the v3 runs (`results/v3-repro/20261107-202528`,
`results/v3/20261107-203206`, `results/v2-postv3fix/20261107-203958`), the frozen
`fixtures/manifest-v3.json` / `predictions-v3.md` (addendum appended, body unchanged),
`RESULTS_V3.md` (addendum appended) and the paper versions under `../paper/a2a-identity/`.

## Identities

| item | value |
|---|---|
| retained final run | `results/v3-final/20261108-000017` |
| source snapshot | `results/audit/20261107T230016Z-v3final-snapshot/source-v3final.tar.gz`, sha256 `8f8b4256…` (per-file hashes in `source-sha256-v3final.txt`, copied into the run) |
| binary | `bin/a2aid` built with `-trimpath` from the tree **and** from the extracted snapshot: both sha256 `ecfc5b01…` (byte-identical) |
| provenance | `provenance.json`: source-tree `1a5eeda7…`, manifest `33f31480…` (`manifest-v3-final.json`), predictions `b15a749d…` (`predictions-v3-final.md`) |
| pre-edit snapshot | `results/audit/20261107T223952Z-v3final-prefix/` (source, binary, paper hashes before any edit of this task) |
| failed attempts (retained) | `results/v3-final/20261107-235740`, `results/v3-final/20261107-235908` — harness defects (evidence path, checker classification), see `FAILED-ATTEMPT-NOTE.txt` in each. The plan budgeted two retries; this used three attempts in total, one more than declared. |
| working tree after the run | every Go, fixture and script file in `source-sha256-v3final.txt` still matches (`sha256sum -c`); the only post-run changes are documentation (`README.md`, `SCOPE_AND_LIMITATIONS.md`, `RESULTS_V3.md` addendum, this file) whose post-run hashes are in `docs-and-paper-sha256-postrun.txt` in the snapshot directory. `internal/audit/audit.go` is kept byte-identical to the snapshot even though `gofmt -l` would realign one block (formatting only). |

## 1. Accounting corrections (Priority: §1 of the brief)

* **Retained fixed V3 matrix** (`results/v3/20261107-203206`, confirmed from `matrix.csv`):
  24 cells, 20 prediction matches, **4** misses (V3_S-env+tls, V3_T+tls, V4_S-env+tls,
  V4_T+tls). The earlier "six" is corrected in a dated addendum to
  `fixtures/predictions-v3.md`. The pre-fix reproduction has 17 matches and 7 misses
  against the same post-fix predictions (the four, plus V3_S-env+cb, V3_T+cb, V4_T+cb
  accepting with delivery to B — the reproduced defect).
* **Honest controls**: six V1 cells deliver to A. The generated "0/0" line was an F1/F2
  name filter; the summary now counts the explicit fixture `class`.
* **New prediction schema** (`manifest-v3-final.json` v4): `class` per fixture
  (honest / malicious / ablation), `policy_classes` (ablation / secured-baseline /
  defended) and, per policy, `expected_decision` **and** `expected_recipient`.
  `accept` is never read as "delivered to A".
* **V3/V4 under +tls**: predicted and observed `reject → none`, with the explanation
  retained: the chosen-nonce rewrite is self-defeating off +cb; the attacker's working
  attack against the +tls proof policies is the untouched relay V2, which delivers to B.
* **Reverification wording**: `reverify.md` describes the offline pass as shared-code
  consistency with cryptographic recomputation where applicable, conditional on
  recorded transport/ordering facts; categories are reported, not summed.

### Final matrix (`results/v3-final/20261108-000017`)

24 cells; decision matches 24/24; recipient matches 24/24. Honest 6 → A. Malicious 18:
10 reject → none, 8 accept → **B** (V2 × {C+url, C+tls, S-env+tls, T+tls}; V3, V4 ×
{C+url, C+tls}). 0 deliveries to B under S-env+cb and T+cb. Offline reappraisal 24/24
agree (shared code). Wall time 4.0 s.

| Fixture | C+url (ablation) | C+tls | S-env+tls | S-env+cb | T+tls | T+cb |
|---|---|---|---|---|---|---|
| V1 honest | A | A | A | A | A | A |
| V2 stolen-TLS relay, untouched | B | B | B | R | B | R |
| V3 binding downgrade | B | B | R\* | R | R\* | R |
| V4 cross-policy oracle | B | B | R\* | R | R\* | R |

\* attack-script self-defeat, not protection (see above). Every cell as declared in
`predictions-v3-final.md`; no divergence.

## 2. Release-evidence checker (§2)

Replaced `release_oracle.go` with `internal/audit` (`a2aid audit-release`). It does **not**
call `Appraise`/`finalize`; it joins retained records by ids and recomputes relations.

**Instrumentation exported per decision** (`cells/<cell>/decision.json`, mirrored to the
controller as `req_event`): `decision_id`; expected label and enrolled deployment id;
policy, action, audience, nonce (session id), job token; `connections[]` with per-decision
`conn_id`, requester-observed peer-certificate SHA-256 and exporter; `discovery_conn_id`,
`proof_conn_id` (httptrace `GotConn`), `pinned_conn_id`, `dispatch_conn_id`; `job_sent`
(httptrace `WroteRequest` without error — "written to the transport", not wire proof);
dial and refused-dial counters; ordered `requester_events` with sequence numbers
(`connect`, `card_fetched`, `challenge_sent`, `proof_received`, `appraised`,
`authorized`, `sealed`, `dispatch_attempt`, `got_conn`, `sent`, `ack` | `no_ack` |
`refused_reconnect` | `refused_dispatch` | `unknown_outcome` | `dispatch_error`). Agents'
`job_received` now carries the echoed `decision_id`, their enrolled `deployment_id` and
**their own** exporter for the receiving connection. The job message carries the
decision id as a causal identifier.

**Checks and trust classes** (per decision; see `release-audit.md`): recomputed
(sequence contiguity; appraised < authorized < dispatch_attempt < sent; authorization
context = decision context = issued session; pinned = proof connection; exactly one TLS
connection; dispatch written to the pinned connection; one business release per token;
refused ⇒ no send/receipt; rejected ⇒ no token/dispatch/receipt), requester TLS
observation (pinned connection's peer certificate = the decision's authenticated peer;
+cb proof checked against that connection's exporter; receipt exporter = requester's
pinned exporter), cooperative event (receipt source label = expected label, derived from
the decision's expected enrolled identity through the registry, never a literal; claimed
deployment id = enrollment), copied appraisal (the accept flag, reported as copied),
stipulated order (receipt after dispatch across processes rests on the token's causal
origin; arrival order is the trusted controller's).

**Outcomes** (each decision once): verified_dispatch, verified_non_dispatch,
violation, violation_expected_by_fixture (malicious class whose declared expected
recipient is B and only the recipient checks fail), insufficient_evidence,
unsupported_historical_schema, malformed, ablation_excluded. Run-level: inventory
mismatch (declared `run-inventory.json`, written before execution), orphan receipts,
duplicate tokens, malformed files. Exit 0 = no unexpected violation and complete; 1 =
unexpected violation; 2 = incomplete/unsupported/malformed/missing cells. An empty run
or missing cell cannot audit clean.

**Results**

| input | verdict | exit | decisions | dispatches | receipts | outcomes | checks by class (failed/total) |
|---|---|---|---|---|---|---|---|
| final matrix run | NO UNEXPECTED VIOLATION | 0 | 24 | 14 | 14 | 6 verified_dispatch, 10 verified_non_dispatch, 8 violation_expected_by_fixture | recomputed 0/164 · requester TLS 0/22 · cooperative 8/28 (the eight B receipts) · copied 0/24 · stipulated 0/14 |
| continuity S-env+cb | NO UNEXPECTED VIOLATION | 0 | 7 | 6 | 2 | 2 verified_dispatch, 4 verified_non_dispatch, 1 ablation_excluded | recomputed 1/56 (the ablation's unset pin) · TLS 0/12 · cooperative 0/4 · copied 0/7 · stipulated 0/2 |
| continuity T+cb | NO UNEXPECTED VIOLATION | 0 | 7 | 6 | 2 | same | same |
| copy of retained `results/v3/20261107-203206` | INCOMPLETE | 2 | 24 | 0 | 0 | 24 unsupported_historical_schema | the historical records have no decision ids or requester events; the checker does not pretend otherwise |

The eight `violation_expected_by_fixture` rows are the release invariant genuinely
violated — a job expected for A reached B — exactly where the manifest predicts it (the
unbound policies with stolen TLS credentials). The ten TLS deliveries to A carry a
receipt whose server-side exporter equals the requester's pinned connection exporter
(`receipt_exporter_match = yes`, 10/10; `n/a` for the four plain-HTTP C+url deliveries).
All 14 receipts join by decision id.

**Negative controls** (`internal/audit/audit_test.go`, 14 tests, all passing in the run's
`audit-negative-controls.log`): mutated copies of real records (`testdata/base`, the
S-env+cb continuity set) run through the same `Run` the CLI calls. Missing receipt for a
sent dispatch → insufficient, exit 2. Missing connection evidence → violation, 1. Wrong
recipient → violation, 1. Dispatch on another connection → violation, 1. Changed context →
violation, 1. Removed authorization → violation, 1. Reordered requester events →
violation, 1. Duplicate business release → violation, 1. Malformed/truncated JSON (record
and event line) → malformed, 2. Missing cell vs inventory and an empty `cells/` →
incomplete, 2. Unknown policy → malformed, 2. Stripped ids (historical schema) →
unsupported, 2. Orphan receipt → violation, 1. Receipt exporter mismatch → violation, 1.
Positive: the unmodified base is clean (0) and the legitimate rejected attempt (split
connection) is `verified_non_dispatch`.

**Bounded claim.** This is a structural audit of cooperative, requester-observed and
controller-attributed records. Authorization validity is conditional on the recorded
appraisal; it is not tamper-proof evidence or a security proof.

## 3. Continuity coverage (§3)

`internal/verifier/continuity_final_test.go`, real a2a-go HTTPS servers and the production
requester; both **S-env+cb** and **T+cb with a real swtpm** (restricted AK, `TPM2_Quote`
over the domain-separated context; swtpm present, so nothing was skipped). B holds A's
TLS certificate and key, is placed at A's name by the resolver and can reach A, but has
**no proof key and no signer access** (it answered 0 challenges). C presents a lab-CA
certificate for the other enrolled name. Barriers are the requester's synchronous lab
hooks (`after-connect`, `after-appraise`, `before-dispatch`; nil in production). Delivery
is asserted from the servers' receipt logs (token, decision id, exporter), never from
`JobReleased`.

| case | S-env+cb | T+cb | evidence |
|---|---|---|---|
| 1 uninterrupted honest | 1 A receipt; receipt exporter = requester's dispatch conn exporter; order authorized<dispatch<sent<ack | same | `continuity/*/cells/1_*` |
| 2 valid proof, close before send, next dial → B (TLS cert/key only) | `refused_reconnect`, 0 bytes written, 1 refused dial, no B receipt, no A receipt, B asked for 0 proofs | same | `cells/2_*` |
| 3 discovery and proof on separate connections | fail-closed at stage `binding` (two distinct exporters in one decision); no token, no dispatch | same | `cells/3_*` |
| 4 replacement with a certificate for the other enrolled name | sealed requester refuses **before dialing** (layer = seal; TLS never saw the replacement) | same | `cells/4_cert_swap_sealed` |
| 4 ablation (seal disabled, labelled, non-production) | dial attempted, TLS hostname validation rejected it (layer = tls); no receipt | same | `cells/4_cert_swap_noseal_ABLATION` |
| 5 honest close before dispatch, then a NEW decision | decision 1 refused pre-send, no receipt; decision 2 fresh nonce/proof, exactly one A receipt | same | `cells/5_*` |

**Pre-send check.** `Release` seals the transport (new dials are refused before any
connect) and, before the task is handed to the transport, requires exactly one recorded
TLS connection equal to the proof connection (card connection for C policies). Every SDK
or transport retry needs a connection and every connection passes through the sealed
recorder, so no retry path reaches a connection the proof did not use. a2a-go v2.3.1
itself adds no retry layer; it uses the supplied `http.Client`.

**Churn** (60 trials per defended policy, even trials close the proof connection and
repoint the name to B; retained `churn.txt`):

```
S-env+cb: attempts=60 accepted=60 dispatch_attempts=60 written_to_transport=30 refused_reconnect=30 client_unknown_outcome=0 acks=30 A_receipts=30 (all matching acked tokens) B_receipts=0 errors=0
T+cb:     attempts=60 accepted=60 dispatch_attempts=60 written_to_transport=30 refused_reconnect=30 client_unknown_outcome=0 acks=30 A_receipts=30 (all matching acked tokens) B_receipts=0 errors=0
```

**A client-side ambiguity, kept visible.** The churn test deliberately omits the
drop barrier used in case 2. In development runs, 0–2 of the 30 interrupted S-env+cb
trials (0 of 30 for T+cb) reached `client_unknown_outcome`: the HTTP transport buffered
the request to the already-closed proof connection, the flush failed, and the retry dial
was refused. The client cannot prove by itself that nothing left on the dead connection;
the server logs showed no receipt in every such trial, and no task was ever retried on
another connection. The retained run recorded 0 unknowns for both policies; the category
exists because it can occur.

**Historical P0-B.** No retained pre-fix continuity execution existed. A minimal
close-then-swap test was added to an **isolated extraction** of the archived v2 source
(`source-v2.tar.gz`, sha256 `4d5b73cf…`; test file sha256 and the extracted-tree hashes
in `results/audit/20261107T225036Z-v2-continuity-historical/`). With TLS cert/key only
(B answered 0 challenges), the v2 requester accepted A's proof and **delivered the job to
B** over a new connection (B acknowledged as dep-B; A received nothing). The archive and
the production tree were not modified; the test file is stored with a `.txt` suffix.
Both P0 attacks therefore have pre-fix reproductions on archived code: P0-A in
`results/v3-repro`, P0-B in this adapted test.

## 4. Tests and runs (§4)

* `go test -race -count=1 ./...`: all packages ok (run log `go-test-race.log`). A
  verbose pass of the whole module ran 113 tests with exactly **one skip**: the opt-in
  integration test, which skips without `A2AID_INTEGRATION=1` and was run separately
  with it (PASS, below). swtpm was present, so every emulator-backed test ran.
* Opt-in `A2AID_INTEGRATION=1 go test -run Integration ./internal/matrix`: PASS (7.8 s),
  lab ports, output under `results/integration/`.
* Continuity/churn/regression verbose log: `continuity-test.log`, 13 top-level tests
  PASS (T+cb cases included), 0 SKIP.
* Audit negative controls: 14 PASS.
* Not rerun: v1/v2 full matrices, fuzz campaigns (no regression reason).

## 5. Claim-to-evidence table

| claim | evidence | trust basis | not covered |
|---|---|---|---|
| Six honest V1 cells deliver to A; 24/24 decisions and recipients as declared | `results/v3-final/20261108-000017/matrix.csv`, `predictions-v3-final.md` | typed controller receipts, requester records | population rates |
| Under stolen TLS credentials the +tls proof policies deliver to B, the +cb policies reject, identically for S-env and T | same run, V2 row; v3 retained run | same | universal relay resistance; proxies/replicas |
| Binding downgrade and cross-policy oracle were real pre-fix and are rejected post-fix | `results/v3-repro/20261107-202528` vs `results/v3/…` and the final run; `binding_regression_test.go` | retained runs on archived vs current binaries | all possible protocol attacks |
| Pre-fix dispatch reached B after A's proof (connection swap) | adapted test on the archived v2 source, `results/audit/…-v2-continuity-historical/` | isolated archive copy, hashes | realism of client-side close |
| Post-fix: swap, split, cert-swap, honest recovery behave as declared for S-env+cb and swtpm T+cb | `continuity/*/cells/*`, `continuity-test-summary.txt` | server receipt logs + requester records, audited | automatic retry; OS-level enforcement |
| Churn 60/60 per policy, 0 B receipts | `churn.txt` | server-side counts | scheduling beyond 60 concurrent trials |
| Structural release audit clean with 8 fixture-predicted invariant violations | `release-audit*.{md,json,jsonl}` | cooperative records, requester TLS observations | tamper-proof evidence; independent crypto appraisal |
| Checker detects corrupted artifacts | `audit-negative-controls.log`, `internal/audit/audit_test.go` | mutated copies of real records | corruptions not in the list |
| Snapshot ↔ run ↔ binary linkage | snapshot tarball/hashes, byte-identical builds, `provenance.json` | sha256 | reproducibility on other toolchains |

## 6. Unresolved and out of scope

* Requester authentication (mTLS), OS isolation, containers, physical TPMs, model
  inference, ZK proofs: not built (per brief).
* Honest interrupted deliveries fail closed; recovery is a new explicit decision, not
  automatic retry.
* The interrupted-write ambiguity above is inherent to client-side observation; the
  design never resolves it by retrying on another connection.
* F21's copied assets differ; PCR 16 is an operator-supplied synthetic value; emulator
  cloning says nothing about hardware.
* The structural audit depends on cooperative logs and the harness's process attribution.

## 7. Reproduction

```
./scripts/setup.sh
./scripts/v3final.sh          # snapshot, build, 24-cell rerun, continuity/churn evidence, audits, tests
bin/a2aid audit-release --results results/v3-final/<run>              # exit 0/1/2
bin/a2aid audit-release --results results/v3-final/<run>/continuity/T_cb
A2AID_EVIDENCE_DIR=$PWD/some/dir GOFLAGS=-buildvcs=false go test -run 'ContinuityFinal|ChurnFinal' -v ./internal/verifier
```

## Corrections (8 Nov 2026, after `../paper/a2a-identity/REVIEW_V3_FINAL.md`; the text above is left as written)

* **Checker.** The `audit-release` described in §2 (checker v1) returned a clean exit
  for five corrupted-copy controls (empty decisions array in an inventoried cell,
  undeclared malformed cell, removed appraisal event with renumbered sequences, changed
  session action/audience, inventory policy differing from the decision). Checker v2
  (`internal/audit`, evidence schema 2) classifies all five as non-clean; before/after
  reproductions and the new retained run `results/v3-final/20261108-004047` are in
  `RESULTS_V3_CORRECTIONS.md`. The "negative controls" claim in §2 therefore held only
  for the fourteen listed corruptions, not for these five.
* **TLS receipts.** §2 says the ten TLS deliveries reached A. The matrix has ten TLS
  receipts in total: five at A and five at B (the untouched relay under C+tls,
  S-env+tls, T+tls and the rewrite fixtures under C+tls); the four C+url receipts are
  plain HTTP. Exporter equality on a B connection shows connection consistency, not
  authorization.
* **24/24.** Agreement with revised expectations on already-observed scenarios,
  including eight attacker successes; not 24 secure outcomes, not a held-out result,
  not an improvement over the earlier 20/24.
* **Attempts.** One initial attempt and two retries are three attempts, within the
  plan's numerical allowance; the retries were caused by harness defects rather than
  the environment failures the plan named. The "exceeds the budget by one" statement
  in the identities table was arithmetically wrong.
* **Continuity inventory timing.** For run `20261108-000017` the continuity
  `run-inventory.json` was written after the cases ran (`finishInventory`); only the
  matrix inventory was declared before execution. From run `20261108-004047` on, the
  continuity inventory is declared from a static case table before any case runs, with
  expected decision counts.
* **Runner.** `scripts/v3final.sh` did not enforce failure status, did not assert
  binary-hash equality and selected the latest run directory; it now does all three,
  with failure-injection controls (`scripts/test_v3final_runner.sh`).
