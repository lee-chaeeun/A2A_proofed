# RESULTS v3 corrections — checker, runner and reporting (8 Nov 2026)

Scope: the actionable findings of `../paper/a2a-identity/REVIEW_V3_FINAL.md` on the
release-evidence checker, the finalization runner and factual reporting. No defense,
proof format, fixture or paper file changed. Plan declared first:
`CORRECTION_PLAN_V3.md` (sha256 `4dddb2a6…`, recorded in
`results/audit/20261107T233054Z-v3corr-prefix/PLAN.sha256`, which also holds the
pre-edit source and binary hashes).

## Identities

| item | value |
|---|---|
| before-fix binary (checker v1) | sha256 `ecfc5b01…` (the retained v3-final binary) |
| after-fix binary (checker v2) | sha256 `9d91bdbd…`, built with `-trimpath` from the tree **and** from the new snapshot, byte-identical |
| new snapshot | `results/audit/20261107T234045Z-v3final-snapshot/` (tarball sha256 `8772d156…`, per-file hashes inside and copied into the run) |
| new retained run (producer evidence schema 2) | `results/v3-final/20261108-004047` |
| previous retained run (producer evidence schema 1) | `results/v3-final/20261108-000017`, unchanged |
| before-fix reproduction | `results/audit/20261107T233054Z-checker-falseclean-before/` |
| after-fix reproduction | `results/audit/20261107T234220Z-checker-falseclean-after/` (same mutations, new binary) |
| checker v2 over the schema-1 run | `results/audit/20261107T234220Z-checker-v2-over-run-20261108-000017/` (copy; producer and checker versions recorded in its README) |
| reviewer controls | `results/reviewer-v3-final/20261107T232312Z/`, unchanged |

## 1. Before/after: the five reviewer corruptions

Each mutation is applied to a fresh COPY of `internal/audit/testdata/base` (real
continuity records) and run through `bin/a2aid audit-release`, the same `Run` entry
point the Go tests call. These controls alter retained evidence; they are not online
authentication exploits.

| mutation | checker v1 (before, retained binary) | checker v2 (after) |
|---|---|---|
| unmodified base | exit 0, 7 decisions | exit 0, 7 decisions, NO UNEXPECTED VIOLATION |
| inventoried rejected cell with `decisions: []` | exit 0, **6 decisions, clean** | exit 2 INCOMPLETE, cardinality error "declared 1 decisions, found 0" |
| undeclared cell with malformed JSON | exit 0, listed but ignored | exit 2 INCOMPLETE, unexpected cell + malformed file reported |
| `appraised` removed, sequences renumbered, mirrored event removed | exit 0, verified_dispatch | exit 1 UNEXPECTED VIOLATION ("challenge_sent < proof_received < appraised" and "appraised < authorized" fail) |
| session action and audience changed (also each alone) | exit 0 | exit 1 UNEXPECTED VIOLATION ("issued session equals the decision context") |
| inventory policy T+cb vs decision S-env+cb | exit 0 | exit 1 UNEXPECTED VIOLATION ("inventory policy equals decision policy") |

Raw outputs: `before-fix-results.json` and `after-fix-results.json` in the two audit
directories above, each with the binary hash used.

## 2. What changed

### Evidence schema 2 (producer: `internal/verifier`, continuity tests, matrix runner)
* `Decision` carries `evidence_schema: 2`, a typed `context`
  {decision_id, expected_label, expected_deployment_id, policy, action, audience,
  session_key} and typed `authorization_context` / `dispatch_context` (same fields plus
  token), set at the `authorized` and `dispatch_attempt` events; the controller mirror
  of those events carries the same typed object. The session key is the issued nonce
  for proof policies and the synthetic release key for card-only policies (the
  legitimate difference is preserved; both appear in the session dump).
* `run-inventory.json` (`inventory_schema: 2`) declares per cell the policy, class,
  expected decision/recipient and `expected_decisions` (2 for the two-appraisal
  F12/F13-type cells and the two-decision recovery case, 1 otherwise). The matrix
  writes it before execution; the continuity tests now write it from a static case
  table **before any case runs** and write the observed list separately as
  `observed-cases.json`. The old continuity inventory (run `…000017`) was written
  after execution by `finishInventory`; that is stated in the addendum below.
* `a2aid matrix --run-path-file F` writes the created run path for exact handoff.

### Checker v2 (`internal/audit`)
* Inventory: duplicate entries, invalid ids, missing `expected_decisions` →
  inventory errors (exit 2); missing cells → incomplete; undeclared cells → inventory
  mismatch (exit 2) **and** their contents are parsed and audited (malformed → exit 2,
  violations → exit 1); decision count ≠ declared, or a missing/null/empty
  `decisions` array → cardinality error (exit 2); duplicate decision ids across the
  run → violation; decision policy ≠ inventory policy → violation.
* Events: required events must exist exactly once with positive, strictly increasing
  sequence numbers (a missing event never passes by defaulting to zero); duplicate
  critical events and contradictory terminals are violations; the valid paths are
  connect_failed, exchange_failed, rejected, release_suppressed, refused_dispatch,
  refused_reconnect, dispatch_error, write_failed→{refused_reconnect | unknown_outcome
  | dispatch_error}, sent→{ack | no_ack | unknown_outcome}; tokens on authorized /
  dispatch_attempt / sent / ack / refused_reconnect and the connection id on `sent`
  are compared with the decision. Write-to-transport, receipt and acknowledgement stay
  distinct; unknown outcome is never converted into non-delivery.
* Context: exact typed equality of decision context, authorization context, dispatch
  context, issued session (expected, policy, action, audience, release token) and
  inventory policy. Missing typed context → unsupported schema; a missing
  authorization/dispatch context on a dispatching decision → violation.
* Reporting: `checker_version` and the producer evidence schemas seen are recorded in
  every summary. Schema-1 records remain `unsupported_historical_schema`; no absent
  evidence is invented for them.
* Exit codes unchanged in meaning: 0 no unexpected violation and complete; 1
  unexpected violation, orphan receipt or duplicate id; 2 incomplete / malformed /
  unsupported / inventory mismatch / empty run.

### Runner (`scripts/v3final.sh`, `scripts/test_v3final_runner.sh`)
`set -euo pipefail`; every gate asserts its status; the historical-schema audit is
asserted to exit **exactly 2**; tree and snapshot binary hashes must be equal; the
matrix hands over its run path through a file (never "latest directory");
`--audit-only <run>` re-runs the gates on an existing run. Controls (5/5 passed on
`results/v3-final/20261108-004047`): injected `go build` failure → exit 1 at the build
gate before any lab process; injected matrix failure → exit 1 at the matrix gate with
no run attached; injected `audit-release` failure → exit 1; injected `go test` failure
→ exit 1 after the audits passed; intact `--audit-only` copy → exit 0 with the
historical-schema control asserted at exit 2.

## 3. Regression tests (`internal/audit/audit_test.go`, 26 tests, all passing)
The 14 earlier controls, the five reviewer controls (with action-only and
audience-only variants, and null/missing decision arrays), duplicate and contradictory
critical events, event token/connection mismatch, extra decision and duplicate ids
(including the one-of-two recovery decision with and without its orphaned receipt),
absent typed context (decision/authorization/dispatch) and a disagreeing typed field,
inventory integrity (duplicate entry, path-like id, missing count), and the positive
cases: the regenerated base is clean, the refused reconnect and the rejected split
connection are `verified_non_dispatch`, and a declared attack success is reported as
`violation_expected_by_fixture` with exit 0 and appears in the Markdown report.

## 4. New run `results/v3-final/20261108-004047` (runner: all gates ok)
* Matrix: 24 cells, decision and recipient matches 24/24 against the declared
  `manifest-v3-final.json` expectations. Recipients: A 6, B 8, none 10. **TLS receipts:
  10 in total, 5 at A and 5 at B**; the four C+url receipts are plain HTTP. Exporter
  equality on a B connection shows connection consistency, not authorization.
* Checker v2 on the matrix: NO UNEXPECTED VIOLATION, exit 0; 6 verified_dispatch, 10
  verified_non_dispatch, 8 violation_expected_by_fixture; checks recomputed 0/502,
  requester TLS 0/22, cooperative 8/28 (the eight B receipts), copied 0/24, stipulated
  0/14; producer schema 2 for all 24 decisions; inventory declared before execution
  with 24 × 1 expected decisions.
* Continuity (both policies): NO UNEXPECTED VIOLATION, exit 0; 7 decisions (2
  verified_dispatch, 4 verified_non_dispatch, 1 ablation_excluded); inventory declared
  before execution with the recovery case at 2 decisions.
* Churn (reran because the producer changed): T+cb 30 refused / 30 acked / 30 A
  receipts / 0 B; S-env+cb 28 refused + **2 client-unknown** / 30 acked / 30 A
  receipts / 0 B. The unknown category is the documented dead-connection buffer case;
  the server logs show no receipt for those two tokens.
* Historical-schema control on a copy of `results/v3/20261107-203206`: exit 2,
  24 unsupported_historical_schema, 24 cardinality errors (legacy inventory declares no
  count). Checker v2 over a copy of run `…000017`: exit 2, unsupported (schema 1).
* `go test -race -count=1 ./...` ok (8 packages with tests); opt-in integration PASS.

## 5. Factual corrections (also appended to `RESULTS_V3_FINAL.md`)
1. 24/24 is agreement with revised expectations on scenarios already observed, and
   includes eight deliberate attacker successes; it is not 24 secure outcomes, not a
   held-out result, and not an improvement in security over the earlier 20/24.
2. The final matrix has ten TLS receipts in total (5 at A, 5 at B) plus four plain-HTTP
   C+url receipts; "ten TLS deliveries reached A" was wrong.
3. Attempt count: an initial attempt plus two retries is three attempts, within the
   plan's numerical allowance; the retries were caused by harness defects, not the
   environment failures the plan named. "Exceeds the budget by one" was arithmetically
   wrong.
4. The old continuity inventory was written after execution; only the matrix inventory
   was pre-declared. New continuity inventories are declared first.
5. The cooperative-log, recorded-appraisal, emulator, synthetic-PCR and non-durable
   execution limitations are unchanged.

## 6. Not done here (by scope)
* No paper edits; pending factual changes are listed in
  `../paper/a2a-identity/PAPER_CORRECTIONS_PENDING.md`.
* The archived-v2 connection-swap test still logs rather than asserts the B receipt
  (`results/audit/20261107T225036Z-v2-continuity-historical/go-test-output.txt` is the
  evidence); no new historical rerun was performed.
* The checker remains a structural audit over trusted observations; it does not
  establish appraisal validity or that every context field is signed by every policy.

## 7. Commands
```
./scripts/v3final.sh                                  # strict: snapshot, build, matrix, continuity, audits, tests
./scripts/v3final.sh --audit-only results/v3-final/<run>
./scripts/test_v3final_runner.sh results/v3-final/<run>   # 5 failure-injection controls
bin/a2aid audit-release --results <dir>               # exit 0 / 1 / 2 (checker version printed)
GOFLAGS=-buildvcs=false go test -race -count=1 ./internal/audit/
```
