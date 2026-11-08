# Correction plan — checker and runner defects from REVIEW_V3_FINAL.md

Declared 2026-11-08 before collecting new results (hash in
`results/audit/<ts>-v3corr-prefix/PLAN.sha256`). Scope: `internal/audit`, the
evidence schema it reads, `scripts/v3final.sh`, and factual reporting outside the
paper. No new defenses, no paper edits (pending notes go to
`../paper/a2a-identity/PAPER_CORRECTIONS_PENDING.md`).

## Before-fix reproduction
Run the reviewer's five mutations (plus the unmodified base) through the retained
binary `bin/a2aid` (sha256 `ecfc5b01…`) on fresh copies under
`results/audit/<ts>-checker-falseclean-before/`. Expected: all five exit 0 ("false
clean"), matching `results/reviewer-v3-final/20261107T232312Z/reviewer-findings.json`.

## Evidence schema v2 (producer: verifier + tests; consumer: checker)
* Decision record: `evidence_schema: 2`; typed `context` {decision_id,
  expected_label, expected_deployment_id, policy, action, audience, session_key};
  typed `authorization_context` and `dispatch_context` (same fields + token),
  set at the authorized / dispatch_attempt events; the session dump already carries
  expected, policy, action, audience, nonce.
* Inventory: every cell declares `expected_decisions` (int ≥ 1) and `policy`;
  `declared_before_execution: true`. The matrix declares 2 for F12/F13-type cells,
  1 otherwise. Continuity inventories are written from a static table BEFORE any
  case runs (the old `finishInventory` post-run writer is removed).
* Historical records (schema 1 or none) stay `unsupported_historical_schema`.

## Checker rules (exit 0 clean · 1 violation · 2 incomplete/malformed/mismatch)
1. Inventory: duplicates, invalid ids, missing `expected_decisions` → malformed
   inventory (2). Cells found but undeclared → inventory mismatch (2) **and** their
   contents are parsed and audited: malformed → malformed (2); failing decisions →
   violation (1). Missing cell → incomplete (2).
2. Decisions: missing/null/empty array or fewer than declared → incomplete (2); more
   than declared → inventory mismatch (2); duplicate decision ids across the run →
   violation (1); decision policy ≠ inventory policy → violation (1).
3. Events: required events must exist exactly once with positive sequence numbers;
   valid paths: rejected (`appraised`, `not_authorized`, nothing else); authorized →
   `sealed`|`seal_disabled_ablation` → `dispatch_attempt` → exactly one terminal
   among `sent`→(`ack`|`no_ack`|`unknown_outcome`), `refused_reconnect`,
   `dispatch_error`, `write_failed`→(`refused_reconnect`|`unknown_outcome`|
   `dispatch_error`); `refused_dispatch` (pre-attempt); `release_suppressed`.
   Duplicate or contradictory critical events → violation. Token on authorized /
   dispatch_attempt / sent / ack must equal the decision token; conn id on `sent` must
   equal the pinned connection. `sent` is "written to transport", receipt and ack are
   separate; unknown outcome is never converted into non-delivery.
4. Context: exact typed equality of decision context, authorization context,
   dispatch context, issued session and inventory policy. Missing typed context →
   unsupported schema, never a pass.
5. Expected attack successes (malicious class, declared recipient = observed B, only
   recipient checks failing) stay visible as `violation_expected_by_fixture`.

## Runner
`set -euo pipefail`; each gate asserts its status; the historical-schema audit asserts
exit == 2 exactly; working-tree and extracted-snapshot binary hashes must be equal;
the matrix writes its run path to a file the script reads (no "latest directory"
selection); an `--audit-only <run>` mode re-runs the gates on an existing run.
Controls (`scripts/test_v3final_runner.sh`): a failing-command wrapper makes build,
matrix, audit and test fail in turn; each must yield a nonzero overall exit; the
historical-audit control must still pass with exit 2.

## Validation
Regression tests for the five reviewer controls and the new rules; the existing
controls keep passing; the regenerated base and valid rejected/refused cases are
clean. New snapshot; `go test -race -count=1 ./...`; rerun the 24-cell subset and
both policies' continuity cases (instrumentation changed, so new fields must be
observed); churn rerun only if its code path changed. Record checker version and
producer version separately for any checker run over older evidence.
