# Review of checker v2 and the corrected final run

Reviewed 8 November 2026. Run: `results/v3-final/20261108-004047`.

**Decision: no remaining blocker found within this review's scope to starting the
optional ZK component. Freeze the identity baseline at its current snapshot.**

This is a scoped review, not a proof that the implementation has no other defects.
Production source and manuscript files were not changed by this review.

## Independently verified

- Inspected the checker changes, typed context comparisons, event rules, inventory
  handling, strict runner and runner failure controls.
- Reapplied all five original reviewer mutations to fresh copies of the current
  test base using the current retained binary. The unmodified base exits 0; the
  five corruptions now exit **2, 2, 1, 1, 1**, respectively. Evidence:
  `results/reviewer-v3-final/20261107T235840Z/reviewer-findings.json`.
- `go test -race -count=1 ./...` passed independently.
- `scripts/test_v3final_runner.sh results/v3-final/20261108-004047` passed all five
  controls: build failure, matrix failure, audit failure, test failure and the
  intact audit-only path. The historical-schema control is asserted at exit 2.
- Listed code, fixtures and scripts match the final snapshot. The only per-file
  hash differences are the disclosed post-run documentation updates. Current
  binary SHA-256 matches the recorded `9d91bdbd71280f99a986102ccd5bf1ecf0631577d7c0be235e40c5b585d0e87f`.
  Unlike the prior review, this review did not independently rebuild the tarball.
- The new CSV has 24 decision and 24 recipient matches: six A receipts, eight B
  receipts, ten rejections. Baseline attack successes remain explicitly visible.
- Reviewed retained integration and churn logs. T+cb records 30 refusals, 30
  acknowledged A receipts and zero B receipts. S-env+cb records 28 refusals, two
  client-unknown outcomes, 30 acknowledged A receipts and zero B receipts.
- The manuscript, TeX, converter, PDF and ZIP match their previous recorded hashes;
  the pending paper note lists the later reconciliation work.

## Interpretation and remaining limits

The five demonstrated audit defects and the runner failure-propagation gap are
resolved by the checks exercised here. Unknown delivery outcomes remain explicit;
they are not falsely upgraded to confirmed non-delivery. Absence of receipts in
the controlled server logs is an experimental observation, not a production
cryptographic proof of non-delivery.

The checker remains structural and conditional on trusted observations and the
recorded appraisal. The archived historical reproduction still logs rather than
asserts its B receipt. These disclosed boundaries do not block a separate ZK
component. Neither the old nor new results establish hardware TPM superiority,
measured workload integrity, durable exactly-once execution or general swarm safety.

Before submission, the paper still needs the factual updates listed in
`PAPER_CORRECTIONS_PENDING.md`, a shorter abstract and removal of its ninth main
page. These were deliberately deferred, not completed by this correction task.

## ZK handoff

Use `CLAUDE_ZK_COMPONENT_PROMPT.md`. Preserve the current identity snapshot and
results, keep ZK separately runnable with separate evidence, and first establish
one genuine local RISC Zero receipt with fake/dev acceptance disabled. Apply the
90-minute feasibility gate. Verify a genuine failing result without approving it,
then test wrong-task and Pinned/Current input contracts. Do not alter the frozen
identity results to incorporate the new component.
