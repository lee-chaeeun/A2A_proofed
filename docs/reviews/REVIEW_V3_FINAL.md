# Independent review of Claude's V3-final completion

Review date: 8 November 2026 (Europe/Amsterdam). Retained run:
`results/v3-final/20261108-000017`. This review leaves production code, the paper
and all retained runs unchanged. New evidence is under
`results/reviewer-v3-final/20261107T232312Z/`; that identifier uses the execution
host's UTC clock. Reviewer-created corrupted copies are not experimental results.

## Judgment

The runtime and reproducibility evidence is materially stronger than V3. The
connection-continuity cases now exercise both software-envelope and swtpm-backed
TPM proofs, count actual recipient receipts, and include explicit honest recovery.
The archived-code connection-swap reproduction is retained. The final matrix and
source/binary linkage are supported.

However, "the specific gaps are resolved" is too broad. The replacement audit
checker still returns a clean exit status for five additional corrupted-copy
controls. These are evidence-checking defects, not newly demonstrated runtime
authentication bypasses. The manuscript also exceeds the current submission
requirements for main-body pages and abstract length.

## Confirmed findings in Claude's favour

- The final matrix has 24 cells: six receipts at A, eight at B, ten rejections.
  Decision/recipient predictions match for all 24. The two +cb policies have no
  attacker receipts in this finite fixture set. The eight B deliveries are explicit
  baseline/ablation attack successes, not a secure-system success rate.
- All 85 entries in the final snapshot's per-file list were checked. The only
  differences are the three disclosed documentation files: README.md,
  RESULTS_V3.md and SCOPE_AND_LIMITATIONS.md. Listed Go, fixture and script files
  match. The tarball SHA-256 matches the reported `8f8b4256…` value.
- The reviewer independently extracted and rebuilt the snapshot with `-trimpath`.
  Its binary is byte-identical to `bin/a2aid`, SHA-256
  `ecfc5b01998ea8968e32db4e0952303272e23bf49944761cca60be265c8a4247`.
- `go test -race -count=1 ./...` passed independently on current source. This runs
  the new continuity/churn and audit tests; the separately gated full integration
  test was inspected through its retained log, not rerun by the reviewer.
- The retained churn logs report, for each policy, 60 accepted attempts, 30
  acknowledged A deliveries, 30 refused reconnects and zero B receipts. Source
  inspection confirms the new tests check receipt logs rather than relying solely
  on JobReleased. The T condition actually invokes swtpm quoting.
- The archived-v2 test's retained log records a B receipt after A's valid proof,
  with B answering zero challenges. Its capabilities now match the intended
  TLS-key-only attacker. The historical test itself logs rather than asserts this
  result, so its PASS line alone is insufficient; the receipt log supplies the
  positive evidence. Add assertions if using it as an automated reproduction check.

## Remaining actionable findings

### [P1] Incomplete inventory evidence can still produce a clean audit

Source: `internal/audit/audit.go:551` accepts an empty decisions array.
`Run` verifies cell-directory presence but not the expected decision cardinality.
At line 244, the verdict includes missing cells but omits `UnexpectedCells`.
Unexpected cell contents are not inspected.

Reviewer reproductions using the retained binary and COPIES of
`internal/audit/testdata/base`:

| Mutation | Observed result | Required result |
|---|---|---|
| Replace the split-connection cell's decisions with `[]`, retaining its directory | Exit 0, six rather than seven decisions, NO UNEXPECTED VIOLATION | Incomplete evidence |
| Add an undeclared cell containing malformed JSON | Exit 0, unexpected cell displayed but ignored | Non-clean inventory mismatch |

Fix: declare expected per-cell decision count or IDs, including the two-decision
honest recovery case; reject empty/null/missing decision arrays and duplicate IDs.
Include unexpected cells in the final verdict and define how their contents are
handled. A directory existing is not evidence that its planned observation exists.

### [P1] Missing appraisal event passes the claimed ordering check

Source: `internal/audit/audit.go:343`. `seqOf("appraised")` returns zero when
absent, and zero compares less than a valid authorization sequence number.

Reproduction: remove the appraised event from the honest decision, renumber the
remaining requester sequence contiguously, and remove the mirrored appraisal
event from controller records. The real CLI still returns exit 0 and classifies
the decision as verified_dispatch. This directly contradicts the claim that the
checker establishes a preceding appraisal event.

Fix: require required events to exist exactly as specified before comparing their
positive sequence numbers. Define valid terminal paths and reject duplicate or
contradictory critical events. Compare event tokens/connection IDs with their
decision fields rather than only checking the first occurrence of each event name.

### [P2] Context equality is incomplete

Source: `internal/audit/audit.go:350`. Authorization context is parsed with string
substring tests. Session matching checks identity/policy but omits action/audience.
The inventory's declared policy is not compared with each decision's policy.

Two separate reviewer controls both return exit 0:

- Change the honest session's action and audience to different values.
- Change the inventory policy for the honest S-env+cb cell to T+cb, leaving the
  actual decision unchanged.

Fix: export structured authorization context and compare exact typed fields across
inventory, issued session, decision, authorization and dispatch as applicable.
Add the missing action/audience to the records if needed; absence must not silently
pass a claim about full-context matching. These controls alter retained records;
they do not show that the online verifier accepts a wrong audience.

### [P2] Finalization script does not enforce failure status

`scripts/v3final.sh:5` enables nounset/pipefail but not errexit, and later test/audit
commands print their statuses and continue. The last echo can make the overall
script exit successfully after a failed test. Build hashes are printed but not
asserted equal. The run directory is selected as the latest directory, so a failed
matrix invocation could cause later operations to attach to a different run.

This is a source-inspection concern; no destructive failure injection was performed.
It does not invalidate the retained successful logs. Fix by checking every exit
status, explicitly allowing only the historical-schema check's expected exit 2,
asserting build-hash equality, and passing an exact new run path/ID through the
workflow. Add a lightweight failing-command smoke control for the runner.

### [P1 submission] Paper is outside two published formatting requirements

The official event checklist requires at most eight pages BEFORE references and
appendices and a 150–250-word abstract:
https://apartresearch.com/sprints/swarm-alignment-2026

The PDF has 11 total pages, with references starting on page 10. Main text therefore
occupies nine pages. Page 9 was visually inspected: it contains only the concluding
line "remain outside what was verified." A small editorial cut should remove that
overflow without shrinking the template fonts. The Markdown abstract has 332 words
by whitespace counting, well above 250. Aim for approximately 200–230 words, focusing
on question, design, decisive results and scope. Author affiliation is still absent.

The Markdown editing comment still says TeX is reconciled by hand, although md2tex.py
now generates it. That is a minor documentation issue. The converter also reuses
the archived hand-set v2 table, so future Markdown table edits will not necessarily
propagate; validate table values explicitly rather than assuming full synchronization.

## Reporting corrections and interpretation

1. **24/24 is expected-result agreement, not 24 secure outcomes.** It includes eight
   deliberate attacker successes. The revised predictions incorporate earlier
   observations, so this final run is a reproducibility check, not a held-out
   generalization result or an improvement in security from 20/24 to 24/24.
2. **TLS-receipt arithmetic:** RESULTS_V3_FINAL.md says ten TLS deliveries went to A.
   The matrix actually has ten TLS receipts in total: five at A and five at B.
   Four additional C+url HTTP receipts bring the total to fourteen. Exporter equality
   on a B connection establishes connection consistency, not that B is authorized.
3. **Retry budget:** the plan allows an initial attempt and at most two retries.
   Three total attempts do not exceed that numerical allowance. The stated causes
   were harness defects rather than the plan's specified environment failures, so
   report that distinction if discussing a deviation. The initial attempt-count
   explanation is arithmetically wrong.
4. **Continuity inventory timing:** the matrix inventory is written before execution,
   but continuity `finishInventory` writes its cases after the tests have run.
   The source-defined cases still document a fixed test set; do not describe that
   particular inventory file as a pre-execution artifact. Prefer declaring it first.
5. **Unknown outcome is handled conservatively.** It is good that a failed write
   is not assumed absent and automatically retried. Server logs give controlled
   experimental observations, not production proof of non-delivery. Keep the
   availability limitation and process-restart/durable-execution limits explicit.

## Smallest next step

Repair and regression-test the five reproduced false-clean cases, enforce the
runner's exit status, and perform a narrow fresh audit against a newly identified
snapshot. Retain old results. If runtime dispatch is unchanged, do not rerun every
old matrix or add new mechanisms to compensate. Shorten the abstract and remove
the single-line ninth main page, then regenerate and visually inspect the PDF.

The defensible central finding remains: protected second-key channel authentication
prevents the tested relay/connection substitutions for both software and emulated
TPM keys. The experiment demonstrates TPM integration, not a hardware-specific
advantage, actual workload integrity or general swarm safety.
