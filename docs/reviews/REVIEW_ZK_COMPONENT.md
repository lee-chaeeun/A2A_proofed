# Review of the RISC Zero / A2A component

Reviewed 8 November 2026. Code: `swarmalign/a2a-identity-zkp`.
Retained matrix: `results/zk/20261108-002724`.
Reviewer evidence: `results/reviewer-zk/20261108T103550Z/`.

## Judgment

The genuine-proof component works, and the central Pinned/Current comparison is
supported. This is a useful reference integration and regression suite. It correctly
separates proof validity from authorization to approve a particular request.

However, the ZK transport does not fully enforce the C+tls policy it names, and
the offline scoring oracle can report clean results on incomplete/corrupted
evidence. Fix those narrow integration/audit issues before describing the component
as completely validated. No extra circuit, dataset or model call is needed.

## What was independently confirmed

- Re-ran the pinned verification CLI on all **ten unique receipt/image-ID pairs**
  referenced by the 52 retained rows. Seven verify; the corrupted, wrong-image and
  fake controls reject. Every recorded validity flag matches. For successful
  receipts, the actual verified journal exactly matches the journal in the rows.
  Receipt content hashes match their filenames.
- The guest recomputes the commitment and sum predicate, uses a fixed limit and
  publishes the challenge/commitment/result journal. The verifier explicitly rejects
  fake receipts and verifies against the caller's expected image ID before exposing
  a journal. The Go bridge checks the verifier-reported receipt hash and journal
  encoding. These are genuine proof checks, not just mock transport.
- Z6/Z7 reference byte-identical receipts. The recorded approvals support the stated
  difference between Pinned and Current. The fresh-challenge stale-witness case
  distinguishes input authorization from task-challenge binding.
- Independently counted 52 rows and 52 expected-result matches; the wrong-context
  and unauthorized-input approval counts are 3/8 and 5/12. These are finite fixture
  coverage counts, not population attack rates or 52 independently generated proofs.
- `go test -race -count=1 ./...` passes independently. The existing compiled Rust
  host test executable also passes all four tests, including embedded-image-ID
  agreement. The reviewer did not rebuild Rust or generate new proofs.
- All 25 source entries in run provenance match the current files, and the larger
  snapshot hash list differs only at README.md. The original identity tree still
  has only its previously disclosed documentation differences from its final
  snapshot. Production source, manuscript and retained runs were not changed here.
- Reviewed the retained second integration execution log; it reports another
  52-cell execution. The reviewer did not rerun its approximately three minutes of
  proof generation.

## [P1] ZK task dispatch skips required Agent Card appraisal

`internal/zk/requester.go` calls `verifier.Requester.Connect` and then directly
sends `zk_task`. Connect verifies the card into `d.Card`, but does not reject an
invalid card itself: the normal identity flow enforces that verdict in Appraise.
The ZK caller never invokes that step or checks the card verdict.

Reproduced with a local HTTPS server in an isolated extraction of the snapshot:
its TLS certificate is trusted and matches the enrolled name, its Agent Card has
**no signature**, and the ZK requester still sends a task POST. Evidence:
`unsigned-card-characterization.log` and `.go.txt` in the reviewer directory.
The characterization PASS means the undesired dispatch was observed; it is not a
passing security regression.

TLS is still validated. This does not show a TLS bypass or invalidate the arithmetic
proofs. It does mean the claimed C+tls baseline is incomplete: C includes the
publisher signature. Fix by enforcing the complete card/endpoint/TLS appraisal
before sending the computation task, with positive and invalid-card controls.
The ZK Requester's configurable Policy field should either support the full
identity handshake or explicitly reject proof policies it does not implement;
Connect alone does not implement T+cb authentication.

## [P1] Oracle does not establish matrix completeness

The oracle scores whatever appears in `decisions.jsonl` without checking the expected
fixture/policy inventory, uniqueness or row counts. Two actual CLI controls on
copies return exit 0 with no incomplete cases or disagreements:

| Alteration | Reported result |
|---|---|
| Remove all four Z4 rows (the fresh-challenge stale-witness fixture) | 48/48 rows scored clean |
| Duplicate the first fixture/policy row | 53/53 rows scored clean |

The retained integration test's explicit length check helps its own generated run,
but does not repair the standalone oracle, detect duplicate/missing key substitutions,
or establish complete evidence for an arbitrary retained run.

Fix: freeze the intended fixture × policy inventory before execution, require exactly
one row per declared key, and reject missing, extra, duplicate or unknown entries.
Validate request IDs, contracts, challenge lengths, markers and sequence integrity.
Check scanner errors rather than silently treating truncated reads as complete.
Retain all existing negative controls and add these cases through the actual CLI.

## [P1] Receipt files are checked for presence, not bound to the scored journal

The oracle's loader only lists receipt filenames. It takes proof validity and the
verified journal from decision rows. Replacing **every receipt file** with the
literal bytes `not-a-receipt` still yields 52 scored, zero incomplete, zero
disagreements and exit 0.

It is legitimate to trust a pinned verifier instead of independently implementing
RISC Zero. But retained bytes must be bound to that verification result. At minimum,
check file SHA-256 against the row/content address. Prefer cheaply rerunning the
pinned verifier on each unique receipt/image pair and comparing its journal and
status with the row; the reviewer did this successfully for the unmodified run.
This needs no new proving. Include same-filename tampering and journal/status
substitution controls. Label reused proof-system verification honestly; the business
authorization computation can still be independently implemented.

## [P2] Actual approvals are not reconciled with the event ledger

Removing every `approval_inserted` event leaves the oracle's result at 52/52 clean.
The oracle uses the row's ApprovalInserted flag as observed outcome and only joins
decision markers/authority updates. The Z11 duplicate outcome is hard-coded from
the fixture name, rather than derived from a preceding matching approval.

Fix: reconcile actual insert events with request, policy, receipt and evaluation ID,
checking expected absence, presence, duplicate counts and order. Derive duplicate
suppression from approval history. Do not infer it simply because the fixture is
named Z11. Record a unique evaluation ID so a repeated request can be joined to
the correct decision and ledger state without first/last-marker heuristics.
Use a separate simple arithmetic/commitment implementation for the oracle, or state
that those helpers are shared with production; it currently calls the same Go
Opening.Commitment and Pass helpers.

## [P2] Proof-cache key omits the guest identity in the actual worker path

`Bridge.Prove` includes `b.ImageIDHex` in its cache key and compares it on reads
only when non-empty. `internal/agent/zk.go:82` constructs the bridge without setting
that field. Therefore the actual cache is keyed by an empty image prefix and the
inputs, contrary to the report's image-and-input description.

After a guest rebuild, identical inputs can return an old cached receipt. The pinned
requester verifier would reject a different-image proof; this is a stale-cache and
availability/provenance issue, not demonstrated false proof acceptance. Resolve the
local prover's embedded guest ID before cache lookup, include it (or a trustworthy
build namespace) in the key, and check cached response identity. A two-image cache
regression can use test fixtures; it does not need a new circuit benchmark.

## Reporting corrections

- **Frozen timestamp:** `predictions.json` says `2026-11-08T01:20:00Z`, later than
  the first matrix at 00:20Z and retained run at 00:27Z. The plan's recorded hash
  at 00:06:31Z matches its current contents and its table already states the
  intended outcomes, which supports prior specification. The JSON timestamp itself
  remains inconsistent, likely a timezone-recording mistake. Explain with a dated
  addendum and supporting evidence; do not silently rewrite historical freeze times.
- The snapshot directory is timestamped 00:32Z, after the 00:27Z run started.
  Matching hashes support linkage, but do not describe it as a pre-run snapshot.
- The matrix contains nine network exchanges plus local receipt reuse/modification
  evaluations. It is not 52 independent A2A task deliveries. Z7 is explicitly a
  locally stored contract comparison reusing Z6's task/receipt.
- The ZK transport uses the TLS baseline, not the repaired TPM/channel-binding
  handshake. Do not describe it as a measured combined TPM+ZK defense.
- Synthetic openings and values are published for reproducibility. Say they are
  absent from the public journal, rather than literally never published. No
  empirical privacy advantage was measured.
- Context and trusted data selection are the experimental interventions; ZK itself
  is present in every policy. The study does not compare ZK with a signature-only
  baseline or establish that ZK is necessary for this toy predicate. That limitation
  is acceptable for a reference integration; no new comparison is required now.

## Smallest useful follow-up

Enforce the declared transport checks, repair the oracle's inventory/hash/ledger
joins and fix the cache identity. Use fresh copies for negative controls, preserve
the original result tree, and identify the corrected source/checker versions. Most
validation can reuse and reverify the genuine receipts already generated. Only
rerun network/proving cases affected by an actual producer or guest change.

Retain the independent proof-verification evidence and the core Pinned/Current
result. Update the separate ZK results and pending paper note after correction;
the deferred abstract/length pass is still separate. No datasets, Adaption spending,
additional circuits, standards extension or physical hardware are needed.
