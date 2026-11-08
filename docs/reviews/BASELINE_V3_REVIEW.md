# Review of the V3 source, retained artifacts and manuscript

Reviewed 7 November 2026. This review inspects the retained runs and current source;
it does not repeat the full matrices or claim a formal security proof. Production
code was not modified. The editable manuscript and experiment documentation have
been corrected; the existing LaTeX/PDF still predates this review.

## Judgment

V3 materially improves the project. The retained evidence supports the active binding
attack reproductions and the narrow comparison that software and emulated TPM keys
both provide the tested second-key channel authentication. Current-source networked
tests support fail-closed dispatch under the tested connection replacement. This is
a credible bounded integration and implementation study. It does not demonstrate a
hardware-specific security advantage or complete independent release verification.

## Findings

### 1. Binding reproductions and fixes are supported

`results/v3-repro/20261107-202528/matrix.csv` records delivery to B for
V3_S-env+cb, V3_T+cb and V4_T+cb. V4_S-env+cb already rejects because the envelope
signs the policy. `results/v3/20261107-203206/matrix.csv` rejects all six attacker
cells across S-env+cb and T+cb, while both honest +cb controls deliver to A.

Current `agent.go` derives the binding requirement from parsed policy, rejects an
inconsistent binding field and derives its own exporter. `wire.ProofContext` hashes
the domain, policy, issued nonce and exporter. The verifier uses its own exporter
and rejects decisions with multiple distinct recorded exporters. These are
appropriate repairs for the demonstrated downgrade and cross-policy attacks.

This is finite attack coverage, not evidence that arbitrary attacker-controlled
inputs or every connection lifecycle are safe.

### 2. Continuity evidence is narrower than the completion message

`continuity_test.go` exercises S-env+cb over real SDK HTTPS servers. It tests an
uninterrupted delivery and then closes the connection after appraisal and switches
the resolver to B. B has A's TLS certificate **and the same proof signer**, rather
than the planned no-proof-key capability. The fixed transport refuses its new
connection. No retained pre-fix continuity run was located alongside the retained
P0-A reproduction; therefore the statement that both P0 attacks were reproduced
before the fix is not fully supported by the located artifacts.

The file does not implement the planned split-connection, different-certificate or
post-interruption fresh-proof reconnect cases. Its uninterrupted positive control
does not establish an honest reconnect path. The current design can fail closed
without providing an automatic retry; that availability limitation is acceptable
if reported accurately.

`churn_test.go` exercises S-env+cb only. In the reviewer rerun it reports 60 attempts,
60 accepted appraisals, 30 uninterrupted deliveries, 30 refused reconnects and zero B
receipts. A-delivery counts derive from client state, whereas the B count drains the
server receipt channel; the test does not independently assert 30 A receipts. T+cb
shares the requester transport but was not separately churn-tested.

### 3. The release oracle does not provide the claimed independent verification

`internal/matrix/release_oracle.go` reads appraisal rows, rather than replaying the
ordered controller events. It trusts the recorded acceptance flag, copies the
observed recipient, hard-codes expected recipient A, and reads the connection-reuse
boolean without independently deriving it. It does not validate complete request
context or preceding event order.

The matrix `Appraisal` schema does not export `job_reused_proof_connection`.
Consequently the retained `release-invariant.md` reports **zero recomputed checks**
and **ten missing connection-reuse fields**. These ten incomplete checks concern
TLS dispatch rows, not rejected cells without receipts. Rows without job tokens
are skipped. The checker considers all 14 dispatches, including unbound policies,
although it labels them "Protected dispatches".

The negative control constructs a map with no recipient and directly checks that
the field is absent. It does not pass corrupted data through the actual checking
path. It cannot establish that the whole checker detects corrupted artifacts.
The final flagged-count calculation also subtracts one despite the synthetic
control being a passing check, producing a misleading total.

The receipt summary supports "no observed B receipt in the tested +cb matrix
cells." It does not establish an independently checked exact-connection release
invariant. Shared-code offline reappraisal is likewise conditional consistency
evidence; labels such as "independently recomputed" should not imply an independent
implementation or trust source.

### 4. Fixed-matrix prediction misses are four, not six

There are 24 fixed matrix rows and 20 matches. The misses are V3_S-env+tls,
V3_T+tls, V4_S-env+tls and V4_T+tls. Their chosen-nonce attacks fail even though the
untouched V2 relay succeeds under +tls. This is an attack-script limitation,
not stronger transport protection. Preserve the frozen expectations and append
corrections; do not edit them to improve the match count.

The generated honest-rejection denominator 0/0 is also stale: the summary counts
F1/F2 labels, whereas the new honest fixture is V1. There are six actual honest
V1 controls, all successful. Prediction tables use A ambiguously for acceptance
versus recipient even though attack cells deliver to B; report recipients directly.

### 5. Current source is newer than retained matrix provenance

At review start, these current files differ from the retained V3 provenance hashes:
`cmd/a2aid/main.go`, `fixtures/predictions-v3.md`, `internal/matrix/reverify.go`,
`internal/verifier/testkit_test.go`, `internal/verifier/transport.go`,
`internal/verifier/verifier.go` and `scripts/matrix.sh`. Some differences may be
post-run reporting or test work; the hashes alone do not identify their significance.
The provenance source list omits `binding_regression_test.go`, `continuity_test.go`
and `churn_test.go` entirely. Do not claim the retained matrix validates every
current-source change. A clean final snapshot and narrowly rerun critical fixtures
would improve reproducibility without expanding the research question.

### 6. The manuscript had contradictory older claims

The v3 section withdrew metadata equivalence, all-fixture custody equivalence and
aggregate independent verification, while earlier sections still asserted them.
The abstract also claimed both P0 attacks had retained reproductions. These claims
have been corrected in `paper-draft.md`, along with the current versus historical
proof-format description. Hardware non-exportability, physical cloning resistance
and measured workload integrity are explicitly untested. F19/F21 remain useful
emulator-boundary observations, with unequal copied assets disclosed.

## Verification performed in this review

* Parsed both retained V3 CSV matrices and inspected the appraisals, summaries,
  release-checker output, predictions and provenance.
* Inspected policy enforcement, proof-context derivation, requester exporter
  selection, dispatch sealing, continuity/churn tests and audit code.
* `go test -race -count=1 ./...` passed on current source after allowing local
  sockets. The first sandboxed attempt failed because it could not open a local
  listener; that was an environment failure, not a failed security assertion.
* A separate verbose targeted race-enabled rerun passed the three binding
  regressions, continuity test and 60-trial churn test.
* The opt-in full integration matrix was not rerun; the standard test command skips
  it unless `A2AID_INTEGRATION=1`. No paid inference was used.

## Smallest useful remaining work

The paper can report the narrow results honestly now. Before final submission,
prioritize a complete source/test snapshot, a narrow run of the critical V3 fixtures
against that snapshot, and either repairing the audit checker or keeping its claim
at receipt-summary level. Add a genuine honest-reconnect test only if claiming that
behaviour. Physical hardware, model inference and ZK proofs are not required to
complete this scoped study.
