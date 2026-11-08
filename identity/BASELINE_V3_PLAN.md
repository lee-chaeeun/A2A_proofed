# Baseline v3 plan — validate the binding defense under active manipulation

Frozen before execution: 2026-11-07. Preserves v1 (`results/full/20261106-231737`),
v2 (`results/v2/20261107-194025`) and all predictions. Source snapshot of the
pre-v3 (v2) tree: `results/audit/<ts>-v2snapshot/source-v2.tar.gz` with hashes.

## Objective

Decide whether the +cb defense binds job delivery to the proven endpoint when a
malicious intermediary *actively* rewrites protocol fields or forces reconnection,
and attribute each protection to a specific layer (endpoint authentication,
second-key signature, channel binding, configuration check).

## Two suspected attacks (from BASELINE_V2_REVIEW.md, code-review only so far)

### A. Binding downgrade / chosen-nonce substitution (P0)
Code fact (v2): `internal/agent/agent.go:384` activates binding on the request's
`ch.Binding`, not on the parsed policy; `wire.BoundNonce` returns the supplied nonce
unchanged when no binding is selected. So a +cb challenge carried with an empty
`binding` field makes the agent sign the raw supplied nonce.

Threat model: F15 capabilities only — B holds A's TLS certificate and key and can
reach honest A, but has **no** access to A's signer gate and **cannot** read A's
proof keys. Candidate sequences, to be run on real A2A, not asserted:
1. **Downgrade**: B terminates the requester's TLS (exporter `c_RB`), computes
   `m = BoundNonce(n, c_RB)`, sends A a `T+cb` (and `S-env+cb`) challenge with
   nonce `m` and `binding` omitted, forwards A's evidence with the outer nonce
   restored to `n`.
2. **Cross-policy oracle**: B asks A for a plain-`T` quote (or a plain `S-env`
   envelope) over `m`, then presents it to a `T+cb` / `S-env+cb` verifier. Shared
   proof keys across interfaces are the risk.

Frozen expectation **before the fix** (reproduction): at least the downgrade route
ACCEPTS and delivers the job to B on the v2 code, for T+cb and S-env+cb. If a route
does not reproduce, it is recorded as falsified, not asserted.

Frozen expectation **after the fix**: every downgrade and cross-policy route
REJECTS with an evidence-backed reason; F1/F2 and a legitimate +cb client still
ACCEPT; B's capabilities are unchanged.

### B. Proof-to-delivery connection continuity (P0)
Code fact (v2): `verifier.cbCandidate` may pick an exporter using the agent's
claimed hint; `Release` dispatches through the general client, and nothing checks
that the dispatch reuses the connection that carried the accepted proof.
`MaxConnsPerHost=1` bounds concurrency, not sequential replacement.

Deterministic connection-lifecycle fixtures (controlled switchable dial target, no
timing luck):
1. **close-then-swap**: A answers discovery/challenge/proof; its connection closes;
   the next dial is routed to B (A's TLS creds, no proof signer). Does the job reach
   B with no fresh proof?
2. **split-connection**: discovery, proof and job forced onto distinct connection
   instances; present a proof tied to an earlier recorded exporter.
3. **cert-swap**: peer certificate changes between discovery and challenge/job,
   including a cert valid for another enrolled name. Enrolled-identity must be
   checked on the actual recipient connection.
4. **positive control — honest reconnect**: ordinary reconnect to honest A must
   either reauthenticate and obtain a fresh proof safely, or fail clearly without
   leaking the job. A normal reconnect is not an attack.

Frozen expectation after the fix: the job is written only to the connection that
carried the accepted proof; any new connection before dispatch forces a fresh proof
or a clean no-delivery failure. Checked before task bytes are written.

## Fix design (domain-separated, signer-controlled)

* `wire.ProofContext(policy, issuedNonce, selfExporter)` replaces `BoundNonce`: a
  domain-separated digest `sha256("a2aid-proof-v3\0" ‖ policy ‖ "\0" ‖ issuedNonce ‖
  "\0" ‖ exporter)`. Every proof (S binding, TPM `qualifyingData`, PTV envelope
  nonce, S-env nonce) commits to the exact policy string and, for +cb, the signer's
  own exporter. A weaker-mode proof lives in a different domain and cannot satisfy a
  stronger mode; the signed value is a hash of structured context, never
  attacker-chosen raw bytes.
* The agent derives the binding mode from the **parsed policy** (`pol.CB`), requires
  its own TLS exporter for +cb (error on plain transport), and rejects a `binding`
  field inconsistent with the policy. It never signs an attacker-supplied binding.
* The verifier computes the expected context from **its own** connection's exporter
  and its own policy; the agent's claimed hint is removed from selection.
* Connection pinning: after a successful appraisal the requester **seals** its
  transport; the job reuses the proof connection or the dial is refused, so a job is
  never written to a connection that did not carry the proof. A reconnect yields a
  specific `reconnect-without-fresh-proof` rejection, not a silent send.

## Matched baseline comparison (Priority 1)

Add `S-env+tls`. On a fixed fixture subset (honest, legitimate reconnect, the two
P0 attacks, F15 relay), with endpoint selection, certificates, signer access,
nonce freshness and delivery rules held constant, compare:
C+tls · S-env+tls · S-env+cb · T+tls · T+cb. `C+url` is retained only as a labelled
ablation. Stolen TLS credentials are stated as a capability escalation above the
plain TLS baseline; a requester-authentication (mTLS client-cert) control is
evaluated as one option, not claimed as a universal relay defense.

## Claim boundaries

* No TPM-specific advantage is asserted; if S-env+cb and T+cb both hold, the
  defense is ordinary second-key channel authentication.
* S-env is *not* byte-identical to PTV; a signed-field/checked-field table is
  produced and the equivalence is narrowed to the shared timestamp-tamper test.
* "Independent reverification" is split into recomputed primitives, shared-code
  reappraisals, copied facts and unverified; copied facts are never summed into a
  verification score.
* OS isolation, workload measurement and vTPM unclonability remain simulated and
  out of scope.

## Deliverables

Reproductions/falsifications with networked evidence; targeted fixes with rejecting
regressions; new versioned results with per-connection accounting and an independent
release-invariant oracle; `RESULTS_V3.md` separating measured facts, code-review
suspicions, failed predictions and untested claims; updated paper and reconciled
PDF. v1/v2 kept intact. No Adaption spending; no gratuitous full-matrix/fuzz reruns.
