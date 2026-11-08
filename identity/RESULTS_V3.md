# RESULTS v3 — binding under active manipulation, and a matched baseline (7 Nov 2026)

> **Post-run reviewer correction (7 Nov 2026):** This initial report overstates parts of
> the retained evidence. The fixed matrix has **four** prediction misses (20/24 matches),
> not six. Binding attacks have retained pre-fix reproductions; no pre-fix continuity
> execution was located. Continuity/churn tests exercise S-env+cb with an uninterrupted
> positive control, not a demonstrated fresh-proof reconnect, split-connection or
> different-certificate case. The release checker reports zero recomputed checks and ten
> missing connection-reuse fields; its negative control does not exercise its actual
> record-validation path. It does not independently establish connection continuity.
> Several current source hashes differ from the retained matrix provenance; the three
> new V3 tests are absent from that provenance. See
> `../paper/a2a-identity/BASELINE_V3_REVIEW.md` and `SCOPE_AND_LIMITATIONS.md`.
> The original account below and all raw artifacts are preserved for auditability.

Scope: the two Priority-0 attacks the v2 review raised by code inspection, a matched
transport baseline, and the overstated-claim corrections. v1 and v2 are preserved
unchanged (`results/full/20261106-231737`, `results/v2/20261107-194025`). The v2
source and binary are snapshotted in `results/audit/<ts>-v2snapshot/`.

Everything here is about this implementation under this harness. No claim is made
about A2A, the PTV draft beyond the routine slice, or hardware TPMs.

Retained v3 runs:
* `results/v3-repro/20261107-202528` — the two attacks on the **v2 binding logic**
  (attacker mode added, verifier untouched). Reproduction artifact.
* `results/v3/20261107-203206` — the same fixtures on the **fixed** code.
* `results/v2-postv3fix/20261107-203958` — the full v2 matrix on the fixed code, to
  show the fix changes no v2 outcome.
Plus unit/networked tests: `internal/verifier/binding_regression_test.go`,
`continuity_test.go`, `churn_test.go`.

## 1. Measured facts

### 1.1 Both Priority-0 attacks were real on the v2 code, and are now closed

**A. Binding downgrade / chosen-nonce substitution.** With F15 capabilities only (B
holds A's TLS certificate and key, can reach A, has no signer access and holds no
proof key), B computed the channel-bound nonce for its own requester connection and
made honest A sign that exact value by sending a +cb challenge with the binding
field omitted. On the v2 code this delivered the job to B:

| cell | v2-repro | fixed |
|---|---|---|
| V3 S-env+cb (downgrade, binding stripped) | **accept → B** | reject (A refuses the inconsistent challenge) |
| V3 T+cb (downgrade) | **accept → B** | reject |
| V4 T+cb (cross-policy oracle: plain-T quote) | **accept → B** | reject (quote is in the "T" domain, not "T+cb") |
| V4 S-env+cb (cross-policy oracle) | reject on v2 already | reject |

The cross-policy oracle was confirmed for T and **falsified for S-env**: the software
envelope already signs the policy string, so a plain-`S-env` envelope never satisfied
`S-env+cb`. The TPM quote carried no policy identifier, which is why `T+cb` fell.

Fix: proofs commit to a domain-separated context `sha256("a2aid-proof-v3" ‖ policy ‖
nonce ‖ self_exporter)` (`wire.ProofContext`). The agent derives the binding mode
from the **parsed policy**, always mixes its **own** TLS exporter for +cb, and
rejects a binding field inconsistent with the policy; the verifier computes the
expected value from **its own** connection and policy and never trusts a value in
the response. A proof made under a weaker policy now lives in a different hash domain
and cannot satisfy a stronger one.

**B. Proof-to-delivery connection continuity.** The networked `continuity_test.go`
stands up two real HTTPS A2A servers (honest A, swap-target B with A's certificate
and the same signer) and runs a real `S-env+cb` decision. In the positive control the
job reuses the proof connection and reaches A. In the attack the proof connection is
closed and the name repointed to B after a valid appraisal; the sealed transport
refuses the new dial and the job never reaches B. The declared churn budget
(`churn_test.go`, 60 concurrent trials, half with the proof connection closed) gives:

```
trials=60 appraisals_accepted=60 delivered_to_A=30 reconnect_refused=30 run_errors=0 B_receipts=0
```

Fix: after a successful appraisal the requester **seals** its transport; the job
reuses the proof connection or the dial is refused with
`reconnect-without-fresh-proof`, so a job is never written to a connection the proof
did not use. A legitimate reconnect obtains a fresh proof (a new decision), which is
the positive-control path.

### 1.2 The fix changes no v2 outcome

`results/v2-postv3fix` reproduces every v2 decision and recipient except `F13_S-file`,
which flips A↔B between runs while still releasing exactly one job — the concurrency
scheduler artifact the v2 report already documented. So the v3 differences are
attributable to the new policies and fixtures, not to the repair.

### 1.3 Matched baseline comparison

Held constant within the comparison (endpoint selection, A's certificate, signer
access, nonce freshness, delivery rules); only the policy changes. `S-env+tls` was
added so the software control has its transport baseline.

| fixture | C+url | C+tls | S-env+tls | S-env+cb | T+tls | T+cb |
|---|---|---|---|---|---|---|
| V1 honest (positive control) | → A | → A | → A | → A | → A | → A |
| V2 relay, stolen TLS key | → B | → B | → B | **reject** | → B | **reject** |
| V3 downgrade | → B\* | → B\* | reject\* | **reject** | reject\* | **reject** |
| V4 cross-policy oracle | → B\* | → B\* | reject\* | **reject** | reject\* | **reject** |

\* V3/V4 non-+cb cells are not meaningful attacks (the chosen-nonce rewrite is
self-defeating off +cb; the attacker uses V2 for those). The decisive column pair is
`+tls` vs `+cb`: with stolen TLS credentials, `+tls` delivers to B and `+cb` rejects,
for **both** the software envelope and the TPM quote. `C+url` is an ablation, not a
production configuration.

**Attribution.** Endpoint authentication (the `+url`/`+tls` layers) stops the
different-address and hijack attacks; the channel binding is what rejects a relay that
already holds A's TLS credentials; it does so identically for S-env and T, so the
benefit is **ordinary second-key channel authentication, not a TPM-specific advance**.
Stolen TLS credentials are a capability escalation above the plain TLS baseline; an
independently authenticated requester (mTLS client credentials held only by the real
requester) would deny B the ability to obtain fresh proofs from A at all, but that is
a requester-authentication control, not supplied by A's server certificate, and is
listed under untested claims.

### 1.4 Independent release-invariant oracle

`a2aid audit-release` re-derives, from the per-appraisal records and controller
events, whether every protected dispatch had a preceding acceptance and reached the
expected recipient, classifying each check as recomputed, shared-code, copied-fact or
unverified, and carrying a negative control (a record missing its recipient is flagged
incomplete, never agreed). On `results/v3` it reports 14 dispatches, 6 authorized (the
V1 honest cells → A), 8 unauthorized (every non-+cb delivery to B), 10 incomplete
(rejected cells with no receipt). It independently confirms no +cb cell delivered to B.

## 2. Code-review suspicions that did NOT hold as stated

* The cross-policy oracle does **not** apply to S-env (the envelope binds the policy);
  it applied only to the TPM quote. Recorded as falsified-for-S-env.
* "+cb implements RFC 9266": only the exporter primitive is used. The lifecycle rules
  (connection closure/reuse) are now implemented by the sealing design and documented;
  we do not claim blanket RFC-9266 compliance.

## 3. Corrections to overstated v2 claims

### 3.1 S-env is not metadata-identical to PTV

| signed field | S-env payload | PTV ProveResp / embedded quote | checked by S-env | checked by P |
|---|---|---|---|---|
| version | yes | yes | yes | yes |
| attester id | yes | yes | yes | yes (trust anchor) |
| nonce (domain-separated) | yes | yes (quote extraData) | yes | yes |
| action | yes | no | yes | no |
| audience | yes | no | yes | no |
| policy string | yes | via proof context only | yes | via proof context only |
| issued-at / expiry | yes | no (single timestamp) | yes | no |
| timestamp (freshness) | via iat/exp | yes (tag-1) | yes | yes (300 s) |
| msg_type / triage_band | no | yes | no | yes |
| evidence present | no | yes | no | yes |
| PCR selection / digest | no | yes | no | yes |
| qualified signer | no | yes | no | yes |

The equivalence is therefore narrowed: S-env and P share **a signed, freshness-checked
response envelope**, which is what the timestamp-tamper fixture (F8) exercises and all
F8 observations support. S-env adds action/audience/expiry that PTV lacks; PTV adds the
configuration evidence that S-env has no analogue for. "Same metadata coverage" is
withdrawn.

### 3.2 Software and TPM policies are not identical on every custody case

F21 is a genuine divergence: a cloned emulator state (T/P) accepts while S-iso/S-env
reject, because the copied assets differ (the TPM clone carries the AK; the software
isolated signer was not copied). The equivalence claim is restricted to the genuinely
matched cases F5 and F7, where access and copied material are the same for all policies.

### 3.3 "217/217 offline agree" is not 217 independent verdicts

For the retained v2 run the 217 reverify records split into independently recomputed
cryptographic primitives (149), copied transport/exchange-stage facts (58) and copied
nonce-consumption order (10); the checker also reuses the production appraisal code, so
its agreement is consistency, not independence. `reverify.md` now prints these
categories and states that copied facts are never summed into a verification score.

### 3.4 Rejection-stage reporting

With the layered policies, `+tls` implies `+url` and `+cb` implies both, and `+url` is
checked first. Different-address cells therefore reject at `connect-url`, not
`connect-tls` as the v2 prose said; the retained per-cell records carry the true stage
and the v3 paper states it from the records.

### 3.5 Race trials

The v2 500-trial race covered only the unbound proof policies. The defended +cb policy
now has its own declared churn budget (§1.1 B); the v2 race numbers are not cited as
channel-binding stress evidence.

## 4. Failed predictions (retained, not edited)

Six frozen V3/V4 `+tls` cells predicted `accept` but observed `reject`, because the
chosen-nonce rewrite is applied uniformly and is self-defeating off +cb. Recorded in
`fixtures/predictions-v3.md`; not a security finding (the attacker uses V2 for +tls).
The F19 T/P misses from v2 remain as before.

## 5. Untested claims and remaining holes

* A requester-authentication (mTLS) control that would deny B the proof oracle
  entirely was not built; +cb is the tested defense for the stolen-TLS-key relay.
* Legitimate TLS-terminating proxies and authorized replicas remain unsupported, not
  defeated: +cb rejects them like an attacker. A proxy-compatible design is a separate
  extension.
* OS isolation, workload measurement and vTPM unclonability remain simulated. The
  connection pin is enforced in the requester's own transport, not by the OS.
* The sealing design fails a dropped honest connection closed (no delivery until a
  fresh proof); the honest-reconnect positive control shows the safe reauthenticate
  path, not transparent retry.

## 6. Reproduction

```
./scripts/setup.sh
go test -race ./...                                   # unit + e2e + continuity + churn
bin/a2aid matrix --manifest fixtures/manifest-v3.json --predictions fixtures/predictions-v3.md --out results/v3 --races=false
bin/a2aid reverify     --results results/v3/<run>
bin/a2aid audit-release --results results/v3/<run>
A2AID_INTEGRATION=1 GOFLAGS=-buildvcs=false go test -run 'Integration|Continuity|Churn' ./internal/...
```

The reproduction of the attacks on the v2 logic is `results/v3-repro/20261107-202528`
(see `results/audit/<ts>-v2snapshot/P0A-reproduction.md`).


> **Addendum (8 Nov 2026):** the gaps listed in the reviewer correction above are closed
> in `RESULTS_V3_FINAL.md` (retained run `results/v3-final/20261108-000017`, snapshot
> `results/audit/20261107T230016Z-v3final-snapshot`): a structural release-evidence
> checker with negative controls replaces the `audit-release` described in §1.4; the
> continuity cases (close-then-swap with a proof-key-less B, split connection,
> certificate swap, honest recovery) and the 60-trial churn now run for S-env+cb **and**
> swtpm-backed T+cb; a pre-fix connection-swap reproduction exists on the archived v2
> source; the four-miss count is corrected in `fixtures/predictions-v3.md`. The text of
> this file is left as written.
