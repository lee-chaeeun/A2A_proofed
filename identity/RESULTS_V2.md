# RESULTS v2 — repaired verifier, transport controls, channel binding (7 Nov 2026)

Retained v2 run: `results/v2/20261107-194025` (21 fixtures × 11 policies = 231 cells,
201 applicable, 217 appraisals; wall time 132 s). Earlier v2 runs are retained as
evidence: `20261107-193256` (aborted in F12_S-env by a harness panic) and
`20261107-193413` (complete, 188/190, before three fixes; see the change log in
`fixtures/predictions-v2.md`). The v1 run `results/full/20261106-231737` is unchanged.
Pre-change hashes, the v1 source tarball, the review-audit reproduction, fuzz logs and
the discovery finding are in `results/audit/20261107T180305Z/`.

Provenance of the retained run (`provenance.json`): binary sha256 `cad112e9…`, source
tree sha256 `cde0c254…`, manifest sha256 `bb0fda9c…`, predictions sha256 `e74a26e5…`.
Offline reverification: **217 / 217** appraisals agree (`reverify.md`).

Everything below is about *this implementation under this harness*. Nothing here is a
claim about A2A in general, about the PTV draft beyond the routine-mode slice
implemented, or about hardware TPMs.

## 1. Confirmed observations

### 1.1 The v1 verifier was wrong in ways the v1 fixtures could not show
The review's three characterization cases reproduced (`results/audit/…/reviewaudit-before-fix.txt`):
a correctly signed routine envelope with proof-only, empty or null evidence was accepted
with no quote appraisal; the stored nonce session (identity, action, policy) was ignored;
an unknown policy string fell through to accept. A fourth defect, not in the review, was
found by the deterministic mutation baseline on 7 Nov: an envelope with `triage_band`
absent or null decoded to band 0 and was accepted. All four are now rejecting
regression tests in the default suite (`internal/verifier/review_regression_test.go`),
the characterization test is retained as an artifact, and the repaired verifier enforces
acceptance invariants in one place (`finalize`): T/P accept only with a fully valid
quote; P only with an enrolled-AK-signed, schema-valid, fresh envelope carrying evidence
and no proof; S-* only with a verifying signature; proof policies only with a consumed,
unexpired, context-matching session; +url/+tls/+cb only with their transport facts.

Evidence that the repair did not change v1 behaviour: the 59 applicable v1 cells
(F1–F13 × C, S-file, S-iso, T, P) produced the same decisions and recipients on the
repaired verifier as in the retained v1 run.

Tests: `go test -race ./...` passes (software-key unit tests labelled `[UNIT/software-key]`,
emulator tests labelled `[E2E/emulator]` using a real swtpm per test). The restricted AK
refuses to sign a forged TPMS_ATTEST through the hash-ticket path (`TPM_RC_TICKET`);
arbitrary bytes it does sign do not parse as a quote. Six fuzz targets ran 20–30 s each
(≈1.0–1.9 M executions per target); three URL-normalization crashers (non-idempotent
trailing slashes, `::` host, unbracketed IPv6) were found, fixed and kept as regression
corpus. Passing tests do not prove the absence of vulnerabilities.

### 1.2 Decision grid (observed → job recipient; frozen predictions matched 199/201)

| Fixture | C | S-file | S-iso | S-env | T | P | C+url | C+tls | T+tls | S-env+cb | T+cb |
|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 honest | A | A | A | A | A | A | A | A | A | A | A |
| F2 rename | A | A | A | A | A | A | A | A | A | A | A |
| F3 name collision | R | R | R | R | R | R | R | R | R | R | R |
| F4 card copy + replay | B | R | R | R | R | R | R | R | R | R | R |
| F5 volume copy | B | B | R | R | R | R | R | R | R | R | R |
| F6 relay | B | B | B | B | B | B | R | R | R | R | R |
| F7 signer access | B | B | B | B | B | B | R | R | R | R | R |
| F8 relay + timestamp edit | B | B | B | R | B | R | R | R | R | R | R |
| F9 PCR changed | A | A | A | A | R | R | A | A | R | A | R |
| F10 evidence+proof | – | – | – | – | – | R | – | – | – | – | – |
| F11 unenrolled key | B | R | R | R | R | R | R | R | R | R | R |
| F12 nonce burn (B then A) | – | RR | RR | RR | RR | RR | – | – | R,A | R,A | R,A |
| F13 concurrent | – | 1A | 1B | 1B | 1B | 1B | – | – | 1A | 1A | 1A |
| F14 hijack, no creds | B | B | B | B | B | B | **B** | R | R | R | R |
| F15 hijack + A's TLS key | B | B | B | B | B | B | B | **B** | **B** | R | R |
| F16 F15 + cb injection | – | – | – | – | – | – | – | – | B | R | R |
| F17 hijack + self-signed | – | – | – | – | – | – | B | R | R | R | R |
| F18 TOCTOU | A* | A* | A* | A* | A* | A* | A* | A* | A* | A* | A* |
| F19 TPM state clone + AK pw | B | B | R | R | **R**† | **R**† | R | R | R | R | R |
| F20 hijack + TLS key + signer access | B | B | B | B | B | B | B | B | B | B | B |
| F21 F19 + PCR re-extended | B | B | R | R | B | B | R | R | R | R | R |

A/B = job delivered to that deployment, R = rejected, RR / R,A = two sequential
appraisals, 1X = one release among two concurrent deliveries, – = n/a.
† diverged from the frozen prediction (see 1.6). A* = delivered, configuration changed.

### 1.3 Counts with denominators (coverage of this fixture set, not prevalence)
* False endpoint acceptances (job to B while expecting A), attacker-endpoint cells, F12/F13 excluded: **55 / 140**. Per policy: C 11/12 · S-file 9/12 · S-iso 6/12 · S-env 5/12 · T 7/12 · P 6/12 · C+url 4/13 · C+tls 2/13 · T+tls 3/14 · S-env+cb 1/14 · T+cb 1/14. Denominators differ because F16/F17 are n/a for most policies.
* Honest baseline rejections (F1, F2): **0 / 22**. Reported separately: F9 configuration rejections 4 (T, P, T+tls, T+cb; legitimate by policy); F12 valid-second-response rejections 5 (consume-on-failure availability cost, v1/S-env policies only).
* False signer attributions (accepted attack appraisal with no A-enrolled key used, typed from `key_id`/gate owner): **0 / 49**. Custody broken among those (A's key used by B's process or from copied materials): 18 / 49 (F5_S-file, F7 ×5, F19_S-file, F20 ×9, F21 ×3).
* Concurrency (F13, deterministic): 8 cells, one release each; B's relayed copy won 4, A won 4; duplicate dispatch 0, duplicate receipt 0. Randomized race trials (500, seeds 20261107..20261206, delays U[0,40] ms, appraisal on arrival): two releases **0 / 500**, zero releases 0, B wins 1 / 500 (policy T), A-leg latency p50 ≈ 20 ms, B-leg p50 ≈ 43 ms. These measure this harness's race behaviour, not attack prevalence.
* TOCTOU: 18 appraisals delivered a job to a deployment whose PCR 16 at receipt differed from its reference (F18 ×11: changed *after* acceptance; F9 ×7 for policies without configuration appraisal). No policy enforces continuity between appraisal and execution; "execution" itself is not implemented (the job is acknowledged, not run).
* Telemetry: 0 appraisals with missing events; 0 released tokens unobserved at a recipient; 0 dropped requester emissions.

### 1.4 What each control bought (networked, real A2A SDK traffic)
* **URL enforcement alone (C+url)** defeats every original different-address fixture (F4–F8, F11) and the state-clone fixtures (F19/F21): the copied card declares A's URLs and B is not at them. It is defeated by an address hijack (F14, F17) because equality of strings says nothing about who answers.
* **Authenticated TLS with enrolled-name checking (C+tls, T+tls)** additionally defeats the hijack without credentials (F14) and the wrong-issuer certificate (F17), and is defeated by stolen TLS credentials (F15). A valid certificate for B never passes as A (every B-address TLS cell fails at `connect-tls`, not at the crypto).
* **Channel binding (+cb, RFC 9266 tls-exporter)** defeats F15 and F16: A derives the exporter from its own connection with B, the requester from its own with B, the two differ, and the bound nonce in the quote (`quote extraData != issued nonce`) or in the software envelope does not verify. Injecting B's observed binding into the forwarded challenge (F16) changes nothing because signers ignore supplied bindings. Positive controls F1, F2, F9 (S-env+cb), F18 all accept. **The defense fails by design against F20** (attacker with A's TLS key *and* A's signer access): that attacker is a second instance of A, and no tested policy distinguishes it. Legitimate TLS-terminating proxies or authorized replicas are *not* supported: +cb rejects them exactly like F15. This is a narrowing of the claim, not a defense against proxies.
* **S-env (matched software envelope)** behaves like P on F8 (edited metadata rejected, 10 envelope-signature rejections across the run come from S-env and P) and like S-iso on custody (F5 reject, F7 accept). Signature coverage of the metadata, not the key type, is what F8 measured.
* **Attestation (T/P) vs software signer (S-iso/S-env)**: identical on every custody and transport fixture; T/P differ only by configuration appraisal (F9) and the related TOCTOU window (F18). F19/F21 show that the emulator's AK is copied with its state directory; the only thing the clone lost was the volatile PCR, which the attacker restores with a public string. No hardware property was tested or demonstrated.
* **+url/+tls move the failure before nonce issuance**, which removes the F12 nonce-burn availability cost (A gets a fresh nonce and the job) and makes F13 always resolve to A (B's leg never gets a nonce).

### 1.5 Accounting and auditability
Every appraisal is one row (`appraisals.csv`), including both F12 and F13 decisions
(v1 flattened F13 to A's rejected decision). Recipients come from `job_received(token)`,
key attribution from typed `key_id` / gate `owner` fields, and each row carries the
typed attacker capability list, failure stage, PTV code, dispatch/receipt/ack flags and
a telemetry-completeness column. `provenance.json` records clocks, binary and per-file
source hashes, manifest/predictions hashes, versions and every command. `reverify`
re-derives card JWS (from the fetched card in the trace), session context/expiry
(clock fixed at the recorded appraisal time), signatures, quotes, envelopes and bound
nonces; TLS peer identity and endpoint equality are copied from the record and labelled
so; nonce-consumption *order* for the second F12/F13 appraisal is likewise copied.

### 1.6 Divergences and failed runs (all retained)
* Run 1 (`20261107-193256`) aborted: B's software-key fallback signer (S-env
  unenrolled/garbage modes) passed a nil random reader to ECDSA and panicked in the
  agent; fixed, predictions unchanged.
* Run 2 (`20261107-193413`): 188/190. F19_T and F19_P rejected (PTV_ERR_007) against a
  prediction of accept: the cloned emulator state carries A's persistent AK but PCRs are
  volatile, so the clone booted with PCR 16 = 0. The prediction was wrong, the
  divergence stands in run 3 as well (199/201), and F21 (clone + attacker extends PCR 16
  with the public configuration string) was added with its prediction frozen before
  run 3; it accepted under T and P as predicted. Run 2 also exposed that the offline
  reverifier could not reproduce consumption order (10 disagreements) and that the
  TOCTOU flag compared B's PCR with A's reference; both fixed before run 3.
* Discovery baseline before the schema fix: 2 findings (missing/null `triage_band`),
  retained in `results/audit/…/discovery-finding-triage-band.md`. After the fix: 300
  plans (63 single + 237 pairwise mutations), 0 invalid, 8 identity, **0 findings**,
  rejections spread over 10 stage/code families. Zero findings under this budget is not
  evidence of absence.

## 2. Untested hypotheses (stated, not measured)
* That a hardware TPM resists what F19/F21 did to the emulator (state copy). Only an
  emulator was used; nothing here speaks to hardware.
* That channel binding survives a legitimate deployment topology (load balancer, TLS
  termination, authorized replicas). It was tested only with A terminating TLS itself.
* That the one-release property holds across verifier restarts or send failures. The
  release flag is in memory and set before the send; no crash/restart test exists.
* That the gate boundary holds against a hostile process. All processes share one OS
  account; the ACL is harness-enforced. Separate OS identities or containers were not
  used (no sudo; a user-namespace or docker variant is feasible on this host but was
  not built).
* That the measured PCR says anything about the running workload. PCR 16 holds an
  operator-chosen string; measured boot and workload continuity are not modelled.
* That a model-driven planner finds mechanisms the mutation baseline does not. The
  Adaption adapter exists (`a2aid discover --planner adaption`), with model discovery,
  a free `estimate=true` dataset probe, a credit ledger with the 100/400/400/300 phase
  caps, a 1 200-credit total cap and a 300-credit reserve, memory disabled
  (`agentic_memory:false`, `store:false`), frozen prompt and sampling, and a local
  allowlisted interpreter. **No paid call was made**: `ADAPTION_API_KEY` is not set in
  this environment, and the Responses API documents token usage but no credit price,
  so paid inference stays disabled unless an operator supplies a verified
  credits-per-1k-tokens figure. The dry run, pilot and held-out phases are unrun.

## 3. Remaining limitations and the most important hole
* One OS account; harness-enforced custody; unauthenticated loopback admin endpoints.
* Static name resolution instead of DNS; a lab CA; one deployment pair; scripted agents.
* Execution is an acknowledgement, not work; no durable exactly-once; no restart tests.
* The PTV implementation is a routine-mode slice with a lab evidence format (not EAT);
  no proxy mode, ZK band or verdict signing.
* Fixtures are hand-chosen coverage, not a population; counts are not rates.

**Most important remaining hole:** the +cb defense is only as good as the boundary
around A's signer and TLS key, and that boundary is simulated. F20 shows that an
attacker with both is indistinguishable from A under every tested policy, and the
harness cannot say how hard obtaining them is. A real test needs separate OS identities
(at least user namespaces or containers), a hardware or vTPM-backed key that cannot be
copied with a directory, and a legitimate-proxy design so that "reject every
intermediary" is a choice rather than an accident.

## 4. Reproduction (exact commands, from `a2a-identity/`)
```
./scripts/setup.sh                      # emulators, lab CA, provisioning (clean state)
./scripts/test.sh                       # go test -race ./... + 20 s fuzz budgets
./scripts/smoke.sh                      # F1 × 11 policies
./scripts/matrix.sh                     # full v2 matrix + races + reverify + traces
A2AID_INTEGRATION=1 GOFLAGS=-buildvcs=false go test -count=1 -run Integration -v ./internal/matrix
bin/a2aid discover --planner mock --plans 300
./scripts/cleanup.sh
```
Commands executed for the retained run and their child processes are in
`results/v2/20261107-194025/commands-executed.txt` and `provenance.json`; the networked
integration run is `results/integration/20261107-194255` (45 appraisals, all as frozen).
