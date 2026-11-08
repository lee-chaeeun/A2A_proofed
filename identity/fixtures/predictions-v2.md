# Frozen predictions and attacker permissions, matrix v2

Frozen: 2026-11-07 19:30 CET, before any v2 matrix cell was run (the v1 run
`results/full/20261106-231737` is retained unchanged as the historical baseline).
Edits after this point are recorded in the change log at the bottom of this file.
The machine-readable copy is `fixtures/manifest-v2.json`; each run stores a copy of
both files and their hashes in `provenance.json`.

## What changed since v1 (and why the v1 policies are rerun)

1. The verifier was repaired (Phase 1): routine PTV responses must carry evidence
   and no proof; acceptance requires a fully valid quote; the stored nonce session
   (expected identity, action, policy, audience, expiry) is enforced; unknown
   policies are refused at every entry point; TPM attestation magic and signature
   parameters are checked. The five v1 policies are rerun on the patched verifier so
   that "patched implementation" and "new policy" effects are separable. Prediction:
   every v1 fixture outcome is unchanged by the patch.
2. New controls (Phase 2), composed as `Base[+url|+tls|+cb]`:
   * **S-env**: the isolated software signer (same key as S-iso) signs a COSE_Sign1
     envelope with the same metadata coverage as the PTV response (attester, nonce,
     action, audience, policy, iat, exp). Isolates "signature coverage" from "key type".
   * **+url**: the signed card must declare the discovery endpoint (normalized
     equality; redirects refused; fail closed) BEFORE a nonce is issued.
   * **+tls**: HTTPS with standard certificate validation under the lab root for the
     URL's name, minimum TLS 1.3, AND the authenticated peer must carry the ENROLLED
     name of the expected deployment. A valid certificate for B never authorizes B as A.
   * **+cb**: RFC 9266 `tls-exporter` channel binding. The agent derives the exporter
     value from its own TLS connection and uses `sha256("a2aid-cb-v1"||nonce||cb)` as
     the nonce in every signed structure; the requester recomputes the value from the
     connection it terminated itself. A signer never uses a binding supplied in the
     challenge.
3. New fixtures F14–F20 (address hijack, stolen TLS credentials, binding injection,
   wrong certificate, TOCTOU, emulator-state clone, full capability union).
4. Accounting: one row per appraisal (F12/F13 export both decisions), typed key
   attribution from event fields, recipient from `job_received(token)`, telemetry
   completeness flags, randomized race trials, provenance, offline reverification.

## Security objective and attacker model for +cb (written before implementation)

Objective: a job token is released only to the endpoint that (a) terminated the TLS
connection the requester opened to the enrolled name and (b) produced a fresh proof
under an enrolled key bound to that very connection. A party that merely forwards
traffic between the requester and A cannot obtain the job, even if it holds A's TLS
credentials, because exporter values differ between the requester↔B and B↔A legs.

Capability classes (distinct, tested separately):
* C1 different address, no credentials (F4–F8, F11, F19): stopped by +url.
* C2 expected address, no credentials (F14, F17): stopped by +tls.
* C3 expected address + A's TLS credentials (F15, F16): stopped by +cb only.
* C4 C3 + A's signer access (F20): not covered by any tested defense; B *is* a
  second instance of A from the protocol's point of view.
Legitimate proxies/replicas: NOT supported by +cb. A TLS-terminating proxy in front
of A is indistinguishable from F15 and is rejected. This is a narrowing of the claim,
not a successful defense against proxies; an authorized-replica design would need
its own enrollment and is out of scope.

## Ground truths (controller only)

* **keys used**: owner label of every enrolled key that produced a proof, from typed
  event fields (`key_id` → registry, gate `owner`), never from substrings.
* **invokers**: gate peer labels (pid→label, harness-enforced) and in-process signers.
* **endpoint contacted**: which agent served the exchange / received the job.
* **observed recipient**: the label that reported `job_received` for the token.

Harness assumptions carried over from v1 and still true: one OS account; the gate's
pid→label ACL is harness-enforced; emulator state and signer secrets are readable by
the account and only used where a fixture's capability list says so; agent-reported
events are cooperative telemetry, not hostile-process ground truth. New: name
resolution is a static map in the requester and the relay (no DNS).

## Predicted job decision per cell

Columns: C, S-file, S-iso, S-env, T, P, C+url, C+tls, T+tls, S-env+cb, T+cb.
`A`/`B` = accept with job to that deployment; `R` = reject; `–` = n/a.

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
| F12 nonce burn | – | RR | RR | RR | RR | RR | – | – | R,A | R,A | R,A |
| F13 concurrent | – | one | one | one | one | one | – | – | one(A) | one(A) | one(A) |
| F14 hijack, no creds | B | B | B | B | B | B | **B** | R | R | R | R |
| F15 hijack + A's TLS key | B | B | B | B | B | B | B | **B** | **B** | R | R |
| F16 F15 + cb injection | – | – | – | – | – | – | – | – | B | R | R |
| F17 hijack + self-signed | – | – | – | – | – | – | B | R | R | R | R |
| F18 TOCTOU | A* | A* | A* | A* | A* | A* | A* | A* | A* | A* | A* |
| F19 TPM state clone + AK pw | B | B | R | R | **B** | **B** | R | R | R | R | R |
| F20 hijack + TLS key + signer access | B | B | B | B | B | B | B | B | B | **B** | **B** |

`A*` in F18: the job is delivered to A, but A's PCR at receipt differs from the
reference; no policy enforces continuity between appraisal and execution.

Key predictions in words:
* URL enforcement alone (C+url) defeats every original different-address fixture
  (F4–F8, F11) and F19, and is defeated by an address hijack (F14).
* Standard authenticated TLS with enrolled-name checking (C+tls, T+tls) defeats the
  hijack without credentials (F14, F17) and is defeated by stolen TLS credentials (F15).
* Channel binding (+cb) defeats F15 and F16 while accepting F1/F2/F9(S-env)/F18
  (legitimate positive controls), and is defeated by F20.
* Attestation adds configuration appraisal (F9, F19 for T/P? no: F19 accepts because
  the clone carries the same AK and PCR state) and nothing else that transport
  authentication does not; the TPM emulator's state is clonable (F19).
* S-env matches P on F8 (metadata coverage, not key type) and matches S-iso on
  custody (F5, F7).
* The patched verifier changes no v1 outcome.

## Randomized race trials (declared before running)

Policies S-file, S-iso, S-env, T, P; 100 trials each; seeds 20261107+i; A and B
processing delays drawn uniformly from [0, 40] ms; each response appraised on
arrival. Prediction: zero trials with two releases; the split between A and B wins
follows the delays (B's leg = A's delay + B's delay + an extra hop, so A should win
most trials); latency distributions reported, not interpreted as prevalence.

## Change log

(empty at freeze)
* 2026-11-07 19:35 CET, after v2 run 1 (results/v2/20261107-193256, retained,
  incomplete): the run aborted in F12_S-env because B's software-key fallback
  signer (used only for the unenrolled-key and garbage modes of S-env) passed a nil
  random reader to ECDSA and panicked inside the agent; F11_S-env therefore showed
  "no artifact in response" (a harness error, recorded as reject) and the nonce-burn
  runner panicked on the exchange error. Fixed in internal/ptv (software signer
  defaults to crypto/rand) and internal/matrix (exchange errors are recorded, not
  fatal). Predictions unchanged. Cells F1–F11 of run 1 all matched their predictions.
* 2026-11-07 19:50 CET, after v2 run 2 (results/v2/20261107-193413, retained,
  complete, 188/190 matched): two divergences, both F19 (T and P rejected with
  PTV_ERR_007). Cause: PCRs are volatile. The byte copy of A's swtpm state carries
  A's persistent AK, but the clone boots with PCR 16 = 0, so the clone's genuine
  quote fails the digest check. The prediction overlooked this. F19's predictions
  are left as frozen (counted as misses); **F21** is added with its prediction
  frozen before run 3: F19 plus the attacker extending the clone's PCR 16 with the
  public string `deployment-A-config-v1` → T and P accept → B. If F21 behaves as
  predicted, the F19 rejections are a volatility accident, not a defense.
  Also fixed before run 3: (a) the deterministic mutation baseline
  (internal/discover, mock enumeration of 63 single mutations) found that a
  routine envelope with `triage_band` absent or null was ACCEPTED (typed decode
  produced band 0); SchemaCheck now requires every mandatory field to be present
  with the right CBOR type, with a regression test; (b) the offline reverifier
  could not reproduce nonce-consumption ORDER for the second appraisal of
  F12/F13 (10 disagreements, all "consumed" cases); it now copies that single
  ordering fact from the record and says so; (c) the TOCTOU flag compared B's PCR
  against A's reference; it now compares against the recipient's own reference.
  Predictions for F1–F20 unchanged.
