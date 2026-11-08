> **Superseded (7 Nov 2026).** This is the v1 report for run `results/full/20261106-231737`. A review found three verifier defects behind these numbers (`../paper/a2a-identity/REVIEW.md`); the verifier was repaired and the experiment extended. Read `RESULTS_V2.md` for the current results. This file is kept unchanged as the historical baseline.

# Freshness, custody, or the whole response? What an A2A requester can rely on to tell deployment A from a copy of it

*Research report, Apart Research Swarm Alignment hackathon, Track 3. Retained run: `results/full/20261106-231737`. All numbers below come from that run; predictions were frozen in `fixtures/predictions.md` before the first run.*

## Abstract

An A2A requester releases a synthetic job to the endpoint it believes is enrolled deployment A. We ask whether it can keep doing so after A is legitimately renamed, and stop doing so after an attacker B copies A's application volume, replays old proofs, relays live challenges, or edits the response around a valid TPM quote. We built a zero-token local harness: two scripted agents on real a2a-go v2 JSON-RPC endpoints, two swtpm TPM 2.0 emulators holding restricted attestation keys, an independent controller recording which process served each exchange, which process invoked which signer, and where each job token landed. Five policies were compared on 13 fixtures (65 cells, 59 applicable): signed card only (C), card plus software challenge with the key inside the copied volume (S-file), the same signer behind an access-controlled service (S-iso), card plus fresh TPM quote (T), and T plus the PTV draft-01 routine-mode COSE_Sign1 envelope signed by the same AK (P). Every applicable cell matched its frozen prediction. Freshness (S/T/P) stopped replay; custody, not key type, stopped the volume copy (S-iso and T both held, S-file fell, and granting B the signer socket plus authorization defeated S-iso, T and P alike); a live relay produced a correct signer verdict with a wrong endpoint under every policy; and only P detected an edit to outer metadata around an unchanged, valid quote. False endpoint acceptances: 18/39 B-endpoint cells. Rejected honest requests: 0/13. Duplicate releases: 0/4.

## 1. Question and hypotheses

Two ground truths are kept apart: **which enrolled key signed** and **which endpoint received the job**. The controller knows both; the requester sees only protocol evidence.

* **H1** A fresh challenge stops replay for both a software signer and an emulated TPM.
* **H2** Copying a volume that contains an exportable key lets B answer as A; excluding the signer from the copy blocks this for an isolated software signer and for an emulated TPM under equivalent access controls.
* **H3** A live relay obtains valid evidence from A while the requester stays connected to B; an endpoint attribution error coexists with a correct signer verdict.
* **H4** Authenticating the complete PTV response detects edits to outer metadata that leave the embedded signed quote valid.

## 2. What was built

Everything under `a2a-identity/` is new for this sprint (the repository previously held only notes). One Go binary, `a2aid`, provides every role:

* **Agents A and B** (`internal/agent`): a2a-go v2.3.1 `a2asrv` JSON-RPC servers on 127.0.0.1:9101 and :9102 with signed Agent Cards. B is scripted with attack modes selected per fixture through a lab admin endpoint. A has one lab hook (emit a malformed envelope) used by a single fixture.
* **Requester/verifier** (`internal/verifier`): resolves the card at the configured discovery endpoint with the SDK resolver, verifies the JWS against the operator registry (the `kid` must be the expected deployment's enrolled publisher key; `jku` is ignored), issues a fresh random 32-byte nonce per decision bound to the expected deployment and action, appraises, and releases the job idempotently. Nonces are consumed atomically on first appraisal including failure (draft §4.2). Each cell has its own session store.
* **Trust anchors** (`internal/registry`): provisioned out of band at setup: card key, S-file key, S-iso key, AK public key and qualified name, and the PCR 16 reference value for each deployment. No key named in a response is ever trusted.
* **TPM** (`internal/tpmsig`): go-tpm v0.9.8 direct API over swtpm's raw unix socket. Provisioning creates an ECC P-256 SRK and a restricted signing AK (`fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign`) with a random password, makes it persistent at 0x81010002, extends PCR 16 with the deployment configuration digest and records the value. Quotes use `TPM2_Quote`; the PTV envelope is signed with the same restricted AK through `TPM2_Hash` (owner-hierarchy validation ticket) and `TPM2_Sign`. The AK private part never leaves the emulator. The probe run also confirmed that `TPM2_Sign` without a ticket, and a ticket over bytes starting with `TPM_GENERATED`, are refused (`TPM_RC_TICKET`).
* **PTV slice** (`internal/ptv`): draft-01 §§5.1–5.5, direct routine mode only. `PTV_PROVE_RESP` (type 2, `ptv_version` "1.1", `triage_band` 0, `evidence` bstr, `timestamp` tag 1) encoded with deterministic CBOR and wrapped in a tagged COSE_Sign1 (ES256, `kid` = attester_id). Evidence is the documented raw-quote alternative, not an EAT: a CBOR map `{fmt:"a2aid-tpm2-quote-v1", quoted, signature, bank, pcrs}`. The verifier resolves `attester_id` through the registry, verifies the outer signature with the enrolled AK, checks schema (evidence XOR proof, PTV_ERR_008), nonce (PTV_ERR_006), freshness (300 s, PTV_ERR_005), then independently verifies the embedded quote (PTV_ERR_001/007/010). Exact COSE bytes travel base64-encoded inside an A2A DataPart.
* **Signer gate** (`internal/gate`): a unix-socket proxy in front of each swtpm data socket and each isolated software signer. It identifies the peer process by `SO_PEERCRED` pid, maps it to a label the runner registered, applies a per-signer ACL and reports every decision to the controller. The software signer additionally requires a token, mirroring the AK password. **This boundary is harness-enforced**: all processes share one OS account.
* **Controller** (`internal/controller`): records `exchange_served`, `gate_conn`, `signer_attempt`, `relay_leg`/`relay_forwarded` (with the full forwarded payload), `job_released`, `job_received`. It plays no part in any decision.

Constant across all cells: plain loopback HTTP, no TLS, no transport authentication, and the routing rule "send to the discovery endpoint". Whether the card's URL equals that endpoint is recorded as `url_binding` and never enforced; it was `mismatch` in every B-endpoint cell and would have been a cheap additional signal against the card-copy fixtures, though not against a relay placed at A's address.

Attacker permissions per fixture are in `fixtures/predictions.md`. The copied volume is `run/A/app/` (signed card, config with socket paths, S-file private key); excluded are the AK password, the isolated-signer token and key, the publisher key, the emulator state directory and gate access (see `copy-manifest-F5.json`).

## 3. Results

Decision grid (observed; every applicable cell equals the frozen prediction). "→ X" is the controller's record of who received the job token.

| Fixture | C | S-file | S-iso | T | P |
|---|---|---|---|---|---|
| F1 honest baseline | accept → A | accept → A | accept → A | accept → A | accept → A |
| F2 legitimate rename of A | accept → A | accept → A | accept → A | accept → A | accept → A |
| F3 B uses A's display name, B's own key | reject | reject | reject | reject | reject |
| F4 B serves copy of A's card, replays old proof | **accept → B** | reject (nonce) | reject (nonce) | reject (nonce) | reject (nonce) |
| F5 B copies A's application volume | **accept → B** | **accept → B** | reject (sig) | reject (AK) | reject (010) |
| F6 B relays live challenge to A | **accept → B** | **accept → B** | **accept → B** | **accept → B** | **accept → B** |
| F7 B granted A's sockets + authorizations | **accept → B** | **accept → B** | **accept → B** | **accept → B** | **accept → B** |
| F8 relay, outer timestamp edited, quote intact | **accept → B** | **accept → B** | **accept → B** | **accept → B** | reject (010) |
| F9 A's PCR 16 changed | accept → A | accept → A | accept → A | reject (007) | reject (007) |
| F10 envelope with evidence and proof, correctly signed | n/a | n/a | n/a | n/a | reject (008) |
| F11 never-enrolled key claiming A | **accept → B** | reject (sig) | reject (sig) | reject (010) | reject (010) |
| F12 one nonce: invalid then valid | n/a | reject, reject (006) | reject, reject (006) | reject, reject (006) | reject, reject (006) |
| F13 one nonce: two simultaneous valid responses | n/a | one release | one release | one release | one release |

Counts with denominators (from `summary.md`):

| Measure | Count |
|---|---|
| Cells matching frozen prediction | 59 / 59 applicable (6 cells n/a by design) |
| False endpoint acceptances (job to B while expecting A) | 18 / 39 cells with B as contacted endpoint (F13 counted separately) |
| False signer attributions (accepted proof, no A-enrolled key material invoked) | 0 / 12 accepted-attack cells |
| Accepted-attack cells where A's key was used by B's process or from a copied volume | 5 / 12 |
| Rejected honest requests | 0 / 13 honest cells (F1, F2, F9 for C/S) |
| Duplicate releases for one nonce | 0 / 4 concurrent cells |

The 18 false endpoint acceptances split as: C 6 (F4, F5, F6, F7, F8, F11), S-file 4 (F5, F6, F7, F8), S-iso 3 (F6, F7, F8), T 3 (F6, F7, F8), P 2 (F6, F7).

### Hypothesis verdicts

**H1 supported.** F4: C accepted the verbatim copy of A's genuine card and released the job to B. S-file, S-iso, T and P all failed at the nonce stage ("response nonce != issued nonce"); the replayed proofs were cryptographically valid signatures by A's keys over yesterday's nonce. The improvement is attributable to fresh proof of possession alone, since the card check was identical.

**H2 supported, with the boundary located.** F5: B signing with A's copied S-file key produced a valid signature under A's enrolled key; the requester's signer verdict was "A's key" and correct in the key sense, while custody was broken (controller: `sfile-key:A-sfile-k1 (copied-volume, in-process by B)`). S-iso and T both rejected: the gate denied B's connections to `swA` and `tpmA` (`gate denied swA to B`, `gate denied tpmA to B`), B fell back to its own signers, and the verifier rejected B's key / B's AK. F7 then granted B the ACL entry plus A's AK password and token: S-iso, T and P all accepted and the job went to B, with the gate recording `tpmA` invoked by peer label B. So in this harness the protection against a volume copy comes from the signer being outside the copy and behind an access control, and the emulated TPM and the isolated software signer behave identically under equivalent access controls. What the TPM adds beyond the software control is not exercised here (see §5).

**H3 supported.** F6: under all five policies the signer truth was A (`tpmA via gate` invoked by A, after B's `relay_leg`), the verifier's signer verdict was correct, the contacted endpoint was B, and the job token was delivered to B. The relay transcript (`traces/relay-pair.md`) shows B forwarding A's response byte-for-byte. Nothing in C/S/T/P binds the evidence to the channel; fixing this needs a separate channel-binding design, which was out of scope.

**H4 supported.** F8: B kept the inner quote bytes identical (sha256 recorded before and after by the relay and equal in both T and P cells) and moved the outer timestamp by about 60 s, still inside the 300 s window. T accepted; its record shows the edited, unauthenticated timestamp next to a fully valid quote. P rejected with PTV_ERR_010 on the outer COSE_Sign1 while `inner_quote_valid = yes`, i.e. the two signatures have different coverage and only the outer one covers the envelope fields (`traces/cose-tamper-pair.md`).

### Isolated failure classes (F9–F11)

F9 isolates configuration appraisal: with A's key, nonce and envelope all valid, a changed PCR 16 produced PTV_ERR_007 in T and P and no job; C and S, which do not appraise measurements, released the job to honest A (counted as honest acceptances, not errors). F10 isolates schema: an envelope with both `evidence` and `proof`, correctly signed by A's AK, was rejected with PTV_ERR_008 while its signature verified. F11 isolates the trust anchor: a never-enrolled TPM-resident AK claiming attester_id dep-A failed the enrolled-AK signature check (PTV_ERR_010); an unenrolled software key failed the S policies; C again accepted the card copy.

### Nonce handling (F12, F13)

F12: B burned the nonce with garbage (first appraisal rejected at the signature stage and consumed the nonce); A's subsequent valid response for the same nonce was rejected with PTV_ERR_006, with the crypto checks recorded as passing. This confirms consume-on-failure and also shows the availability cost the brainstorm predicted: an attacker who can observe a nonce can burn it. F13: both deliveries were cryptographically valid; the atomic claim admitted exactly one appraisal per cell and the store released one token. In all four cells the relay's copy won; this is most likely a scheduler ordering artifact of the test driver (the most recently started goroutine tends to run first), not a property of either path.

## 4. Divergences from predictions and harness fixes

Run 1 (not retained, see below) produced seven rejects that contradicted the predictions: F5_S-file, F7_S-file, F7_S-iso, and F5/F7/F11/F12_P. All had one cause: the requester placed the registry label "A" instead of the deployment ID "dep-A" in the challenge, so B's impersonation bound its proofs to the wrong identifier string and P cells reported "attester_id is not enrolled" instead of a signature failure. This is a harness identifier bug, not an identity-protocol finding. It was fixed in `internal/verifier/verifier.go` (one line, logged in `fixtures/predictions.md`), predictions were left unchanged, and the matrix was rerun from clean emulator state twice; both reruns matched 59/59. The directories of runs 1 and 2 were deleted by mistake during an output-format fix; only run 3 (`20261106-231737`) is retained. The post-fix P reasons are the more informative ones ("COSE_Sign1 signature invalid under the enrolled AK of A").

## 5. Limitations

* **Coverage, not prevalence.** Hand-written fixtures measure which protections a policy provides against a stated attacker. They say nothing about how often these attacks occur.
* **Custody boundary is simulated.** One OS account runs everything; the gate's pid-to-label ACL stands in for OS or hardware isolation. A working emulator run establishes behavior for the stated custody boundary only. Whether a real TPM resists what a copied swtpm state directory would not (restoring the emulator's NVRAM into a second instance) was not tested; the state directory was simply excluded from the copy manifest. Physical tamper resistance and cloning a full host snapshot require other experiments.
* **TPM versus isolated software signer.** Under equivalent access controls they behaved identically. The specific TPM properties (non-exportability under a compromised host, measured boot binding of the PCRs) were not exercised; PCR 16 was set by the operator to a synthetic configuration digest.
* **PTV slice is partial.** Direct routine mode only; evidence is a raw quote encoding rather than an EAT; no proxy mode, ZK band, sovereign_bound or verdict signing. The timestamp window relies on the local clock. The embedded-evidence format is lab-defined and documented, not interoperable.
* **Workload correctness is out of scope.** All policies attest identity and configuration; none says anything about what the agent then does.
* **Card canonicalization** follows the official sample's JCS approximation; a full RFC 8785 implementation was not added.

## 6. Reproduction

Prerequisites present on the host before the sprint: Go 1.27.1, swtpm 0.10.2 (Debian `swtpm`, `swtpm-tools`), network access to proxy.golang.org. Not available: `tpm2-tools` (no sudo), `tpm2-pytss` headers; both unnecessary because go-tpm speaks to swtpm directly. Pinned: a2a-go/v2 v2.3.1 (the version the official signed-card sample pins; v2.8.0 was current), go-tpm v0.9.8, go-cose v1.3.0, fxamacker/cbor v2.10.0, golang-jwt/jwt v5.3.1, PTV draft-01 of 29 Sep 2026.

Commands (from `a2a-identity/`):

```bash
./scripts/setup.sh
```

```bash
./scripts/smoke.sh
```

```bash
./scripts/matrix.sh
```

```bash
bin/a2aid traces --results results/full/20261106-231737
```

```bash
./scripts/cleanup.sh
```

Commands actually executed for the retained run: `scripts/setup.sh` (builds, starts two swtpm instances with `--flags not-need-init,startup-clear` from empty state, provisions A and B), `scripts/matrix.sh`, `bin/a2aid traces`. The matrix run's own child-process and publish commands are listed in `results/full/20261106-231737/commands-executed.txt`. A standalone go-tpm probe against a throwaway swtpm (quote, ticketed sign, negative cases) preceded the build; its output is summarised in §2.

Changed paths: everything under `a2a-identity/` (new). Pre-existing code reused: `internal/cardsig` adapts `signing.go` from the official a2a-samples Go signed-card sample (canonicalization and JWS layout), with the key provider changed to the operator registry. Unrun cells: the six cells marked n/a by design (F10 for C/S/T, F12 and F13 for C). No cell is pending; the TPM path ran on emulators.

## 7. Dual-use note

The attacker behaviors here (card copy, replay, volume copy, relay, metadata edit, nonce burning) are textbook identity attacks reproduced against scripted loopback agents to measure defenses. The code contains no exploitation of any third-party implementation and no capability beyond what the fixtures describe.
