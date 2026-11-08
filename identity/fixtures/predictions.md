# Frozen predictions and attacker permissions

Frozen: 2026-11-06 23:05 CET, before any matrix cell was run. Edits after this
point are recorded in the git-free change log at the bottom of this file.

## Ground truths (controller only)

* **signer**: which enrolled key material produced the proof (`A`, `B`,
  `A-copy` = A's exportable key copied into B's volume, `none`, `unknown`).
* **invoker**: which process label the signer gate saw on the socket
  (`A`, `B`, `operator`), from SO_PEERCRED pid → label registration.
* **endpoint**: which agent process served the A2A HTTP exchange (`A` or `B`).
* **job recipient**: which agent process received the synthetic job token.

The requester sees only protocol evidence and must name the endpoint it believes
is deployment `A`. A **false endpoint acceptance** is a job delivered to `B` when
the requester expected `A`. A **false signer attribution** is a verdict naming an
enrolled key that did not sign. A **rejected honest request** is any reject in
F1/F2. A **duplicate release** is more than one job token released for one nonce.

## Attacker permissions per fixture

| Fixture | B may … | B may not … |
|---|---|---|
| F1 honest | (B idle) | |
| F2 rename | (B idle) | |
| F3 name-collision | publish a card with A's display name signed with B's own enrolled publisher key | hold any of A's key material |
| F4 copied-card-replay | serve a verbatim copy of A's signed card; replay a complete earlier response captured from A | reach A's signers; obtain fresh proofs |
| F5 copied-volume | hold a byte copy of A's application volume (`app/`: signed card, config, S-file private key); use its own TPM/isolated signer | connect to A's TPM gate or A's isolated software signer (gate ACL denies label B); hold A's AK password or A's isolated-signer token |
| F6 relay | serve A's card; open a live A2A client to A and forward the current challenge and A's untouched response | modify anything; hold A's keys |
| F7 socket-access | everything in F5 **plus** gate ACL entry for A's TPM and A's isolated signer, **plus** A's AK password and isolated-signer token | |
| F8 tamper-timestamp | everything in F6, and edit the outer `timestamp` field of A's response to another time inside the 300 s window, keeping the inner quote bytes identical | hold A's keys |
| F9 pcr-changed | (B idle; operator extends A's PCR 16 with a non-reference value) | |
| F10 schema-both | (B idle; A is told by a lab hook to put both `evidence` and `proof` in a routine envelope and sign it correctly with A's AK) | |
| F11 unknown-key | serve A's card; answer with a freshly generated, never-enrolled key (TPM-resident AK for T/P, software key for S) and claim attester_id = A | hold enrolled keys of A |
| F12 nonce-burn | first answer the nonce with an invalid proof (as B); the same nonce is then sent to honest A | |
| F13 nonce-concurrent | relay (as F6) while the same nonce is simultaneously sent to A directly | |

Constant across all cells: plain loopback HTTP, no TLS, no transport auth,
routing = the requester always sends to the discovery endpoint it was configured
with (never to the URL inside the card). Whether the card's URL equals the
discovery endpoint is recorded as a separate `url_binding` column and never
enforced.

Harness assumption: all processes run under one OS account. The signer gate
enforces the socket boundary by peer-pid label; this is harness-enforced, not
OS-enforced. The swtpm state directories and AK passwords are readable by the
account; fixtures only use them where the permissions table says so.

## Predicted job decision per cell (expected result)

`accept` = job released to the contacted endpoint; `reject` = no job;
`n/a` = policy does not apply to the fixture; `one` = exactly one release.

| Fixture | C | S-file | S-iso | T | P | Notes |
|---|---|---|---|---|---|---|
| F1 honest | accept | accept | accept | accept | accept | job → A |
| F2 rename | accept | accept | accept | accept | accept | job → A, renamed card verifies under same kid |
| F3 name-collision | reject | reject | reject | reject | reject | card kid is B's; stage=card |
| F4 copied-card-replay | **accept (false endpoint)** | reject | reject | reject | reject | C has no freshness; S/T/P fail at nonce |
| F5 copied-volume | accept (false endpoint) | **accept (false endpoint; signer=A-copy)** | reject | reject | reject | S-iso denied at gate; T/P wrong AK |
| F6 relay | accept (false endpoint) | accept (false endpoint; signer=A correct) | same | same | same | endpoint attribution error coexists with correct signer verdict |
| F7 socket-access | accept (false endpoint) | accept (false endpoint) | **accept (signer=A, invoker=B)** | **accept** | **accept** | custody boundary moved to the gate ACL |
| F8 tamper-timestamp | accept (false endpoint) | accept | accept | **accept; timestamp edit undetected** | **reject (PTV_ERR_010); inner quote still valid** | H4 |
| F9 pcr-changed | accept (job → A) | accept | accept | reject (PTV_ERR_007-equivalent) | reject (PTV_ERR_007) | C/S do not appraise PCRs |
| F10 schema-both | n/a | n/a | n/a | n/a | reject (PTV_ERR_008) | envelope signature valid |
| F11 unknown-key | accept (false endpoint) | reject | reject | reject | reject (PTV_ERR_010) | trust-anchor failure |
| F12 nonce-burn | n/a | reject,reject | reject,reject | reject,reject | reject,reject (second = PTV_ERR_006) | nonce consumed on failure |
| F13 nonce-concurrent | n/a | one | one | one | one | at most one release |

## Hypothesis mapping

* H1 (freshness): F4 — S/T/P reject, C accepts.
* H2 (custody): F5 — S-file accepts (copy works), S-iso and T reject under
  equivalent access control; F7 shows the boundary is the gate, not the key type.
* H3 (relay): F6/F13 — signer verdict correct (A), endpoint B receives job.
* H4 (envelope): F8 — T accepts edited metadata, P rejects on outer signature
  while inner quote still verifies.

## Change log

* 2026-11-06 23:20 CET, after matrix run 1 (results/full/20261106-231434): the
  requester put the registry label ("A") instead of the deployment ID ("dep-A")
  into the challenge, so B's impersonation claimed the wrong identifier string and
  F5/F7 S-policies and F5/F7/F11/F12 P cells rejected for a harness reason
  ("attester_id is not enrolled" / S binding mismatch). Fixed in
  internal/verifier/verifier.go (SendChallenge). Predictions unchanged. Run 1 (results/full/20261106-231434) showed every
  other cell matching; its 7 harness-caused rejects were F5_S-file, F7_S-file,
  F7_S-iso, F5_P (reason "attester_id is not enrolled"), F7_P, F11_P, F12_P. Run 2
  (20261106-231520) matched 59/59. Both directories were deleted by mistake while
  fixing output formatting (rm -rf results/full); run 3 (20261106-231737) is the
  retained run and also matched 59/59.
