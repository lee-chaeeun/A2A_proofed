# Results

This page lists what each experiment found and where the saved records are. Every outcome was predicted before testing, and every prediction was met. **Meeting a prediction is not the same as stopping an attack:** some predictions say that Mallory succeeds, and the results report those successes.

**How to read the saved records.** The records use deployment names instead of the paper's names. **Deployment A (Atlas) is Bob**, the intended recipient. **Deployment B (Boreas) is Mallory**, the attacker. So a line such as `accept → B` in a saved summary means *Mallory received the task*. Each folder's README maps the paper's configuration names to the identifiers used in the records.

## Emulator check

Saved in `pq-identity/results/device/20261108T130125Z/`.

The wolfTPM emulator created an ML-DSA-65 key and signed with TPM commands, without returning the private key to the application. The key still worked after a restart. A wrong password produced no signature. A changed message failed verification. CIRCL, an independent ML-DSA library, verified the emulator's signatures.

## Experiment 1: Identity authentication

Saved run: `pq-identity/results/pq/20261108-153049`. Eight configurations were tested in sixteen scenarios: twelve attack and delivery scenarios (P1–P12) and four boundary controls (X1–X4), giving **128 tests**.

**Overall.** All 128 outcomes match the predictions recorded before testing. In **25 tests Mallory received Bob's task**, as predicted. The verification script re-checked 35 valid and 84 invalid proofs; the remaining tests stopped before a proof was checked.

| Scenario | What Mallory has | What happened |
|---|---|---|
| P6, stolen files | Bob's application and credential files, including the file-held ML-DSA key, and Bob's TLS credentials | Mallory received Bob's task with the baseline and with the key file. Every signing-service and emulator configuration rejected her. |
| P8, plain relay | Bob's TLS credentials; she forwards Alice's challenge to Bob unchanged | Mallory received Bob's task with the baseline and with every configuration without channel binding. Every configuration with channel binding rejected her, whether the key was ECDSA, software ML-DSA or emulated-TPM ML-DSA. |
| P12, classical signer | Access to Bob's ECDSA signer but not the ML-DSA key | Mallory received Bob's task with the baseline and both ECDSA configurations, including bound ECDSA. Every ML-DSA configuration rejected her. This tests key separation, not a quantum attack. |
| P3–P5, P9, X3, X4 | Altered action, her own keys, the wrong algorithm, a rewritten binding value, or a key the registry replaced | The baseline, which has no identity proof, let her through. Every configuration with an identity proof rejected her. |
| X1, signer access | Permission to use Bob's ML-DSA signing service and emulated TPM | Mallory received Bob's task with the baseline and every ML-DSA configuration, bound or not. Access to the signer is enough. |
| X2, emulator copy | A full copy of the emulator's state and password | Mallory received Bob's task with the baseline and the file and emulator ML-DSA configurations. The emulator's state is a copyable file. |
| P1, P11, P10 | No attacker; two deliveries at once; connection closed after the proof | Bob received the task exactly once in every configuration. When the connection closed before delivery, no task was sent. |

**Sizes and timings** (`pq-identity/results/pq-bench/20261108-132255/bench.json` and the honest tests of the run):

| Measure | ECDSA P-256 | ML-DSA-65 |
|---|---|---|
| Public key | 65 bytes | 1,952 bytes |
| Signature | 64 bytes | 3,309 bytes |
| Proof response | about 0.6 kB | about 4.9 kB |
| Challenge to proof, local | 1.4–2.6 ms | 3.8–4.9 ms with the emulator |

One emulator signing request takes about 2.4 ms.

## Experiment 2: TPM quote comparison

There are two comparisons with different sizes.

**Broad comparison** (`identity/results/broad/20261107-194025`). 21 scenarios × 11 configurations give 231 cases. 201 of them apply, and 199 match their predictions. In the two that differ (scenario F19), Mallory was rejected although the prediction said she would succeed. Mallory received the task in 55 of 140 attack cases. No honest delivery was rejected (0 of 22).

- Checking Bob's address stopped attacks from a different address.
- TLS stopped Mallory when she did not hold Bob's TLS credentials, including with a self-signed certificate.
- A quote with the wrong register value was rejected. But when Mallory copied the swtpm emulator's state and restored the expected register value, she received Bob's task under both quote configurations (F21).

**Focused comparison** (`identity/results/binding/20261108-004047`). All 24 tests match their predictions. Mallory received Bob's task in 8 of them, as predicted. The verification script confirmed 6 deliveries to Bob and 10 tests where nothing was sent.

- Without channel binding, Mallory's plain relay worked against both software signatures and TPM quotes. With channel binding, both rejected it.
- In V3 and V4, Mallory's rewrite of the binding value broke her own proof. Those rejections do not show relay protection, because the plain relay (V2) still worked.
- In 60 trials per bound configuration, half with the proof connection deliberately closed, no task ever reached Mallory's server (`churn.txt`).

**Checking the broad comparison again.** Its proofs were re-checked when the data was collected: `reverify.md` reports that 217 of 217 checks agree. The published copy keeps the results table, the checks and that report, but not the per-test records that `a2aid reverify` reads. Running `reverify` on the published copy therefore finds nothing, prints `0/0 agree` and exits with 0. That output is not a check. The focused comparison keeps its per-test records and can be re-checked with `a2aid audit-release`.

## Experiment 3: ZK result verification

Saved run: `zk-component/results/zk/20261108-111817`.

**The task.** Bob checks whether four portfolio holdings add up to at most 100. The earlier portfolio totals 80 and passes. The updated portfolio totals 120 and fails.

**The four approval rules.** All require a valid proof and a passing result.

| Rule | Also checks the request challenge | Also checks the allowed input |
|---|---|---|
| Receipt only | no | no |
| Request check | yes | no |
| Input check | no | yes |
| Request + input check | yes | yes |

**Size.** 13 scenarios × 4 rules give **52 evaluations**. These are not 52 separate network exchanges. Nine A2A exchanges produced seven new proofs; some evaluations re-check proofs already received. Each proof took 22.1–23.6 seconds to make and is 223,348 bytes. All 52 outcomes match the predictions recorded before testing.

**What happened.**
- *Outdated input, historical request.* After the portfolio changed from 80 to 120, a request that names the earlier snapshot was approved under all four rules. That is correct: the proof is about the snapshot the request asked for.
- *Outdated input, current request.* For a request that requires the latest snapshot, Input check and Request + input check refused the proof about 80. Receipt only and Request check approved it, although the current total of 120 exceeds the limit.
- *Right request, outdated input.* A proof with the correct challenge but computed over the earlier portfolio was approved by Receipt only and Request check.
- *Proof for another request.* A genuine proof made for a different request was approved by Receipt only and Input check.
- *Both checks.* Request + input check refused every substitution.
- *Broken or fake proofs.* Damaged or fake receipts, a wrong program identifier, a failing result with misleading extra data, and a second delivery of the same result were never approved.

Counts: proofs for the wrong request were approved in 3 of 8 relevant evaluations, and proofs over input the request did not allow in 5 of 12. These groups overlap; there were seven wrong approvals in total, all predicted. None of the 12 legitimate results was refused.

## Separate integration test

Saved in `pq-identity/results/zk-pq-smoke/20261108-154419/`.

This test combines emulator-based authentication with a real computation proof. Bob received the task once, on the connection that carried Bob's identity proof. Bob's result about the earlier portfolio (total 80) was approved under all four rules. Mallory was rejected before any task was sent. Separate tests in `pq-identity/internal/zk/pq_transport_test.go`, using a software ML-DSA key and a placeholder receipt, show that no task is sent over a replacement connection.

This test does not repeat the 52 evaluations of Experiment 3 over post-quantum authentication.

## Testing the verification scripts

Each verification script was given deliberately damaged copies of the saved records. Each damaged copy must produce the outcome predicted for it: 17 copies for Experiment 1 (listed in `pq-identity/fixtures/pq-audit-controls-expected.json`) and 24 for Experiment 3.

## Saved records

Every run folder contains the predictions recorded before testing (`manifest-frozen.json` or `run-inventory.json`, and `predictions-frozen.*`), the identities of the code and programs used (`provenance.json`), a summary (`summary.md`) and logs. The records keep the absolute paths of the original machine so that their hashes stay checkable.

| File in Experiments 1 and 2 | What it contains |
|---|---|
| `matrix.csv`, `matrix.jsonl` | Alice's decision and the actual recipient for each test |
| `cells/<scenario>_<configuration>/decision.json` | Alice's decision, the proof bytes, the signed records, connection details and the order of events |
| `cells/.../controller-events.jsonl` | Independent observations of which server received which task |
| `enrollment-registry.json`, `registry-overrides.json` | The public keys Alice used; no private keys |
| `copy-manifest-*.json` | What Mallory was given in each scenario |
| `pq-audit*`, `release-audit*`, `reverify*` | Verification-script reports written when the run finished |

| File in Experiment 3 | What it contains |
|---|---|
| `requests.json`, `run-inventory.json` | Alice's stored requests and the predicted outcome of each evaluation |
| `decisions.jsonl`, `events.jsonl`, `ledgers.json` | Every rule's decision, the order of input updates and approvals, and the final approvals |
| `exchanges.jsonl`, `receipts/<hash>.bin` | The nine A2A exchanges and the saved proof bytes |
| `oracle*` | Verification-script reports |

## Corrections made before the reported runs

These notes belong with the evidence; the reported runs already include the fixes.

- **Client errors.** Two problems found during development were mistakes in this project's first client, not flaws in A2A. An attacker's challenge could choose whether channel binding was used, and a task could be sent over a replacement connection. Both were fixed before the reported runs: Alice now enforces her own configured setting and keeps the authenticated connection. In the computation client, the task was first sent after the connection step alone, and on the post-quantum connection without the delivery guard. Server logs now show no task requests in either case.
- **Verification scripts.** Earlier versions accepted some damaged records, such as removed or duplicated decisions, missing or reordered events, changed records, replaced receipts and an unreadable timestamp. The final versions require one result per predicted evaluation, the exact event order, identical signed records at each stage, receipts linked to their decision and connection, and a fresh check of every saved proof.
- **Prediction records.** One label of the concurrent-delivery tests in Experiment 1 was renamed after a first trial run and before the reported run; the prediction that Bob receives exactly one task did not change. The Experiment 3 predictions carry a timestamp written in local time with a UTC suffix; the hash recorded before testing is unaffected.
