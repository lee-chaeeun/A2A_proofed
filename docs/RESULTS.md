# Results

Every outcome was predicted before testing, and every prediction was met. Some predictions are attack successes, and they are reported as such.

Saved records call Bob deployment A and Mallory deployment B, so `accept → B` in a summary means Mallory received the task.

## Emulator check

`pq-identity/results/device/20261108T130125Z/`

The wolfTPM emulator created an ML-DSA-65 key and signed with it through TPM commands; the private key never reached the application. The key survived a restart, a wrong password produced no signature, a changed message failed verification, and CIRCL (an independent ML-DSA library) accepted the signatures.

## Experiment 1: Identity authentication

`pq-identity/results/pq/20261108-153049`: 8 configurations × 16 scenarios (P1–P12 and controls X1–X4) = 128 tests.

Mallory received Bob's task in 25 tests. The verification script re-checked 35 valid and 84 invalid proofs; the other tests ended before a proof was checked.

| Scenario | Mallory has | Mallory received Bob's task with |
|---|---|---|
| P6 | Bob's files, including the file-held key and TLS credentials | baseline, key file |
| P8 | Bob's TLS credentials; relays the challenge unchanged | baseline and every unbound configuration |
| P12 | Bob's ECDSA signer, not the ML-DSA key | baseline, both ECDSA configurations |
| X1 | Bob's ML-DSA signers | baseline and every ML-DSA configuration |
| X2 | A full copy of the emulator state and password | baseline, key file, both emulator configurations |
| P3–P5, P9, X3, X4 | Altered action, own keys, wrong algorithm, rewritten binding, replaced key | baseline only |
| P2, P7 | Replayed proof from her own address; Bob's address without TLS credentials | none |

Honest delivery (P1) and two simultaneous deliveries (P11) reached Bob exactly once in every configuration. When the connection closed after the proof (P10), no task was sent.

Costs (`pq-identity/results/pq-bench/20261108-132255/bench.json`):

| | ECDSA P-256 | ML-DSA-65 |
|---|---|---|
| Public key | 65 B | 1,952 B |
| Signature | 64 B | 3,309 B |
| Proof response | ~0.6 kB | ~4.9 kB |
| Challenge to proof | 1.4–2.6 ms | 3.8–4.9 ms (emulator) |

## Experiment 2: TPM quote comparison

**Broad comparison** (`identity/results/broad/20261107-194025`): 21 scenarios × 11 configurations. 201 of the 231 combinations apply and 199 matched their prediction; in the other two (F19) Mallory was rejected although she was expected to succeed. Mallory received the task in 55 of 140 attack cases, and no honest delivery was refused. Address and TLS checks stopped attackers without Bob's credentials. A quote with the wrong register value was rejected, but a copied swtpm state with the register value restored passed (F21).

**Focused comparison** (`identity/results/binding/20261108-004047`): all 24 tests matched; Mallory received Bob's task in 8. Without channel binding the plain relay worked against software signatures and TPM quotes alike; with binding both rejected it. In V3 and V4 Mallory's own binding rewrite broke her proof, so those rejections say nothing about relay protection. In 60 trials per bound configuration, half with the connection closed early, no task reached Mallory (`churn.txt`).

The broad comparison was re-checked when it ran (`reverify.md`, 217 of 217 checks agree). The published copy does not include the per-test records, so it cannot be re-checked again: `a2aid reverify` on it prints `0/0 agree` and exits 0.

## Experiment 3: ZK result verification

`zk-component/results/zk/20261108-111817`: 13 scenarios × 4 approval rules = 52 evaluations, from 9 A2A exchanges and 7 new proofs (some evaluations re-check proofs already received). Each proof took 22–24 s and is 223,348 bytes.

| Rule | Checks challenge | Checks input |
|---|---|---|
| Receipt only | no | no |
| Request check | yes | no |
| Input check | no | yes |
| Request + input check | yes | yes |

All rules need a valid proof and a passing result. The earlier portfolio totals 80 (passes); the updated one totals 120 (fails).

- A request naming the earlier snapshot: all four rules approved the proof about 80, which is correct.
- A request for the latest snapshot: Input check and Request + input check refused the proof about 80; the other two approved it.
- Correct challenge, old input: approved by Receipt only and Request check.
- Proof made for another request: approved by Receipt only and Input check.
- Request + input check refused every substitution.
- Damaged or fake receipts, a wrong program identifier, a failing result and a repeated delivery were never approved.

In total the weaker rules made 7 wrong approvals, all predicted. No legitimate result (0 of 12) was refused.

## Integration test

`pq-identity/results/zk-pq-smoke/20261108-154419/`

Bob authenticated with the emulator key and channel binding, received the task once, and returned a real proof about the earlier portfolio, which all four rules approved. Mallory was rejected before delivery. This run does not repeat Experiment 3's scenarios.

## Testing the verification scripts

Each verification script was fed deliberately damaged copies of the records and had to catch each one as predicted: 17 copies for Experiment 1 (`pq-identity/fixtures/pq-audit-controls-expected.json`) and 24 for Experiment 3.

## Record files

Every run folder has the predictions (`manifest-frozen.json` or `run-inventory.json`, `predictions-frozen.*`), code and binary hashes (`provenance.json`), a `summary.md` and logs. Absolute paths from the original machine are left in place so the hashes still match.

| Experiments 1 and 2 | |
|---|---|
| `matrix.csv`, `matrix.jsonl` | decision and actual recipient per test |
| `cells/<scenario>_<configuration>/decision.json` | proof bytes, signed record, connection details, event order |
| `cells/.../controller-events.jsonl` | which server received which task |
| `enrollment-registry.json` | public keys used (no private keys) |
| `copy-manifest-*.json` | what Mallory was given |
| `pq-audit*`, `release-audit*`, `reverify*` | verification-script reports |

| Experiment 3 | |
|---|---|
| `requests.json`, `run-inventory.json` | Alice's requests and predicted outcomes |
| `decisions.jsonl`, `events.jsonl`, `ledgers.json` | every decision, input updates, approvals |
| `exchanges.jsonl`, `receipts/` | the nine exchanges and saved proofs |
| `oracle*` | verification-script reports |

## Corrections before the reported runs

- Two bugs in our first client, not in A2A: a challenge from the attacker could switch channel binding off, and a task could go out over a replacement connection. Alice now enforces her own setting and keeps the authenticated connection. The computation client had the same replacement-connection problem; server logs now show no task requests in either case.
- Earlier verification scripts missed some damaged records (removed or duplicated decisions, reordered events, replaced receipts, a bad timestamp). The final scripts require one result per prediction, the exact event order and a fresh check of every proof.
- One label in Experiment 1's concurrent-delivery tests was renamed between a trial run and the reported run; the prediction itself did not change. Experiment 3's prediction timestamp is local time with a UTC suffix; its recorded hash is unaffected.
