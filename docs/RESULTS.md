# Results

Configuration names follow the paper; each component README maps them to the policy identifiers used in code and records. A or B is the deployment that received the synthetic task, R a rejection, and N an accepted proof whose delivery was refused because the proof connection had closed.

## PQ identity (`pq-identity/`)

Published run: `pq-identity/results/pq/20261108-153049` — 8 configurations × (12 scenarios + 4 boundary controls) = 128 cells.

| Finding | Evidence |
|---|---|
| All 128 decisions and recipients match the declared predictions, including 25 deliberate deliveries to B | `summary.md`, `matrix.csv`; audit: 35 proofs valid, 84 invalid as recorded, 16 verified deliveries, 95 verified non-deliveries |
| A relay holding A's TLS credentials reaches B under every unbound configuration and is rejected under every bound one, for ECDSA, software ML-DSA and device ML-DSA alike | scenario P8; binding rewrites fail (P9); a closed proof connection blocks delivery (P10) |
| Copied application files plus TLS credentials impersonate A only when the ML-DSA key is file-held | scenario P6 |
| Access to A's classical signer defeats bound ECDSA but no ML-DSA configuration | scenario P12; credential separation, not a quantum attack |
| A response cannot select another key, algorithm, fresh key under A's identifier, or a key the registry replaced | P4, P5, X3, X4 |
| Authorized use of the signing service, or a full copy of the emulator state, reproduces the device key | controls X1, X2: the limits of the simulated boundary |
| The emulator creates the ML-DSA key inside the device, signs with its own commands, refuses a wrong authorization secret and keeps the key across restarts; CIRCL verifies its signatures | `results/device/20261108T130125Z/` |
| Signed contexts are 271–310 bytes; ML-DSA-65 keys and signatures are 1952 and 3309 bytes; a device signing request takes about 2.4 ms; local challenge-to-proof latency is 1.4–2.6 ms (ECDSA), 1.9–2.6 ms (software ML-DSA) and 3.8–4.9 ms (device) | `results/pq-bench/20261108-132255/bench.json` (fixed 306-byte message) and the honest cells of the run |
| The computation task sent over the bound device configuration arrives once, on the proof connection, with a genuine receipt; an impostor is rejected before delivery | `results/zk-pq-smoke/20261108-154419/`; zero task requests at a replacement connection are tested in `internal/zk/pq_transport_test.go` |

## Classical identity (`identity/`)

| Run | Finding |
|---|---|
| `identity/results/binding/20261108-004047` (24 cells) | With A's TLS credentials, the relay reaches B under TLS alone and under unbound software-envelope and TPM-quote proofs; both bound proofs reject it. All 24 cells agree with the declared decision and recipient, including 8 deliberate attacker deliveries; the release audit reports 6 verified deliveries and 10 verified non-deliveries. Continuity cases refuse a replacement connection before any byte, and in 60 concurrent trials per bound configuration with half of the proof connections closed, no server logged a receipt at B (`churn.txt`) |
| `identity/results/broad/20261107-194025` (21 scenarios × 11 configurations; 201 applicable cells, 199 as predicted) | Endpoint equality stops copy, replay and different-address attacks; authenticated TLS stops the credential-less hijack and the self-signed certificate; a copied swtpm state with its PCR value restored impersonates A under both quote configurations |

## Task binding (`zk-component/`)

Published run: `zk-component/results/zk/20261108-111817` — 13 scenarios × 4 policies = 52 evaluations from nine A2A exchanges and seven genuine proofs (22.1–23.6 s each, 223,348-byte receipts). All 52 match the declared predictions.

- The same receipt and challenge are approved by every policy under Pinned(v1); once the authority moves to v2, the two input-checking policies reject them under Current.
- A fresh challenge with an obsolete input passes *Receipt only* and *Request check*; a receipt for another request passes *Receipt only* and *Input check*.
- Corrupted receipts, a wrong program identifier, fake receipts, a failing result with misleading metadata and a second delivery produce no approval.
- The result checker re-verifies ten receipt/program-identifier pairs (seven valid, three rejected) and lists the seven deliberate weak-policy approvals.

## Reading the published records

Every run directory contains `run-inventory.json` (cells and expected outcomes declared before execution), `manifest-frozen.json` and `predictions-frozen.*` (the scenario definitions used), `provenance.json` (source, binary and dependency identities), `summary.md` and logs. Absolute paths of the original workspace inside these records are kept so their hashes stay checkable.

| Identity runs | Meaning |
|---|---|
| `matrix.csv`, `matrix.jsonl` | Decision and recipient per cell |
| `cells/<scenario>_<policy>/decision.json` | Requester verdict, proof bytes, typed contexts, connection records, ordered requester events, issued sessions |
| `cells/.../controller-events.jsonl` | Controller and recipient observations, including the receipts that show who got the task |
| `enrollment-registry.json`, `registry-overrides.json` | Public keys and pins used for verification; no private keys |
| `copy-manifest-*.json` | What the copy or clone attacker received |
| `pq-audit*`, `release-audit*` | Audit reports written at run time |

| Task-binding run | Meaning |
|---|---|
| `requests.json`, `run-inventory.json` | Stored requests, contracts and declared evaluations |
| `decisions.jsonl`, `events.jsonl`, `ledgers.json` | Every policy evaluation, ordered authority and approval events, final approval state |
| `exchanges.jsonl`, `receipts/<hash>.bin` | The nine A2A exchanges and the retained receipt bytes |
| `oracle*` | Result-checker reports |

An audit exit code of 0 means the records are complete and agree with the declared experiment, including declared attacker successes; 1 means a violation or disagreement; 2 means incomplete, malformed or unsupported evidence. The paper's appendix describes the checkers and the corruption controls that validate them.
