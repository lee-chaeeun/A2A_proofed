# Final PQ identity results

The corrected experiment is `results/pq/20261108-153049/`; the integration execution is `results/pq-integration/20261108-164204/`. Each contains 128 cells and passes the composite audit. [RESULTS_PQ_CORRECTIONS.md](RESULTS_PQ_CORRECTIONS.md) records the correction history.

## What was tested

Eight configurations combine signed-card/endpoint/TLS checks with ECDSA or ML-DSA proof keys, different key-access assumptions and optional connection binding. Twelve scenarios and four boundary controls are declared in `fixtures/manifest-pq.json`; expectations are in `fixtures/predictions-pq.md`. A and B are scripted A2A deployments on local HTTPS.

The device key is created and used through native ML-DSA-65 commands in the wolfTPM firmware TPM. CIRCL verifies the signatures. Software ML-DSA and ECDSA supply matched controls. All processes share one OS account; signer permissions model an isolation boundary.

## Findings

| Comparison | Observation | Interpretation |
|---|---|---|
| Honest requests | All eight configurations deliver to A | Normal paths work in the testbed |
| Copied application files plus TLS credentials | PQ-file permits impersonation; gated/device keys reject | The copy excludes signer/emulator state by assumption |
| Relay holding A's TLS credentials | Unbound proofs deliver to B; bound proofs reject | Connection binding stops this relay, independent of signature algorithm |
| Classical signer access plus TLS credentials | EC bound delivers to B; PQ configurations reject | Independently enrolled PQ capability was not granted; not a quantum attack |
| Authorized PQ signer/device access | Corresponding PQ configurations deliver to B | A permitted caller can use the key without extracting it |
| Complete emulator-state copy and authorization | Device configurations deliver to B | Copyable software, not physical protection |
| Proof connection replaced | Dispatch refused | A valid proof does not authorize a new connection |
| Concurrent delivery attempts | One release per session | In-memory suppression, not crash-safe exactly-once execution |

All 128 decisions and recipients agree, including **25 expected attacker deliveries**. The audit reports 35 valid v4 proofs, 84 invalid proofs, 16 verified dispatches and 95 verified non-dispatches. These count different things, not one security score. All 17 evidence-mutation controls and nine runner controls pass.

## PQ-to-ZK composition

The ZK requester uses `GuardedSend` for PQ-device+cb. HTTPS regressions isolate continuity with a software test key and stub receipt. A replacement receives zero tasks; unknown outcomes differ from refusal; a new decision recovers.

The genuine-receipt smoke test is `results/zk-pq-smoke/20261108-154419/`. The honest emulator-authenticated task returns a verified receipt and all four policies approve under Pinned; an impostor is rejected before delivery. This is not a new 52-cell matrix or proof that the device computed the receipt.

## Costs and limits

ML-DSA-65 keys/signatures are 1,952/3,309 bytes. Honest signed contexts vary from 271 to 310 bytes. The timing benchmark uses a fixed 306-byte message (`results/pq-bench/20261108-132255/`). These are host/emulator measurements, not physical TPM timings.

The registry enforces algorithm, key id and public key; its version is a label. No production enrollment, rotation or revocation protocol was evaluated. Cards, TLS and the CA remain classical. The audit checks consistency of cooperative records, not their truth. No physical hardware, real-agent behavior or end-to-end PQ security was measured.

## Recheck

From the repository root, `make check` checks both retained runs, controls and tests without modifying evidence. [REPRODUCING.md](../docs/REPRODUCING.md) gives fresh-run steps. Publication removes the unused discovery CLI and corrects help; [PROVENANCE.md](../docs/PROVENANCE.md) distinguishes these changes from the recorded producer.
