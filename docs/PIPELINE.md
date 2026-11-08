# From agent discovery to approval

There are two decisions: where to send a task, and whether to act on its result. They need different evidence.

```text
Trusted enrollment: expected endpoint, TLS name, algorithm, key id, public key
       |
       v
1. Discover Agent Card --> check publisher signature, endpoint and TLS name
       |
2. Issue fresh challenge + stored request context
       |
3. Agent asks gated signer --> software control OR native TPM-emulator commands
       |                                      |
       |                              ML-DSA signature (no key returned)
       v
4. Requester rebuilds context --> verifies pinned key and its own TLS exporter
       |
5. GuardedSend --> seal transport; use proof connection; consume authorization once
       |
       v
6. Worker computes bounded sum --> RISC Zero guest --> receipt + public journal
       |
7. Verify receipt against locally pinned guest image ID
       |
8. Match journal challenge and authorized input commitment to stored task
       |
9. Record approval once, under Pinned or Current contract
```

Steps 1–5 are the identity experiment. Steps 6–9 form the standalone ZK experiment, originally delivered under `C+tls`. A smoke test connects the PQ-device+cb path through all nine steps; the full matrices were evaluated separately.

## What the identity evidence means

The registry supplies the expected key rather than accepting a key chosen by the response. The proof context names the policy, algorithm, key identifier, deployment, requester, action, nonce, expiry, session and, when required, connection exporter. Each policy uses the same field schema, not identical bytes.

The TLS exporter is a value derived separately for each connection. A relay with A's TLS certificate can impersonate A at the TLS layer, but its connection to the requester differs from its connection to A. An additional proof that A signs using its own exporter will not verify against the requester's exporter on the relay connection.

`GuardedSend` keeps the proof and delivery together. It refuses a new connection after appraisal. A lost response can leave the outcome unknown; a fresh attempt needs a fresh decision. The identity proof does not sign the later ZK task payload. The requester is trusted to choose that payload; the result policy checks its request challenge and input contract.

The device path is `agent` → `gate` → `pqdev` → C bridge → wolfTPM firmware TPM. The bridge uses native create/sign commands and the requester verifies with CIRCL. Application files exclude the simulated device state. Copying the emulator state and authorization files, or granting signer access, defeats that exclusion as expected. This is not physical isolation.

## What the computation evidence means

The Rust guest reads a snapshot and challenge, recomputes a SHA-256 commitment, adds four bounded holdings, and publishes whether their sum is at most 100. The receipt authenticates the journal under the compiled guest's image ID. It does not establish where the inputs came from or who physically computed the proof.

A request stores a challenge and a contract. `Pinned` permits a named historical snapshot. `Current` requires the authority's head when approval is inserted. Thus identical valid proof bytes can authorize Pinned(v1) and fail Current after an update to v2. Freshness alone cannot establish input currency.

Every result policy verifies a genuine receipt; V0/VT/VI/VTI remove or retain the task and input checks to isolate their effects. This does not compare ZK against ordinary recomputation. The published synthetic openings make evidence checking possible, but prevent an empirical privacy claim.

## Why the evaluations use scripted tasks

A deterministic synthetic token identifies the task recipient without interpreting model behavior. A four-number computation makes stale or substituted inputs unambiguous. Fixed attacker grants separate endpoint authentication, proof binding, key access and result authorization. These are protocol tests; real-agent traces would answer different questions about frequency, intent or emergent interaction.

See [CODE_MAP.md](CODE_MAP.md) for the implementation and [EVIDENCE.md](EVIDENCE.md) for the observations.
