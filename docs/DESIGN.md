# Design and trust model

## The two decisions

```text
Enrollment registry: endpoint, TLS name, algorithm, key identifier, public key
      |
1. Discover the Agent Card       -> check publisher signature, endpoint and TLS name
2. Issue a fresh challenge       -> stored with the request context
3. Agent signs the context       -> signing service, file key, or emulated TPM
4. Rebuild and verify the context -> enrolled key, own TLS exporter for bound proofs
5. Deliver the task              -> only on the connection that carried the proof, once
      |
6. Worker proves the computation -> RISC Zero receipt with a public journal
7. Verify the receipt            -> against the locally pinned program identifier
8. Check the journal             -> request challenge and authorized input commitment
9. Record the approval           -> once, under the request's Pinned or Current contract
```

Steps 1–5 are the identity decision (`identity/`, `pq-identity/`); steps 6–9 are the result decision (`zk-component/`). One smoke test in `pq-identity/` runs all nine steps; the full attack matrices are evaluated separately.

**Identity proof.** The signed context names the configuration, algorithm, key identifier, expected deployment, requester, action, nonce, expiry and session, and, for *bound* configurations, the TLS exporter of the signer's own connection (RFC 9266). The requester rebuilds the expected context from its own session and the registry, so a response cannot choose the key, algorithm or exporter. A relay holding A's TLS certificate passes the TLS check, but its two connections have different exporters, so a bound proof made for the relay's connection to A fails on the requester's connection to the relay.

**Delivery guard.** After an accepted proof the requester seals its transport: no new connection can be opened, the task may be written only to the connection that carried the proof, and only once per issued challenge. If a request is written but no response arrives, the outcome is recorded as *unknown*; only the recipient's log can settle it. A new attempt needs a new connection, challenge and decision. The computation task in `pq-identity/` goes through the same guard.

**Key locations.** A key is held by a signing service that answers only listed processes, stored in the agent's application files, or created and held by a firmware TPM emulator (wolfTPM) that signs through its ML-DSA commands and never returns the private key. A matched ECDSA key separates the effect of the algorithm from the effect of key location and binding.

**Result proof.** The RISC Zero guest recomputes a commitment to four holdings, sums them and publishes whether the sum is at most 100. A receipt proves that the pinned guest produced this journal on some input. The requester's stored request supplies the challenge and the contract: *Pinned* authorizes a named historical snapshot, *Current* requires the authority's latest snapshot at approval time. The same valid receipt can therefore be approved under one contract and refused under the other.

## Trust model

**Trusted:** the requester and its own TLS observations; the enrollment registry (it enforces algorithm, key identifier and public key; its version field is a label); the lab certificate authority; the emulator administration; the signing service's access list; the task authority's history of authorized input commitments; the pinned guest identifier and verifier.

**Untrusted:** everything an agent or worker sends: Agent Cards, challenge responses, quotes, envelopes, receipts and unsigned metadata.

**Attacker capabilities (deployment B impersonating A), in increasing order:** copying A's card; copying A's application files; taking over A's address without credentials; holding A's TLS certificate and key; using A's classical or PQ signing service; copying the emulator's complete state. Active variants rewrite the challenge, strip or inject the binding, substitute keys or algorithms, replace the connection after appraisal, or race two deliveries. The computation attacker replays, corrupts or substitutes receipts, proves over obsolete inputs or wrong challenges, lies in unsigned metadata and delivers twice.

## What the experiments do and do not establish

They show, in a local testbed with scripted agents, that an emulator-created ML-DSA key can authenticate A2A deliveries under independent verification; that connection binding, not the signature algorithm, stops a relay holding A's TLS credentials; that copying application files does not copy a key behind the modeled signing boundary; that access to the classical signer does not yield a separately enrolled PQ key; and that a valid computation receipt still needs a matching request and authorized input.

They do not establish:

- **Hardware protection.** swtpm and the wolfTPM firmware TPM are software; their state, including the key protecting the firmware TPM's storage, is a host file. Copying it, or being granted the signing service, reproduces the capability, and the experiments show this on purpose. A physical TPM would need provisioning, enrollment and measurement policies, not only a different socket.
- **End-to-end post-quantum security.** Agent Card signatures, TLS 1.3, the certificate authority and the classical TPM quote are classical. An adversary who recovers TLS session keys also obtains the exporter, which is a stronger attacker than the stolen-certificate relay measured here.
- **Measured boot or workload integrity.** The checked PCR holds an operator-chosen string.
- **Production isolation or lifecycle.** All processes share one operating-system account; enrollment, rotation and revocation are not modeled beyond one replaced key; delivery suppression is in memory, not durable exactly-once execution.
- **Tamper-proof evidence.** The checkers validate the consistency of cooperative records with the same cryptographic libraries as the application; they do not prove the records describe reality.
- **Frequencies or real agents.** Scenarios are hand-selected protocol cases, not attack rates, and no model-driven agent is involved.

PTV ([draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01)) motivates the attested identity response; the classical experiment implements its routine response with a TPM quote inside a signed envelope, not its full flow. A TPM changes where a key lives, ML-DSA changes the algorithm: neither substitutes for the other.

## Dual use

The scenarios implement generic copy, replay, relay, hijack, credential-reuse, downgrade and emulator-cloning behaviour against local processes and synthetic tokens. No third-party system is attacked, and the errors the experiments exposed were in this project's code.
