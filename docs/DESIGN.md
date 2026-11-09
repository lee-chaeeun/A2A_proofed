# Design

Alice is the client, Bob the agent she wants to reach, Mallory the attacker. In code and records Bob is deployment A (Atlas) and Mallory is deployment B (Boreas).

## Flow

```text
1. Alice reads Bob's Agent Card     check its signature, Bob's address and TLS server name
2. Alice sends a random challenge   and stores the request it belongs to
3. Bob signs a request record       with a key in a signing service, a key file or the TPM emulator
4. Alice checks the record          signature under Bob's enrolled key; every field against her stored request
5. Alice sends the task             once, on the connection that carried the proof
6. Bob returns a RISC Zero receipt  a proof plus the program's public output (the journal)
7. Alice verifies the receipt       against the program identifier she expects
8. Alice checks the journal         result passed, challenge matches, input is one the request allows
9. Alice records the approval       at most once per request
```

Steps 1–5 are tested in Experiments 1 and 2, steps 6–9 in Experiment 3. The integration test runs all nine once.

Alice keeps an enrollment registry: for each agent, its address, TLS server name, signature algorithm and public key. Everything she checks is compared against this registry or her own stored request, never against values the agent supplies.

## Identity

Bob signs a record naming the challenge, the intended agent, the requester, the action, the session, the algorithm, the key and an expiry time. It is encoded as deterministic CBOR, so both sides produce the same bytes, and signed directly with ML-DSA-65 or, for comparison, ECDSA P-256. There is no COSE wrapper.

**Channel binding.** TLS lets both ends of a connection derive an *exporter* value that is different for every connection (RFC 9266). In bound configurations Bob puts the exporter of Bob's own connection into the record. A relay that holds Bob's TLS certificate still has two connections, one to Alice and one to Bob, with two different exporters, so Alice rejects the forwarded proof.

**Delivery guard.** Once a proof is accepted, the task goes only on that connection and only once per challenge. If the connection closes, nothing is sent and Alice has to start again.

**Key locations.** The signing service signs only for listed processes; it models a key-access boundary and is not a hardware measurement (`env` in `EC-env` and `PQ-env` refers to it). The key file sits among the agent's credentials. The wolfTPM firmware TPM emulator creates the ML-DSA key and signs through TPM commands without returning the private key.

## Result approval

Bob's program checks whether four portfolio holdings add up to at most 100. A valid receipt shows that this program produced the journal from some input. It says nothing about whether the journal answers Alice's request or used an input she allowed, so Alice checks those separately.

Example: the earlier portfolio totals 80 and passes; after an update it totals 120 and fails. A proof about the earlier portfolio stays valid. If the request named that earlier snapshot (*Pinned*), approving it is correct. If the request asked for the latest snapshot (*Current*), the same proof has to be refused.

## TPM quotes

A quote is a TPM-signed report of its register values. In Experiment 2 the checked register holds a string the operator chose, so a passing quote shows that the enrolled key signed that value, not that trustworthy code is running. One configuration wraps the quote in a signed COSE response of our own design; some of its fields and checks follow the routine response in the PTV Internet-Draft ([draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01)), but it does not implement PTV.

## What each part protects against

| Part | Protects against | Does not protect against |
|---|---|---|
| ML-DSA | Quantum attacks on the signature | Someone who can use Bob's signer |
| Physical TPM, non-exportable key (expected, not tested) | Copying the key through files or key blobs | Someone who can ask the TPM to sign; hardware attacks |
| TPM emulator (tested) | The application handling the private key | Copying the emulator's state file (control X2) |
| Channel binding | The tested relay with Bob's TLS credentials | Mallory using Bob's signer |
| Request and input checks | Approving a valid proof for another request or outdated data | A wrong but authorized input |

Keeping an ECDSA key in a TPM does not make it quantum-resistant.

## Trust and attacker

Trusted: Alice, the registry, the local certificate authority, the emulator operator, the signing service's access list, the record of allowed inputs, and the expected program identifier. Not trusted: anything an agent sends.

Mallory's capabilities, weakest first: Bob's Agent Card; Bob's application and credential files; Bob's address without credentials; Bob's TLS certificate and key; use of Bob's ECDSA or ML-DSA signer; a full copy of the emulator state. Some scenarios add rewriting the challenge or binding, swapping keys or algorithms, replacing the connection, or racing two deliveries. In Experiment 3 the worker may replay, damage or substitute receipts, prove over old input or the wrong challenge, or deliver twice.

## Limits

- Both TPMs are emulators. Physical key protection and physical-TPM performance are untested.
- Agent Cards, TLS, the certificate authority and the quotes are classical, so the system is not post-quantum end to end. Anyone with the TLS session secrets also has the exporter.
- All processes share one operating-system account. Key registration and revocation are tested only for one replaced key.
- The verification scripts check proofs and record consistency with the same libraries as the application; they cannot show that logged events happened.
- Nothing is formally verified, the scenarios are hand-picked, and the agents are scripted.

The scenarios run only against local processes with synthetic tasks.
