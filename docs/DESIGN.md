# Design and trust model

This page explains how each check works, what the prototype trusts, what the attacker can do, and what the experiments do not show.

Participants: **Alice (A)** is the requester. **Bob (B)** is the intended recipient and the worker who computes the result. **Mallory (M)** is the attacker. In code and saved records, deployment A (Atlas) is Bob and deployment B (Boreas) is Mallory.

## Terms used on this page

- **TPM (Trusted Platform Module):** a security chip that creates keys and signs with them without giving the private key to the application. This prototype uses software emulators of a TPM.
- **ML-DSA-65:** a post-quantum signature scheme (NIST FIPS 204). **ECDSA P-256:** a widely used classical signature scheme, included for comparison.
- **TLS:** the encryption layer of HTTPS. **Exporter:** a 32-byte value that both ends of one TLS connection can compute and that differs for every connection (RFC 9266).
- **CBOR:** a compact binary data format. *Deterministic* CBOR always encodes the same data as the same bytes, so Alice and Bob sign and check identical bytes.
- **COSE:** a standard way to wrap signed CBOR data.
- **Enrollment registry:** Alice's list of each agent's expected address, TLS server name, signature algorithm and public key.

## The two decisions, step by step

```text
Enrollment registry: address, TLS name, algorithm, key identifier, public key
      |
1. Read Bob's Agent Card           -> check its signature, Bob's address and TLS name
2. Send a fresh random challenge   -> Alice stores it with the request
3. Bob signs a request record      -> key in a signing service, a key file or an emulated TPM
4. Check the signed record         -> Bob's registered public key; Alice's own TLS exporter
5. Send the task                   -> once, only on the connection that carried the proof
      |
6. Bob proves the computation      -> RISC Zero receipt: proof plus public output
7. Check the proof                 -> against the program identifier Alice expects
8. Check the public output         -> right request challenge, allowed input
9. Record the approval             -> at most once per request
```

Steps 1–5 are **identity authentication**, tested in Experiment 1 (`pq-identity/`) and Experiment 2 (`identity/`). Steps 6–9 are **ZK result verification**, tested in Experiment 3 (`zk-component/`). The separate integration test in `pq-identity/` runs all nine steps once with the emulated TPM. It does not repeat Experiment 3's attack scenarios.

## Identity authentication

**What Bob signs.** Bob signs a short record that names the challenge, the intended agent, the requester, the action, the session, the expected algorithm and key, and an expiry time. The record is deterministic CBOR, signed directly with ML-DSA-65 or ECDSA. It is not wrapped in COSE. Alice rebuilds the record from her own stored request and compares it field by field. A response therefore cannot choose a different key, algorithm or session, and an answer to an old challenge cannot be reused.

**Why channel binding matters.** Suppose Mallory holds a copy of Bob's TLS certificate and private key. She can then pass the TLS check and sit between Alice and Bob as a relay. The relay has two separate TLS connections: one with Alice and one with Bob. Each connection has its own exporter value. With channel binding, Bob signs the exporter of the connection Bob sees, and Alice expects the exporter of the connection she sees. The values differ, so Alice rejects the proof and Mallory does not receive the task. This works with software keys and with the emulated TPM.

**Delivery guard.** After accepting a proof, Alice sends the task only on the connection that carried that proof, and only once per challenge. She does not open a new connection. If the connection closes first, the task is not sent; a new attempt needs a new challenge.

**Where the key is kept.** Experiment 1 compares three places:
- a **signing service** that signs only for listed processes. It stands in for the key-access boundary we model; it is not a hardware measurement. The `env` in the configuration names `EC-env` and `PQ-env` refers to this service;
- a **key file** among the agent's credential files;
- the **wolfTPM firmware TPM emulator**, which creates the ML-DSA key and signs through TPM commands without returning the private key to the application.

## ZK result verification

Bob runs a small program that checks whether four portfolio holdings add up to at most 100. RISC Zero produces a **receipt**: a proof that this exact program ran, plus its public output (the **journal**). The journal states whether the limit is met, the request challenge, and a hash that identifies the input.

**A valid proof is not permission to approve.** Checking the receipt tells Alice that the program produced this journal from some input. It does not tell her that the journal answers her request, or that the input is the one she allowed. Alice approves only if all of these hold:

1. the receipt verifies for the expected program;
2. the computation passed (the total is at most 100);
3. the challenge in the journal matches her stored request;
4. the input hash matches an input her request allows;
5. the request has not been approved before.

**A concrete example.** Bob's earlier portfolio totals 80, which is within the limit of 100. The portfolio is then updated to a total of 120, which exceeds it. A proof about the old portfolio stays valid forever: it truly shows that 80 is at most 100. But it says nothing about the updated portfolio. Each request therefore states which input it allows. A *Pinned* request names one historical snapshot, so the proof about 80 is acceptable. A *Current* request requires the latest snapshot, so the same proof must be refused once the total is 120.

## TPM quote comparison

Experiment 2 asks what a TPM quote adds. A **quote** is a TPM-signed report of the values in its platform configuration registers (PCRs). Here the checked register holds a string chosen by the operator, not a measurement of running software.

The comparison includes a quote inside a signed COSE response that we designed. Some of its fields and checks are taken from the routine response of the Prove-Transform-Verify (PTV) Internet-Draft ([draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01)), a work-in-progress proposal for attested agent identity: the version, message type, attester identifier, triage band, evidence and timestamp fields; the rule that a routine response carries evidence and no separate proof; PTV's error codes; and a 300-second time window. This is our own design. It does not implement PTV and claims no conformance with it.

## What each protection adds

- **ML-DSA** protects the signature scheme against quantum attacks. A large enough quantum computer could work out an ECDSA private key from its public key, even if the private key never leaves a TPM.
- **A physical TPM with a key that cannot be exported** protects against copying the key. Copying the agent's files, or the TPM's encrypted key blobs, does not give another machine the ability to sign. Copying such a key would require defeating the TPM's hardware protections, for example with physical access to the device. It does not stop someone who can already ask the original TPM to sign (control X1). Keeping an ECDSA key in a TPM does not make ECDSA quantum-resistant.
- **The emulator** shows that an ML-DSA key can be created and used through TPM commands inside A2A. It does not show hardware protection: its whole state is a file that can be copied, and control X2 shows that Mallory can then impersonate Bob.
- **Channel binding** stopped the tested relay from reusing Bob's valid response on Mallory's connection with Alice (scenario P8).
- **Request and input checks** stopped genuine proofs that answered the wrong request or used outdated data from being approved (Experiment 3).

These results come from fixed scenarios on one machine. They do not show that TPMs, post-quantum signatures or ZK proofs are needed in every deployment.

## What the prototype trusts

**Trusted:** Alice and what she observes on her own TLS connections; the enrollment registry; the laboratory certificate authority; whoever administers the emulators; the signing service's list of allowed processes; the input authority's record of which inputs are allowed; the expected program identifier and the proof checker.

**Not trusted:** anything an agent sends: Agent Cards, challenge responses, quotes, signed responses, receipts and unsigned extra data.

**What Mallory can do, from weakest to strongest:** copy Bob's Agent Card; copy Bob's application and credential files; take over Bob's address without Bob's credentials; hold Bob's TLS certificate and key; use Bob's ECDSA or ML-DSA signer; copy the emulator's entire state. In some scenarios Mallory also rewrites the challenge, removes or injects the binding value, substitutes keys or algorithms, swaps the connection after the check, or races two deliveries. In Experiment 3, the attacker replays, damages or substitutes receipts, proves over outdated input or the wrong challenge, adds misleading unsigned data, or delivers a result twice.

## What the experiments do not show

- **Hardware protection.** Both TPMs are software. Their state, including the key that protects the firmware TPM's storage, is a file on the host. A physical ML-DSA-capable TPM was not tested, and its speed was not measured.
- **End-to-end post-quantum security.** Agent Card signatures, TLS 1.3, the certificate authority and the TPM quotes are classical. Someone who learns the TLS session secrets also learns the exporter.
- **Trustworthy code.** The checked register holds a chosen string. A passing quote shows that the enrolled key signed that register value, not that trustworthy software is running.
- **Production isolation.** All processes share one operating-system account. Registering, replacing and disabling keys are tested only for one replaced key.
- **Proof that events happened.** The verification scripts check that proofs verify and records are consistent. They use the same libraries as the application and cannot prove the logged events occurred.
- **Formal guarantees, attack frequencies or real agents.** Nothing is formally verified. The scenarios are chosen protocol cases, not measured attack rates, and no language-model agent is involved.

## Dual use

The scenarios copy, replay, relay and hijack local test processes with synthetic tasks. No third-party system is attacked.
