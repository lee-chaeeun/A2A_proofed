# A2A Proofed: post-quantum identity and ZK result verification for A2A

Agent2Agent (A2A) is a protocol that lets one software agent find another and hand it a task. This repository contains a working A2A prototype and the evidence behind its paper, *TPM-Emulated Post-Quantum Authentication and ZK Verification for A2A* ([`paper/a2a-identity-paper.pdf`](paper/a2a-identity-paper.pdf)). The LaTeX source in [`paper/`](paper/) is the authoritative description of the work. Built by Chae Eun Lee for the Swarm Alignment Hackathon (Apart Research), Track 3.

## The problem

When one agent hands work to another, it makes two decisions:

1. **Who may receive the task?** A copied identity card or a stolen key could let an impostor receive it.
2. **Should the returned result be approved?** A valid proof can still answer the wrong request or use outdated data.

The prototype checks both before acting.

## Participants

- **Alice (A)** is the requester. She sends the task and decides whether to approve the result.
- **Bob (B)** is the intended recipient. Bob also performs the computation and returns the result.
- **Mallory (M)** is the attacker. She tries to receive Bob's task or to get a wrong result approved.

All three are scripted programs on one machine, not language-model agents.

**Names in the saved records.** The records were written before the paper used these names. In code and records, **deployment A (Atlas) is Bob** and **deployment B (Boreas) is Mallory**. Alice is the requester process. The saved records keep their original names.

## How it works

```text
Alice (requester)                                     Bob (recipient and worker)
 keeps a registry of Bob's expected address,           keeps the signing key in a signing
 server name, signature algorithm and public key       service, a key file or an emulated TPM
     |
     | 1. check Bob's Agent Card, address and TLS certificate -------------->
     | 2. send a fresh random challenge ------------------------------------>
     |   <------------- 3. Bob signs a record naming the challenge and request
     | 4. check the signature with Bob's registered public key,
     |    and check every field against the request Alice stored
     | 5. send the task once, on the same connection that carried the proof ->
     |   <------------- 6. Bob returns a result with a zero-knowledge proof
     | 7. check the proof against the expected program
     | 8. check that the result answers this request and used the allowed input
     | 9. record the approval, at most once
```

**Steps 1–5: identity authentication.** Alice first checks Bob's **Agent Card**, the signed description that an A2A agent publishes, and checks that Bob answers at the registered address with the registered TLS certificate. A copied card alone does not prove who is answering, so Bob must then prove possession of the registered key by signing a fresh challenge.
- The signature uses **ML-DSA-65**, a post-quantum signature scheme standardized by NIST in FIPS 204. It is designed to resist attacks by future quantum computers.
- In the device configurations, the key lives in a **TPM (Trusted Platform Module)** emulator. A TPM is a security chip that creates keys and signs with them without handing the private key to the application. Here the TPM is software: the wolfTPM firmware TPM running on the host.
- With **TLS channel binding**, Bob also signs a value taken from Bob's own TLS connection (TLS is the encryption layer that HTTPS uses). If Mallory relays the challenge over her own connection, that value does not match Alice's connection, and Alice rejects the proof.

**Steps 6–9: ZK result verification.** Bob checks whether four portfolio holdings add up to at most 100 and returns a **zero-knowledge (ZK) proof** made with **RISC Zero**, a system that proves a program ran correctly.
- A valid proof shows that the program produced this result from some input.
- It does not show that the result answers Alice's request or that the input was the one Alice allowed. Alice checks both separately before approving.

**What is not covered.** Physical key protection is not tested, because the TPM is an emulator whose state is an ordinary file. Agent Cards, TLS and the laboratory certificate authority still use classical cryptography, so the whole system is not post-quantum secure. [docs/DESIGN.md](docs/DESIGN.md) lists the assumptions and limits.

## Experiments

| Name in the paper | Question it answers | Folder | Size |
|---|---|---|---|
| **Experiment 1: Identity authentication** | In which of eight configurations does Mallory receive Bob's task? The configurations vary the signature algorithm, where the key is kept, and whether channel binding is used. | [`pq-identity/`](pq-identity/README.md) | 16 scenarios × 8 configurations = 128 tests |
| **Experiment 2: TPM quote comparison** | Do TPM quotes protect better than ordinary software signatures? A TPM quote is a TPM-signed report of the values in its registers. | [`identity/`](identity/README.md) | broad comparison: 231 cases, of which 201 apply (some scenarios make no sense for some configurations); focused comparison: 24 tests |
| **Experiment 3: ZK result verification** | Which approval rules accept a genuine proof that answers the wrong request or uses outdated data? | [`zk-component/`](zk-component/README.md) | 13 scenarios × 4 approval rules = 52 evaluations, from 9 A2A exchanges |
| **Separate integration test** | Do emulator-based authentication and result verification work together? It does not repeat Experiment 3's attack scenarios. | [`pq-identity/`](pq-identity/README.md) | one honest delivery and one impostor |

Each experiment folder is a self-contained Go module. It holds the source code, the scenarios and the predictions recorded before testing (`fixtures/`), and the saved records of the reported run (`results/`). `pq-identity/` also contains the code of the other two folders, because it builds on both. [docs/TOOLS.md](docs/TOOLS.md#code-origins) separates project code from upstream libraries.

## Verification scripts

A verification script checks the saved proofs and execution records of a run without running the agents again. It re-checks every signature or proof, checks who received each task, and compares each outcome with the prediction recorded before testing. The verification scripts are subcommands of the project's Go program `a2aid`; two small Python programs supply the damaged copies used to test them.

| Experiment | Command | Saved run it checks |
|---|---|---|
| Experiment 1 | `a2aid audit-pq`, plus `scripts/pq_audit_controls.py`, which feeds it 17 deliberately damaged copies | `pq-identity/results/pq/20261108-153049` |
| Experiment 2, focused | `a2aid audit-release` | `identity/results/binding/20261108-004047` |
| Experiment 2, broad | `a2aid reverify` was run when the data was collected; its report is saved (see [RESULTS.md](docs/RESULTS.md#experiment-2-tpm-quote-comparison)) | `identity/results/broad/20261107-194025` |
| Experiment 3 | `a2aid zk-oracle`, which calls the RISC Zero proof checker `zkverify`; `scripts/zk_oracle_controls.py` feeds it damaged copies | `zk-component/results/zk/20261108-111817` |

Exit codes: **0** means every outcome matches the prediction recorded before testing, including the predicted attack successes. **1** means an outcome differs from its prediction or a rule was broken. **2** means records are missing or unreadable.

A clean result does not mean every attack failed. It means each attack succeeded or failed as predicted. The scripts also cannot prove that the logged events really happened; they check that the records are complete and consistent.

## Try it

You need Go (tested with 1.27.1), Python 3.11 or newer, a C compiler (for Go's race detector) and `make`. From the repository root, run:

```sh
make check
```

This takes several minutes. It builds Experiment 1, runs its tests, re-checks the saved 128-test run, confirms that 17 damaged copies of that run are caught, and confirms that the experiment runner stops when a step fails. The saved records are not changed. Reports go to a new folder named `/tmp/a2a-proofed-check-*`.

You should see `controls: 17 cases, 0 mismatches` and `Requested checks finished`, and the command exits with 0. The re-checked run includes **25 tests in which Mallory received Bob's task**, all of them predicted before testing. [docs/REPRODUCING.md](docs/REPRODUCING.md) explains how to check the other experiments and which steps are slow.

## Documentation

- [DESIGN.md](docs/DESIGN.md): how each check works, what is trusted, what the attacker can do, and the limits.
- [RESULTS.md](docs/RESULTS.md): what each experiment found and how to read the saved records.
- [CODE_MAP.md](docs/CODE_MAP.md): what each package and script does.
- [REPRODUCING.md](docs/REPRODUCING.md): installation, checks, new runs and the paper build.
- [TOOLS.md](docs/TOOLS.md): libraries, versions, code origins and licences.

## License

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The C bridge in `pq-identity/tools/pqtpm/` links the GPLv3 wolfTPM and wolfSSL libraries and is therefore GPLv3. The Go code runs it as a separate program.
