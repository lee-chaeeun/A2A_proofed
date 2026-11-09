# A2A Proofed

Code and evidence for the paper *TPM-Emulated Post-Quantum Authentication and ZK Verification for A2A*.

When an Agent2Agent (A2A) client hands a task to another agent, it has to decide two things: whether the agent answering is really the one it meant, and whether the result that comes back can be approved. This prototype checks both.

- **Identity.** The receiving agent signs a fresh challenge with an ML-DSA-65 key (a post-quantum signature, FIPS 204). The key can live in a TPM emulator, which signs without handing the private key to the application. With TLS channel binding, the signature also covers the TLS connection, so a relay cannot reuse it.
- **Results.** The agent returns a RISC Zero zero-knowledge (ZK) proof of its computation. The client approves the result only if the proof is valid, answers the original request and used the input that request allowed.

The paper names three parties, and so do these docs: **Alice** is the client, **Bob** the agent she wants to reach, and **Mallory** an attacker. The saved records are older and call Bob *deployment A (Atlas)* and Mallory *deployment B (Boreas)*.

The TPM is software, so physical key protection is not tested. Agent Cards, TLS and the certificate authority are still classical.

## Experiments

| | Question | Folder | Size |
|---|---|---|---|
| Experiment 1: Identity authentication | Which of eight configurations let Mallory receive Bob's task? | [`pq-identity/`](pq-identity/README.md) | 128 tests |
| Experiment 2: TPM quote comparison | Do TPM quotes protect better than software signatures? | [`identity/`](identity/README.md) | 201 + 24 tests |
| Experiment 3: ZK result verification | Which approval rules accept a valid proof for the wrong request or old data? | [`zk-component/`](zk-component/README.md) | 52 evaluations |
| Integration test | Do emulator-based identity and result checks work together? | [`pq-identity/`](pq-identity/README.md) | 1 run |

Each folder is a Go module with its code, its scenarios and predictions (`fixtures/`) and the saved records of the reported run (`results/`). `pq-identity/` includes the code of the other two.

## Quick check

With Go 1.25+ (tested with 1.27.1), Python 3.11+, a C compiler and `make`:

```sh
make check
```

This runs the Experiment 1 tests and re-checks the saved 128-test run without starting any agents. It should end with `controls: 17 cases, 0 mismatches` and exit 0. The run includes 25 tests in which Mallory received Bob's task; those were predicted before testing.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): how the checks work, trust assumptions, limits
- [docs/RESULTS.md](docs/RESULTS.md): findings and how to read the saved records
- [docs/REPRODUCING.md](docs/REPRODUCING.md): all checks and how to rerun the experiments
- [docs/CODE_MAP.md](docs/CODE_MAP.md): packages and scripts
- [docs/TOOLS.md](docs/TOOLS.md): dependencies, code origins, licences

## License

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)), except `pq-identity/tools/pqtpm/`, which links wolfTPM and wolfSSL and is GPLv3.
