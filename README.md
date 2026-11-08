# A2A Proofed

A local research prototype for two decisions an A2A requester makes when it delegates work: **whom to send a task to**, and **whether to act on the result**. Built by Chae Eun Lee for the Swarm Alignment Hackathon, Track 3. The accompanying paper is in [`paper/`](paper/a2a-identity-paper.pdf).

- **Who receives the task.** An agent proves its identity with an ML-DSA-65 (post-quantum) key that a TPM 2.0 emulator creates and uses through its command interface. The requester verifies the proof under an enrolled key, checks that it was made for this request and this TLS connection, and delivers the task only on that connection.
- **Whether to act on the result.** The agent returns a RISC Zero proof of a small computation. The requester verifies it and approves only if it answers the stored request over the input that request authorizes.

This is a runnable simulation, not a hardware or end-to-end post-quantum security result: the emulator's state is a host file, and Agent Cards, TLS and the lab certificate authority remain classical. [docs/DESIGN.md](docs/DESIGN.md) states the trust model and limits.

## Repository layout

| Path | Contents |
|---|---|
| [`pq-identity/`](pq-identity/README.md) | Main experiment: ML-DSA identity proofs from an emulated TPM, eight configurations × 16 scenarios, and the identity-to-result delivery guard |
| [`identity/`](identity/README.md) | Classical comparison: software signatures and TPM quotes, with and without connection binding |
| [`zk-component/`](zk-component/README.md) | Task-binding experiment: RISC Zero receipts checked against the request and the authorized input |
| `paper/` | Manuscript source (`main.tex`, `appendix.tex`, `references.bib`), PDF and self-contained LaTeX archive |
| `docs/` | Design, results, code map, reproduction guide, tools and licences |

Each experiment directory is a self-contained Go module (all three share the module name `a2aid`) with its source code, declared scenarios and predictions (`fixtures/`), and the published records of its experiment (`results/`). `pq-identity/` contains the code of the other two plus the PQ additions; the other two are kept because they produced the classical and task-binding results.

## First check

Requires Go (recorded: 1.27.1), Python 3.11+, a C compiler for Go's race detector, and `make`:

```sh
make check
```

This builds the PQ experiment, runs its tests, re-audits the published 128-cell run, checks that 17 deliberately corrupted copies of that run are rejected as declared, and checks that the experiment runner stops when any stage fails. Published records are not modified; reports go to a new temporary directory. A clean audit means agreement with the declared experiment, including **25 deliberate deliveries to the attacker**, not that every configuration is secure.

## Documentation

- [DESIGN.md](docs/DESIGN.md): the two decisions, trust model, attacker capabilities and limits.
- [RESULTS.md](docs/RESULTS.md): findings of the three experiments and how to read the published records.
- [CODE_MAP.md](docs/CODE_MAP.md): what each package and script does.
- [REPRODUCING.md](docs/REPRODUCING.md): the shortest reproduction of the paper's findings, the emulator build, fresh runs, receipt verification and the paper build.
- [TOOLS.md](docs/TOOLS.md): dependencies, versions, code origins and licences.

## License

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The C bridge in `pq-identity/tools/pqtpm/` links the GPLv3 wolfTPM and wolfSSL libraries and is GPLv3; the Go code runs it as a separate process.
