# A2A Proofed

A local research prototype for authenticating A2A agents and checking their returned results.
Built by Chae Eun Lee for the Swarm Alignment Hackathon, Track 3.

The main experiment uses **ML-DSA-65 keys created and used through a TPM emulator's command interface**. The requester verifies signatures with a separate library, checks the enrolled identity and request context, and sends the task on the connection that carried the proof. A RISC Zero component then checks a returned computation against the request and authorized input.

This is a runnable simulation. The emulator's state is a host file; the tests do not establish physical key protection or end-to-end post-quantum security. Agent Cards, TLS and the lab CA remain classical.

## Start here

With Python 3.11+, Go (recorded: 1.27.1), a C compiler for Go's race detector, and `make`:

```sh
make package-check
make check
```

`make check` builds the PQ application, runs its Go race tests, rechecks both retained 128-cell matrices, runs all 17 evidence-mutation controls, and checks runner failure propagation. It **does not generate proofs or start a persistent lab**. First builds need network access for pinned Go modules; HTTPS tests bind local ports. Temporary binaries and reports are written outside the repository.

A successful audit means agreement with the declared experiment, including **25 expected attacker deliveries**. It is not a claim that every configuration is secure. Device and genuine-proof integrations are opt-in; ordinary Go tests do not replace them.

For installation, fresh experiments and expected outputs, follow [Reproducing the experiments](docs/REPRODUCING.md).

## What is included?

```text
A2A_proofed/
├── pq-identity/       Main PQ experiment and PQ-to-ZK integration
├── identity/          Final classical identity comparison used in the paper
├── zk-component/      Final standalone ZK result-authorization experiment
├── paper/             Editable Markdown and LaTeX, PDF, fonts and source ZIP
├── docs/              Code map, pipeline, reproduction guide and evidence index
├── scripts/check.py   Test and audit entry point; leaves retained evidence untouched
└── Makefile           Short commands for the common checks
```

The three Go modules are the final implementations of **three separately measured studies**, not a sequence of releases to install. Start with `pq-identity/`. The other two retain the exact experimental paths used for the classical and standalone ZK comparisons; merging their source would obscure which code produced those measurements. There are no archived implementations or source tarballs in this publication tree.

- [Code map](docs/CODE_MAP.md): annotated source tree, every source file, and where to start reading.
- [Pipeline](docs/PIPELINE.md): what crosses each boundary and what each proof means.
- [Results](docs/RESULTS.md): observations, expected failures and limits.
- [Evidence guide](docs/EVIDENCE.md): how to read decisions, receipts and audit reports.
- [Paper source](paper/paper-draft.md), [editable LaTeX](paper/main.tex), [PDF](paper/a2a-identity-paper.pdf), [LaTeX ZIP](paper/a2a-identity-latex.zip).

## Main tools

| Tool | Role |
|---|---|
| [A2A Go SDK](https://github.com/a2aproject/a2a-go), v2.3.1 | Agent discovery, JSON-RPC messages and task artifacts |
| [wolfTPM](https://github.com/wolfSSL/wolfTPM), `1362e1e5`, on [wolfSSL](https://github.com/wolfSSL/wolfssl), `0ac786e0` | Firmware-TPM emulator and native ML-DSA command implementation |
| [CIRCL](https://github.com/cloudflare/circl), v1.6.5 | ML-DSA verification, software-signature controls and vector tests |
| [swtpm](https://github.com/stefanberger/swtpm), 0.10.2, and [go-tpm](https://github.com/google/go-tpm), v0.9.8 | Classical TPM quote comparison |
| [RISC Zero](https://github.com/risc0/risc0), 3.0.6 | Prove and verify the bounded-sum guest computation |
| [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) | Bind an identity proof to its TLS connection |

Go implements the application and harness, Rust the ZK guest and host wrappers, and a C subprocess drives the PQ emulator. A2A is language-independent. See [tools and versions](docs/TOOLS.md) and [code origins](docs/ATTRIBUTION.md).

## More commands

```sh
make check-all           # Go tests in all three modules; PQ and classical audits
make pq-toolchain        # Download/build the pinned C dependencies; CMake and Ninja needed
make pq-device           # Actual emulator create/sign/restart test after that build
make verify              # Check hashes against the publication inventory
```

ZK verification and proving require the additional Rust/RISC Zero toolchain. See [the reproduction guide](docs/REPRODUCING.md); no model account, API key, Adaption credits or external agent dataset is needed.

Runtime state and lab credentials are generated under ignored `run/` directories. Retained `results/` files are published observations; do not overwrite them. Selected earlier observations remain only where the paper or a regression test needs them. Superseded working notes, alternate code releases, generated toolchains and compiled binaries are excluded. One frozen correction plan remains so its recorded pre-run hash can be checked.

## License

The Go application is [Apache-2.0](LICENSE). The C bridge in `pq-identity/tools/pqtpm/` is GPLv3 and links wolfTPM/wolfSSL; it runs as a separate process. Agent Card signing adapts the official [A2A sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card). See [NOTICE](NOTICE), [attribution](docs/ATTRIBUTION.md) and the component license files.
