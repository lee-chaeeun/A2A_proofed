# A2A Proofed

An A2A prototype for TPM-based agent identity and proof-carrying task results.
Built by Chae Eun Lee for the Swarm Alignment Hackathon, Track 3.

The project asks how an agent can present evidence of an enrolled identity and how a
requester can check a returned computation before acting on it. It contains two
separately evaluated components:

- **TPM identity over A2A:** fresh attestation evidence, configuration appraisal and
  a connection-bound proof before task delivery. The PTV-inspired routine response
  carries a TPM quote in a signed envelope. The weekend implementation uses swtpm;
  a physical TPM is the intended source of protected identity keys.
- **Proof-carrying A2A results:** a RISC Zero guest proves a small computation.
  The requester checks the proof, request challenge and authorized input commitment
  before recording an approval.

The final implementation is in this tree. Superseded runs, review notes and development
plans are excluded. The retained comparison and regression evidence supports the paper;
these are test inputs and observations, not multiple implementations to install.

## Why use a TPM?

An ordinary private key stored with an agent can be copied with its files. A properly
provisioned physical TPM can keep a non-migratable identity key tied to a device and
support appraisal of platform measurements. This motivates hardware-rooted agent identity.

Here, swtpm makes the integration runnable without hardware. It exercises real TPM
commands and evidence checks, but does not measure physical key-extraction or cloning
resistance. The PCR measurement is synthetic. See
[hardware benefits, threat assumptions and the PTV connection](docs/HARDWARE_AND_PTV.md)
for the distinction between implemented behavior and expected hardware protection.

## Main tools

| Component | Tool |
|---|---|
| Agent communication | [A2A](https://github.com/a2aproject/A2A) through the [Go SDK](https://github.com/a2aproject/a2a-go), v2.3.1 |
| TPM emulation | [swtpm](https://github.com/stefanberger/swtpm), 0.10.2 |
| TPM commands | [go-tpm](https://github.com/google/go-tpm), v0.9.8 |
| Computation proofs | [RISC Zero](https://github.com/risc0/risc0), v3.0.6 |
| Attestation design reference | [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01), a work-in-progress Experimental draft |

Go runs the A2A application and test harness; Rust supplies the RISC Zero guest and
prover/verifier wrappers. A2A itself is language-independent.
[All tools and code attribution](docs/TOOLS.md).

## Pipeline

```text
Identity: discover agent -> validate card, endpoint and TLS -> obtain fresh proof
          -> appraise key/configuration/connection -> deliver task on proven connection

Task result: store request and input contract -> send task over appraised A2A HTTPS
             -> receive RISC Zero receipt -> verify pinned guest
             -> check request and authorized inputs -> record approval once
```

The ZK component uses the signed-card / endpoint / TLS baseline (`C+tls`). It is a separate
experiment, not a combined TPM-plus-ZK deployment. Results and limitations are described
in [docs/RESULTS.md](docs/RESULTS.md) and the [paper](paper/a2a-identity-paper.pdf).

## Layout

| Path | Contents |
|---|---|
| `identity/` | Final identity implementation, tests, fixture definitions and selected evidence |
| `zk-component/` | Identity-derived application with the separate ZK component, Rust guest and proof tools |
| `paper/` | Markdown source, TeX, PDF and source ZIP |
| `docs/` | Hardware/PTV rationale, tools, threat model, results, provenance and artifact inventory |

Start with [docs/README.md](docs/README.md). Runtime keys and emulator state are generated
under ignored `run/` directories and are not distributed.

## Check the identity component

Requires Go (recorded compiler 1.27.1). First build downloads pinned Go modules; HTTPS
tests need permission to bind localhost ports. From the repository root:

```sh
cd identity
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
cp -R results/v3-final/20261108-004047 /tmp/a2a-proofed-identity-run
bin/a2aid audit-release --results /tmp/a2a-proofed-identity-run
```

Use a new destination for each copied audit run. The checker writes reports into its
input directory. Exit 0 means complete evidence with no unexpected violation; expected
weak-policy attack outcomes remain listed.

## Check the ZK component

```sh
cd zk-component
go build -o bin/a2aid ./cmd/a2aid
go test -race -count=1 ./...
```

Proof-dependent tests skip if the verifier or required retained data is unavailable;
inspect skips. To verify retained genuine receipts, install the pinned Rust/RISC Zero
toolchain described in [zk-component/README.md](zk-component/README.md), then:

```sh
# From the repository root:
cd zk-component/zk
cargo build --release --bin zkverify
cd ..
bin/a2aid zk-oracle --results results/zk/20261108-111817 \
  --verify-bin zk/target/release/zkverify --out /tmp/a2a-proofed-zk-oracle
```

Start this block from the repository root. Verification does not generate new proofs;
building the guest/verifier does require the toolchain. New CPU proving took about
23 seconds per proof on the recorded machine. See each component README for fresh lab runs.

## Provenance and license

From the repository root:

```sh
python3 docs/packaging/verify_manifest.py
```

[PROVENANCE.md](docs/PROVENANCE.md) distinguishes unchanged experimental evidence from
publication-only documentation. Retained rows are scenario coverage, not real-world
attack rates. The current implementation uses classical P-256 signatures and does not
implement post-quantum cryptography.

Apache-2.0: [LICENSE](LICENSE), [NOTICE](NOTICE). Agent Card signing adapts the official
preexisting [A2A Go sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card).
Third-party and sprint-work attribution: [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).
