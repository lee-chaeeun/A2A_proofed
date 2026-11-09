# Tools, code origins and licences

This project is an application built on existing protocols and libraries; it does not fork A2A, the emulators or RISC Zero, and it implements no cryptographic algorithm of its own.

| Tool | Role | Version |
|---|---|---|
| [A2A](https://a2a-protocol.org/latest/specification/) and its [Go SDK](https://github.com/a2aproject/a2a-go) | Discovery, JSON-RPC messages, task artifacts | a2a-go 2.3.1 |
| [wolfTPM](https://github.com/wolfSSL/wolfTPM) | Firmware TPM emulator with the TPM 2.0 v1.85 ML-DSA commands; client library for the C bridge | commit `1362e1e5`, GPLv3 |
| [wolfSSL / wolfCrypt](https://github.com/wolfSSL/wolfssl) | ML-DSA implementation inside the firmware TPM | commit `0ac786e0`, GPLv3 |
| [CIRCL](https://github.com/cloudflare/circl) | ML-DSA-65 verification, software ML-DSA keys, NIST vector tests | 1.6.5, BSD-3-Clause |
| [swtpm](https://github.com/stefanberger/swtpm) and [go-tpm](https://github.com/google/go-tpm) | Classical TPM emulator and command API for quotes | 0.10.2 (BSD-3-Clause), 0.9.8 (Apache-2.0) |
| [RISC Zero](https://github.com/risc0/risc0) | zkVM proving and receipt verification | 3.0.6, Apache-2.0 |
| [go-cose](https://github.com/veraison/go-cose), [fxamacker/cbor](https://github.com/fxamacker/cbor), [golang-jwt](https://github.com/golang-jwt/jwt) | COSE_Sign1 responses in Experiment 2, deterministic CBOR, Agent Card JWS | 1.3.0 (MPL-2.0), 2.10.0 (MIT), 5.3.1 (MIT) |
| Go, Rust | Application and harness; guest and prover wrappers | Go 1.27.1 (module minimum 1.25), Rust 1.93 |
| CMake, Ninja, Python, LuaLaTeX with BibTeX | Emulator build, check scripts and damaged-copy tests, paper | local installation |

`go.mod`, `go.sum` and `zk/Cargo.lock` are the authoritative dependency records.

References, by kind (the paper's bibliography has the full list):

- **Standards:** [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 186-5 (ECDSA)](https://csrc.nist.gov/pubs/fips/186-5/final), [TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) (v1.85 adds ML-DSA), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) (TLS 1.3), [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) (TLS channel binding), [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) (CBOR, Section 4.2 deterministic encoding), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) (COSE), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) (JWS). [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) (RATS architecture) is Informational with IETF consensus.
- **Work-in-progress Internet-Draft:** [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01), an individual submission; used as a design reference only, with no conformance claim.
- **Peer-reviewed papers:** VRASED (USENIX Security 2019); Shor (SIAM J. Computing 1997); Nissenbaum (Washington Law Review 2004).
- **Implementation documentation:** the A2A specification and a2a-go SDK, RISC Zero proof-system paper and `risc0-zkvm` 3.0.6 API documentation, swtpm, wolfTPM, wolfSSL and CIRCL repositories.

## Code origins

`internal/cardsig/cardsig.go` adapts the official [A2A Go signed-card sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card) (canonicalization and JWS layout); its key lookup uses the enrollment registry instead of a key URL from the response. Everything else in the experiment directories — the testbed, scenarios, proof format, delivery guard, verification scripts, C bridge and Rust guest and host programs — was written for this project with AI coding assistance; the author selected the design, reviewed the evidence and is responsible for the content.

## Licences

The repository is Apache-2.0 ([LICENSE](../LICENSE), [NOTICE](../NOTICE)), including the published records and the paper. The C bridge `pq-identity/tools/pqtpm` links wolfTPM and wolfSSL and is therefore GPLv3 ([its licence](../pq-identity/tools/pqtpm/LICENSE)); the Go code only runs it as a separate process. The wolfSSL and wolfTPM sources are fetched and built locally and are not distributed. The paper's Old Standard TT fonts are under the SIL Open Font License (`paper/fonts/OFL.txt`).
