# Tools, code origins and licences

The project builds on existing protocols and libraries. It does not fork A2A, the emulators or RISC Zero, and it implements no cryptography of its own.

| Tool | Used for | Version, licence |
|---|---|---|
| [A2A](https://a2a-protocol.org/latest/specification/), [a2a-go](https://github.com/a2aproject/a2a-go) | Discovery, messages, tasks | 2.3.1 |
| [wolfTPM](https://github.com/wolfSSL/wolfTPM) | Firmware TPM emulator with ML-DSA commands (TPM 2.0 v1.85) | commit `1362e1e5`, GPLv3 |
| [wolfSSL / wolfCrypt](https://github.com/wolfSSL/wolfssl) | ML-DSA inside the emulator | commit `0ac786e0`, GPLv3 |
| [CIRCL](https://github.com/cloudflare/circl) | ML-DSA-65 verification and software keys | 1.6.5, BSD-3-Clause |
| [swtpm](https://github.com/stefanberger/swtpm), [go-tpm](https://github.com/google/go-tpm) | TPM emulator and API for quotes | 0.10.2 (BSD-3-Clause), 0.9.8 (Apache-2.0) |
| [RISC Zero](https://github.com/risc0/risc0) | Proving and verifying computations | 3.0.6, Apache-2.0 |
| [go-cose](https://github.com/veraison/go-cose), [fxamacker/cbor](https://github.com/fxamacker/cbor), [golang-jwt](https://github.com/golang-jwt/jwt) | COSE responses, deterministic CBOR, Agent Card signatures | 1.3.0 (MPL-2.0), 2.10.0 (MIT), 5.3.1 (MIT) |
| Go, Rust | Application; proved program and prover | Go 1.27.1 (minimum 1.25), Rust 1.93 |
| CMake, Ninja, Python | Emulator build, check scripts | system packages |

`go.mod`, `go.sum` and `zk/Cargo.lock` are the exact dependency records.

Specifications: [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA), [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) (ECDSA), [TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) (TLS 1.3), [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) (channel binding), [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) (CBOR), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) (COSE), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) (JWS), [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) (remote attestation architecture, Informational). The [PTV draft](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01) is a work-in-progress individual Internet-Draft, used only as a design reference.

## Code origins

`internal/cardsig/cardsig.go` adapts the [A2A Go signed-card sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card); its key lookup was changed to use the enrollment registry. Everything else (testbed, scenarios, proof format, delivery guard, verification scripts, C bridge, Rust programs) was written for this project with AI coding assistance. The author chose the design, reviewed the evidence and is responsible for the content.

## Licences

Apache-2.0 ([LICENSE](../LICENSE), [NOTICE](../NOTICE)), including the saved records. `pq-identity/tools/pqtpm` links wolfTPM and wolfSSL and is GPLv3 ([licence](../pq-identity/tools/pqtpm/LICENSE)); the Go code runs it as a separate program. wolfSSL and wolfTPM are downloaded and built locally, not distributed here.
