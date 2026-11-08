# Tools, libraries and attribution

This is an application built with existing protocols and libraries. It is not a fork of the A2A protocol or of RISC Zero. The two local components share code: `zk-component/` was copied from the identity testbed and extended.

| Tool or project | Role here | Version recorded by the experiment | Upstream |
|---|---|---|---|
| A2A | Agent discovery, messages and task artifacts | SDK pinned below; protocol is language-independent | [Specification](https://a2a-protocol.org/latest/specification/), [protocol repository](https://github.com/a2aproject/A2A) |
| A2A Go SDK | A2A server, client, data types and JSON-RPC plumbing | `a2a-go/v2 v2.3.1` | [a2a-go](https://github.com/a2aproject/a2a-go) |
| A2A samples | Foundation adapted for signed Agent Cards | Exact upstream sample commit not recovered | [Go signed-card sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card) |
| swtpm | Software TPM 2.0 emulator; no physical TPM is required | 0.10.2 | [swtpm](https://github.com/stefanberger/swtpm) |
| go-tpm | TPM command API used to provision keys and obtain quotes | 0.9.8 | [go-tpm](https://github.com/google/go-tpm) |
| RISC Zero | zkVM proving and receipt verification | 3.0.6 | [risc0](https://github.com/risc0/risc0), [documentation](https://dev.risczero.com/api/zkvm/) |
| rzup | RISC Zero toolchain installation | 0.6.0 | [rzup](https://github.com/risc0/risc0/tree/release-3.0/rzup) |
| Go | Application, TLS, orchestration and evidence checks | Recorded compiler 1.27.1; module minimum 1.25.0 | [Go](https://go.dev/) |
| Rust | Proved guest and prover/verifier wrappers | Recorded host toolchain 1.93; guest toolchain supplied by RISC Zero | [Rust](https://www.rust-lang.org/) |
| go-cose | Signed CBOR envelopes | 1.3.0 | [go-cose](https://github.com/veraison/go-cose) |
| fxamacker/cbor | CBOR encoding/decoding | 2.10.0 | [cbor](https://github.com/fxamacker/cbor) |
| golang-jwt/jwt | Agent Card JWS signatures | 5.3.1 | [jwt](https://github.com/golang-jwt/jwt) |
| Python | Evidence-mutation and publication-manifest scripts | See local interpreter; not part of proof validity | [CPython](https://github.com/python/cpython) |
| Pandoc and LuaLaTeX | Paper conversion and typesetting | See paper build instructions | [Pandoc](https://github.com/jgm/pandoc), [LuaTeX](https://www.luatex.org/) |

The application-specific parts are the enrollment and policy logic, requester/agent integration, signer gate, proof-context and dispatch rules, synthetic fixtures, result ledgers and evaluation tools. The Rust bounded-sum guest and CLI wrappers use RISC Zero's proof system; they do not implement a new proof system.

`identity/internal/cardsig/cardsig.go` and its copy in `zk-component/` explicitly adapt the official preexisting signing sample. The local verifier resolves key IDs through the operator registry instead of accepting response-directed key discovery. Preserve the sample attribution. `go.mod`, `go.sum` and `zk-component/zk/Cargo.lock` are the authoritative dependency records. Licenses and pre-sprint attribution are in [ATTRIBUTION.md](ATTRIBUTION.md).

Related specifications: [RFC 9266 TLS channel bindings](https://www.rfc-editor.org/rfc/rfc9266.html), [RFC 9334 RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html), [RFC 9052 COSE](https://www.rfc-editor.org/rfc/rfc9052.html), [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01). These are design references, not claims that every feature or interoperability requirement was implemented.
