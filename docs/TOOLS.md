# Tools, libraries and attribution

This is an application built with existing protocols and libraries. It is not a fork of the A2A protocol or of RISC Zero. The three local components share code: `zk-component/` was copied from the identity testbed and extended, and `pq-identity/` was copied from `zk-component/` and extended with the ML-DSA proof format, the emulated device signer and the PQ audit.

| Tool or project | Role here | Version recorded by the experiment | Upstream |
|---|---|---|---|
| A2A | Agent discovery, messages and task artifacts | SDK pinned below; protocol is language-independent | [Specification](https://a2a-protocol.org/latest/specification/), [protocol repository](https://github.com/a2aproject/A2A) |
| A2A Go SDK | A2A server, client, data types and JSON-RPC plumbing | `a2a-go/v2 v2.3.1` | [a2a-go](https://github.com/a2aproject/a2a-go) |
| A2A samples | Foundation adapted for signed Agent Cards | Exact upstream sample commit not recovered | [Go signed-card sample](https://github.com/a2aproject/a2a-samples/tree/main/samples/go/agents/sign-and-verify-agent-card) |
| wolfTPM | Firmware TPM emulator (`fwtpm_server`) with the TPM 2.0 v1.85 ML-DSA key type and sign/verify sequence commands; client library linked by `pq-identity/tools/pqtpm` | commit `1362e1e53ad3282973eefd6234be34fb774d06d3` (2026-11-07), GPLv3 | [wolfTPM](https://github.com/wolfSSL/wolfTPM), `docs/FWTPM.md`, `docs/fwtpm/post-quantum.md` |
| wolfSSL / wolfCrypt | ML-DSA implementation inside the firmware TPM | commit `0ac786e0405978697f2ebfb079a47b27bca7fce9` (2026-11-06), GPLv3 | [wolfssl](https://github.com/wolfSSL/wolfssl) |
| CIRCL | ML-DSA-65 verification in the requester, software control signers, NIST ACVP vectors | 1.6.5 | [circl](https://github.com/cloudflare/circl) |
| swtpm | Software TPM 2.0 emulator for the classical quote; no physical TPM is required. libtpms had no ML-DSA code at the time (master `165c303c`), so the PQ component uses wolfTPM | 0.10.2 | [swtpm](https://github.com/stefanberger/swtpm) |
| go-tpm | TPM command API used to provision keys and obtain quotes | 0.9.8 | [go-tpm](https://github.com/google/go-tpm) |
| RISC Zero | zkVM proving and receipt verification | 3.0.6 | [risc0](https://github.com/risc0/risc0), [documentation](https://dev.risczero.com/api/zkvm/) |
| rzup | RISC Zero toolchain installation | 0.6.0 | [rzup](https://github.com/risc0/risc0/tree/release-3.0/rzup) |
| Go | Application, TLS, orchestration and evidence checks | Recorded compiler 1.27.1; module minimum 1.25.0 | [Go](https://go.dev/) |
| Rust | Proved guest and prover/verifier wrappers | Recorded host toolchain 1.93; guest toolchain supplied by RISC Zero | [Rust](https://www.rust-lang.org/) |
| go-cose | Signed CBOR envelopes | 1.3.0 | [go-cose](https://github.com/veraison/go-cose) |
| fxamacker/cbor | CBOR encoding/decoding | 2.10.0 | [cbor](https://github.com/fxamacker/cbor) |
| golang-jwt/jwt | Agent Card JWS signatures | 5.3.1 | [jwt](https://github.com/golang-jwt/jwt) |
| CMake and Ninja | Task-local build of wolfSSL and wolfTPM (`pq-identity/scripts/build_pq_toolchain.sh`; options recorded in the gate evidence) | See local installation | [CMake](https://cmake.org/), [Ninja](https://ninja-build.org/) |
| Python | Evidence-mutation and publication-manifest scripts | See local interpreter; not part of proof validity | [CPython](https://github.com/python/cpython) |
| Pandoc and LuaLaTeX | Paper conversion and typesetting | See paper build instructions | [Pandoc](https://github.com/jgm/pandoc), [LuaTeX](https://www.luatex.org/) |

The application-specific parts are the enrollment and policy logic, requester/agent integration, signer gate, proof-context and dispatch rules, synthetic fixtures, result ledgers and evaluation tools. The Rust bounded-sum guest and CLI wrappers use RISC Zero's proof system; they do not implement a new proof system.

`pq-identity/tools/pqtpm/pqtpm.c` is a bounded C bridge (create, read-public, sign-sequence, verify, evict) written during the sprint on the wolfTPM client API; it links the GPLv3 libraries and is GPLv3 itself. `identity/internal/cardsig/cardsig.go` and its copies in `zk-component/` and `pq-identity/` explicitly adapt the official preexisting signing sample. The local verifier resolves key IDs through the operator registry instead of accepting response-directed key discovery. Preserve the sample attribution. `go.mod`, `go.sum` and `zk-component/zk/Cargo.lock` are the authoritative dependency records. Licenses and pre-sprint attribution are in [ATTRIBUTION.md](ATTRIBUTION.md).

Related specifications: [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final), [TCG TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) (v1.85 adds ML-DSA), [RFC 9266 TLS channel bindings](https://www.rfc-editor.org/rfc/rfc9266.html), [RFC 9334 RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html), [RFC 9052 COSE](https://www.rfc-editor.org/rfc/rfc9052.html), [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01). These are design references, not claims that every feature or interoperability requirement was implemented.
