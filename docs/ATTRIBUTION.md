# Attribution, pre-existing work and licence status

## Work done during the sprint (6–8 November 2026)
The testbed (`cmd/a2aid`, `internal/*` except as noted), fixtures, matrices, checkers,
scripts, the ZK component (`internal/zk`, `internal/agent/zk.go`, the Rust guest and host
programs under `zk/`), all retained evidence, reports and the paper were written during the
sprint with AI coding assistants; the author selected the design, reviewed the evidence and
is responsible for the content.

## Pre-sprint code (marked as required by the sprint rules)
- `identity/internal/cardsig/cardsig.go` and the same file in `zk-component/`: adapted from
  the official a2a-samples Go "sign and verify agent card" sample (canonicalization and JWS
  layout). Modification: the key provider resolves `kid` through the operator registry and
  ignores `jku`. The file header states this.

## Third-party dependencies (unmodified, fetched by the build tools; licences unchanged)
Go (`go.mod`): `github.com/a2aproject/a2a-go/v2 v2.3.1` (Apache-2.0), `github.com/google/go-tpm v0.9.8`
(Apache-2.0), `github.com/veraison/go-cose v1.3.0` (MPL-2.0), `github.com/fxamacker/cbor/v2 v2.10.0`
(MIT), `github.com/golang-jwt/jwt/v5 v5.3.1` (MIT), `golang.org/x/sys v0.40.0` (BSD-3-Clause).
Rust (`zk-component/zk/Cargo.lock`): `risc0-zkvm`, `risc0-build` and related crates 3.0.6
(Apache-2.0), `serde`, `serde_json`, `sha2`, `hex`, `base64`, `bincode` (MIT/Apache-2.0).
Tools: swtpm 0.10.2 (BSD-3-Clause), the RISC Zero toolchain via `rzup` (Apache-2.0), pandoc,
LuaLaTeX. Licence names above are the projects' published licences at the pinned versions;
consult each dependency for the authoritative text.

## Paper template and fonts
The paper uses the Apart Research sprint template (LaTeX port of the provided docx) and the
Old Standard TT fonts (SIL Open Font License 1.1), shipped in `paper/fonts/`.

## Licence of this repository: Apache License 2.0
Chosen by the author on 8 Nov 2026: `LICENSE` (Apache-2.0) and `NOTICE` (copyright line and
the a2a-samples attribution for `internal/cardsig`) are at the repository root. Apache-2.0 is
compatible with the adapted a2a-samples code (Apache-2.0) and with every dependency above.
The retained evidence files and the paper are distributed under the same licence; the fonts
keep the SIL OFL.
