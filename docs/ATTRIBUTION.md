# Attribution, pre-existing work and licence status

## Work done during the sprint (6–8 November 2026)
The testbed (`cmd/a2aid`, `internal/*` except as noted), fixtures, matrices, checkers,
scripts, the ZK component (`internal/zk`, `internal/agent/zk.go`, the Rust guest and host
programs under `zk/`), the PQ component (`internal/pqsig`, `internal/pqdev`,
`internal/pqaudit`, the `EC-env`/`PQ-*` signers and fixtures, the C bridge
`pq-identity/tools/pqtpm/pqtpm.c`), all retained evidence, reports and the paper were written during the
sprint with AI coding assistants; the author selected the design, reviewed the evidence and
is responsible for the content.

## Pre-sprint code (marked as required by the sprint rules)
- `identity/internal/cardsig/cardsig.go` and the same file in `zk-component/` and `pq-identity/`: adapted from
  the official a2a-samples Go "sign and verify agent card" sample (canonicalization and JWS
  layout). Modification: the key provider resolves `kid` through the operator registry and
  ignores `jku`. The file header states this.

## Third-party dependencies (unmodified, fetched by the build tools; licences unchanged)
Go (`go.mod`): `github.com/a2aproject/a2a-go/v2 v2.3.1` (Apache-2.0), `github.com/google/go-tpm v0.9.8`
(Apache-2.0), `github.com/veraison/go-cose v1.3.0` (MPL-2.0), `github.com/fxamacker/cbor/v2 v2.10.0`
(MIT), `github.com/golang-jwt/jwt/v5 v5.3.1` (MIT), `golang.org/x/sys v0.40.0` (BSD-3-Clause);
`pq-identity/` additionally `github.com/cloudflare/circl v1.6.5` (BSD-3-Clause) and `golang.org/x/sys v0.47.0`.
Rust (`zk-component/zk/Cargo.lock`): `risc0-zkvm`, `risc0-build` and related crates 3.0.6
(Apache-2.0), `serde`, `serde_json`, `sha2`, `hex`, `base64`, `bincode` (MIT/Apache-2.0).
Tools: swtpm 0.10.2 (BSD-3-Clause), the RISC Zero toolchain via `rzup` (Apache-2.0), pandoc,
LuaLaTeX. PQ device emulation: wolfTPM commit `1362e1e5` and wolfSSL commit `0ac786e0`
(GPLv3; built task-locally by `pq-identity/scripts/build_pq_toolchain.sh`, never
distributed here). `pq-identity/tools/pqtpm` links those libraries and is therefore
licensed under GPLv3 (`pq-identity/tools/pqtpm/LICENSE`); the Apache-2.0 Go code only
executes it as a separate process and never links it. Licence names above are the projects' published licences at the pinned versions;
consult each dependency for the authoritative text.

## Paper template and fonts
The paper uses the Apart Research sprint template (LaTeX port of the provided docx) and the
Old Standard TT fonts (SIL Open Font License 1.1), shipped in `paper/fonts/`.

## Licence of this repository: Apache License 2.0
Chosen by the author on 8 Nov 2026: `LICENSE` (Apache-2.0) and `NOTICE` (copyright line and
the a2a-samples attribution for `internal/cardsig`) are at the repository root. Apache-2.0 is
compatible with the adapted a2a-samples code (Apache-2.0) and with every dependency above.
The retained evidence files and the paper are distributed under the same licence; the fonts
keep the SIL OFL and the `pq-identity/tools/pqtpm` bridge is GPLv3 as stated above.

Publication helpers `scripts/check.py`, `docs/packaging/check_package.py` and its tests, and the source/reproduction guides are project packaging work. They do not implement cryptographic algorithms. The bundled Old Standard TT fonts retain their upstream SIL Open Font License in `paper/fonts/OFL.txt`.
