# Code map

The three experiment directories are Go modules with the same package layout. `identity/` (Experiment 2: TPM quote comparison) has the classical packages; `zk-component/` (Experiment 3: ZK result verification) adds the result-verification code and the Rust programs; `pq-identity/` (Experiment 1: identity authentication, and the integration test) adds the post-quantum proof format, the emulated device and its verification script on top of both. Every package below is described once, with the modules that contain it. Run Go commands inside one module.

**Original code versus upstream.** Everything listed in this map is project code, except that `internal/cardsig` adapts the official A2A Go signed-card sample. The A2A SDK, the TPM emulators, CIRCL, go-tpm, go-cose, RISC Zero, wolfTPM and wolfSSL are upstream dependencies pinned in `go.mod`, `go.sum`, `zk/Cargo.lock` and `scripts/build_pq_toolchain.sh`; see [TOOLS.md](TOOLS.md).

**Participants in code.** Deployment A (Atlas) is Bob, the intended recipient; deployment B (Boreas) is Mallory, the attacker; the requester (`internal/verifier`) is Alice.

Suggested reading order for Experiment 1: `cmd/a2aid` → `internal/wire` and `internal/registry` → `internal/agent`, `internal/gate`, `internal/pqdev` and `tools/pqtpm` → `internal/pqsig` → `internal/verifier` → `internal/zk` → `internal/pqaudit` and `internal/audit`.

## Go packages

| Path | Modules | Responsibility |
|---|---|---|
| `cmd/a2aid` | all | The single Go program. Subcommands provision the lab (CA, keys, emulators, enrollment), run the agent, controller and signing-service processes, run experiments and benchmarks, and run the verification scripts (`audit-pq`, `audit-release`, `reverify`, `zk-oracle`). `a2aid` without arguments lists the subcommands of that module |
| `internal/wire` | all | A2A payload types, the closed set of policy (configuration) identifiers, binding context and URL normalization |
| `internal/registry` | all | Enrollment registry: per deployment, the publisher key, endpoint, TLS name and the pinned proof keys |
| `internal/cardsig` | all | Agent Card canonicalization, JWS signing and verification, adapted from the official A2A Go sample; key lookup through the registry |
| `internal/agent` | all | One scripted A2A deployment (Bob or Mallory): answers challenges in honest or attack modes, logs task receipts; in `zk-component/` and `pq-identity/` also runs the proving worker |
| `internal/gate` | all | Signing service: serves listed processes only and routes requests to software keys, swtpm or, in `pq-identity/`, the emulated ML-DSA device |
| `internal/tpmsig` | all | swtpm lifecycle and provisioning; TPM quote encoding, signing and appraisal |
| `internal/senv` | all | Software-signed COSE_Sign1 response, the software counterpart of the TPM quote in Experiment 2 |
| `internal/ptv` | all | Project-defined signed COSE response carrying a TPM quote; selected fields, error codes and checks are drawn from the PTV draft's routine response, without implementing PTV |
| `internal/verifier` | all | The requester (Alice): discovery, challenge, appraisal of every proof type, connection recording, TLS exporters and the delivery guard (`GuardedSend`, `transport.go`), issued-session store |
| `internal/controller`, `internal/ctl` | all | Independent controller that records which process received what, and its client |
| `internal/matrix` | all | Runs every scenario against every configuration, sets up each attack, runs concurrent-delivery trials, re-checks saved proofs offline (`a2aid reverify`), and writes summaries and traces |
| `internal/audit` | all | Verification script for Experiment 2 (`a2aid audit-release`), also used inside the Experiment 1 script. It checks the order of events, that the signed record matches the issued challenge, that the task stayed on the proof connection, and that each task was received exactly once and by whom |
| `internal/zk` | zk-component, pq-identity | Alice's result checks and the four approval rules, the input authority and approval records, the bridge to the RISC Zero prover and checker (with a proof cache keyed by program identifier), the 13 scenarios of Experiment 3, the Experiment 3 verification script (`oracle.go`, `a2aid zk-oracle`) and, in `pq-identity/`, the integration test and bound-transport tests |
| `internal/pqsig` | pq-identity | Deterministic CBOR proof context (signed directly, no COSE envelope), strict decoding, ML-DSA-65 and ECDSA signing and verification, benchmark, NIST vector tests |
| `internal/pqdev` | pq-identity | Starts and stops firmware-TPM emulators, copies emulator state for the clone control, and calls the C bridge to create, read, sign with and evict a device key |
| `internal/pqaudit` | pq-identity | Verification script for Experiment 1 (`a2aid audit-pq`): checks record completeness and event order, re-verifies every saved proof, and compares each outcome with the prediction recorded before testing |

Tests sit next to the code they test. Tests that need a running lab, an emulator or the RISC Zero tools are opt-in and skip with a message otherwise.

## Other source

| Path | Modules | Responsibility |
|---|---|---|
| `tools/pqtpm` | pq-identity | GPLv3 C bridge to the wolfTPM firmware TPM: create, read, sign and verify with an ML-DSA key through TPM commands; prints the command codes and timings it observed |
| `zk/methods/guest` | zk-component, pq-identity | The proved Rust program: recomputes the input commitment, sums four bounded holdings and writes the 61-byte journal |
| `zk/methods` | zk-component, pq-identity | Builds the guest and exposes its binary and program identifier |
| `zk/host` | zk-component, pq-identity | `zkprove`, `zkverify` (strict verification under a caller-pinned identifier) and the test-only `zkfake`, plus Rust tests over a retained genuine receipt |

## Scripts

| Script | Module | Purpose |
|---|---|---|
| `scripts/setup.sh`, `scripts/cleanup.sh` | all | Build and provision the disposable lab under `run/`; stop its processes |
| `scripts/test.sh` | all | Race-detector tests followed by short fuzzing runs |
| `scripts/binding_matrix.sh` | identity | Experiment 2 focused comparison with connection-continuity trials; stops if the verification script or tests fail |
| `scripts/test_binding_runner.sh` | identity | Injects failures into `binding_matrix.sh` and checks that it stops |
| `scripts/broad_matrix.sh`, `scripts/smoke.sh` | identity | Experiment 2 broad comparison with concurrent-delivery trials; a quick run with honest scenarios only |
| `scripts/build_pq_toolchain.sh` | pq-identity | Fetches and builds the pinned wolfSSL and wolfTPM versions and the C bridge into `.toolchain/` |
| `scripts/pq_matrix.sh` | pq-identity | Runs Experiment 1, then its verification script, the damaged-copy tests and the Go tests; stops at the first failure |
| `scripts/pq_audit_controls.py` | pq-identity | Makes 17 deliberately damaged copies of an Experiment 1 run and confirms the verification script gives the predicted result for each |
| `scripts/test_pq_runner.sh` | pq-identity | Injects failures into `pq_matrix.sh` and checks that it stops |
| `scripts/zk_oracle_controls.py` | zk-component, pq-identity | Makes deliberately damaged copies of an Experiment 3 run and records the verification script's result for each |

## Data and published records

| Path | Contents |
|---|---|
| `fixtures/manifest-*.json`, `fixtures/predictions-*` | Scenarios and the predictions recorded before testing: `binding` and `broad` (Experiment 2), `pq` (Experiment 1); `fixtures/zk/` holds the Experiment 3 requests, authority history, synthetic inputs and predictions. These files are byte-identical to the copies saved with the runs |
| `fixtures/pq-audit-controls-expected.json` | Predicted verification result for each damaged copy of the Experiment 1 run |
| `fixtures/testdata/` | Small fixtures for tests: a six-test Experiment 1 run and a record set without schema-2 fields |
| `zk/image-id.txt`, `zk/image-id.json` | The pinned guest program identifier |
| `results/` | Published records of each experiment; see [RESULTS.md](RESULTS.md) |
| `run/`, `bin/`, `.toolchain/`, `zk/target/` | Generated locally and never published |

## Repository files

| Path | Purpose |
|---|---|
| `Makefile`, `scripts/check.py` | Short commands for tests and evidence checks; verification scripts run on copies or write to a separate output directory |
| `docs/packaging/` | `check_package.py` (source coverage of this map, links, Rust sources, secret patterns) and its tests; `update_manifest.py` and `verify_manifest.py` for `docs/PROVENANCE_MANIFEST.json`, the hash list of every published file |
| `paper/` | `main.tex`, `appendix.tex` and `references.bib` (the manuscript source), `Makefile` (build, watch, check, release), fonts, PDF and the self-contained LaTeX archive |
| `.vscode/` | LaTeX Workshop settings: build the paper through `make` on save, PDF and SyncTeX in VS Code |
