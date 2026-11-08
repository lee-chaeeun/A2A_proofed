# Code map

The three experiment directories are Go modules with the same package layout. `identity/` has the classical packages; `zk-component/` adds the task-binding code and the Rust programs; `pq-identity/` adds the PQ proof format, the emulated device and the composite audit on top of both. Every package below is described once, with the modules that contain it. Run Go commands inside one module.

Suggested reading order for the main experiment: `cmd/a2aid` → `internal/wire` and `internal/registry` → `internal/agent`, `internal/gate`, `internal/pqdev` and `tools/pqtpm` → `internal/pqsig` → `internal/verifier` → `internal/zk` → `internal/pqaudit` and `internal/audit`.

## Go packages

| Path | Modules | Responsibility |
|---|---|---|
| `cmd/a2aid` | all | Command-line entry point: lab provisioning (CA, keys, emulators, enrollment), agent, controller and signing-service processes, matrix runs, audits and benchmarks. `a2aid` without arguments lists the commands |
| `internal/wire` | all | A2A payload types, the closed set of policy (configuration) identifiers, binding context and URL normalization |
| `internal/registry` | all | Enrollment registry: per deployment, the publisher key, endpoint, TLS name and the pinned proof keys |
| `internal/cardsig` | all | Agent Card canonicalization, JWS signing and verification, adapted from the official A2A Go sample; key lookup through the registry |
| `internal/agent` | all | One scripted A2A deployment: answers challenges in honest or attack modes, logs task receipts; in `zk-component/` and `pq-identity/` also runs the proving worker |
| `internal/gate` | all | Signing service: serves listed processes only and routes requests to software keys, swtpm or, in `pq-identity/`, the emulated ML-DSA device |
| `internal/tpmsig` | all | swtpm lifecycle and provisioning; TPM quote encoding, signing and appraisal |
| `internal/senv` | all | Software-signed COSE envelope, the software counterpart of the TPM quote |
| `internal/ptv` | all | Routine attestation response modeled on the PTV draft: a TPM quote inside a signed envelope |
| `internal/verifier` | all | The requester: discovery, challenge, appraisal of every proof type, connection recording, TLS exporters and the delivery guard (`GuardedSend`, `transport.go`), issued-session store |
| `internal/controller`, `internal/ctl` | all | Independent controller that records which process received what, and its client |
| `internal/matrix` | all | Runs scenario × configuration matrices, attack set-ups, release-race trials, offline reverification, summaries and traces |
| `internal/audit` | all | Structural release checker: event paths, typed contexts, issued sessions, connection continuity, receipt joins and cardinality |
| `internal/zk` | zk-component, pq-identity | Task-binding requester and policies, task authority and approval ledgers, prover/verifier bridge with an image-scoped cache, the 13-scenario matrix, the result checker (`oracle.go`) and the bound-transport tests |
| `internal/pqsig` | pq-identity | Canonical proof context, strict decoding, ML-DSA-65 and ECDSA signing and verification, benchmark, NIST vector tests |
| `internal/pqdev` | pq-identity | Starts and stops firmware-TPM emulators, copies emulator state for the clone control, and calls the C bridge to create, read, sign with and evict a device key |
| `internal/pqaudit` | pq-identity | Composite audit of a PQ run: structural release checks plus re-verification of every proof against the declared inventory |

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
| `scripts/binding_matrix.sh` | identity | Focused classical matrix with continuity and churn cases, audits and tests as gates |
| `scripts/test_binding_runner.sh` | identity | Injects failures into `binding_matrix.sh` and checks that it stops |
| `scripts/broad_matrix.sh`, `scripts/smoke.sh` | identity | Broad classical matrix with release-race trials; a quick honest-only run |
| `scripts/build_pq_toolchain.sh` | pq-identity | Fetches and builds the pinned wolfSSL and wolfTPM versions and the C bridge into `.toolchain/` |
| `scripts/pq_matrix.sh` | pq-identity | PQ matrix with the audit, the asserted corruption controls and the tests as gates |
| `scripts/pq_audit_controls.py` | pq-identity | Applies 17 corruptions to copies of a PQ run and asserts each declared audit outcome |
| `scripts/test_pq_runner.sh` | pq-identity | Injects failures into `pq_matrix.sh` and checks that it stops |
| `scripts/zk_oracle_controls.py` | zk-component, pq-identity | Applies corruptions to copies of a task-binding run and records the result checker's outcomes |

## Data and published records

| Path | Contents |
|---|---|
| `fixtures/manifest-*.json`, `fixtures/predictions-*` | Declared scenarios and expected outcomes: `binding` and `broad` (classical), `pq` (PQ identity); `fixtures/zk/` holds the task-binding requests, authority history, synthetic inputs and predictions. These files are byte-identical to the declarations recorded with the runs |
| `fixtures/pq-audit-controls-expected.json` | Declared outcome of each audit corruption control |
| `fixtures/testdata/` | Small fixtures for tests: a six-cell PQ run and a record set without schema-2 fields |
| `zk/image-id.txt`, `zk/image-id.json` | The pinned guest program identifier |
| `results/` | Published records of each experiment; see [RESULTS.md](RESULTS.md) |
| `run/`, `bin/`, `.toolchain/`, `zk/target/` | Generated locally and never published |

## Repository files

| Path | Purpose |
|---|---|
| `Makefile`, `scripts/check.py` | Short commands for tests and evidence checks; audits run on copies or write to a separate output directory |
| `docs/packaging/` | `check_package.py` (source coverage of this map, links, Rust sources, secret patterns) and its tests; `update_manifest.py` and `verify_manifest.py` for `docs/PROVENANCE_MANIFEST.json`, the hash list of every published file |
| `paper/` | `paper-draft.md` (source), `md2tex.py` (converts it to `main.tex` with pandoc), `main.tex`, fonts, PDF and the self-contained LaTeX archive |
