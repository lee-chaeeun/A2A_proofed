# Code map

The three experiment folders are Go modules with the same layout: `identity/` (Experiment 2), `zk-component/` (Experiment 3) and `pq-identity/` (Experiment 1 and the integration test), which contains the code of the other two plus the post-quantum parts. Run Go commands inside one module. In code, deployment A is Bob, deployment B is Mallory, and the requester is Alice.

All code here was written for this project, except `internal/cardsig`, which adapts the A2A Go signed-card sample. Upstream libraries are listed in [TOOLS.md](TOOLS.md).

A good reading order for Experiment 1: `cmd/a2aid`, `internal/wire`, `internal/registry`, `internal/agent`, `internal/gate`, `internal/pqdev`, `tools/pqtpm`, `internal/pqsig`, `internal/verifier`, `internal/zk`, `internal/pqaudit`, `internal/audit`.

## Go packages

| Path | Modules | What it does |
|---|---|---|
| `cmd/a2aid` | all | The program. Subcommands set up the lab, run agents, the controller and the signing service, run experiments and benchmarks, and run the verification scripts (`audit-pq`, `audit-release`, `reverify`, `zk-oracle`). Run it without arguments for a list |
| `internal/wire` | all | A2A message types, configuration identifiers, binding fields |
| `internal/registry` | all | Alice's enrollment registry: address, TLS name and keys for each deployment |
| `internal/cardsig` | all | Agent Card signing and verification (JWS), adapted from the A2A Go sample |
| `internal/agent` | all | A scripted A2A server (Bob or Mallory) that answers challenges honestly or as an attacker; also the worker in Experiment 3 |
| `internal/gate` | all | The signing service: signs only for listed processes, using a software key, swtpm or the ML-DSA emulator |
| `internal/tpmsig` | all | swtpm set-up, TPM quotes and quote checking |
| `internal/senv` | all | Software-signed COSE response, the software counterpart of a quote |
| `internal/ptv` | all | Our signed COSE response carrying a quote; some fields and error codes follow the PTV draft |
| `internal/verifier` | all | Alice: discovery, challenges, proof checks, TLS exporters, the delivery guard (`GuardedSend` in `transport.go`) |
| `internal/controller`, `internal/ctl` | all | An independent observer that records which server received which task, and its client |
| `internal/matrix` | all | Runs each scenario against each configuration, sets up the attacks, writes summaries; also `a2aid reverify` |
| `internal/audit` | all | Verification script for Experiment 2 (`audit-release`), reused by Experiment 1's: event order, matching records, delivery on the proof connection, one delivery per task |
| `internal/zk` | zk-component, pq-identity | Alice's result checks and approval rules, the record of allowed inputs, the RISC Zero bridge, Experiment 3's scenarios and verification script (`oracle.go`); in `pq-identity/` also the integration test |
| `internal/pqsig` | pq-identity | The signed request record: deterministic CBOR, ML-DSA-65 and ECDSA signing and checking, NIST test vectors |
| `internal/pqdev` | pq-identity | Starts the wolfTPM emulator, copies its state for control X2, and drives the C bridge |
| `internal/pqaudit` | pq-identity | Verification script for Experiment 1 (`audit-pq`): re-checks every saved proof and compares each outcome with its prediction |

Tests sit next to the code. Tests that need a running lab, the emulator or RISC Zero skip unless enabled.

## Other source

| Path | Modules | What it does |
|---|---|---|
| `tools/pqtpm` | pq-identity | C bridge to the wolfTPM emulator: create, read, sign and verify with an ML-DSA key (GPLv3) |
| `zk/methods/guest` | zk-component, pq-identity | The proved Rust program: hashes the input, sums four holdings, writes the journal |
| `zk/methods` | zk-component, pq-identity | Builds the guest and exposes its program identifier |
| `zk/host` | zk-component, pq-identity | `zkprove`, `zkverify` and the test-only `zkfake` |

## Scripts

| Script | Module | What it does |
|---|---|---|
| `scripts/setup.sh`, `scripts/cleanup.sh` | all | Start a throwaway lab under `run/`; stop it |
| `scripts/test.sh` | all | Race-detector tests and short fuzzing runs |
| `scripts/binding_matrix.sh` | identity | Runs Experiment 2's focused comparison and its checks |
| `scripts/test_binding_runner.sh` | identity | Checks that `binding_matrix.sh` stops when a step fails |
| `scripts/broad_matrix.sh`, `scripts/smoke.sh` | identity | Runs Experiment 2's broad comparison; a quick honest-only run |
| `scripts/build_pq_toolchain.sh` | pq-identity | Downloads and builds pinned wolfSSL, wolfTPM and the C bridge into `.toolchain/` |
| `scripts/pq_matrix.sh` | pq-identity | Runs Experiment 1 and its checks; stops at the first failure |
| `scripts/pq_audit_controls.py` | pq-identity | Feeds 17 damaged copies of a run to `audit-pq` and checks each is caught |
| `scripts/test_pq_runner.sh` | pq-identity | Checks that `pq_matrix.sh` stops when a step fails |
| `scripts/zk_oracle_controls.py` | zk-component, pq-identity | Feeds damaged copies of a run to `zk-oracle` |

## Data

| Path | Contents |
|---|---|
| `fixtures/manifest-*.json`, `fixtures/predictions-*` | Scenarios and predictions: `binding`, `broad` (Experiment 2), `pq` (Experiment 1); `fixtures/zk/` for Experiment 3. Identical to the copies saved with the runs |
| `fixtures/pq-audit-controls-expected.json` | Expected result for each damaged copy |
| `fixtures/testdata/` | Small runs used by tests |
| `zk/image-id.txt`, `zk/image-id.json` | The expected program identifier |
| `results/` | Saved runs; see [RESULTS.md](RESULTS.md) |
| `run/`, `bin/`, `.toolchain/`, `zk/target/` | Created locally, not published |

## Repository files

| Path | What it does |
|---|---|
| `Makefile`, `scripts/check.py` | The `make` checks |
| `docs/packaging/` | `check_package.py` and its tests; `update_manifest.py` and `verify_manifest.py` for `docs/PROVENANCE_MANIFEST.json`, the hash of every published file |
