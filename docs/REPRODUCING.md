# Reproducing

Commands run from the repository root unless noted. The reported runs used Linux, Go 1.27.1, Python 3.11, swtpm 0.10.2, Rust 1.93 and RISC Zero 3.0.6. Versions are pinned in `go.mod`/`go.sum`, `zk/Cargo.lock` and, for the emulator, `pq-identity/scripts/build_pq_toolchain.sh`.

`a2aid` is the project's Go program; each experiment folder builds its own copy from `cmd/a2aid`. Its subcommands `audit-pq`, `audit-release`, `reverify` and `zk-oracle` are the verification scripts: they re-check the saved proofs and records of a run without starting any agents. They exit 0 when every outcome matches its prediction, 1 when one does not, and 2 when records are missing or unreadable.

| Step | Needs | Time |
|---|---|---|
| 1. Re-check saved results | Go, Python | minutes |
| 2. Build the TPM emulator | C compiler, CMake, Ninja, network | optional |
| 3. Rerun Experiment 1 | step 2, swtpm | optional |
| 4. Re-check Experiment 3 proofs | RISC Zero 3.0.6, several GB | optional |
| 5. New proofs, integration test | steps 2 and 4 | optional; ~23 s per proof |
| 6. Rerun Experiment 2 | swtpm | optional |

## 1. Re-check saved results

```sh
make package-check
make verify
make check
make check-all
```

| Command | Does | Expect |
|---|---|---|
| `make package-check` | every source folder is documented, links work, no keys are published | `0 failure(s)` |
| `make verify` | every file matches `docs/PROVENANCE_MANIFEST.json` | `mismatches=0 missing=0 unlisted=0` |
| `make check` | Experiment 1 tests; `audit-pq` on the saved run; 17 damaged copies; runner tests | `agree=128 ... attacker_deliveries=25 ... exit=0`, then `controls: 17 cases, 0 mismatches` |
| `make check-all` | also the other two modules' tests and `audit-release` on Experiment 2's focused run | `NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes ...) exit=0` |

Reports go to a new `/tmp/a2a-proofed-check-*` folder, with each step's exit code in `checks.json`. The saved records are not modified. Tests that need the emulator, a running lab or RISC Zero print `SKIP`.

Experiment 2's broad comparison cannot be re-checked from this copy, because the per-test records are not published. Its run-time report is `identity/results/broad/20261107-194025/reverify.md`.

## 2. Build the TPM emulator

```sh
make pq-toolchain   # downloads and builds wolfSSL, wolfTPM and the C bridge into pq-identity/.toolchain/
make pq-device      # creates a key, signs, checks with CIRCL, rejects bad input, restarts
```

The device test uses ports 2361–2362 (`A2AID_PQ_DEVICE_PORT` changes the first). Expect `ok` for `./internal/pqdev`.

## 3. Rerun Experiment 1

Needs swtpm. Only one lab can run at a time.

```sh
cd pq-identity
scripts/pq_matrix.sh
scripts/cleanup.sh
```

`pq_matrix.sh` sets up the lab, runs the 128 tests, then the verification script, the damaged copies and the Go tests. It stops at the first failure with a non-zero exit, and on success prints `run: <folder>`. New runs are ignored by Git.

## 4. Re-check Experiment 3 proofs

Install the [RISC Zero tools](https://dev.risczero.com/api/zkvm/install) 3.0.6, then:

```sh
cd zk-component/zk
cargo build --locked --release --bin zkverify
cargo test --locked --release
cd ../..
make check-zk ZK_VERIFY="$PWD/zk-component/zk/target/release/zkverify"
```

Expect `agree=52 ... attack_successes=7 ... denied_legit=0/12 exit=0`. The rebuilt program must have the identifier in `zk-component/zk/image-id.txt`.

## 5. New proofs and the integration test

```sh
cd zk-component
(cd zk && cargo build --locked --release)
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-matrix --run-path-file /tmp/new-zk-run
bin/a2aid zk-oracle --results "$(cat /tmp/new-zk-run)" --verify-bin zk/target/release/zkverify --out /tmp/new-zk-audit
scripts/cleanup.sh
```

This makes seven real proofs. Leave `RISC0_DEV_MODE` unset; it produces fake proofs.

Integration test (needs steps 2 and 4):

```sh
cd pq-identity
(cd zk && cargo build --locked --release)
scripts/setup.sh
A2AID_PQ_ZK_SMOKE=1 go test -count=1 -v -run TestPQSmoke ./internal/zk
scripts/cleanup.sh
```

## 6. Rerun Experiment 2

```sh
cd identity
scripts/binding_matrix.sh   # focused comparison
scripts/broad_matrix.sh     # broad comparison
scripts/cleanup.sh
```

## Updating the file list

After an intentional change: `python3 docs/packaging/update_manifest.py`, then `make verify`.
