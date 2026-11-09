# Reproducing the experiments

Run commands from the repository root unless a step says otherwise. The reported runs used Linux, Go 1.27.1, Python 3.11, swtpm 0.10.2, Rust 1.93 and RISC Zero 3.0.6. Library versions are fixed by `go.mod` and `go.sum` (Go) and `zk/Cargo.lock` (Rust). The emulator sources are fixed by commit in `pq-identity/scripts/build_pq_toolchain.sh`.

## Programs you will use

- **`a2aid`** is the project's Go program; each experiment folder builds its own copy from `cmd/a2aid`. Its subcommands start the test lab, run experiments and run the **verification scripts**. A verification script checks the saved proofs and execution records of a run without running the agents again.
- **Python scripts:** `scripts/check.py` runs the standard checks; `pq_audit_controls.py` and `zk_oracle_controls.py` feed deliberately damaged copies of saved records to a verification script and confirm each is caught.
- **Bash scripts:** `setup.sh` and `cleanup.sh` start and stop a disposable local lab; `pq_matrix.sh`, `binding_matrix.sh` and `broad_matrix.sh` run a full experiment.

## Which steps you need

| Step | What it does | Needs | Cost |
|---|---|---|---|
| 1 | Re-check the saved results of Experiments 1 and 2 | Go, Python | several minutes |
| 2 | Build and test the TPM emulator | C compiler, CMake, Ninja, internet | optional |
| 3 | Run Experiment 1 again | step 2, swtpm | optional |
| 4 | Re-check the saved proofs of Experiment 3 | RISC Zero 3.0.6 | optional; several GB of disk and memory |
| 5 | Make new proofs; run the integration test | steps 2 and 4 | optional, slow: about 23 s per proof |
| 6 | Run Experiment 2 again | swtpm | optional |
| 7 | Build the paper | LuaLaTeX, BibTeX | about a minute |

## 1. Re-check the saved results (Go and Python only)

```sh
make package-check   # every source folder is documented, links work, no keys are published
make verify          # every published file matches its recorded hash
make check           # Experiment 1: tests, verification script, 17 damaged copies, runner tests
make check-all       # also: tests of all three folders and the Experiment 2 focused check
```

What you should see:

- `make package-check` ends with `Package checks: 6 declared Rust binaries; 0 failure(s)`.
- `make verify` prints `mismatches=0 missing=0 unlisted=0`.
- `make check` prints an `audit-pq` line with `declared=128 found=128 agree=128 ... attacker_deliveries=25 ... exit=0`. The 25 are the predicted tests in which Mallory received Bob's task. It then prints `controls: 17 cases, 0 mismatches, 0 uncovered, status 0` and a list of `PASS` lines for the runner tests.
- `make check-all` also prints an `audit-release` line with `NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes ...)` and `exit=0`. The 8 are the predicted tests in Experiment 2's focused comparison in which Mallory received Bob's task.

The first run downloads Go libraries. Some tests open local network ports. Reports go to a new folder named `/tmp/a2a-proofed-check-*`; its `checks.json` lists each step with its exit code. If any step fails, `scripts/check.py` stops and exits with a non-zero code. Tests that need the emulator, a running lab or RISC Zero print `SKIP` and are covered by the steps below.

Verification-script exit codes: **0** means every outcome matches the prediction recorded before testing, including predicted attack successes; **1** means an outcome differs or a rule was broken; **2** means records are missing or unreadable.

**The broad comparison of Experiment 2 cannot be re-checked from this copy.** The published copy keeps its results table and the report written when the data was collected (`reverify.md`: 217 of 217 checks agree), but not the per-test records that `a2aid reverify` reads. Running `reverify` on it prints `0/0 agree` and exits with 0; that is not a check.

## 2. Build and test the TPM emulator (optional)

Needs Git, a C compiler, CMake, Ninja and internet access to download the fixed wolfSSL and wolfTPM versions. Everything is built under `pq-identity/.toolchain/`.

```sh
make pq-toolchain    # builds wolfSSL, the wolfTPM firmware TPM and the C bridge
make pq-device       # creates a key, signs, checks with CIRCL, rejects bad input, restarts, deletes
```

The device test starts its own emulator on ports 2361–2362; set `A2AID_PQ_DEVICE_PORT` to use another first port. Expected: Go reports `ok` for `./internal/pqdev`. The saved result of this check is `pq-identity/results/device/20261108T130125Z/README.md`.

## 3. Run Experiment 1 again (optional)

Also needs swtpm. Only one lab can run at a time, because the labs use fixed ports.

```sh
cd pq-identity
scripts/pq_matrix.sh   # lab set-up, 128 tests, verification script, damaged copies, Go tests
scripts/cleanup.sh
```

`pq_matrix.sh` prints a `[pq_matrix]` line for each stage and stops with a non-zero exit code at the first stage that fails. When it succeeds, its last line is `run: <folder>`, the new run's folder. New runs are ignored by Git.

## 4. Re-check the saved proofs of Experiment 3 (optional)

Install the [RISC Zero tools](https://dev.risczero.com/api/zkvm/install), version 3.0.6. Then:

```sh
cd zk-component/zk
cargo build --locked --release --bin zkverify
cargo test --locked --release
cd ../..
make check-zk ZK_VERIFY="$PWD/zk-component/zk/target/release/zkverify"
```

Expected: a `zk-oracle` line with `declared=52 ... agree=52 ... attack_successes=7 wrong_context=3/8 unsafe=5/12 denied_legit=0/12 exit=0`. The seven are predicted wrong approvals by the weaker rules. The rebuilt program must have the identifier in `zk-component/zk/image-id.txt`; never replace it with an identifier supplied by a worker.

## 5. New proofs and the integration test (optional, slow)

```sh
cd zk-component
(cd zk && cargo build --locked --release)
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-matrix --run-path-file /tmp/new-zk-run
bin/a2aid zk-oracle --results "$(cat /tmp/new-zk-run)" --verify-bin zk/target/release/zkverify --out /tmp/new-zk-audit
scripts/cleanup.sh
```

`zk-matrix` makes seven real proofs, about 23 seconds each on the recorded machine, and writes the new run's folder name to `/tmp/new-zk-run`. Leave `RISC0_DEV_MODE` unset; that mode produces fake proofs.

The separate integration test sends a computation task over emulator-based authentication with channel binding. It needs steps 2 and 4. It does not repeat the 52 evaluations of Experiment 3.

```sh
cd pq-identity
(cd zk && cargo build --locked --release)
scripts/setup.sh
A2AID_PQ_ZK_SMOKE=1 go test -count=1 -v -run TestPQSmoke ./internal/zk
scripts/cleanup.sh
```

Expected: the test passes, Bob receives one task, and Mallory is rejected before delivery.

## 6. Run Experiment 2 again (optional)

```sh
cd identity
scripts/binding_matrix.sh   # focused comparison, with connection-continuity trials
scripts/broad_matrix.sh     # broad comparison: 21 scenarios × 11 configurations
scripts/cleanup.sh
```

## 7. Build the paper

The paper's only sources are `paper/main.tex`, `paper/appendix.tex` and `paper/references.bib`. From `paper/`:

```sh
make           # LuaLaTeX, BibTeX, then LuaLaTeX twice, into build/main.pdf
make check     # page count and LaTeX warnings
make release   # refreshes a2a-identity-paper.pdf, a2a-identity-latex.zip and SHA256SUMS
```

`make check` should report 22 pages, `overfull: 0`, `undefined: 0` and `references start on page 9`. To edit on Overleaf, upload `a2a-identity-latex.zip` and choose LuaLaTeX; the included `latexmkrc` selects it.

## Updating the published file list

After an intentional change, run `python3 docs/packaging/update_manifest.py` and then `make verify`.
