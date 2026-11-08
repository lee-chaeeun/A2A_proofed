# Reproducing the experiments

Run commands from the repository root unless a step says otherwise. The experiments were run on Linux with Go 1.27.1, swtpm 0.10.2, Rust 1.93 and RISC Zero 3.0.6; Go modules and Rust crates are pinned by their lock files.

## 0. Shortest path to the paper's central findings

With Go and Python installed, from the repository root:

```sh
make check
```

This re-audits the published 128-cell PQ run (Table 2 of the paper, including the 25 declared attacker deliveries) and the 17 corrupted-evidence controls. The emulator check behind Section 4.1 is read from `pq-identity/results/device/20261108T130125Z/README.md`; re-running it needs the emulator build in step 2. The task-binding results (Section 4.5) are re-verified in step 4, which needs the RISC Zero tools.

## 1. Check the published evidence (Go and Python only)

```sh
make package-check   # source coverage, links, Rust sources, secret patterns
make verify          # hashes of all published files
make check           # PQ tests, PQ audit, 17 corruption controls, runner failure tests
make check-all       # additionally: tests of all three modules and the classical release audit
```

Expected: the PQ audit reports 128 declared, found and agreeing cells and 25 declared attacker deliveries; all 17 controls return their declared outcome; the runner tests pass; the classical audit exits 0 with 8 declared attacker deliveries. The first build downloads Go modules, and HTTPS tests bind local ports. Reports go to a new `/tmp/a2a-proofed-check-*` directory. Tests that need an emulator, a running lab or the RISC Zero tools skip with a message; they are run explicitly in the steps below.

## 2. Build and test the PQ emulator

Needs Git, a C compiler, CMake, Ninja and network access to fetch the pinned wolfSSL and wolfTPM versions. Everything is built under `pq-identity/.toolchain/`.

```sh
make pq-toolchain    # wolfSSL, wolfTPM firmware TPM and the C bridge
make pq-device       # create, sign, verify with CIRCL, reject bad inputs, restart, evict
```

The device test starts its own emulator on ports 2361–2362 (`A2AID_PQ_DEVICE_PORT` overrides the first).

## 3. Run a fresh PQ matrix

Also needs swtpm. Only one lab can run at a time because the labs share fixed ports.

```sh
cd pq-identity
scripts/pq_matrix.sh   # setup, 128 cells, audit, controls, tests; stops at the first failing stage
scripts/cleanup.sh
```

The last line prints the new run directory. New runs are ignored by Git.

## 4. Verify the task-binding receipts

Install the [RISC Zero tools](https://dev.risczero.com/api/zkvm/install) at version 3.0.6. Building needs several GB of disk and memory.

```sh
cd zk-component/zk
cargo build --locked --release --bin zkverify
cargo test --locked --release
cd ../..
make check-zk ZK_VERIFY="$PWD/zk-component/zk/target/release/zkverify"
```

Expected: 52 of 52 evaluations agree, with seven declared weak-policy approvals. The rebuilt guest must match the identifier in `zk-component/zk/image-id.txt`; never replace it with an identifier supplied by a worker.

## 5. Generate new proofs and the PQ-to-ZK smoke test

```sh
cd zk-component
(cd zk && cargo build --locked --release)
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-matrix --run-path-file /tmp/new-zk-run
bin/a2aid zk-oracle --results "$(cat /tmp/new-zk-run)" --verify-bin zk/target/release/zkverify --out /tmp/new-zk-audit
scripts/cleanup.sh
```

The matrix generates seven genuine proofs (about 23 s each on the recorded CPU). Keep `RISC0_DEV_MODE` unset.

For the smoke test that sends a computation task over the bound device configuration (needs steps 2 and 4):

```sh
cd pq-identity
(cd zk && cargo build --locked --release)
scripts/setup.sh
A2AID_PQ_ZK_SMOKE=1 go test -count=1 -v -run TestPQSmoke ./internal/zk
scripts/cleanup.sh
```

## 6. Classical identity matrices

```sh
cd identity
scripts/binding_matrix.sh   # focused matrix with continuity and churn cases
scripts/broad_matrix.sh     # broad 21-scenario comparison
scripts/cleanup.sh
```

## 7. Rebuild the paper

The manuscript sources are `paper/main.tex`, `paper/appendix.tex` (included by `main.tex`) and `paper/references.bib`; there is no other source. From `paper/`: `make` runs LuaLaTeX, BibTeX and LuaLaTeX twice into `build/main.pdf`; `make watch` rebuilds on every save; `make check` reports pages and LaTeX warnings; `make release` refreshes the published PDF, the self-contained source ZIP and the checksums. In VS Code, the LaTeX Workshop extension uses the repository settings to build through `make` on save.

## Updating the published file list

After an intentional change, run `python3 docs/packaging/update_manifest.py` and then `make verify`.
