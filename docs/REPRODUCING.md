# Reproducing the experiments

Start from the repository root. Use Linux for the emulator lab; macOS and Windows were not evaluated. The retained experiment used Go 1.27.1, Python, swtpm 0.10.2, Rust 1.93 and RISC Zero 3.0.6. Go modules and Rust crates are pinned in the lock files. A newer toolchain can change build hashes; it does not change the pinned guest identifier automatically.

## 1. Check the package and retained PQ evidence

Requirements: Python 3.11+, Go, a C compiler for `-race`, Bash and Make. The first Go build downloads dependencies. Local HTTPS tests need available localhost ports.

```sh
make package-check
make verify
make check
```

Expected: both PQ audits report 128 declared / 128 found / 128 agree, zero unexpected violations, 25 declared attacker deliveries; all 17 mutation controls match; all nine runner checks pass. Reports and temporary binaries go to a new `/tmp/a2a-proofed-check-*` directory printed at the end. Published evidence is not changed. No emulator, Rust or model API is needed for these checks.

For all three modules:

```sh
make check-all
```

This also audits a temporary copy of the classical identity evidence. It explicitly skips retained ZK receipt verification unless a verifier is supplied. Some Go tests are opt-in or require omitted historical records; inspect skip messages and the documentation rather than treating them as executed integrations.

## 2. Build and exercise the PQ emulator

Additional requirements: Git, a C toolchain, CMake, Ninja, Make and network access to the pinned upstream commits. The build is task-local under `pq-identity/.toolchain/`; it does not replace system libraries.

```sh
make pq-toolchain
make pq-device
```

The first command builds wolfSSL, wolfTPM and the C bridge. The second test starts its own temporary emulator, creates an ML-DSA-65 key, signs through TPM commands, verifies with CIRCL, rejects altered inputs and wrong authorization, checks restart persistence and evicts the test key. It does not need an already running lab. Ports 2361 and 2362 must be free; override the command port with `A2AID_PQ_DEVICE_PORT` if needed.

A missing `tools/pqtpm/pqtpm` means the bridge has not been built; it is deliberately not shipped as a binary. If the libraries already exist, `make -C pq-identity/tools/pqtpm` rebuilds only the bridge.

To generate a fresh 128-cell experiment, also install swtpm and make sure no other component's lab is running:

```sh
cd pq-identity
scripts/pq_matrix.sh
# Later, stop the processes started for this lab:
scripts/cleanup.sh
```

The runner builds, resets disposable live state under `run/`, provisions both emulators and the lab CA, runs the matrix, audits it, asserts the mutation controls and runs tests. A failure stops the runner. The last line prints the new run directory; use that exact path for subsequent checks. Fresh runs are ignored by Git until deliberately selected. Setup erases disposable `run/` state, not retained `results/` evidence. Labs share fixed ports, so run them sequentially.

## 3. Verify existing RISC Zero receipts

Install the [official RISC Zero tools](https://dev.risczero.com/api/zkvm/install), selecting **3.0.6**, plus its guest Rust toolchain. The recorded setup used rzup 0.6.0. The host Rust and the RISC Zero guest compiler are different toolchains. Build dependencies need network access, several GB of disk, and substantial memory; the recorded CPU machine had 62 GB RAM.

With those tools selected:

```sh
cd zk-component/zk
cargo build --locked --release --bin zkverify
cargo test --locked --release
cd ../..
make check-zk ZK_VERIFY="$PWD/zk-component/zk/target/release/zkverify"
```

Expected: 52/52 evaluations agree, with seven expected weak-policy attack approvals. Verification uses retained receipts and does not generate new proofs. The pinned guest identifier is in `zk-component/zk/image-id.txt`; compare builds against it rather than replacing it with a worker's identifier. Both CLIs refuse dev mode. A different verifier binary hash is reported and must be understood; the guest identifier remains the trust anchor.

## 4. Generate new computation proofs

From the repository root, with the RISC Zero toolchain ready and swtpm available:

```sh
cd zk-component
(cd zk && cargo build --locked --release)
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid zk-matrix --run-path-file /tmp/a2a-proofed-new-zk-run
bin/a2aid zk-oracle --results "$(cat /tmp/a2a-proofed-new-zk-run)" \
  --verify-bin zk/target/release/zkverify --out /tmp/a2a-proofed-new-zk-audit
scripts/cleanup.sh
```

The matrix prepares the lab and generates seven genuine proofs unless a validated cache entry is used. The recorded final proof times were 22.1–23.6 seconds each. A fresh run need not reproduce those timings. Keep `RISC0_DEV_MODE` unset. The synthetic openings are published for reproducibility; this is not an empirical privacy test.

## 5. PQ-to-ZK smoke test

Use the main `pq-identity/` component, with its PQ toolchain and the RISC Zero tools available. The Rust host sources are present under `zk/host/src/bin/` and must never be excluded as build output.

```sh
cd pq-identity
(cd zk && cargo build --locked --release)
scripts/setup.sh
A2AID_PQ_ZK_SMOKE=1 go test -race -count=1 -v -run TestPQSmoke ./internal/zk
scripts/cleanup.sh
```

This combines an actual device-command signature with a genuine receipt in the honest case and rejects an impostor. It is a smoke test, not a fresh 52-cell ZK adversarial matrix over PQ transport. The default `pq_transport_test.go` regressions separately isolate connection continuity using a software test key and a stub receipt.

## 6. Classical identity comparison

```sh
cd identity
scripts/v3final.sh
scripts/cleanup.sh
```

This runs the focused classical matrix and its continuity checks; swtpm is required. `scripts/matrix.sh` selects the broader comparison in the appendix. Versioned fixture and runner names identify experiment definitions, not old executable releases.

## Edit and rebuild the paper

The manuscript is [paper-draft.md](../paper/paper-draft.md). Either edit the Markdown and run `python3 md2tex.py` from `paper/`, or edit `main.tex` directly and omit that conversion step. Then run LuaLaTeX twice. The [source ZIP](../paper/a2a-identity-latex.zip) includes fonts and build instructions. Regenerating TeX overwrites direct TeX edits.

## Interpreting failures

- Audit exit **0**: complete supported evidence agrees, including declared attack successes.
- Audit exit **1**: a violation or disagreement; read the per-cell report.
- Audit exit **2**: incomplete, malformed or unsupported evidence. Older schemas are not silently upgraded.
- `unknown` delivery: the requester wrote a request but received no response. Server observations may resolve it; do not call it undelivered solely from the client error.
- Missing emulator/prover: run the appropriate build step. Do not substitute a software signer or dev-mode receipt and report it as the device/genuine-proof experiment.
