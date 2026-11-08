# Proof-carrying A2A task results

This component extends the identity application with a RISC Zero bounded-sum guest.
A requester verifies a returned receipt, checks its request challenge and authorized
input commitment, and records an approval at most once.

It uses the fully appraised signed-card / enrolled-endpoint / authenticated-TLS baseline
`C+tls`. It does not measure a combined TPM-plus-ZK or channel-binding-plus-ZK handshake.
All four result policies use ZK; they differ in task/input checks.

| Policy | Require request challenge | Require authorized commitment |
|---|---|---|
| V0 | No | No |
| VT | Yes | No |
| VI | No | Yes |
| VTI | Yes | Yes |

## Tools and source

[A2A Go SDK](https://github.com/a2aproject/a2a-go) carries the messages.
[RISC Zero](https://github.com/risc0/risc0) 3.0.6 supplies the proof system.
`internal/zk/` contains transport appraisal, authority/ledger policies, matrix and oracle.
`zk/methods/guest/src/main.rs` is the proved application; `zk/host/src/bin/` contains
`zkprove`, `zkverify` and the test-only `zkfake`. Dependencies are pinned in Cargo.lock.

The two snapshots sum to 80 and 120, with a limit of 100. Pinned requests authorize a
specified historical snapshot; Current requests require the authority's head at approval.
The openings are synthetic and deliberately published; no privacy advantage is measured.

## Go build and tests

```sh
go build -o bin/a2aid ./cmd/a2aid
go test -race -count=1 ./...
```

HTTPS tests require localhost binding. Receipt-dependent tests skip without a built
verifier; legacy audit tests also skip because superseded run archives are omitted.
The final schema-2 run remains included.

## RISC Zero setup and receipt verification

The experiment used Rust 1.93 for the host, rzup 0.6.0 and RISC Zero tools/crates 3.0.6.
Use the [official installation instructions](https://dev.risczero.com/api/zkvm/install).
Install/select the pinned RISC Zero release rather than silently using the latest one.
The original task-local configuration used `RISC0_HOME=$PWD/.toolchain`; toolchain files
are not shipped here. Cargo builds may need network access and several GB of disk/RAM.

With the toolchain available, from this directory:

```sh
(cd zk && cargo build --release --bin zkverify)
bin/a2aid zk-oracle --results results/zk/20261108-111817 \
  --verify-bin zk/target/release/zkverify --out /tmp/a2a-proofed-zk-check
(cd zk && cargo test --release)
```

The guest build's image ID must match `zk/image-id.txt`. Do not overwrite the pinned
trust anchor with a worker-supplied ID. Verification checks existing receipts; it does
not generate new proofs. A rebuilt verifier may have a different binary hash; the oracle
reports the difference from original provenance. It reuses RISC Zero, rather than
independently implementing the cryptographic proof system.

## Fresh proving and matrix

Build all Rust CLIs with `cd zk` then `cargo build --release`. From this component root,
with no other lab running:

```sh
bin/a2aid zk-matrix --run-path-file /tmp/a2a-proofed-zk-run
```

This starts a local lab and generates seven genuine proofs. The retained CPU run took
roughly three minutes for the full matrix; performance depends on machine and workload.
Use the exact run directory written to the path file when invoking `zk-oracle`.

[Results](../docs/RESULTS.md), [artifact inventory](../docs/ARTIFACT_INVENTORY.md),
[tool links and attribution](../docs/TOOLS.md).
