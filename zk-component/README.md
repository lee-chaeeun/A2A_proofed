# Task-binding experiment

A worker proves with RISC Zero whether four portfolio holdings sum to at most 100. The requester verifies the receipt under a locally pinned program identifier and approves at most once, if the verified journal matches the stored request and the input that request authorizes. Tasks are delivered over the identity baseline (signed card, endpoint, authenticated TLS). Design and limits: [DESIGN.md](../docs/DESIGN.md); findings: [RESULTS.md](../docs/RESULTS.md); packages: [CODE_MAP.md](../docs/CODE_MAP.md).

## Policies and contracts

| Paper name | Policy identifier | Requires the request challenge | Requires the authorized input |
|---|---|---|---|
| Receipt only | `V0` | no | no |
| Request check | `VT` | yes | no |
| Input check | `VI` | no | yes |
| Request + input check | `VTI` | yes | yes |

Every policy requires a valid receipt and a passing result. A *Pinned* request authorizes a named historical snapshot; a *Current* request requires the authority's latest snapshot when approval is recorded. The two synthetic snapshots sum to 80 and 120; their inputs are published in `fixtures/zk/openings.json`, so no privacy property is measured.

The published run is `results/zk/20261108-111817` (13 scenarios × 4 policies, seven genuine receipts).

## Commands

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
```

Receipt verification needs the RISC Zero 3.0.6 toolchain:

```sh
(cd zk && cargo build --locked --release --bin zkverify && cargo test --locked --release)
bin/a2aid zk-oracle --results results/zk/20261108-111817 --verify-bin zk/target/release/zkverify --out /tmp/zk-check
```

A rebuilt guest must match `zk/image-id.txt`. Generating new proofs is described in [REPRODUCING.md](../docs/REPRODUCING.md).
