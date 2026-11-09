# Experiment 3: ZK result verification

Which approval rules accept a valid proof for the wrong request or old data? Bob's program checks whether four portfolio holdings add up to at most 100, and RISC Zero proves it ran. Alice verifies the proof against the program identifier she expects, then checks the result, the request challenge and the input before approving, at most once.

| Rule | Identifier | Checks challenge | Checks input |
|---|---|---|---|
| Receipt only | `V0` | no | no |
| Request check | `VT` | yes | no |
| Input check | `VI` | no | yes |
| Request + input check | `VTI` | yes | yes |

There are two input snapshots: `v1` totals 80 (passes) and `v2` totals 120 (fails). A *Pinned* request names one snapshot; a *Current* request needs the latest one. Both inputs are public in `fixtures/zk/openings.json`, so privacy is not tested.

Saved run: `results/zk/20261108-111817`, 13 scenarios × 4 rules = 52 evaluations from 9 A2A exchanges.

## Check the saved run

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
```

Re-checking the proofs needs RISC Zero 3.0.6 and several GB of disk:

```sh
(cd zk && cargo build --locked --release --bin zkverify && cargo test --locked --release)
bin/a2aid zk-oracle --results results/zk/20261108-111817 --verify-bin zk/target/release/zkverify --out /tmp/zk-check
```

`zk-oracle` re-verifies each saved proof and compares each decision with its prediction. Expect `agree=52 ... attack_successes=7 ... exit=0`. The rebuilt program must match `zk/image-id.txt`. New proofs: [REPRODUCING.md](../docs/REPRODUCING.md).
