# Experiment 3: ZK result verification

**Question:** which approval rules accept a genuine proof that answers the wrong request or uses outdated data?

Bob, the worker, runs a small program that checks whether four portfolio holdings add up to at most 100. RISC Zero produces a **receipt**: a zero-knowledge (ZK) proof that this exact program ran, plus its public output, called the **journal**. Alice, the requester, checks the receipt against the program identifier she expects. Then she checks the journal: did the computation pass, does it answer her request, and did it use an input her request allows? She approves at most once per request. Tasks travel over the identity baseline: signed Agent Card, Bob's address and TLS.

A valid proof is not permission to approve. It shows that the program produced this journal from some input, nothing more.

## Approval rules and input contracts

| Name in the paper | Identifier in records | Also checks the request challenge | Also checks the allowed input |
|---|---|---|---|
| Receipt only | `V0` | no | no |
| Request check | `VT` | yes | no |
| Input check | `VI` | no | yes |
| Request + input check | `VTI` | yes | yes |

Every rule requires a valid receipt and a passing result.

The example data has two portfolio snapshots. The earlier one totals 80, within the limit of 100. The updated one totals 120, over the limit. A **Pinned** request names one historical snapshot; a proof about the total of 80 answers it correctly. A **Current** request requires the latest snapshot at the moment of approval; after the update, the same proof about 80 must be refused. In the fixture files, `v1` is the earlier snapshot and `v2` the updated one. Both inputs are published in `fixtures/zk/openings.json`, so the experiment does not test privacy.

The saved run is `results/zk/20261108-111817`: 13 scenarios × 4 rules = 52 evaluations. These come from nine A2A exchanges and seven new proofs; they are not 52 separate network exchanges, because some evaluations re-check proofs already received.

## Check the saved run

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
```

`zk-oracle` is the verification script for this experiment. It re-checks every saved receipt with `zkverify`, RISC Zero's proof checker, then checks request and input matching and approvals against the predictions recorded before testing, without running the agents again. It needs the RISC Zero 3.0.6 tools (optional; several GB of disk):

```sh
(cd zk && cargo build --locked --release --bin zkverify && cargo test --locked --release)
bin/a2aid zk-oracle --results results/zk/20261108-111817 --verify-bin zk/target/release/zkverify --out /tmp/zk-check
```

Expected: `declared=52 ... agree=52 ... attack_successes=7 ... exit=0`. The seven are predicted wrong approvals by the weaker rules. The rebuilt program must match `zk/image-id.txt`. Making new proofs is described in [REPRODUCING.md](../docs/REPRODUCING.md). More: [DESIGN.md](../docs/DESIGN.md), [RESULTS.md](../docs/RESULTS.md), [CODE_MAP.md](../docs/CODE_MAP.md).
