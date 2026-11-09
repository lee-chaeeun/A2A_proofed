# Experiment 1: Identity authentication

Can Mallory receive the task Alice meant for Bob? Bob signs Alice's challenge; Alice checks the signature with Bob's enrolled key and every field against her stored request. Eight configurations are tested in 16 scenarios (128 tests). In the device configurations the ML-DSA-65 key is created and used inside the wolfTPM emulator through the C bridge [`tools/pqtpm`](tools/pqtpm/README.md).

In records, deployment A is Bob and deployment B is Mallory. This folder also holds the code of Experiments 2 and 3 and the integration test.

| Configuration | Identifier | Signature | Key | Channel binding |
|---|---|---|---|---|
| Baseline | `C+tls` | none (card, address, TLS only) | — | no |
| Service ECDSA | `EC-env+tls` / `EC-env+cb` | ECDSA P-256 | signing service | no / yes |
| Service ML-DSA | `PQ-env+tls` / `PQ-env+cb` | ML-DSA-65 | signing service | no / yes |
| File ML-DSA | `PQ-file+cb` | ML-DSA-65 | key file | yes |
| Device ML-DSA | `PQ-device+tls` / `PQ-device+cb` | ML-DSA-65 | TPM emulator | no / yes |

Scenarios are in `fixtures/manifest-pq.json`, predictions in `fixtures/predictions-pq.md`.

## Saved runs

| Folder | |
|---|---|
| `results/pq/20261108-153049` | the 128 tests |
| `results/device/20261108T130125Z` | emulator check |
| `results/pq-bench/20261108-132255` | sizes and timings |
| `results/zk-pq-smoke/20261108-154419` | integration test |

## Check the saved run

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid audit-pq --results results/pq/20261108-153049 --out /tmp/pq-audit
python3 -I scripts/pq_audit_controls.py --bin bin/a2aid --run results/pq/20261108-153049 --out /tmp/pq-controls
```

`audit-pq` re-checks every saved proof and delivery and compares each outcome with its prediction. Expect `attacker_deliveries=25 ... exit=0` (the 25 tests in which Mallory received Bob's task), then `controls: 17 cases, 0 mismatches`. Without `--out` it writes into the run folder.

## Rerun

Needs the emulator build and swtpm ([REPRODUCING.md](../docs/REPRODUCING.md)):

```sh
scripts/build_pq_toolchain.sh
A2AID_PQ_DEVICE=1 go test -race -run TestDevice ./internal/pqdev
scripts/pq_matrix.sh
scripts/cleanup.sh
```

`scripts/setup.sh` (called by `pq_matrix.sh`) wipes and recreates `run/`.
