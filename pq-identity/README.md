# PQ identity experiment

An agent proves its identity with an ML-DSA-65 signature over a canonical context. In the device configurations the key is created and used by the wolfTPM firmware TPM (TPM 2.0 v1.85) through [`tools/pqtpm`](tools/pqtpm/README.md), and the requester verifies every proof with CIRCL under the enrolled public key. Eight configurations meet 12 scenarios and 4 boundary controls. This module also contains the classical and task-binding code, and sends the computation task through the same delivery guard as the identity task. Design and limits: [DESIGN.md](../docs/DESIGN.md); findings: [RESULTS.md](../docs/RESULTS.md); packages: [CODE_MAP.md](../docs/CODE_MAP.md).

## Configurations

| Paper name | Policy identifier | Signature | Key location |
|---|---|---|---|
| Baseline | `C+tls` | none (card signature, endpoint, TLS) | — |
| Service ECDSA / Service ECDSA (bound) | `EC-env+tls` / `EC-env+cb` | ECDSA P-256 | signing service |
| Service ML-DSA / Service ML-DSA (bound) | `PQ-env+tls` / `PQ-env+cb` | ML-DSA-65 | signing service |
| File ML-DSA (bound) | `PQ-file+cb` | ML-DSA-65 | application files |
| Device ML-DSA / Device ML-DSA (bound) | `PQ-device+tls` / `PQ-device+cb` | ML-DSA-65 | emulated TPM |

`+cb` (bound) puts the requester's TLS exporter into the signed context; `+tls` does not. Scenarios P1–P12 and controls X1–X4 are declared in `fixtures/manifest-pq.json` with their predictions in `fixtures/predictions-pq.md`.

## Published records

| Directory | Contents |
|---|---|
| `results/pq/20261108-153049` | The 128-cell matrix |
| `results/device/20261108T130125Z` | Emulator check: key creation, signing, wrong authorization, tampered message, restart persistence, CIRCL cross-verification, build options |
| `results/pq-bench/20261108-132255` | Sizes and timings |
| `results/zk-pq-smoke/20261108-154419` | Computation task over the bound device configuration with a genuine receipt |

## Commands

From this directory; only Go is needed for the first block.

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid audit-pq --results results/pq/20261108-153049 --out /tmp/pq-audit
python3 -I scripts/pq_audit_controls.py --bin bin/a2aid --run results/pq/20261108-153049 --out /tmp/pq-controls
```

`audit-pq` checks every declared cell: complete and well-formed records, event order, typed contexts, delivery on the proof connection, receipt joins, and re-verification of every proof under the recorded registry. Exit 0 means complete and in agreement with the declared outcomes, 1 a violation or disagreement, 2 incomplete or malformed evidence. Without `--out` it writes its report into the run directory.

Emulator, fresh matrix and smoke test:

```sh
scripts/build_pq_toolchain.sh
A2AID_PQ_DEVICE=1 go test -race -run TestDevice ./internal/pqdev
scripts/pq_matrix.sh
scripts/cleanup.sh
```

The setup script resets `run/` (emulator state and disposable lab credentials). See [REPRODUCING.md](../docs/REPRODUCING.md) for prerequisites.
