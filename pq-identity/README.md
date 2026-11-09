# Experiment 1: Identity authentication

**Question:** in which configurations does Mallory, the attacker, receive the task that Alice, the requester, meant for Bob?

Bob proves identity by signing a fresh challenge from Alice. The signed record is deterministic CBOR (a binary format that always encodes the same data as the same bytes), signed directly; it is not wrapped in COSE. Alice checks the signature with Bob's registered public key and compares every field with her stored request. In the device configurations, the ML-DSA-65 key is created and used inside the wolfTPM firmware TPM emulator through [`tools/pqtpm`](tools/pqtpm/README.md), a small C bridge program. Alice verifies every signature with CIRCL, an independent ML-DSA library.

Eight configurations meet sixteen scenarios: twelve scenarios (P1–P12) and four boundary controls (X1–X4), for 128 tests. This folder also contains the code of Experiments 2 and 3 and runs the separate integration test.

**Names in the saved records:** deployment A (Atlas) is Bob and deployment B (Boreas) is Mallory. A record that says the task went to `B` means Mallory received it.

More: [DESIGN.md](../docs/DESIGN.md) explains the checks, [RESULTS.md](../docs/RESULTS.md) the findings, [CODE_MAP.md](../docs/CODE_MAP.md) the packages.

## Configurations

| Name in the paper | Identifier in records | Signature | Where the key is kept | TLS channel binding |
|---|---|---|---|---|
| Baseline | `C+tls` | none: only the Agent Card signature, address and TLS are checked | — | no |
| Service ECDSA | `EC-env+tls` | ECDSA P-256 | signing service | no |
| Service ECDSA (bound) | `EC-env+cb` | ECDSA P-256 | signing service | yes |
| Service ML-DSA | `PQ-env+tls` | ML-DSA-65 | signing service | no |
| Service ML-DSA (bound) | `PQ-env+cb` | ML-DSA-65 | signing service | yes |
| File ML-DSA (bound) | `PQ-file+cb` | ML-DSA-65 | credential file | yes |
| Device ML-DSA | `PQ-device+tls` | ML-DSA-65 | emulated TPM | no |
| Device ML-DSA (bound) | `PQ-device+cb` | ML-DSA-65 | emulated TPM | yes |

With channel binding (`+cb`), Bob signs a value taken from Bob's own TLS connection, and Alice compares it with the value from her connection. A relay has two different connections, so the values differ. `env` in `EC-env` and `PQ-env` refers to the signing service; these proofs are not COSE envelopes. The scenarios are defined in `fixtures/manifest-pq.json`, and the predictions recorded before testing are in `fixtures/predictions-pq.md`.

## Saved records

| Folder | Contents |
|---|---|
| `results/pq/20261108-153049` | Experiment 1: all 128 tests, including the 25 predicted tests in which Mallory received Bob's task |
| `results/device/20261108T130125Z` | Emulator check: key creation, signing, wrong password, changed message, restart, CIRCL cross-check, build options |
| `results/pq-bench/20261108-132255` | Key, signature and proof sizes and signing times |
| `results/zk-pq-smoke/20261108-154419` | Separate integration test: a computation task delivered over the bound emulator configuration with a real proof. It does not repeat Experiment 3 |

## Check the saved run

From this folder, with only Go and Python:

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
bin/a2aid audit-pq --results results/pq/20261108-153049 --out /tmp/pq-audit
python3 -I scripts/pq_audit_controls.py --bin bin/a2aid --run results/pq/20261108-153049 --out /tmp/pq-controls
```

`audit-pq` is the verification script for this experiment. It reads the saved records without running the agents again. For every test it checks that the records are complete, that events happened in the right order, that each signed record matches Alice's request, that the task was sent only on the connection that carried the proof, and that every saved signature verifies with the registered key. It then compares each outcome with the prediction recorded before testing.

Expected: a line ending in `attacker_deliveries=25 ... exit=0`, then `controls: 17 cases, 0 mismatches, 0 uncovered, status 0`. Exit code 1 means an outcome differs from its prediction; 2 means records are missing or unreadable. Without `--out`, `audit-pq` writes its report into the run folder.

## Run it again (optional)

These steps build the emulator and need swtpm; see [REPRODUCING.md](../docs/REPRODUCING.md):

```sh
scripts/build_pq_toolchain.sh
A2AID_PQ_DEVICE=1 go test -race -run TestDevice ./internal/pqdev
scripts/pq_matrix.sh
scripts/cleanup.sh
```

`scripts/setup.sh`, which `pq_matrix.sh` calls, deletes and recreates `run/`, the folder holding the emulator state and throwaway lab credentials.
