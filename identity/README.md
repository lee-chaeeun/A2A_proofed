# Experiment 2: TPM quote comparison

**Question:** does a TPM quote protect Alice better than an ordinary software signature?

A **TPM quote** is a report of the values in a TPM's platform configuration registers (PCRs), signed by a TPM key that Alice has registered. Here the TPM is swtpm, a software emulator, and the checked register holds a string chosen by the operator, not a measurement of running software.

Scripted A2A servers answer Alice's fresh challenge in one of four ways: a software signature; a software-signed COSE response (COSE is a standard format for signed binary data); a TPM quote; or a TPM quote inside a signed COSE response that we designed. Some fields and checks of that last response are taken from the Prove-Transform-Verify (PTV) Internet-Draft, a work-in-progress proposal; it is our own design, not an implementation of PTV. Matching software and TPM versions separate the effect of the message format from the effect of where the key is kept.

**Names in the saved records:** deployment A (Atlas) is Bob, the intended recipient, and deployment B (Boreas) is Mallory, the attacker. `accept → B` means Mallory received the task.

More: [DESIGN.md](../docs/DESIGN.md), [RESULTS.md](../docs/RESULTS.md), [CODE_MAP.md](../docs/CODE_MAP.md).

## Configurations

| Name in the paper | Identifier in records | What Alice checks |
|---|---|---|
| Card | `C` | Only the signature on Bob's Agent Card |
| File key, Service key | `S-file`, `S-iso` | A fresh signature from a key in Bob's files, or from the signing service |
| Envelope | `S-env` | A software-signed COSE response over the request |
| Quote | `T` | A fresh TPM quote, compared with the registered register value |
| COSE-wrapped quote | `P` | A TPM quote inside our signed COSE response |
| Endpoint only | `+url` | Bob's address matches the signed card (plain HTTP) |
| Baseline | `+tls` | Bob's address, plus TLS with Bob's registered server name |
| (bound) | `+cb` | Baseline, plus TLS channel binding: the proof is tied to Alice's connection, and the task goes only on that connection |

Identifiers combine: `T+cb` is *Quote (bound)*. A proof identifier without a suffix is checked without the address and TLS checks.

## Saved records

| Folder | Contents |
|---|---|
| `results/binding/20261108-004047` | Focused comparison: 24 tests (`fixtures/manifest-binding.json`), connection-continuity trials, and verification-script reports |
| `results/broad/20261107-194025` | Broad comparison: 21 scenarios × 11 configurations = 231 cases, 201 applicable (`fixtures/manifest-broad.json`). Results table and the report written when the data was collected; no per-test records |

## Check the saved run

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
cp -R results/binding/20261108-004047 /tmp/binding-check
bin/a2aid audit-release --results /tmp/binding-check
```

`audit-release` is the verification script for the focused comparison. It checks the saved records without running the agents again and compares each outcome with the prediction recorded before testing. It writes its report into the folder it checks, so check a copy. Expected: `NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes ...) exit=0`. The 8 are predicted tests in which Mallory received Bob's task.

The broad comparison was re-checked with `a2aid reverify` when the data was collected (`reverify.md`: 217 of 217 agree). The published copy lacks the per-test records that command reads, so it cannot be re-run here.

## Run it again (optional)

Needs swtpm: `scripts/binding_matrix.sh` or `scripts/broad_matrix.sh`, then `scripts/cleanup.sh`.
