# Classical identity experiment

Scripted A2A deployments answer a fresh challenge with a software signature, a software-signed COSE envelope or a swtpm quote, and the requester delivers a synthetic task only if the configured checks pass. The matched software and TPM proofs separate the effect of the protocol from the effect of where the key lives. Design and limits: [DESIGN.md](../docs/DESIGN.md); findings: [RESULTS.md](../docs/RESULTS.md); packages: [CODE_MAP.md](../docs/CODE_MAP.md).

## Configurations

| Paper name | Policy identifier | Added check |
|---|---|---|
| Card only | `C` | Enrolled publisher's Agent Card signature |
| File key, Service key | `S-file`, `S-iso` | Fresh signature from a key in the application files or in the signing service |
| Software envelope | `S-env` | Software-signed COSE envelope over the request context |
| TPM quote | `T` | Fresh TPM quote and comparison with the enrolled PCR reference |
| PTV quote | `P` | TPM quote inside a PTV-style signed response |
| Endpoint only | `+url` | Endpoint matches the signed card |
| Baseline | `+tls` | Endpoint plus TLS authenticated with the enrolled name |
| (bound) | `+cb` | Baseline plus a proof bound to the requester's TLS connection, delivered on that connection only |

Proof identifiers combine with a transport suffix (for example `T+cb` = *TPM quote (bound)*); without a suffix the proof is checked without endpoint or TLS checks.

## Published records

| Directory | Contents |
|---|---|
| `results/binding/20261108-004047` | Focused 24-cell matrix (`fixtures/manifest-binding.json`) with continuity and churn cases and audit reports |
| `results/broad/20261107-194025` | Broad 21-scenario × 11-configuration matrix (`fixtures/manifest-broad.json`) |

## Commands

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
cp -R results/binding/20261108-004047 /tmp/binding-check
bin/a2aid audit-release --results /tmp/binding-check
```

The release audit writes its report into the directory it checks, so audit a copy. Fresh runs need swtpm: `scripts/binding_matrix.sh` or `scripts/broad_matrix.sh`, followed by `scripts/cleanup.sh`.
