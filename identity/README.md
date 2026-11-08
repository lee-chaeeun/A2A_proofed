# TPM identity over A2A

This is the final identity implementation. It runs scripted A2A requester and agent
processes, obtains fresh software or TPM proofs, and gates task delivery on the selected
policy. TPM operations use swtpm; no physical key-protection measurement is claimed.

## Tools and design

- [A2A Go SDK](https://github.com/a2aproject/a2a-go): discovery, JSON-RPC and task artifacts.
- [swtpm](https://github.com/stefanberger/swtpm) and [go-tpm](https://github.com/google/go-tpm): TPM commands and emulator-backed attestation keys.
- [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01): routine attestation-response design reference.
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html): TLS exporter channel binding.

The physical-TPM motivation and its assumptions are explained in
[hardware and PTV](../docs/HARDWARE_AND_PTV.md). Package responsibilities:
`registry` enrollments; `cardsig` signed discovery; `tpmsig` TPM evidence; `ptv` outer
response; `senv` software-envelope control; `gate` harness signer permissions; `verifier`
appraisal and dispatch; `matrix` evaluation; `audit` release-evidence checks.

## Policies

| Policy | Added check |
|---|---|
| C | Enrolled publisher's Agent Card signature |
| S-file | Fresh proof using a software key copied with the application |
| S-iso | Fresh proof from a gated software signer |
| S-env | Signed software envelope covering request context |
| T | Fresh TPM quote and synthetic PCR reference appraisal |
| P | TPM quote plus checked PTV routine response |
| +url | Enrolled endpoint equality |
| +tls | Endpoint checks plus enrolled-name authenticated TLS |
| +cb | TLS plus own-connection-bound proof and pinned task dispatch |

The software controls separate protocol effects from key-custody assumptions. All
processes share one OS account; the gate is a simulated permission boundary. TLS uses
freshly generated lab credentials. Actual workload integrity and physical TPM extraction
resistance are outside the measured scope.

## Build and inspect retained results

From this directory:

```sh
go build -o bin/a2aid ./cmd/a2aid
go test -race -count=1 ./...
cp -R results/v3-final/20261108-004047 /tmp/a2a-proofed-identity-check
bin/a2aid audit-release --results /tmp/a2a-proofed-identity-check
```

Use a fresh destination for each audit copy. Results and file meanings:
[RESULTS.md](../docs/RESULTS.md), [artifact inventory](../docs/ARTIFACT_INVENTORY.md).

## Run a fresh experiment

Requires Go and swtpm, with loopback ports available. Setup resets live state under
`run/`, including emulators and disposable lab credentials. Do not run simultaneous labs.

```sh
./scripts/setup.sh
./scripts/v3final.sh
```

The runner's name is retained for compatibility; it runs the final focused binding
matrix, continuity/churn checks and audit/test gates. Its historical-schema negative
control uses the selected `results/v3/` input. That directory is test evidence, not a
second implementation. `scripts/matrix.sh` runs the broader 21-fixture comparison.

The release checker validates complete supported records and reports expected weak-policy
attack outcomes separately. It relies on cooperative observations, not tamper-proof logs.
