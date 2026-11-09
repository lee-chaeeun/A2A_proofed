# Experiment 2: TPM quote comparison

Does a TPM quote protect better than a software signature? Agents answer Alice's challenge with a software signature, a software-signed COSE response, a swtpm quote, or a quote inside our own signed COSE response (some fields follow the PTV draft). The checked register holds an operator-chosen string.

In records, deployment A is Bob and deployment B is Mallory.

| Configuration | Identifier | Alice checks |
|---|---|---|
| Card | `C` | the Agent Card signature only |
| File key, Service key | `S-file`, `S-iso` | a signature from a key file or the signing service |
| Envelope | `S-env` | a software-signed COSE response |
| Quote | `T` | a TPM quote and its register value |
| COSE-wrapped quote | `P` | a quote inside our signed COSE response |
| Endpoint only | `+url` | Bob's address (plain HTTP) |
| Baseline | `+tls` | address and TLS |
| bound | `+cb` | baseline plus channel binding |

Identifiers combine, so `T+cb` is Quote (bound). A proof without a suffix is checked without address and TLS.

## Saved runs

| Folder | |
|---|---|
| `results/binding/20261108-004047` | focused comparison, 24 tests (`fixtures/manifest-binding.json`) |
| `results/broad/20261107-194025` | broad comparison, 201 applicable tests (`fixtures/manifest-broad.json`); summary files only |

## Check the saved run

```sh
go test -race -count=1 ./...
go build -o bin/a2aid ./cmd/a2aid
cp -R results/binding/20261108-004047 /tmp/binding-check
bin/a2aid audit-release --results /tmp/binding-check
```

`audit-release` writes into the folder it checks, so give it a copy. Expect `NO UNEXPECTED VIOLATION (8 fixture-predicted attack successes ...) exit=0`. The broad run lacks per-test records and cannot be re-checked; see `reverify.md` in its folder.

Rerun (needs swtpm): `scripts/binding_matrix.sh` or `scripts/broad_matrix.sh`, then `scripts/cleanup.sh`.
