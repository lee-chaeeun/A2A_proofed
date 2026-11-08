#!/usr/bin/env bash
# Unit + emulator e2e tests with the race detector, then short fuzz budgets.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-buildvcs=false
go test -race -count=1 ./...
for spec in "internal/tpmsig FuzzVerifyQuote" "internal/ptv FuzzOpen" "internal/ptv FuzzDecodeEvidence" "internal/senv FuzzOpen" "internal/wire FuzzNormalizeURL" "internal/wire FuzzParsePolicy"; do
  set -- $spec
  go test -run '^$' -fuzz "^$2\$" -fuzztime "${FUZZTIME:-20s}" "./$1"
done
