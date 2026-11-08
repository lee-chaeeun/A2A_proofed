#!/usr/bin/env bash
# Clean setup: build, start two swtpm TPM 2.0 emulators from empty state, create the
# lab CA and server certificates, provision A and B.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-buildvcs=false
RUN=${RUN_DIR:-run}
./scripts/cleanup.sh >/dev/null 2>&1 || true
mkdir -p "$RUN" bin
go build -o bin/a2aid ./cmd/a2aid
sha256sum bin/a2aid
bin/a2aid setup --run-dir "$RUN"
