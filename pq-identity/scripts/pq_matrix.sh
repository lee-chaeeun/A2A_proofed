#!/usr/bin/env bash
# PQ identity matrix runner: build, setup (swtpm + wolfTPM fwTPM devices), the 128-cell
# run, the composite PQ audit, the asserting mutation controls and the race suite.
# Every stage is a gate: the script exits non-zero at the first failing stage (no
# `|| true`); expected attack outcomes live in the declared inventory, never in shell
# error suppression. Needs .toolchain (scripts/build_pq_toolchain.sh).
#
# Overrides (used by scripts/test_pq_runner.sh for failure injection with stubs):
#   A2AID_BIN       binary to run (default: build bin/a2aid from source)
#   A2AID_SETUP     setup command (default ./scripts/setup.sh)
#   A2AID_CONTROLS  mutation-control script (default scripts/pq_audit_controls.py)
#   A2AID_EXPECTED  expectation table for the controls (default fixtures/pq-audit-controls-expected.json)
#   A2AID_GOTEST    test command (default: go test -race -count=1 ./...)
#   A2AID_OUT / A2AID_AUDIT_OUT   output roots (default results/pq, results/audit)
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-buildvcs=false
BIN=${A2AID_BIN:-bin/a2aid}
SETUP=${A2AID_SETUP:-./scripts/setup.sh}
CONTROLS=${A2AID_CONTROLS:-scripts/pq_audit_controls.py}
EXPECTED=${A2AID_EXPECTED:-fixtures/pq-audit-controls-expected.json}
GOTEST=${A2AID_GOTEST:-go test -race -count=1 ./...}
OUTROOT=${A2AID_OUT:-results/pq}
AUDITROOT=${A2AID_AUDIT_OUT:-results/audit}

F=$(mktemp "${TMPDIR:-/tmp}/pq-matrix-runpath.XXXXXX")
trap 'rm -f "$F"' EXIT
stage() { echo "[pq_matrix] $(date -u +%H:%M:%SZ) $1"; }

if [ -z "${A2AID_BIN:-}" ]; then
  stage "build"
  go build -o bin/a2aid ./cmd/a2aid
fi
stage "setup ($SETUP)"
$SETUP
stage "matrix"
"$BIN" matrix --manifest fixtures/manifest-pq.json --predictions fixtures/predictions-pq.md --out "$OUTROOT" --races=false --run-path-file "$F"
RUN=$(head -n1 "$F" | tr -d '\r')
if [ -z "$RUN" ] || [ ! -d "$RUN" ] || [ ! -f "$RUN/run-inventory.json" ]; then
  echo "[pq_matrix] run-path handoff invalid: '$RUN' (no directory or no run-inventory.json)" >&2
  exit 3
fi
stage "audit-pq on $RUN (exit code is the gate)"
"$BIN" audit-pq --results "$RUN"
stage "mutation controls (every expected exit code asserted)"
python3 -I "$CONTROLS" --bin "$BIN" --run "$RUN" --out "$AUDITROOT/$(date -u +%Y%m%dT%H%M%SZ)-pq-audit-controls" --expected "$EXPECTED"
stage "tests ($GOTEST)"
$GOTEST
stage "done"
echo "run: $RUN"
