#!/usr/bin/env bash
# Focused binding matrix runner (fixtures/manifest-binding.json). Every mandatory gate
# fails the whole command on an unexpected status; the audit of a record without the
# schema-2 fields is asserted to exit EXACTLY 2; the tree and snapshot binaries must
# hash-equal; the run path is handed over exactly by the matrix.
#
#   scripts/binding_matrix.sh                 full: snapshot, build, matrix, continuity, audits, tests
#   scripts/binding_matrix.sh --audit-only R  run the audit/test gates on existing run dir R
#
# Test hooks (used only by scripts/test_binding_runner.sh): GO (default go),
# A2AID_WRAP (a command prefix put before bin/a2aid invocations), OUT, SNAP_ROOT.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-buildvcs=false
GO=${GO:-go}
A2AID_WRAP=${A2AID_WRAP:-}
OUT=${OUT:-results/binding}
SNAP_ROOT=${SNAP_ROOT:-results/snapshots}
UNSUPPORTED_RUN=${UNSUPPORTED_RUN:-fixtures/testdata/unsupported-schema-run}

a2aid() { ${A2AID_WRAP} bin/a2aid "$@"; }
gate() { # gate <name> <expected-status> <cmd...>; logs are preserved by the callers
  local name=$1 want=$2; shift 2
  set +e; "$@"; local got=$?; set -e
  if [ "$got" -ne "$want" ]; then echo "GATE FAILED: $name (exit $got, expected $want)" >&2; exit 1; fi
  echo "gate ok: $name (exit $got)"
}

audit_gates() { # audit_gates <run dir (absolute)>
  local RUN=$1
  : > "$RUN/audit-exit-codes.txt"
  for d in "$RUN" "$RUN/continuity/S-env_cb" "$RUN/continuity/T_cb"; do
    gate "audit $d" 0 a2aid audit-release --results "$d" | tee -a "$RUN/audit-exit-codes.txt"
  done
  mkdir -p "$RUN/audit-unsupported-schema"
  rm -rf "$RUN/audit-unsupported-schema/copy"
  cp -r "$UNSUPPORTED_RUN" "$RUN/audit-unsupported-schema/copy"
  rm -f "$RUN/audit-unsupported-schema/copy"/release-audit*
  # expected control: records without the schema-2 fields are unsupported -> exit 2 exactly
  gate "unsupported-schema audit (expected exit 2)" 2 a2aid audit-release --results "$RUN/audit-unsupported-schema/copy" | tee -a "$RUN/audit-exit-codes.txt"
  gate "audit negative controls" 0 sh -c "$GO test -count=1 -race -v ./internal/audit/ > '$RUN/audit-negative-controls.log' 2>&1"
  gate "go test -race ./..." 0 sh -c "$GO test -race -count=1 ./... > '$RUN/go-test-race.log' 2>&1"
  gate "opt-in integration (lab ports)" 0 sh -c "A2AID_INTEGRATION=1 $GO test -count=1 -run Integration -v ./internal/matrix > '$RUN/integration-test.log' 2>&1"
}

if [ "${1:-}" = "--audit-only" ]; then
  RUN=$(cd "$2" && pwd)
  audit_gates "$RUN"
  echo "done (audit-only): $RUN"
  exit 0
fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
SNAP=$SNAP_ROOT/$TS-binding-snapshot
mkdir -p "$SNAP" bin
echo "== snapshot $SNAP"
tar czf "$SNAP/source-binding.tar.gz" --exclude='./run' --exclude='./results' --exclude='./bin' --exclude='*.pdf' .
{ find cmd internal fixtures scripts -type f | sort | xargs sha256sum; sha256sum go.mod go.sum *.md; } > "$SNAP/source-sha256-binding.txt"
sha256sum "$SNAP/source-binding.tar.gz" > "$SNAP/tarball-sha256.txt"

echo "== build (trimpath) from the working tree and from the extracted snapshot"
gate "go build (tree)" 0 $GO build -trimpath -o bin/a2aid ./cmd/a2aid
X=$(mktemp -d); tar xzf "$SNAP/source-binding.tar.gz" -C "$X"
gate "go build (snapshot)" 0 sh -c "cd '$X' && $GO build -trimpath -o '$X/a2aid-from-snapshot' ./cmd/a2aid"
H1=$(sha256sum bin/a2aid | cut -d' ' -f1); H2=$(sha256sum "$X/a2aid-from-snapshot" | cut -d' ' -f1)
printf '%s  bin/a2aid\n%s  a2aid-from-snapshot\n' "$H1" "$H2" | tee "$SNAP/binary-sha256-binding.txt"
rm -rf "$X"
if [ "$H1" != "$H2" ]; then echo "GATE FAILED: tree and snapshot binaries differ" >&2; exit 1; fi
echo "gate ok: binaries identical"

echo "== matrix: 24-cell binding subset"
RUNFILE=$(mktemp)
gate "matrix" 0 sh -c "a2aid() { ${A2AID_WRAP} bin/a2aid \"\$@\"; }; a2aid matrix --run-dir run --out '$OUT' --manifest fixtures/manifest-binding.json --predictions fixtures/predictions-binding.md --races=false --run-path-file '$RUNFILE' > '$SNAP/matrix-stdout.txt' 2>&1"
RUN=$(cat "$RUNFILE"); rm -f "$RUNFILE"
[ -n "$RUN" ] && [ -d "$RUN" ] || { echo "GATE FAILED: matrix did not hand over a run path" >&2; exit 1; }
RUN=$(cd "$RUN" && pwd)
echo "run=$RUN" | tee -a "$SNAP/matrix-stdout.txt"
cp "$SNAP/source-sha256-binding.txt" "$SNAP/binary-sha256-binding.txt" "$RUN/"
echo "$SNAP" > "$RUN/snapshot-id.txt"
gate "reverify" 0 sh -c "a2aid() { ${A2AID_WRAP} bin/a2aid \"\$@\"; }; a2aid reverify --results '$RUN' > '$RUN/reverify-stdout.txt'"

echo "== continuity + churn (evidence into the run)"
gate "continuity/churn/regression tests" 0 sh -c "A2AID_EVIDENCE_DIR='$RUN' $GO test -count=1 -race -run 'ContinuityFinal|ChurnFinal|Continuity_|Churn_|Regression' -v ./internal/verifier/ > '$RUN/continuity-test.log' 2>&1"
grep -E '^(--- |    --- |ok|FAIL|PASS)|churn policy' "$RUN/continuity-test.log" | grep -v 'TLS handshake' > "$RUN/continuity-test-summary.txt" || true

echo "== release-evidence audits and test passes"
audit_gates "$RUN"
echo "done: $RUN"
