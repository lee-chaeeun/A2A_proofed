#!/usr/bin/env bash
# Failure-injection tests for scripts/pq_matrix.sh. Stubs replace the expensive stages
# (setup, matrix, tests); the stub matrix copies the six-cell fixture run so that the
# REAL mutation-control script and expectation table can run against a stub or the real
# audit binary. Every case asserts the runner's exit status. No lab is started.
#
# usage: scripts/test_pq_runner.sh            (uses bin/a2aid for the real-audit cases)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
T=$(mktemp -d "${TMPDIR:-/tmp}/pq-runner-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/stub" "$T/out" "$T/audit"
FIX=$ROOT/fixtures/testdata/pq-mini-run

# stub a2aid: matrix copies the fixture run and hands its path over; audit-pq exits
# with STUB_AUDIT_EXIT (and writes a summary); everything else succeeds.
cat > "$T/stub/a2aid" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd=$1; shift
case "$cmd" in
  matrix)
    out=""; rp=""
    while [ $# -gt 0 ]; do case "$1" in --out) out=$2; shift 2;; --run-path-file) rp=$2; shift 2;; *) shift;; esac; done
    [ "${STUB_MATRIX_EXIT:-0}" = 0 ] || exit "$STUB_MATRIX_EXIT"
    run="$out/stub-$(date -u +%Y%m%d-%H%M%S)-$$"
    cp -R "$STUB_FIXTURE_RUN" "$run"
    if [ "${STUB_BAD_RUNPATH:-0}" = 1 ]; then echo "/nonexistent/run-dir" > "$rp"; else echo "$run" > "$rp"; fi
    ;;
  audit-pq)
    out=""; res=""
    while [ $# -gt 0 ]; do case "$1" in --results) res=$2; shift 2;; --out) out=$2; shift 2;; *) shift;; esac; done
    [ -n "$out" ] || out=$res
    mkdir -p "$out"; echo "{\"exit_code\": ${STUB_AUDIT_EXIT:-0}, \"agree\": 6}" > "$out/pq-audit-summary.json"
    exit "${STUB_AUDIT_EXIT:-0}"
    ;;
  *) exit 0;;
esac
EOF
chmod +x "$T/stub/a2aid"
cat > "$T/stub/controls_ok.py" <<'EOF'
import sys; print("stub controls: all as expected"); sys.exit(0)
EOF

export STUB_FIXTURE_RUN=$FIX A2AID_SETUP=true A2AID_GOTEST=true A2AID_OUT=$T/out A2AID_AUDIT_OUT=$T/audit TMPDIR=$T
fails=0
run_case() { # name expected_status env...
  local name=$1 want=$2; shift 2
  set +e
  ( env "$@" scripts/pq_matrix.sh ) > "$T/$name.log" 2>&1
  local got=$?
  set -e
  if [ "$want" = "nonzero" ] && [ "$got" -ne 0 ]; then echo "PASS $name (exit $got)"; return; fi
  if [ "$want" != "nonzero" ] && [ "$got" -eq "$want" ]; then echo "PASS $name (exit $got)"; return; fi
  echo "FAIL $name: exit $got, wanted $want"; tail -5 "$T/$name.log"; fails=$((fails+1))
}

# 1. every stage succeeds (stub audit clean, stub controls clean) -> 0
run_case all-stages-pass 0 A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" STUB_AUDIT_EXIT=0
# 2. audit rejects (exit 1: violation/disagreement) -> runner non-zero
run_case audit-violation nonzero A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" STUB_AUDIT_EXIT=1
# 3. audit incomplete (exit 2) -> runner non-zero
run_case audit-incomplete nonzero A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" STUB_AUDIT_EXIT=2
# 4. a mutation control unexpectedly exits clean: the stub audit says 0 for every
#    mutation, the REAL control script with the frozen table must fail the runner
run_case control-unexpectedly-clean nonzero A2AID_BIN="$T/stub/a2aid" STUB_AUDIT_EXIT=0
# 5. matrix stage fails -> non-zero
run_case matrix-fails nonzero A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" STUB_MATRIX_EXIT=7
# 6. run-path handoff points nowhere -> exit 3
run_case bad-run-path 3 A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" STUB_BAD_RUNPATH=1
# 7. setup fails -> non-zero
run_case setup-fails nonzero A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" A2AID_SETUP=false
# 8. required tests fail -> non-zero
run_case tests-fail nonzero A2AID_BIN="$T/stub/a2aid" A2AID_CONTROLS="$T/stub/controls_ok.py" A2AID_GOTEST=false
# 9. real audit binary + real controls on the fixture run through the runner -> 0
REAL_BIN=${A2AID_RUNNER_TEST_BIN:-$ROOT/bin/a2aid}
if [ -x "$REAL_BIN" ]; then
  cat > "$T/stub/a2aid-real" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ "\$1" = matrix ]; then exec "$T/stub/a2aid" "\$@"; fi
exec "$REAL_BIN" "\$@"
EOF
  chmod +x "$T/stub/a2aid-real"
  run_case real-audit-and-controls 0 A2AID_BIN="$T/stub/a2aid-real"
else
  echo "SKIP real-audit-and-controls (set A2AID_RUNNER_TEST_BIN or build bin/a2aid)"
fi
echo "runner failure-injection: $fails failure(s)"
[ "$fails" -eq 0 ]
