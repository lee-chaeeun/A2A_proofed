#!/usr/bin/env bash
# Runner controls for scripts/v3final.sh: injected command failures must make the
# WHOLE runner exit nonzero, while the expected historical-audit control (exit 2)
# still passes. No full matrix is run: the build/matrix controls fail before any lab
# process starts, and the audit/test controls use --audit-only on a COPY of an
# existing run. Usage: scripts/test_v3final_runner.sh <existing run dir>
set -uo pipefail
cd "$(dirname "$0")/.."
RUN=${1:?existing run dir}
W=$(mktemp -d)
# fail-on wrapper: exits 1 when any argument equals $FAIL_TOKEN, else execs the command.
cat > "$W/failon" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do if [ "$a" = "$FAIL_TOKEN" ]; then echo "INJECTED FAILURE on '$a'" >&2; exit 1; fi; done
exec "$@"
EOF
chmod +x "$W/failon"
# a `go` stub that fails only for the injected subcommand
cat > "$W/go" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "$FAIL_TOKEN" ]; then echo "INJECTED go $1 FAILURE" >&2; exit 1; fi
exec "$(command -v go)" "$@"
EOF
chmod +x "$W/go"
pass=0; fail=0
check() { # check <name> <expected-exit> <cmd...>
  local name=$1 want=$2; shift 2
  "$@" > "$W/$name.log" 2>&1; local got=$?
  if [ "$got" -eq "$want" ]; then echo "PASS control: $name (exit $got)"; pass=$((pass+1)); else echo "FAIL control: $name (exit $got, expected $want)"; tail -5 "$W/$name.log"; fail=$((fail+1)); fi
}
# 1. build failure: `go build` fails -> runner must stop before anything else (no lab started)
check build-failure 1 env FAIL_TOKEN=build GO="$W/go" OUT="$W/out" SNAP_ROOT="$W/snap" scripts/v3final.sh
grep -q 'GATE FAILED: go build' "$W/build-failure.log" && echo "  (stopped at the build gate)"
# 2. matrix failure: build succeeds, the matrix invocation fails -> no run path, runner fails
check matrix-failure 1 env FAIL_TOKEN=matrix A2AID_WRAP="$W/failon" OUT="$W/out" SNAP_ROOT="$W/snap" scripts/v3final.sh
grep -q 'GATE FAILED: matrix' "$W/matrix-failure.log" && echo "  (stopped at the matrix gate; no stale run attached)"
# 3. unexpected audit result on an existing run copy -> runner fails
cp -r "$RUN" "$W/runcopy"
check audit-failure 1 env FAIL_TOKEN=audit-release A2AID_WRAP="$W/failon" scripts/v3final.sh --audit-only "$W/runcopy"
# 4. test failure -> runner fails (audit gates pass first)
rm -rf "$W/runcopy2"; cp -r "$RUN" "$W/runcopy2"
check test-failure 1 env FAIL_TOKEN=test GO="$W/go" scripts/v3final.sh --audit-only "$W/runcopy2"
grep -q 'GATE FAILED: audit negative controls' "$W/test-failure.log" && echo "  (audits passed, stopped at the first test gate)"
# 5. positive control: --audit-only on an intact copy passes, with the historical audit asserted at exit 2
rm -rf "$W/runcopy3"; cp -r "$RUN" "$W/runcopy3"
check audit-only-pass 0 scripts/v3final.sh --audit-only "$W/runcopy3"
grep -q 'gate ok: historical-schema audit (expected exit 2) (exit 2)' "$W/audit-only-pass.log" && echo "  (historical-schema control asserted at exit 2)"
echo "runner controls: $pass passed, $fail failed (logs in $W)"
[ "$fail" -eq 0 ]
