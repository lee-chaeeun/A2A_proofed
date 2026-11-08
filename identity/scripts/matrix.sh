#!/usr/bin/env bash
# Full v2 matrix: 20 fixtures x 11 policies plus randomized race trials, then the
# offline reverification of the run just produced.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-results/v2}
bin/a2aid matrix --run-dir "${RUN_DIR:-run}" --out "$OUT"
LATEST=$(ls -d "$OUT"/*/ | sort | tail -1)
bin/a2aid reverify --results "$LATEST"
bin/a2aid audit-release --results "$LATEST" || echo "audit-release exit $? (0 clean, 1 violation, 2 incomplete)"
bin/a2aid traces --results "$LATEST"
