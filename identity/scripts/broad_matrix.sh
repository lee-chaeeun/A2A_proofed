#!/usr/bin/env bash
# Broad classical matrix (fixtures/manifest-broad.json: 21 fixtures x 11 policies) plus
# randomized release-race trials, then offline reverification, the structural release
# audit and trace export of the run just produced.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-results/broad}
bin/a2aid matrix --run-dir "${RUN_DIR:-run}" --out "$OUT"
LATEST=$(ls -d "$OUT"/*/ | sort | tail -1)
bin/a2aid reverify --results "$LATEST"
bin/a2aid audit-release --results "$LATEST" || echo "audit-release exit $? (0 clean, 1 violation, 2 incomplete)"
bin/a2aid traces --results "$LATEST"
