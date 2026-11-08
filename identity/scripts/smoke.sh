#!/usr/bin/env bash
# Smoke: honest baseline (F1) under every broad-matrix policy against the running lab.
set -euo pipefail
cd "$(dirname "$0")/.."
bin/a2aid matrix --run-dir "${RUN_DIR:-run}" --fixtures F1 --out "${OUT:-results/smoke}"
