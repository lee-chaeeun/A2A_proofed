#!/usr/bin/env bash
# Stop emulators and helper processes, remove all runtime state (keys, TPM state, sockets, certificates).
cd "$(dirname "$0")/.."
RUN=${RUN_DIR:-run}
for p in "$RUN"/tpm*/pid "$RUN"/fwtpm*/pid "$RUN"/pids/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
pkill -f "bin/a2aid (controller|gate|agent)" 2>/dev/null
sleep 0.3
rm -rf "$RUN"
echo "cleaned $RUN"
