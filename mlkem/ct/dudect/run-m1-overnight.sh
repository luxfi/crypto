#!/usr/bin/env bash
# ML-KEM decaps dudect — Apple M1 overnight run (~14 hours for 10^9 samples)
#
# Methodology: 10000 samples/batch × 100000 batches = 10^9 samples.
# 100000 batches is the cap; dudect will exit early as DUDECT_LEAKAGE_FOUND
# or run to the cap and print "no leakage detected within budget".
#
# To get clean timing data on M1:
#   - close all other apps before launching
#   - plug in power
#   - prevent sleep via `caffeinate -d -i -m`
#   - disable Spotlight indexing: `sudo mdutil -a -i off`  (re-enable after with `-i on`)
#   - close Time Machine + iCloud sync
#
# Usage:
#   ./run-m1-overnight.sh decaps     # default
#   ./run-m1-overnight.sh encaps
#   ./run-m1-overnight.sh keygen

set -euo pipefail

TARGET="${1:-decaps}"
BIN="./dudect_${TARGET}"
[ -x "$BIN" ] || { echo "build first: make $TARGET"; exit 1; }

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
OS="$(uname -srm)"
TAG="m1-${TARGET}-${STAMP}"
LOG="results/${TAG}.log"
META="results/${TAG}.meta"

echo "==> ML-KEM ${TARGET} dudect run" | tee "$META"
echo "    CPU: $CPU" | tee -a "$META"
echo "    OS:  $OS" | tee -a "$META"
echo "    started: $STAMP" | tee -a "$META"
echo "    samples/batch: 10000" | tee -a "$META"
echo "    batch cap: 100000  (target 10^9 total samples)" | tee -a "$META"
echo "    binary: $BIN" | tee -a "$META"
echo "    log: $LOG" | tee -a "$META"
echo "" | tee -a "$META"

# Wrap with caffeinate to keep machine awake; redirect everything to log.
exec caffeinate -d -i -m \
    env DUDECT_SAMPLES=10000 DUDECT_MAX_BATCHES=100000 \
    "$BIN" 2>&1 | tee "$LOG"
