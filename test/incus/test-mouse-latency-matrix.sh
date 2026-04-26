#!/usr/bin/env bash
# Run the full 12-cell #905 mouse-latency matrix.
#
# Usage: test-mouse-latency-matrix.sh <out_root>
#
# 12 cells: N ∈ {0, 8, 32, 128} × M ∈ {1, 10, 50}.
# Per cell: 10 reps baseline, auto-extend to 15 if INVALID rate > 30%
# in the first 10. Cell stops at 10 valid reps OR 15 total, whichever
# is first.
#
# Cells run in PASS-gate-relevant order so a wall-budget truncation
# degrades gracefully:
#   1. (0, 10)   ← idle baseline of the gate
#   2. (128, 10) ← loaded measurement of the gate
#   then (8, 10), (32, 10), and the rest of the matrix.
#
# Run echo-server preflight first (plan §4.6); abort if it fails.
#
# Total wall budget cap: 6 hours (plan §4.7).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <out_root>" >&2
    exit 1
fi

OUT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DURATION=60          # per-rep probe seconds
WALL_CAP=$((6*3600)) # seconds, plan §4.7

mkdir -p "$OUT_ROOT"

# Prioritized cell order: gate cells first, then remaining M=10 cells,
# then everything else.
CELLS=(
    "0 10"
    "128 10"
    "8 10"
    "32 10"
    "0 1"
    "8 1"
    "32 1"
    "128 1"
    "0 50"
    "8 50"
    "32 50"
    "128 50"
)

start_t=$(date +%s)

# ---- echo-server preflight (plan §4.6)
PREFLIGHT_DIR="${OUT_ROOT}/preflight"
mkdir -p "$PREFLIGHT_DIR"
echo "Running echo-server preflight..."
"${SCRIPT_DIR}/test-mouse-latency.sh" 0 1 60 "$PREFLIGHT_DIR" || true

# R2 fresh MED 2: orchestrator INVALIDates by writing a marker file
# and exiting 0; preflight must check the marker file too, not just
# the orchestrator exit code.
if compgen -G "${PREFLIGHT_DIR}/INVALID-*" > /dev/null 2>&1; then
    echo "preflight invalidated; aborting matrix" >&2
    ls "$PREFLIGHT_DIR" >&2
    exit 1
fi
if [[ ! -f "$PREFLIGHT_DIR/probe.json" ]]; then
    echo "preflight produced no probe.json; aborting" >&2
    exit 1
fi
preflight=$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
p = d["rtt_us"]["p99"]
err = d["totals"]["error_rate"]
v = d.get("validity", {}).get("ok", False)
reasons = d.get("validity", {}).get("reasons", [])
# R3 MED: also gate on the probes own validity verdict (e.g.
# min-attempts floor, degenerate-coroutine), not just p99/error_rate.
if not v:
    print(f"FAIL validity={reasons}")
elif p is None or p >= 5000:
    print(f"FAIL p99={p}")
elif err >= 0.001:
    print(f"FAIL err={err}")
else:
    print("OK")
' "$PREFLIGHT_DIR/probe.json")
if [[ "$preflight" != "OK" ]]; then
    echo "preflight failed: $preflight" >&2
    exit 1
fi
echo "preflight OK"

rep_is_valid() {
    # Combine: probe.json validity AND no INVALID-* marker file (the
    # orchestrator writes those for HA transitions, RG flaps, elephant
    # collapse, client saturation, etc.).
    local rep_dir="$1"
    if compgen -G "${rep_dir}/INVALID-*" > /dev/null 2>&1; then
        return 1
    fi
    if [[ ! -f "${rep_dir}/probe.json" ]]; then
        return 1
    fi
    python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["validity"]["ok"] else 1)' \
        "${rep_dir}/probe.json"
}

run_cell() {
    local N="$1" M="$2"
    local cell_dir="${OUT_ROOT}/cell_N${N}_M${M}"
    mkdir -p "$cell_dir"
    local valid=0
    local total=0
    local hard_cap=15  # plan §4.7: 15-rep ceiling
    # Per plan §4.7: keep going until 10 valid OR 15 total. Both
    # ordinary replacements (any INVALID rep) AND auto-extension
    # (the >30% rule) draw from the same ceiling. R1 HIGH 2.
    while [[ $total -lt $hard_cap && $valid -lt 10 ]]; do
        # Wall budget guard.
        local now=$(date +%s)
        if [[ $((now - start_t)) -gt $WALL_CAP ]]; then
            echo "wall-budget cap reached, stopping matrix" >&2
            return 0
        fi
        local rep_dir="${cell_dir}/rep_$(printf '%02d' $total)"
        mkdir -p "$rep_dir"
        echo "  cell N=$N M=$M rep=$total ..."
        "${SCRIPT_DIR}/test-mouse-latency.sh" "$N" "$M" "$DURATION" "$rep_dir" || true
        if rep_is_valid "$rep_dir"; then
            valid=$((valid + 1))
        fi
        total=$((total + 1))
    done

    echo "  cell N=$N M=$M done: $valid valid / $total total"
}

for cell in "${CELLS[@]}"; do
    read -r N M <<< "$cell"
    run_cell "$N" "$M"
done

echo "Matrix complete; running aggregator..."
python3 "${SCRIPT_DIR}/mouse_latency_aggregate.py" \
    --root "$OUT_ROOT" \
    --out "${OUT_ROOT}/summary.json"
