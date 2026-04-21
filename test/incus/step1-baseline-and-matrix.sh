#!/usr/bin/env bash
#
# step1-baseline-and-matrix.sh — orchestrator for issue #816 step1 re-run.
#
# Captures 3 baseline pools (5 runs each) + 12 matrix cells by calling
# step1-capture.sh in sequence, relocating the per-run output into
# docs/pr/816-step1-rerun/evidence/ per plan §13.
#
# Exit early on hard-stop conditions; caller must inspect logs.
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SRC_EVIDENCE="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence"
DST_EVIDENCE="$REPO_ROOT/docs/pr/816-step1-rerun/evidence"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

run_cell() {
    local port="$1"
    local dir="$2"
    local cos="$3"
    local dest_dir="$4"

    log "CAPTURE p${port}-${dir}-${cos} -> ${dest_dir}"
    rm -rf "$SRC_EVIDENCE/$cos/p${port}-${dir}"
    mkdir -p "$(dirname "$dest_dir")"
    if ! bash "$SCRIPT_DIR/step1-capture.sh" "$port" "$dir" "$cos" 2>&1 | tail -40; then
        log "FAIL cell $port/$dir/$cos — copying partial output"
    fi
    mkdir -p "$dest_dir"
    if [[ -d "$SRC_EVIDENCE/$cos/p${port}-${dir}" ]]; then
        cp -a "$SRC_EVIDENCE/$cos/p${port}-${dir}/." "$dest_dir/"
    fi
}

# --- baseline pools (3 × 5 = 15 runs) ---
declare -A POOLS=(
    ["fwd-no-cos"]="5203 fwd no-cos"
    ["fwd-with-cos"]="5203 fwd with-cos"
    ["rev-with-cos"]="5203 rev with-cos"
)

# Honor CLI args: baseline [pool] or matrix [cell] or all.
MODE="${1:-all}"
WHICH="${2:-}"

capture_baseline() {
    local pool="$1"
    read -r p d c <<<"${POOLS[$pool]}"
    for run in 1 2 3 4 5; do
        local dest="$DST_EVIDENCE/baseline/$pool/run$run"
        run_cell "$p" "$d" "$c" "$dest"
    done
}

capture_matrix_cell() {
    local rel="$1"      # with-cos/p5201-fwd
    local cos="${rel%%/*}"
    local pd="${rel##*/}"
    local p=$(echo "$pd" | sed 's/^p\([0-9]*\)-.*/\1/')
    local dir=$(echo "$pd" | sed 's/^p[0-9]*-//')
    local dest="$DST_EVIDENCE/$cos/$pd"
    run_cell "$p" "$dir" "$cos" "$dest"
}

MATRIX_CELLS=(
    with-cos/p5201-fwd with-cos/p5201-rev
    with-cos/p5202-fwd with-cos/p5202-rev
    with-cos/p5203-fwd with-cos/p5203-rev
    with-cos/p5204-fwd with-cos/p5204-rev
    no-cos/p5201-fwd no-cos/p5202-fwd no-cos/p5203-fwd no-cos/p5204-fwd
)

case "$MODE" in
    baseline)
        if [[ -n "$WHICH" ]]; then
            capture_baseline "$WHICH"
        else
            for pool in fwd-no-cos fwd-with-cos rev-with-cos; do
                capture_baseline "$pool"
            done
        fi
        ;;
    matrix)
        if [[ -n "$WHICH" ]]; then
            capture_matrix_cell "$WHICH"
        else
            for c in "${MATRIX_CELLS[@]}"; do
                capture_matrix_cell "$c"
            done
        fi
        ;;
    all)
        for pool in fwd-with-cos rev-with-cos; do
            capture_baseline "$pool"
        done
        # switch cluster to no-cos before fwd-no-cos baseline
        # (orchestrator-driven CoS toggle is left to the caller).
        ;;
esac

log "done"
