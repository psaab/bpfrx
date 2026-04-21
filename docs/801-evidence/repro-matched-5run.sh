#!/bin/bash
# Reproduces the matched 5-run iperf3 comparison for #801 (PR #803).
# Addresses PR #803 round-1 review finding M2: commit JSON captures +
# script so the "p=5203 noise claim" is reproducible rather than
# verbal.
#
# Runs iperf3 five times at each (port, direction) combo, dumps JSON
# output, and prints per-run + aggregate stats. Target the userspace
# cluster on `loss:` with WAN target 172.16.80.200.
#
# Usage:
#   ./repro-matched-5run.sh             # runs all 4 matrices + writes JSON
#   ./repro-matched-5run.sh p5201-fwd   # only the p=5201 forward direction
#   ./repro-matched-5run.sh summarize   # re-summarize existing JSONs only
#
# Output files:
#   runs/<port>-<direction>-<iter>.json   raw iperf3 --json capture
#   runs/summary.txt                      aggregate stats
#
# Parameters:
#   port 5201: -P 4 -t 20 (4 streams, 20s, forward + reverse)
#   port 5203: -P 12 -t 20 (12 streams, 20s, forward only — mirrors
#             the regression investigation matrix)
#   RUNS=5 iterations each
#
# Assumes:
#   - loss:cluster-userspace-host reachable via sg incus-admin
#   - 172.16.80.200 has iperf3 servers on ports 5201 and 5203
#   - userspace cluster primary is currently fw0 or fw1 with healthy DP

set -euo pipefail

RUNS="${RUNS:-5}"
RUN_DIR="${RUN_DIR:-$(dirname "$0")/runs}"
HOST="loss:cluster-userspace-host"
TARGET="172.16.80.200"

mkdir -p "$RUN_DIR"

run_matrix() {
    local label="$1"   # e.g. p5201-fwd
    local port="$2"    # 5201 / 5203
    local streams="$3" # 4 / 12
    local duration="$4"
    local reverse="$5" # yes / no

    local rev_flag=""
    [[ "$reverse" == "yes" ]] && rev_flag="-R"

    echo "==[ $label :: port=$port streams=$streams t=$duration rev=$reverse ]=="
    for i in $(seq 1 "$RUNS"); do
        local out="$RUN_DIR/${label}-${i}.json"
        echo "  run $i -> $out"
        sg incus-admin -c "incus exec $HOST -- iperf3 -c $TARGET -p $port -P $streams -t $duration $rev_flag --json" \
            > "$out" 2> /dev/null || { echo "  FAILED run $i"; continue; }
        # 100ms pause so one run's FIN isn't racing the next run's SYN.
        sleep 1
    done
}

# summarize parses the JSON captures and prints min/mean/median/max per
# matrix. Pure python3 (stdlib only — no third-party deps).
summarize() {
    RUN_DIR="$RUN_DIR" python3 <<'PY'
import glob, json, os, statistics, sys
from collections import defaultdict

rd = os.environ.get('RUN_DIR') or 'runs'
matrices = defaultdict(list)
for path in sorted(glob.glob(os.path.join(rd, '*.json'))):
    base = os.path.basename(path)
    # label is "<matrix>-<iter>.json" — strip the iter suffix after '.json'
    stem = base.rsplit('.', 1)[0]
    label = stem.rsplit('-', 1)[0]
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception as e:
        print(f"{base}: parse-error {e}", file=sys.stderr)
        continue
    # iperf3 JSON: sum_sent.bits_per_second (sender). Fall back to
    # end.sum.bits_per_second if sum_sent absent (older iperf3).
    end = d.get('end', {})
    sent = end.get('sum_sent') or end.get('sum') or {}
    bps = sent.get('bits_per_second')
    retrans = sent.get('retransmits', 0)
    if bps is None:
        print(f"{base}: no bits_per_second", file=sys.stderr)
        continue
    matrices[label].append((bps / 1e9, retrans))

print(f"{'matrix':<14} {'n':>2} {'min':>8} {'med':>8} {'mean':>8} {'max':>8} {'stdev':>8} {'retr_total':>10}")
for label in sorted(matrices):
    vals = matrices[label]
    bps = [v[0] for v in vals]
    retr = sum(v[1] for v in vals)
    print(f"{label:<14} {len(bps):>2} "
          f"{min(bps):>8.2f} {statistics.median(bps):>8.2f} "
          f"{statistics.mean(bps):>8.2f} {max(bps):>8.2f} "
          f"{(statistics.stdev(bps) if len(bps)>1 else 0):>8.3f} "
          f"{retr:>10d}")
PY
}

case "${1:-all}" in
    p5201-fwd) run_matrix "p5201-fwd" 5201 4 20 no ;;
    p5201-rev) run_matrix "p5201-rev" 5201 4 20 yes ;;
    p5203-fwd) run_matrix "p5203-fwd" 5203 12 20 no ;;
    summarize) ;;
    all)
        run_matrix "p5201-fwd" 5201 4 20 no
        run_matrix "p5201-rev" 5201 4 20 yes
        run_matrix "p5203-fwd" 5203 12 20 no
        ;;
    *) echo "unknown mode: $1" >&2; exit 2 ;;
esac

echo
echo "==[ summary ]=="
summarize | tee "$RUN_DIR/summary.txt"
