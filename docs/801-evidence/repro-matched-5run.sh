#!/bin/bash
# Reproduces the matched 5-run iperf3 comparison for #801 (PR #803).
# Round-2 update (Codex M2 response): the script now explicitly sets
# `claim-host-tunables true|false` on the active config BEFORE each
# 5-run batch, so the evidence directory tells the reader exactly
# which state produced which JSON:
#
#   docs/801-evidence/baseline-knobs-off/   — claim=false (default)
#   docs/801-evidence/knobs-on/             — claim=true (governor +
#                                             netdev_budget + coalescence)
#
# Note on coalescence scope (round-2 fix in commit f277f60d):
# per-interface coalescence now runs on every userspace-dp start
# regardless of `claim-host-tunables`, because it shares the same
# blast radius as the D3 RSS indirection rewrite. The baseline set
# therefore reflects "coalescence-on (implicit), host-scope OFF".
# The knobs-on set reflects "coalescence-on + governor=performance +
# netdev_budget=600".
#
# Usage:
#   ./repro-matched-5run.sh baseline       # claim=false, runs all 3 matrices
#   ./repro-matched-5run.sh knobs-on       # claim=true, runs all 3 matrices
#   ./repro-matched-5run.sh summarize-all  # print both summaries
#
# Parameters:
#   port 5201: -P 4  -t 20 (4 streams, 20s, forward + reverse)
#   port 5203: -P 12 -t 20 (12 streams, 20s, forward only)
#   RUNS=5 iterations each

set -euo pipefail

RUNS="${RUNS:-5}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$(dirname "$0")}"
HOST="loss:cluster-userspace-host"
TARGET="172.16.80.200"
PRIMARY="loss:xpf-userspace-fw0"

mkdir -p "$EVIDENCE_DIR/baseline-knobs-off" "$EVIDENCE_DIR/knobs-on"

# set_knobs_on_primary edits the active config on the primary node
# so the claim-host-tunables flip matches the labeled run batch.
# The config commit triggers applyConfig() and therefore
# applyStep0Tunables() — no daemon restart needed. A restart would
# invalidate iperf3 cluster-session state.
set_knobs_on_primary() {
    local state="$1" # knobs-on | baseline
    local claim
    case "$state" in
        knobs-on)  claim="true"  ;;
        baseline)  claim="false" ;;
        *) echo "unknown state: $state" >&2; exit 2 ;;
    esac
    echo "==[ set claim-host-tunables=$claim via remote CLI on $PRIMARY ]=="
    # CLI only accepts one '-c' at a time; ship a script file to the
    # VM and pipe it through stdin. We use a file (not heredoc-in-
    # bash-c) because the inner shell would otherwise interpret the
    # `set` lines as the bash builtin via the layered quoting.
    local script_path="/tmp/801-cli-${state}.txt"
    local local_script="/tmp/801-cli-${state}-local.txt"
    # Pre-script clears any stale configuration lock from a previous
    # interrupted `cli < script.txt` invocation. `rollback` drops the
    # candidate; `exit` makes sure we leave config mode cleanly.
    cat > "$local_script" <<EOF
exit
configure exclusive
set system dataplane claim-host-tunables $claim
set system dataplane cpu-governor performance
set system dataplane netdev-budget 600
set system dataplane coalescence rx-usecs 8
set system dataplane coalescence tx-usecs 8
commit
exit
EOF
    # `incus file push` fails with EACCES when the target path already
    # exists with different ownership (seen after daemon restarts).
    # Remove first, then push.
    sg incus-admin -c "incus exec $PRIMARY -- rm -f $script_path" >/dev/null 2>&1 || true
    sg incus-admin -c "incus file push $local_script $PRIMARY$script_path" >/dev/null
    # Retry up to 3 times: a stuck lock from the previous batch
    # sometimes persists ~1s past the previous cli exit. The empty
    # `exit` at the top of the script is our first break attempt;
    # the retry handles the rare case where the daemon hasn't yet
    # cleaned up the session.
    local attempt
    for attempt in 1 2 3; do
        local output
        output=$(sg incus-admin -c "incus exec $PRIMARY -- bash -c '/usr/local/sbin/cli < $script_path'" 2>&1)
        if grep -q "commit complete" <<<"$output"; then
            echo "  claim=$claim committed on attempt $attempt"
            break
        fi
        echo "  attempt $attempt: commit did not complete; retrying..."
        sleep 2
    done
    sleep 2
}

run_matrix() {
    local out_dir="$1"
    local label="$2"
    local port="$3"
    local streams="$4"
    local duration="$5"
    local reverse="$6"

    local rev_flag=""
    [[ "$reverse" == "yes" ]] && rev_flag="-R"

    echo "==[ $out_dir :: $label :: port=$port streams=$streams t=$duration rev=$reverse ]=="
    for i in $(seq 1 "$RUNS"); do
        local out="$EVIDENCE_DIR/$out_dir/${label}-${i}.json"
        echo "  run $i -> $out"
        sg incus-admin -c "incus exec $HOST -- iperf3 -c $TARGET -p $port -P $streams -t $duration $rev_flag --json" \
            > "$out" 2> /dev/null || { echo "  FAILED run $i"; continue; }
        sleep 1
    done
}

run_state() {
    local state="$1"
    local out_dir
    case "$state" in
        baseline)  out_dir="baseline-knobs-off" ;;
        knobs-on)  out_dir="knobs-on" ;;
        *) echo "unknown state: $state" >&2; exit 2 ;;
    esac
    set_knobs_on_primary "$state"
    run_matrix "$out_dir" "p5201-fwd" 5201 4  20 no
    run_matrix "$out_dir" "p5201-rev" 5201 4  20 yes
    run_matrix "$out_dir" "p5203-fwd" 5203 12 20 no
}

summarize_one() {
    local run_dir="$1"
    local header="$2"
    RUN_DIR="$run_dir" HEADER="$header" python3 <<'PY'
import glob, json, os, statistics, sys
from collections import defaultdict

rd = os.environ.get('RUN_DIR') or 'runs'
header = os.environ.get('HEADER') or 'runs'
print(f"==[ {header} ]==")
matrices = defaultdict(list)
for path in sorted(glob.glob(os.path.join(rd, '*.json'))):
    base = os.path.basename(path)
    stem = base.rsplit('.', 1)[0]
    label = stem.rsplit('-', 1)[0]
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception as e:
        print(f"{base}: parse-error {e}", file=sys.stderr); continue
    end = d.get('end', {})
    sent = end.get('sum_sent') or end.get('sum') or {}
    bps = sent.get('bits_per_second')
    retrans = sent.get('retransmits', 0)
    if bps is None:
        print(f"{base}: no bits_per_second", file=sys.stderr); continue
    matrices[label].append((bps / 1e9, retrans))
print(f"{'matrix':<14} {'n':>2} {'min':>8} {'med':>8} {'mean':>8} {'max':>8} {'stdev':>8} {'retr':>8}")
for label in sorted(matrices):
    vals = matrices[label]
    bps = [v[0] for v in vals]
    retr = sum(v[1] for v in vals)
    print(f"{label:<14} {len(bps):>2} "
          f"{min(bps):>8.2f} {statistics.median(bps):>8.2f} "
          f"{statistics.mean(bps):>8.2f} {max(bps):>8.2f} "
          f"{(statistics.stdev(bps) if len(bps)>1 else 0):>8.3f} "
          f"{retr:>8d}")
PY
}

case "${1:-}" in
    baseline)
        run_state "baseline"
        summarize_one "$EVIDENCE_DIR/baseline-knobs-off" "baseline-knobs-off" | tee "$EVIDENCE_DIR/baseline-knobs-off/summary.txt"
        ;;
    knobs-on)
        run_state "knobs-on"
        summarize_one "$EVIDENCE_DIR/knobs-on" "knobs-on" | tee "$EVIDENCE_DIR/knobs-on/summary.txt"
        ;;
    summarize-all)
        summarize_one "$EVIDENCE_DIR/baseline-knobs-off" "baseline-knobs-off"
        echo
        summarize_one "$EVIDENCE_DIR/knobs-on"           "knobs-on"
        ;;
    *)
        cat <<'USAGE'
usage:
  repro-matched-5run.sh baseline       # claim=false, all 3 matrices
  repro-matched-5run.sh knobs-on       # claim=true,  all 3 matrices
  repro-matched-5run.sh summarize-all  # print both summaries from JSONs on disk
USAGE
        exit 2
        ;;
esac
