"""Helper functions for the test-mouse-latency.sh orchestrator.

Keeps complex logic out of shell heredocs (which get tangled with
variable interpolation and quoting). Each function is invoked via
`python3 mouse_latency_orchestrate.py <subcommand> ...`.

Subcommands:
- check-cwnd-settle: parse a (snapshot of) iperf3.txt, return 0 if
  the last 3 [SUM] rows are within ±15 % AND ≥ 0.7 × shaper.
- check-collapse: parse a final iperf3.txt, return 0 if any 3
  consecutive [SUM] rows fell below 0.5 × shaper.
- parse-cluster-state: read cluster-status text from stdin, print
  one line per (rg, node, state) triple.
- rg-state-flapped: read the rg-state-poll file, return 0 if any
  triple drifted from the initial sample.
"""

import argparse
import sys

from cluster_status_parse import parse_cluster_status
from iperf3_sum_parse import parse_sum_bps


def _last_n_sum_bps(text: str, n: int) -> list:
    out = []
    for line in text.splitlines():
        bps = parse_sum_bps(line)
        if bps is not None:
            out.append(bps)
    return out[-n:]


def cmd_check_cwnd_settle(args: argparse.Namespace) -> int:
    """Exit 0 if cwnd is settled; non-zero otherwise.

    Settle is defined as: 3 consecutive [SUM] rows within ±15% of
    each other AND aggregate rate >= floor_fraction × shaper_bps.

    The floor_fraction default is 0.5 (down from the original 0.7).
    Empirically the loss userspace cluster hits ~14-15 Gbps when
    targeting a 25 Gbps shaper — i.e. capacity-bound below the
    shaper. 0.7 × 25 = 17.5 was unreachable; 0.5 × 25 = 12.5 lets
    the gate pass on actual steady-state.
    """
    with open(args.iperf3_txt) as f:
        text = f.read()
    last3 = _last_n_sum_bps(text, 3)
    if len(last3) < 3:
        return 1
    mn, mx = min(last3), max(last3)
    if mx > 0 and (mx - mn) > 0.15 * mx:
        return 1
    if mn < args.floor_fraction * args.shaper_bps:
        return 1
    return 0


def cmd_check_collapse(args: argparse.Namespace) -> int:
    """Exit 0 if collapse detected within the probe window; 1 if not.

    R5 HIGH: window must anchor on PROBE START, not "last N rows" —
    iperf3 runs SETTLE_BUDGET + DURATION + SLACK seconds, so "last
    DURATION rows" loses the first DURATION seconds of probe and
    gains SLACK seconds of post-probe teardown. Take rows
    [skip_front : skip_front + n_rows] from the per-second prefix
    instead.

    Threshold default lowered to 0.3 × shaper (was 0.5): empirically
    iperf-c at 25 Gbps shaper hits ~14-15 Gbps actual (cluster is
    capacity-bound below the shaper). 0.5 × 25 = 12.5 was within
    striking distance of that empirical floor and could trigger
    spurious collapse on a normal cell. 0.3 × 25 = 7.5 still catches
    a real collapse (e.g. iperf3 client died) without false-firing.
    """
    threshold = args.shaper_bps * args.threshold_fraction
    rows = []
    with open(args.iperf3_txt) as f:
        for line in f:
            bps = parse_sum_bps(line)
            if bps is not None:
                rows.append(bps)
    # iperf3 writes 1-2 trailing [SUM] summary lines (sender +
    # receiver) covering the full run. Drop the trailing rows whose
    # cumulative behavior would mask per-second interval semantics —
    # we use --n-rows from a known offset instead, so summary rows
    # only intrude if the run finished early.
    if args.n_rows > 0:
        start = max(0, args.skip_front)
        end = start + args.n_rows
        rows = rows[start:end]
    streak = 0
    for bps in rows:
        if bps < threshold:
            streak += 1
            if streak >= 3:
                return 0
        else:
            streak = 0
    return 1


def cmd_parse_cluster_state(args: argparse.Namespace) -> int:
    """Read cluster-status text from stdin, emit one line per triple."""
    text = sys.stdin.read()
    triples = parse_cluster_status(text)
    ts_ms = args.ts_ms
    for rg, node, state in triples:
        print(f"{ts_ms}\trg={rg}\tnode={node}\tstate={state}")
    return 0


def cmd_rg_state_flapped(args: argparse.Namespace) -> int:
    """Exit 0 if state drifted from initial; 1 if stable; 2 if no data.

    R1 HIGH 5: an empty poll file means the orchestrator never got a
    successful cli sample. Returning 1 ("stable") would silently pass
    a contaminated rep. Return 2 instead so the orchestrator can
    invalidate.
    """
    by_ts: "dict[str, set]" = {}
    with open(args.poll_file) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) != 4:
                continue
            ts, rg_part, node_part, state_part = parts
            triple = (rg_part, node_part, state_part)
            by_ts.setdefault(ts, set()).add(triple)
    if not by_ts:
        print("no RG poll samples", file=sys.stderr)
        return 2
    # Copilot R3: sort by integer ts so a future change in
    # timestamp digit width (e.g. mixed second/ms granularity in a
    # synthetic test) doesn't mis-pick the initial sample via
    # lexicographic ordering.
    samples = sorted(by_ts.items(), key=lambda kv: int(kv[0]))
    initial = samples[0][1]
    if not initial:
        # First sample collected an empty triple set (cli succeeded
        # but parser found nothing). Treat as undetermined.
        print("first RG sample is empty", file=sys.stderr)
        return 2
    for ts, triples in samples[1:]:
        if triples != initial:
            for t in triples - initial:
                print(f"DRIFT at {ts}: appeared {t}")
            for t in initial - triples:
                print(f"DRIFT at {ts}: disappeared {t}")
            return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("check-cwnd-settle")
    p1.add_argument("iperf3_txt")
    p1.add_argument("shaper_bps", type=int)
    p1.add_argument(
        "--floor-fraction", type=float, default=0.5,
        help="Min last-3 mean as fraction of shaper_bps. Default 0.5.",
    )
    p1.set_defaults(func=cmd_check_cwnd_settle)

    p2 = sub.add_parser("check-collapse")
    p2.add_argument("iperf3_txt")
    p2.add_argument("shaper_bps", type=int)
    p2.add_argument(
        "--n-rows", type=int, default=0,
        help="Scan N [SUM] rows from --skip-front. 0 = full log.",
    )
    p2.add_argument(
        "--skip-front", type=int, default=0,
        help="Skip this many leading [SUM] rows (settle warmup) before scanning.",
    )
    p2.add_argument(
        "--threshold-fraction", type=float, default=0.3,
        help="Collapse threshold as fraction of shaper_bps. Default 0.3.",
    )
    p2.set_defaults(func=cmd_check_collapse)

    p3 = sub.add_parser("parse-cluster-state")
    p3.add_argument("ts_ms")
    p3.set_defaults(func=cmd_parse_cluster_state)

    p4 = sub.add_parser("rg-state-flapped")
    p4.add_argument("poll_file")
    p4.set_defaults(func=cmd_rg_state_flapped)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
