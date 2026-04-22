#!/usr/bin/env python3
"""#821 P1 sister harness reducer — perf-script -> 12-block off-CPU histogram.

Consumes `perf script` textual output from a capture of:
    sched:sched_switch
    sched:sched_stat_runtime
    sched:sched_wakeup

along with step1's `flow_steer_cold.json` (stamped with `_sample_ts`) and
`flow_steer_samples.jsonl` (12 warm snapshots), and emits a 12-line JSONL
histogram of off-CPU durations aligned to step1's snapshot-boundary blocks.

Per plan §3.2 "Block-boundary derivation":
    boundaries = [cold._sample_ts_ns] + [warm[i]._sample_ts_ns for i in 0..=11]
    block b covers [boundaries[b], boundaries[b+1])
    (NOT fixed 5 s — this mirrors step1-histogram-classify.py's delta-on-snapshots)

Bucket layout mirrors `userspace-dp/src/afxdp/umem.rs:bucket_index_for_ns`:
    [0, 1024)   -> b0
    [2^(N+9), 2^(N+10)) -> bN for N in [1, 15)
    [2^24, +inf) -> b15

Emit schema (one JSON per line, 12 lines total):
    {
        "b": <int 0..11>,
        "buckets": [<u64 ns> x 16],
        "off_cpu_time_3to6": <u64 ns>,
        "voluntary_3to6": <u64 ns>,
        "involuntary_3to6": <u64 ns>,
        "stat_runtime_check": "PASS" | "WARN"
    }

`buckets[i]` is total nanoseconds (NOT count). Invariant asserted at emit:
    sum(buckets[3:7]) == off_cpu_time_3to6

Usage:
    step2-sched-switch-reduce.py \\
        --perf-script <path> \\
        --step1-cold <path-to-flow_steer_cold.json> \\
        --step1-samples <path-to-flow_steer_samples.jsonl> \\
        --worker-tids <csv-of-tids> \\
        --perf-start-ns <u64>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator


# --- constants ---------------------------------------------------------------

N_BLOCKS = 12
N_BUCKETS = 16
# D1 signature window: buckets 3..=6 = [4096, 65536) ns = ~4-64 us.
D1_LO, D1_HI = 3, 6  # inclusive
DRIFT_WARN_NS = 1_500_000_000  # 1.5 s
DRIFT_HALT_NS = 5_000_000_000  # 5 s (nominal snapshot interval)
INTERVAL_WARN_LO_NS = 3_000_000_000  # 3 s
INTERVAL_WARN_HI_NS = 7_000_000_000  # 7 s
INTERVAL_HALT_LO_NS = 1_000_000_000  # 1 s
INTERVAL_HALT_HI_NS = 30_000_000_000  # 30 s

# Plan §4.1 stat_runtime_check: PASS if |actual - expected| / expected <= 1%.
# Block duration is per-block (boundaries[b+1] - boundaries[b]); nominal 5 s
# is advisory-only for scaling error messages.
STAT_RUNTIME_REL_TOLERANCE = 0.01  # 1%

# HIGH-2 exit convention: match #816 H-STOP-5 — drift >= 5 s returns 5
# so wrappers (capture harness, CI) can distinguish "drift halt" from
# other failures without parsing stderr.
EXIT_DRIFT_HALT = 5


# --- bucket index (port of umem.rs:bucket_index_for_ns) ----------------------


def bucket_index_for_ns(ns: int) -> int:
    """Port of `userspace-dp/src/afxdp/umem.rs:176-202` bucket_index_for_ns.

    Layout:
        [0, 1024)              -> b0
        [2^(N+9), 2^(N+10))    -> bN for N in [1, 15)
        [2^24, +inf)           -> b15

    Spot checks (assertable):
        0       -> 0
        1       -> 0
        1023    -> 0
        1024    -> 1
        2048    -> 2
        4096    -> 3
        2^24    -> 15
        2^64-1  -> 15
    """
    if ns < 0:
        # Match umem.rs semantics: treat negative as 0.  Should never happen
        # after the monotonicity guard upstream, but be defensive.
        ns = 0
    v = ns | 1
    clz = 64 - v.bit_length()
    b = max(0, 54 - clz)
    return min(b, 15)


# --- perf script parsing -----------------------------------------------------

# A perf script line typical form (no call-graph line):
#   <comm> <tid> [CPU]  <ts>: sched:sched_switch: prev_comm=... prev_pid=... prev_prio=... prev_state=... ==> next_comm=... next_pid=... next_prio=...
#
# With call-graph `--call-graph=fp`, each event is followed by indented
# stack-frame lines that we skip.
#
# We only need:
#   - the event name (sched_switch / sched_wakeup / sched_stat_runtime)
#   - the timestamp (float seconds, absolute unix wall-clock — see below)
#   - for sched_switch: prev_pid, prev_state
#   - for sched_wakeup: the target pid (field `pid=`, not `target_cpu=`)
#   - for sched_stat_runtime: the tid (column 2) and `runtime=<ns>`
#
# Timestamp format: `<unix_secs>.<ns>:` when `perf script --ns` is used
# with `perf record -k CLOCK_REALTIME`.  We convert to integer ns:
# `ts_ns = int(left) * 1_000_000_000 + int(right_zero_padded_9)`.
#
# HIGH-3 resolution (this block replaces the old "PERF_START_NS anchor"
# translation).  The capture script passes `-k CLOCK_REALTIME` to
# `perf record`, so each event's `<ts>` IS the absolute unix wall-clock
# time at which the kernel emitted the tracepoint.  We therefore assign
# events to blocks via `block_for_timestamp(ts_ns, boundaries_ns)`
# directly — no `first_perf_ts` offset, no `PERF_START_NS` anchor.
#
# `PERF_START_NS` remains diagnostic only: the capture script captures
# it via `date +%s%N` right before `perf record` starts, and the reducer
# uses it ONCE to compute `drift_ns = PERF_START_NS - STEP1_START_NS`
# (the plan §11 hard-stop gauge).  It is NEVER applied per-event.

LINE_HEADER_RE = re.compile(
    r"""^
        \s*
        (?P<comm>\S+)                    # comm (may contain dashes)
        \s+
        (?P<tid>\d+)                     # tid
        \s+
        (?:\[(?P<cpu>\d+)\]\s+)?         # optional [CPU]
        (?P<ts>\d+\.\d+):                # timestamp in seconds.microseconds/ns
        \s+
        (?P<event>sched:sched_\w+):      # event name, e.g. sched:sched_switch
        \s*
        (?P<rest>.*)$
    """,
    re.VERBOSE,
)

# Field pulls from `rest`.
SWITCH_PREV_PID_RE = re.compile(r"\bprev_pid=(\d+)\b")
SWITCH_PREV_STATE_RE = re.compile(r"\bprev_state=(\S+)")
WAKEUP_PID_RE = re.compile(r"\bpid=(\d+)\b")
STAT_RUNTIME_NS_RE = re.compile(r"\bruntime=(\d+)\b")


def parse_perf_script(path: Path) -> Iterator[tuple[str, int, int, dict]]:
    """Stream (event, tid, ts_ns, fields) from perf-script text.

    Streams line-by-line; does NOT slurp.  Skips indented stack frames
    and blank lines.  Timestamps are converted from seconds to integer
    nanoseconds.
    """
    with path.open("r", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue
            # Indented line => stack frame; skip.
            if line[0] in (" ", "\t"):
                # Stack frames always start with whitespace then a hex
                # address.  Still, any leading-whitespace line that is
                # NOT a header is stack-frame-ish.  Skip.
                continue
            m = LINE_HEADER_RE.match(line)
            if not m:
                continue
            event = m.group("event")
            tid = int(m.group("tid"))
            ts_s_str = m.group("ts")
            # Convert seconds.us (typically 6 or 9 fractional digits) -> ns.
            # Use split to avoid float rounding at the ns digit.
            left, _, right = ts_s_str.partition(".")
            if len(right) < 9:
                right = right + "0" * (9 - len(right))
            elif len(right) > 9:
                right = right[:9]
            ts_ns = int(left) * 1_000_000_000 + int(right)
            rest = m.group("rest")
            fields: dict = {}
            if event == "sched:sched_switch":
                pm = SWITCH_PREV_PID_RE.search(rest)
                sm = SWITCH_PREV_STATE_RE.search(rest)
                if pm:
                    fields["prev_pid"] = int(pm.group(1))
                if sm:
                    fields["prev_state"] = sm.group(1)
            elif event == "sched:sched_wakeup":
                wm = WAKEUP_PID_RE.search(rest)
                if wm:
                    fields["pid"] = int(wm.group(1))
            elif event == "sched:sched_stat_runtime":
                rm = STAT_RUNTIME_NS_RE.search(rest)
                if rm:
                    fields["runtime_ns"] = int(rm.group(1))
            yield event, tid, ts_ns, fields


# --- step1 snapshot parsing --------------------------------------------------


def _read_sample_ts_s(obj: dict) -> int | None:
    """Extract `_sample_ts` (unix seconds) from a snapshot object.

    step1-capture.sh writes it as a string: `{"_sample_ts": "1713571200", ...}`.
    We accept string or int.  Returns None if missing or unparseable.
    """
    ts = obj.get("_sample_ts")
    if ts is None:
        return None
    try:
        return int(ts)
    except (TypeError, ValueError):
        return None


def load_boundaries_ns(
    cold_path: Path, samples_path: Path
) -> tuple[list[int], list[str]]:
    """Build the 13 snapshot-boundary timestamps (unix-ns) plus WARN messages.

    Returns (boundaries_ns, warnings).  Raises ValueError on HALT conditions:
      - cold missing _sample_ts
      - fewer than 12 usable warm snapshots
      - any snapshot interval outside [1, 30] s

    Warning conditions (non-fatal, returned as string list):
      - any interval outside [3, 7] s
      - any warm snapshot with `_error` field (skipped)
    """
    warnings: list[str] = []

    if not cold_path.is_file():
        raise ValueError(f"cold snapshot missing: {cold_path}")
    with cold_path.open() as f:
        cold = json.load(f)
    cold_ts_s = _read_sample_ts_s(cold)
    if cold_ts_s is None:
        raise ValueError(
            f"cold snapshot {cold_path} has no _sample_ts — "
            "step1-capture.sh must be updated per plan §3.2 HIGH-2"
        )

    warm_ts_s: list[int] = []
    if not samples_path.is_file():
        raise ValueError(f"samples jsonl missing: {samples_path}")
    with samples_path.open() as f:
        for i, raw in enumerate(f):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                warnings.append(
                    f"samples line {i + 1}: JSON decode failed ({e}); skipped"
                )
                continue
            if "_error" in obj:
                warnings.append(
                    f"samples line {i + 1}: _error={obj.get('_error')!r}; skipped"
                )
                continue
            ts_s = _read_sample_ts_s(obj)
            if ts_s is None:
                warnings.append(
                    f"samples line {i + 1}: no _sample_ts; skipped"
                )
                continue
            warm_ts_s.append(ts_s)

    if len(warm_ts_s) < N_BLOCKS:
        raise ValueError(
            f"expected {N_BLOCKS} warm snapshots, got {len(warm_ts_s)} "
            f"(cold {cold_ts_s}, warm {warm_ts_s})"
        )
    # Use the first N_BLOCKS warm samples (matches
    # step1-histogram-classify.py which expects exactly 13 total).
    warm_ts_s = warm_ts_s[:N_BLOCKS]

    boundaries_ns = [cold_ts_s * 1_000_000_000] + [
        t * 1_000_000_000 for t in warm_ts_s
    ]

    # Interval validation.
    for i in range(len(boundaries_ns) - 1):
        d = boundaries_ns[i + 1] - boundaries_ns[i]
        if d < INTERVAL_HALT_LO_NS or d > INTERVAL_HALT_HI_NS:
            raise ValueError(
                f"snapshot interval {i}->{i + 1} = {d} ns outside "
                f"[{INTERVAL_HALT_LO_NS}, {INTERVAL_HALT_HI_NS}]; sampler broken"
            )
        if d < INTERVAL_WARN_LO_NS or d > INTERVAL_WARN_HI_NS:
            warnings.append(
                f"snapshot interval {i}->{i + 1} = {d / 1e9:.3f} s outside "
                f"[3, 7] s (expected ~5 s)"
            )

    return boundaries_ns, warnings


# --- block binning -----------------------------------------------------------


def block_for_timestamp(t_event_ns: int, boundaries_ns: list[int]) -> int:
    """Return block index in 0..N_BLOCKS-1 or -1 if outside window.

    boundaries_ns has length N_BLOCKS+1 = 13.  Block b covers
    [boundaries_ns[b], boundaries_ns[b+1]).
    """
    if t_event_ns < boundaries_ns[0] or t_event_ns >= boundaries_ns[-1]:
        return -1
    # Linear scan (only 12 buckets); simple and cache-friendly.
    for b in range(N_BLOCKS):
        if boundaries_ns[b] <= t_event_ns < boundaries_ns[b + 1]:
            return b
    return -1


# --- reducer core ------------------------------------------------------------


def reduce_events(
    events: Iterable[tuple[str, int, int, dict]],
    boundaries_ns: list[int],
    worker_tids: set[int],
    perf_start_ns: int,
    out_stream=None,
    warn_stream=None,
    suspect_reason: str | None = None,
    mono_wall_offset_ns: int = 0,
) -> list[str]:
    """Consume `events` and emit 12 JSONL blocks to `out_stream`.

    Events are `(event_name, tid, ts_ns, fields)` tuples where `ts_ns`
    is an absolute unix wall-clock nanosecond timestamp (perf is recorded
    with `-k CLOCK_REALTIME`).  Block assignment is `block_for_timestamp(
    ts_ns, boundaries_ns)` directly — no anchor offset.  `perf_start_ns`
    is retained in the signature for drift bookkeeping only.

    If `suspect_reason` is non-None, every emitted JSONL line is stamped
    with a top-level `"suspect_reason"` key (HIGH-2 forensic marker).

    Returns the list of WARN messages (for tests).  Writes WARN lines
    to `warn_stream` as they occur.
    """
    # Late-bind defaults so tests that swap sys.stdout / sys.stderr see
    # the swap.  Binding at def-time captures the original streams.
    if out_stream is None:
        out_stream = sys.stdout
    if warn_stream is None:
        warn_stream = sys.stderr

    # perf_start_ns is not consulted for block assignment (HIGH-3).  It
    # is retained as a parameter for API stability and for callers that
    # want to attach drift diagnostics alongside the emitted JSONL.
    _ = perf_start_ns  # unused on the hot path

    warnings: list[str] = []

    buckets_by_block = [[0] * N_BUCKETS for _ in range(N_BLOCKS)]
    voluntary_by_block = [0] * N_BLOCKS
    involuntary_by_block = [0] * N_BLOCKS
    runtime_by_block = [0] * N_BLOCKS
    total_off_cpu_by_block = [0] * N_BLOCKS
    # Worker count for stat_runtime expected on-CPU computation.  Empty
    # worker_tids set would make `expected=0` → division guard trips; we
    # clamp to 1 in that path.
    n_workers = max(1, len(worker_tids))

    # Per-TID off-CPU state.
    off_start_ns: dict[int, int] = {}
    off_state: dict[int, str] = {}

    # Monotonicity guard: perf-script is time-ordered, but we still defend.
    prev_perf_ts_ns: int = -1

    for event, tid, ts_ns, fields in events:
        if ts_ns < prev_perf_ts_ns:
            # Out-of-order perf event; skip.
            msg = (
                f"out-of-order perf ts {ts_ns} < prev {prev_perf_ts_ns}; skipped"
            )
            warnings.append(msg)
            print(f"WARN: {msg}", file=warn_stream)
            continue
        prev_perf_ts_ns = ts_ns

        # HIGH-3 (Round-2 addendum): `-k CLOCK_REALTIME` was rejected
        # by the target kernel's perf (EINVAL). Fallback path: perf
        # emits CLOCK_MONOTONIC timestamps; the capture harness
        # measures `mono_wall_offset_ns` on the guest (difference
        # between CLOCK_REALTIME and CLOCK_MONOTONIC at a single
        # instant) and passes it via --mono-wall-offset-ns. Conversion
        # is exact: `t_wall = t_mono + offset`. This is NOT inferred
        # from first-event latency (which was Codex R2 HIGH-3); it's
        # a one-shot clock measurement (same math NTP uses).
        t_event_wall_ns = ts_ns + mono_wall_offset_ns

        if event == "sched:sched_switch":
            prev_pid = fields.get("prev_pid")
            prev_state = fields.get("prev_state", "")
            if prev_pid in worker_tids:
                off_start_ns[prev_pid] = t_event_wall_ns
                off_state[prev_pid] = prev_state
        elif event == "sched:sched_wakeup":
            pid = fields.get("pid")
            if pid in worker_tids and pid in off_start_ns:
                t_off = off_start_ns[pid]
                delta_ns = t_event_wall_ns - t_off
                state = off_state.get(pid, "")
                # Monotonicity check per §3.2 / test case 4.
                if delta_ns < 0:
                    msg = (
                        f"negative off-CPU delta for tid={pid} "
                        f"(t_off={t_off}, t_wake={t_event_wall_ns}); skipped"
                    )
                    warnings.append(msg)
                    print(f"WARN: {msg}", file=warn_stream)
                    off_start_ns.pop(pid, None)
                    off_state.pop(pid, None)
                    continue
                b = block_for_timestamp(t_off, boundaries_ns)
                if 0 <= b < N_BLOCKS:
                    bi = bucket_index_for_ns(delta_ns)
                    buckets_by_block[b][bi] += delta_ns
                    total_off_cpu_by_block[b] += delta_ns
                    # prev_state classification: startswith("R") -> involuntary
                    if state.startswith("R"):
                        if D1_LO <= bi <= D1_HI:
                            involuntary_by_block[b] += delta_ns
                    else:
                        if D1_LO <= bi <= D1_HI:
                            voluntary_by_block[b] += delta_ns
                off_start_ns.pop(pid, None)
                off_state.pop(pid, None)
        elif event == "sched:sched_stat_runtime":
            rn = fields.get("runtime_ns", 0)
            if tid in worker_tids:
                b = block_for_timestamp(t_event_wall_ns, boundaries_ns)
                if 0 <= b < N_BLOCKS:
                    runtime_by_block[b] += rn
        # Other sched:* events: ignored.

    # Emit 12 JSONL blocks.
    for b in range(N_BLOCKS):
        buckets = buckets_by_block[b]
        off_3to6 = sum(buckets[D1_LO : D1_HI + 1])
        vol = voluntary_by_block[b]
        invol = involuntary_by_block[b]
        # sanity: vol + invol should equal off_3to6 (each wake goes to one).
        if vol + invol != off_3to6:
            # Defensive; would indicate a bug in the reducer itself.
            msg = (
                f"block {b}: vol({vol}) + invol({invol}) != off_3to6({off_3to6})"
            )
            warnings.append(msg)
            print(f"WARN: {msg}", file=warn_stream)

        # MEDIUM-4: plan §4.1 stat_runtime_check is an accounting check,
        # not tracepoint presence.  Expected on-CPU time per block is
        # (block_duration * n_workers) - total_off_cpu.  PASS if the
        # actual sched_stat_runtime sum is within ±1% of expected; WARN
        # otherwise.  Block duration is per-block (boundaries differ),
        # not a fixed 5 s.
        block_duration_ns = boundaries_ns[b + 1] - boundaries_ns[b]
        expected_on_cpu_ns = (
            block_duration_ns * n_workers - total_off_cpu_by_block[b]
        )
        actual_on_cpu_ns = runtime_by_block[b]
        # Guard against degenerate / negative expected (shouldn't happen
        # in practice; defend so a single bad block can't crash).
        denom = max(expected_on_cpu_ns, 1)
        rel_err = abs(actual_on_cpu_ns - expected_on_cpu_ns) / denom
        if rel_err <= STAT_RUNTIME_REL_TOLERANCE:
            stat_runtime_check = "PASS"
        else:
            stat_runtime_check = "WARN"

        obj = {
            "b": b,
            "buckets": buckets,
            "off_cpu_time_3to6": off_3to6,
            "voluntary_3to6": vol,
            "involuntary_3to6": invol,
            "stat_runtime_check": stat_runtime_check,
        }
        # HIGH-2: stamp every emitted line with the drift-halt sentinel
        # so the classifier can emit SUSPECT without a separate marker.
        if suspect_reason is not None:
            obj["suspect_reason"] = suspect_reason
        # Invariant check at emit time (V3 gate per plan §8).
        assert (
            sum(obj["buckets"][D1_LO : D1_HI + 1]) == obj["off_cpu_time_3to6"]
        ), f"block {b}: sum(buckets[3:7]) != off_cpu_time_3to6"
        print(json.dumps(obj), file=out_stream)

    return warnings


# --- main --------------------------------------------------------------------


def parse_worker_tids(csv: str) -> set[int]:
    """Parse the `--worker-tids` CSV into a set of integer TIDs."""
    if not csv:
        return set()
    out: set[int] = set()
    for tok in csv.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.add(int(tok))
        except ValueError:
            pass
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--perf-script", required=True, type=Path)
    ap.add_argument("--step1-cold", required=True, type=Path)
    ap.add_argument("--step1-samples", required=True, type=Path)
    ap.add_argument("--worker-tids", required=True, type=str)
    ap.add_argument(
        "--perf-start-ns",
        required=True,
        type=int,
        help="wall-clock unix-ns captured right before `perf record` spawn",
    )
    ap.add_argument(
        "--mono-wall-offset-ns",
        type=int,
        default=0,
        help=(
            "HIGH-3 R2 addendum: CLOCK_REALTIME - CLOCK_MONOTONIC at "
            "capture time (ns). perf emits CLOCK_MONOTONIC on kernels "
            "that reject `-k CLOCK_REALTIME`; adding this offset to "
            "each event timestamp converts mono → wall. Default 0 "
            "preserves CLOCK_REALTIME behavior when available."
        ),
    )
    # The following two are retained for backward compat with the plan
    # interface but are currently unused (boundaries come from step1).
    ap.add_argument("--block-size-s", type=float, default=5.0)
    ap.add_argument("--n-blocks", type=int, default=N_BLOCKS)
    args = ap.parse_args(argv)

    try:
        boundaries_ns, bwarns = load_boundaries_ns(
            args.step1_cold, args.step1_samples
        )
    except ValueError as e:
        print(f"HALT: {e}", file=sys.stderr)
        return 2
    for w in bwarns:
        print(f"WARN: {w}", file=sys.stderr)

    step1_start_ns = boundaries_ns[0]
    drift_ns = args.perf_start_ns - step1_start_ns
    # HIGH-2: drift-halt now stamps each emitted JSONL line with a
    # `suspect_reason` sentinel AND returns exit 5 (matching #816's
    # H-STOP-5 convention), so the classifier and capture harness can
    # both detect the condition without ambiguity.
    suspect_reason: str | None = None
    drift_halt = False
    if abs(drift_ns) >= DRIFT_HALT_NS:
        print(
            f"HALT: |PERF_START_NS - STEP1_START_NS| = {abs(drift_ns)} ns >= "
            f"{DRIFT_HALT_NS} ns (nominal snapshot interval); capture invalid "
            "per plan §11. Emitting JSONL (with suspect_reason sentinel) for "
            "forensics; classifier will emit SUSPECT.",
            file=sys.stderr,
        )
        suspect_reason = "drift_ge_5s"
        drift_halt = True
    elif abs(drift_ns) > DRIFT_WARN_NS:
        print(
            f"WARN: drift_ns = {drift_ns} (>|{DRIFT_WARN_NS}| threshold)",
            file=sys.stderr,
        )
    else:
        print(f"drift_ns = {drift_ns}", file=sys.stderr)

    worker_tids = parse_worker_tids(args.worker_tids)
    if not worker_tids:
        print("HALT: --worker-tids produced empty set", file=sys.stderr)
        return 2

    events = parse_perf_script(args.perf_script)
    reduce_events(
        events=events,
        boundaries_ns=boundaries_ns,
        worker_tids=worker_tids,
        perf_start_ns=args.perf_start_ns,
        mono_wall_offset_ns=args.mono_wall_offset_ns,
        suspect_reason=suspect_reason,
    )
    return EXIT_DRIFT_HALT if drift_halt else 0


if __name__ == "__main__":
    sys.exit(main())
