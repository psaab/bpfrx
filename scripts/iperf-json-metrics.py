#!/usr/bin/env python3
import argparse
import json
import statistics
import sys
from pathlib import Path


def interval_bps(interval):
    summary = interval.get("sum")
    if isinstance(summary, dict) and summary.get("bits_per_second") is not None:
        return float(summary.get("bits_per_second") or 0.0), float(summary.get("start") or 0.0), float(summary.get("end") or 0.0)
    total = 0.0
    start = None
    end = None
    for stream in interval.get("streams", []):
        total += float(stream.get("bits_per_second") or 0.0)
        if start is None:
            start = float(stream.get("start") or 0.0)
        end = float(stream.get("end") or 0.0)
    return total, float(start or 0.0), float(end or 0.0)


def summarize(path, args):
    summary = {
        "path": str(path),
        "ok": False,
        "error": "",
        "avg_gbps": 0.0,
        "retransmits": 0,
        "interval_gbps": [],
        "peak_gbps": 0.0,
        "peak_interval_index": -1,
        "tail_gbps": [],
        "tail_median_gbps": 0.0,
        "tail_min_gbps": 0.0,
        "tail_peak_ratio": 0.0,
        "zero_intervals_after_peak": 0,
        "stalled_intervals_after_peak": 0,
        "collapse_detected": False,
        "collapse_reason": "",
    }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        summary["error"] = f"failed to parse iperf JSON: {exc}"
        return summary

    if data.get("error"):
        summary["error"] = str(data["error"])
        return summary

    end = data.get("end", {})
    sum_sent = end.get("sum_sent") or end.get("sum") or {}
    summary["avg_gbps"] = float(sum_sent.get("bits_per_second") or 0.0) / 1e9
    summary["retransmits"] = int(sum_sent.get("retransmits") or 0)

    full_intervals = []
    for interval in data.get("intervals", []):
        bps, start, end_s = interval_bps(interval)
        duration = end_s - start
        if duration >= args.min_full_interval_sec:
            full_intervals.append(bps / 1e9)

    summary["interval_gbps"] = full_intervals
    if not full_intervals:
        summary["ok"] = True
        return summary

    peak_gbps = max(full_intervals)
    peak_index = full_intervals.index(peak_gbps)
    tail = full_intervals[-args.tail_window:] if len(full_intervals) >= args.tail_window else list(full_intervals)
    tail_median = statistics.median(tail)
    tail_min = min(tail)
    after_peak = full_intervals[peak_index + 1 :]
    zero_after_peak = sum(1 for value in after_peak if value <= args.zero_gbps)
    stalled_after_peak = sum(1 for value in after_peak if value <= args.stall_gbps)
    tail_peak_ratio = tail_median / peak_gbps if peak_gbps > 0 else 0.0

    summary.update(
        {
            "ok": True,
            "peak_gbps": peak_gbps,
            "peak_interval_index": peak_index,
            "tail_gbps": tail,
            "tail_median_gbps": tail_median,
            "tail_min_gbps": tail_min,
            "tail_peak_ratio": tail_peak_ratio,
            "zero_intervals_after_peak": zero_after_peak,
            "stalled_intervals_after_peak": stalled_after_peak,
        }
    )

    if peak_gbps >= args.min_peak_gbps:
        reasons = []
        if zero_after_peak > 0:
            reasons.append(f"{zero_after_peak} zero interval(s) after peak")
        if len(after_peak) >= 2 and stalled_after_peak >= 2:
            reasons.append(f"{stalled_after_peak} stalled interval(s) after peak")
        if tail_peak_ratio < args.min_tail_ratio:
            reasons.append(
                f"tail/peak ratio {tail_peak_ratio:.3f} below {args.min_tail_ratio:.3f}"
            )
        if reasons:
            summary["collapse_detected"] = True
            summary["collapse_reason"] = "; ".join(reasons)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Summarize and flag iperf3 JSON interval collapse.")
    parser.add_argument("json_path", help="Path to an iperf3 -J output file")
    parser.add_argument("--tail-window", type=int, default=2)
    parser.add_argument("--min-full-interval-sec", type=float, default=0.95)
    parser.add_argument("--min-peak-gbps", type=float, default=2.0)
    parser.add_argument("--min-tail-ratio", type=float, default=0.35)
    parser.add_argument("--zero-gbps", type=float, default=0.05)
    parser.add_argument("--stall-gbps", type=float, default=0.25)
    args = parser.parse_args()

    summary = summarize(Path(args.json_path), args)
    json.dump(summary, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
