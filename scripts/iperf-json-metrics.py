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


def load_iperf_payload(path):
    text = path.read_text(encoding="utf-8")
    try:
        return {"format": "json", "data": json.loads(text)}
    except Exception:
        pass

    events = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            events.append(json.loads(raw))
        except Exception as exc:
            raise ValueError(f"failed to parse iperf JSON stream line {lineno}: {exc}") from exc
    return {"format": "json-stream", "data": events}


def collect_intervals(payload):
    if payload["format"] == "json":
        return [interval_bps(interval) for interval in payload["data"].get("intervals", [])], payload["data"].get("end", {})

    intervals = []
    end = {}
    for event in payload["data"]:
        if event.get("event") == "interval":
            intervals.append(interval_bps(event.get("data") or {}))
        elif event.get("event") == "end":
            end = event.get("data") or {}
    return intervals, end


def summarize(path, args):
    summary = {
        "path": str(path),
        "ok": False,
        "error": "",
        "format": "",
        "protocol": "",
        "completed": False,
        "observed_end_sec": 0.0,
        "avg_gbps": 0.0,
        "retransmits": 0,
        "udp_loss_percent": 0.0,
        "udp_jitter_ms": 0.0,
        "interval_gbps": [],
        "peak_gbps": 0.0,
        "peak_interval_index": -1,
        "tail_gbps": [],
        "tail_median_gbps": 0.0,
        "tail_min_gbps": 0.0,
        "tail_peak_ratio": 0.0,
        "zero_intervals_total": 0,
        "stream_zero_intervals_total": 0,
        "zero_streams_total": 0,
        "zero_intervals_after_peak": 0,
        "stalled_intervals_after_peak": 0,
        "collapse_detected": False,
        "collapse_reason": "",
    }
    try:
        payload = load_iperf_payload(path)
    except Exception as exc:
        summary["error"] = f"failed to parse iperf JSON: {exc}"
        return summary

    summary["format"] = payload["format"]
    data = payload["data"]
    if payload["format"] == "json" and data.get("error"):
        summary["error"] = str(data["error"])
        return summary

    intervals, end = collect_intervals(payload)
    summary["completed"] = bool(end)
    test_start = {}
    if payload["format"] == "json":
        test_start = data.get("start", {}).get("test_start", {}) or {}
    elif payload["format"] == "json-stream":
        start = next((event.get("data") or {} for event in data if event.get("event") == "start"), {})
        test_start = start.get("test_start", {}) or {}
    summary["protocol"] = str(test_start.get("protocol") or "").upper()
    sum_sent = end.get("sum_sent") or end.get("sum") or {}
    summary["avg_gbps"] = float(sum_sent.get("bits_per_second") or 0.0) / 1e9
    summary["retransmits"] = int(sum_sent.get("retransmits") or 0)
    sum_received = end.get("sum_received") or {}
    # Use `is not None` instead of `or` chaining — 0.0 is a valid value
    # that `or` would treat as falsy, falling through to the wrong source.
    def _first_defined(*sources):
        for v in sources:
            if v is not None:
                return float(v)
        return 0.0

    summary["udp_loss_percent"] = _first_defined(
        sum_received.get("lost_percent"),
        sum_sent.get("lost_percent"),
        end.get("sum", {}).get("lost_percent"),
    )
    summary["udp_jitter_ms"] = _first_defined(
        sum_received.get("jitter_ms"),
        sum_sent.get("jitter_ms"),
        end.get("sum", {}).get("jitter_ms"),
    )

    full_intervals = []
    observed_end = 0.0
    normalized_intervals = []
    if payload["format"] == "json":
        normalized_intervals = list(data.get("intervals", []))
    else:
        normalized_intervals = [
            (event.get("data") or {}) for event in payload["data"] if event.get("event") == "interval"
        ]
    stream_zero_total = 0
    zero_stream_ids = set()
    for interval in normalized_intervals:
        for stream in interval.get("streams", []):
            if float(stream.get("bits_per_second") or 0.0) <= args.zero_gbps * 1e9:
                stream_zero_total += 1
                zero_stream_ids.add(str(stream.get("socket") or stream.get("id") or "?"))
    for bps, start, end_s in intervals:
        observed_end = max(observed_end, end_s)
        duration = end_s - start
        if duration >= args.min_full_interval_sec:
            full_intervals.append(bps / 1e9)
    if end:
        observed_end = max(observed_end, float((sum_sent.get("end") or 0.0)))
    summary["observed_end_sec"] = observed_end
    summary["stream_zero_intervals_total"] = stream_zero_total
    summary["zero_streams_total"] = len(zero_stream_ids)
    summary["zero_intervals_total"] = (
        sum(1 for value in full_intervals if value <= args.zero_gbps) + stream_zero_total
    )

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
