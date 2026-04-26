"""Aggregate per-rep JSON outputs into a per-cell summary + verdict.

Cell directory layout: <root>/cell_N{n}_M{m}/rep_{i}/probe.json
Per-rep validity is read from probe.json["validity"]["ok"].

For each cell, the median rep (by p99) of the valid reps is selected
as the representative; its p50/p95/p99 + IQR-of-p99-across-reps +
achieved-RPS summary populate summary.json.

Decision threshold (#905, plan §7.2):
- p99(N=128, M=10, best-effort) ≤ 2 × p99(N=0, M=10, best-effort)

The harness only runs best-effort, so cells are keyed by (N, M).
"""

import argparse
import json
import os
import statistics
import sys
from typing import Dict, List, Optional, Tuple

CellKey = Tuple[int, int]  # (N, M)


def has_invalid_marker(rep_dir: str) -> bool:
    """Return True if the orchestrator wrote an INVALID-* marker file."""
    if not os.path.isdir(rep_dir):
        return False
    for entry in os.listdir(rep_dir):
        if entry.startswith("INVALID-"):
            return True
    return False


def load_cell_reps(cell_dir: str) -> List[dict]:
    """Load all rep_*/probe.json, applying orchestrator INVALID markers."""
    if not os.path.isdir(cell_dir):
        return []
    reps: List[dict] = []
    for entry in sorted(os.listdir(cell_dir)):
        if not entry.startswith("rep_"):
            continue
        rep_dir = os.path.join(cell_dir, entry)
        probe_path = os.path.join(rep_dir, "probe.json")
        # Always collect orchestrator INVALID-* marker reasons first,
        # regardless of probe.json availability (R2 HIGH 1 partial).
        marker_reasons = sorted(
            f"orchestrator: {m}"
            for m in os.listdir(rep_dir)
            if m.startswith("INVALID-")
        )
        if not os.path.isfile(probe_path):
            reasons = ["no-probe-json"] + marker_reasons
            reps.append({
                "validity": {"ok": False, "reasons": reasons},
                "rtt_us": {},
                "totals": {},
            })
            continue
        with open(probe_path) as f:
            try:
                rep = json.load(f)
            except json.JSONDecodeError:
                reasons = ["bad-json"] + marker_reasons
                reps.append({
                    "validity": {"ok": False, "reasons": reasons},
                    "rtt_us": {},
                    "totals": {},
                })
                continue
        if marker_reasons:
            v = rep.setdefault("validity", {"ok": False, "reasons": []})
            v["ok"] = False
            v.setdefault("reasons", []).extend(marker_reasons)
        reps.append(rep)
    return reps


def select_valid_reps(reps: List[dict]) -> List[dict]:
    return [r for r in reps if r.get("validity", {}).get("ok")]


def median_rep_by_p99(valid_reps: List[dict]) -> Optional[dict]:
    """Return the rep at the median position of p99 across valid reps."""
    if not valid_reps:
        return None
    sortable = sorted(
        valid_reps,
        key=lambda r: r.get("rtt_us", {}).get("p99") or 0,
    )
    return sortable[len(sortable) // 2]


def summarize_cell(reps: List[dict]) -> dict:
    """Produce the per-cell summary record."""
    valid = select_valid_reps(reps)
    summary: dict = {
        "n_reps_total": len(reps),
        "n_reps_valid": len(valid),
        "median_rep": None,
        "iqr_p99_across_reps": None,
    }
    if len(valid) < 7:
        summary["status"] = "INSUFFICIENT-DATA"
        return summary
    median = median_rep_by_p99(valid)
    p99s = sorted(
        r.get("rtt_us", {}).get("p99") or 0 for r in valid
    )
    n = len(p99s)
    if n >= 4:
        q1 = p99s[n // 4]
        q3 = p99s[(3 * n) // 4]
        summary["iqr_p99_across_reps"] = q3 - q1
    if median is not None:
        rtt = median.get("rtt_us", {})
        totals = median.get("totals", {})
        summary["median_rep"] = {
            "p50_us": rtt.get("p50"),
            "p95_us": rtt.get("p95"),
            "p99_us": rtt.get("p99"),
            "achieved_rps_total": totals.get("achieved_rps_total"),
            # R2 fresh MED 1: propagate per-coroutine attempt-rate
            # distribution to the summary so the diagnosis surface
            # MED-4 promised actually reaches the report. Field
            # renamed (Copilot R1): per-coroutine values are
            # workload-offered (attempts), not completion-rate.
            "attempts_per_second_per_coroutine_median":
                totals.get("attempts_per_second_per_coroutine_median"),
            "attempts_per_second_per_coroutine_iqr":
                totals.get("attempts_per_second_per_coroutine_iqr"),
            "attempts_per_coroutine": totals.get("attempts_per_coroutine"),
        }
    summary["status"] = "OK"
    return summary


def decide(summaries: Dict[CellKey, dict]) -> dict:
    """Compute the decision-threshold verdict per #905 plan §7.2."""
    gate_loaded = summaries.get((128, 10))
    gate_idle = summaries.get((0, 10))
    if gate_loaded is None or gate_idle is None:
        return {"verdict": "INSUFFICIENT-DATA", "reason": "missing gate cell"}
    if gate_loaded.get("status") != "OK" or gate_idle.get("status") != "OK":
        return {
            "verdict": "INSUFFICIENT-DATA",
            "reason": (
                f"gate cell status: loaded={gate_loaded.get('status')}, "
                f"idle={gate_idle.get('status')}"
            ),
        }
    p99_loaded = (gate_loaded.get("median_rep") or {}).get("p99_us")
    p99_idle = (gate_idle.get("median_rep") or {}).get("p99_us")
    if p99_loaded is None or p99_idle is None or p99_idle == 0:
        return {"verdict": "INSUFFICIENT-DATA", "reason": "missing p99 in gate cell"}
    ratio = p99_loaded / p99_idle
    return {
        "verdict": "PASS" if ratio <= 2.0 else "FAIL",
        "ratio": ratio,
        "p99_idle_us": p99_idle,
        "p99_loaded_us": p99_loaded,
        "threshold": 2.0,
        "gate": "p99(N=128, M=10) <= 2 * p99(N=0, M=10)",
    }


def discover_cells(root: str) -> Dict[CellKey, List[dict]]:
    """Find all cell_N{n}_M{m}/ directories under root and load reps."""
    if not os.path.isdir(root):
        return {}
    out: Dict[CellKey, List[dict]] = {}
    for entry in sorted(os.listdir(root)):
        if not entry.startswith("cell_N"):
            continue
        try:
            _, rest = entry.split("cell_N", 1)
            n_str, m_part = rest.split("_M", 1)
            n = int(n_str)
            m = int(m_part)
        except (ValueError, IndexError):
            continue
        out[(n, m)] = load_cell_reps(os.path.join(root, entry))
    return out


def render_markdown(summaries: Dict[CellKey, dict], verdict: dict) -> str:
    lines: List[str] = []
    lines.append("| N elephants | M mice | reps (valid/total) | p50 µs | p95 µs | p99 µs | RPS | status |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for key in sorted(summaries.keys()):
        n, m = key
        s = summaries[key]
        median = s.get("median_rep") or {}
        lines.append(
            f"| {n} | {m} | {s['n_reps_valid']}/{s['n_reps_total']} "
            f"| {median.get('p50_us', '-')} "
            f"| {median.get('p95_us', '-')} "
            f"| {median.get('p99_us', '-')} "
            f"| {median.get('achieved_rps_total', '-')} "
            f"| {s.get('status', '-')} |"
        )
    lines.append("")
    lines.append(f"**Verdict:** {verdict.get('verdict')}")
    if "ratio" in verdict:
        lines.append(
            f"  ratio = {verdict['ratio']:.2f} "
            f"(p99 loaded {verdict['p99_loaded_us']} µs / "
            f"p99 idle {verdict['p99_idle_us']} µs); "
            f"threshold ≤ {verdict['threshold']}"
        )
    elif "reason" in verdict:
        lines.append(f"  reason: {verdict['reason']}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    cells = discover_cells(args.root)
    summaries = {key: summarize_cell(reps) for key, reps in cells.items()}
    verdict = decide(summaries)

    with open(args.out, "w") as f:
        json.dump(
            {
                "summaries": {f"N{n}_M{m}": s for (n, m), s in summaries.items()},
                "verdict": verdict,
            },
            f,
            indent=2,
        )

    print(render_markdown(summaries, verdict))
    return 0 if verdict["verdict"] in ("PASS", "FAIL") else 2


if __name__ == "__main__":
    sys.exit(main())
