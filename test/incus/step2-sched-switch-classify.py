#!/usr/bin/env python3
"""#821 P1 classifier — Spearman rho on T_D1 vs off-CPU time, T3 verdict.

Consumes two JSONL files:
    --hist-blocks  : step1-histogram-classify.py's per-cell `hist-blocks.jsonl`
                     (12 blocks; each has `shape` array of 16 floats)
    --off-cpu      : step2-sched-switch-reduce.py's output (12 blocks; each
                     has `off_cpu_time_3to6` integer ns)

Computes:
    T_D1,b   = shape[3] + shape[4] + shape[5] + shape[6]   (per block)
    rho, pvalue = scipy.stats.spearmanr(T_D1, off_cpu_time_3to6)
    duty_cycle_pct = 100 * sum(off_cpu_time_3to6) / 60e9

T3 verdict (per plan §3.3):
    rho >= 0.8  and  duty_cycle_pct >= 1.0   -> IN
    rho <= 0.3  or   duty_cycle_pct <  1.0   -> OUT
    else                                     -> INCONCLUSIVE

Writes:
    --out                                  markdown report
    <out>.meta.json (sibling)              machine-readable summary

Usage:
    step2-sched-switch-classify.py \\
        --hist-blocks <path> \\
        --off-cpu <path> \\
        --cell <slug> \\
        --out <report-md-path>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


RHO_IN = 0.8
RHO_OUT = 0.3
DUTY_IN_PCT = 1.0
DUTY_OUT_PCT = 1.0
NOMINAL_WINDOW_NS = 60_000_000_000  # 60 s
D1_LO, D1_HI = 3, 6  # inclusive

# HIGH-2: canonical SUSPECT sentinel.  Reducer writes it to every
# emitted JSONL line when drift exceeds DRIFT_HALT_NS.  Classifier
# short-circuits to SUSPECT the moment it sees this key.
SUSPECT_REASON_KEY = "suspect_reason"


def load_jsonl(path: Path) -> list[dict]:
    out = []
    with path.open() as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            out.append(json.loads(raw))
    return out


def compute_T_D1(hist_blocks: list[dict]) -> list[float]:
    """T_D1,b = shape[3] + shape[4] + shape[5] + shape[6]."""
    out = []
    for blk in hist_blocks:
        shape = blk.get("shape", [])
        if len(shape) != 16:
            raise ValueError(
                f"hist-block b={blk.get('b')}: shape length {len(shape)} != 16"
            )
        out.append(float(sum(shape[D1_LO : D1_HI + 1])))
    return out


def spearman_rho(xs: list[float], ys: list[float]) -> tuple[float | None, float | None]:
    """Compute Spearman rho.  Returns (None, None) if scipy rejects inputs."""
    try:
        import scipy.stats
    except ImportError as e:
        raise RuntimeError(
            f"scipy is required for Spearman rho: {e}. "
            "Install via requirements-step2.txt."
        ) from e
    # Degenerate input: all zeros on one side -> scipy returns nan.
    # Handle explicitly for a clean None in meta.json.
    if len(xs) != len(ys):
        raise ValueError(
            f"xs/ys length mismatch: {len(xs)} vs {len(ys)}"
        )
    if len(xs) < 2:
        return None, None
    # All-identical on either side -> rho undefined.
    if len(set(xs)) == 1 or len(set(ys)) == 1:
        return None, None
    res = scipy.stats.spearmanr(xs, ys)
    rho = float(res.statistic) if hasattr(res, "statistic") else float(res[0])
    pv = float(res.pvalue) if hasattr(res, "pvalue") else float(res[1])
    # Handle nan from scipy (pathological input).
    import math
    if math.isnan(rho):
        rho = None
    if pv is not None and math.isnan(pv):
        pv = None
    return rho, pv


def verdict_from(
    rho: float | None,
    duty_cycle_pct: float,
    suspect_reason: str | None = None,
) -> tuple[str, str]:
    """Apply T3 rules.  Returns (verdict, reason).

    HIGH-2: if `suspect_reason` is set, emit SUSPECT immediately and
    include the reason.  Drift-halt is capture-invalid per plan §11,
    so a verdict-bucket answer would be misleading.

    Low duty-cycle is a sufficient OUT condition independently of rho,
    so we check it before the rho=None degenerate branch.
    """
    if suspect_reason is not None:
        return "SUSPECT", (
            f"capture invalid: {suspect_reason} (plan §11); "
            f"rho={rho if rho is not None else 'n/a'}, "
            f"duty={duty_cycle_pct:.3f}%"
        )
    if duty_cycle_pct < DUTY_OUT_PCT:
        return "OUT", (
            f"duty_cycle_pct={duty_cycle_pct:.3f} < {DUTY_OUT_PCT}"
        )
    if rho is None:
        return "INCONCLUSIVE", (
            "Spearman rho undefined (degenerate input: constant on one side "
            "or too few blocks)."
        )
    if rho >= RHO_IN and duty_cycle_pct >= DUTY_IN_PCT:
        return "IN", (
            f"rho={rho:.3f} >= {RHO_IN} and duty_cycle_pct="
            f"{duty_cycle_pct:.3f} >= {DUTY_IN_PCT}"
        )
    if rho <= RHO_OUT:
        return "OUT", f"rho={rho:.3f} <= {RHO_OUT}"
    return "INCONCLUSIVE", (
        f"rho={rho:.3f} in ({RHO_OUT}, {RHO_IN}); duty={duty_cycle_pct:.3f}"
    )


def render_report(
    cell: str,
    hist_blocks: list[dict],
    off_cpu_blocks: list[dict],
    T_D1: list[float],
    off_times: list[int],
    rho: float | None,
    pvalue: float | None,
    duty_cycle_pct: float,
    verdict: str,
    reason: str,
    voluntary_total: int,
    involuntary_total: int,
    warn_blocks: list[int],
    suspect_reason: str | None = None,
    drift_ns: int | None = None,
) -> str:
    lines: list[str] = []
    lines.append(f"# step2 sched_switch correlation report — `{cell}`")
    lines.append("")
    lines.append(
        "Spearman rank correlation between step1 shape[3..=6] (the D1 "
        "4-64 us mass fraction) and step2 off-CPU time in the same bucket "
        "range, across 12 snapshot blocks."
    )
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"- **{verdict}** — {reason}")
    if suspect_reason is not None:
        lines.append("")
        lines.append(
            f"> **SUSPECT** — capture invalid per plan §11 "
            f"(`suspect_reason={suspect_reason}`). "
            + (f"drift_ns={drift_ns}. " if drift_ns is not None else "")
            + "All downstream metrics below are forensic only; do not use "
            "this cell for any IN/OUT discrimination."
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    rho_s = "n/a" if rho is None else f"{rho:.4f}"
    pv_s = "n/a" if pvalue is None else f"{pvalue:.4g}"
    lines.append(f"- Spearman rho: **{rho_s}**  (p-value: {pv_s})")
    lines.append(f"- duty-cycle: **{duty_cycle_pct:.3f} %**  of 60 s nominal")
    lines.append(
        f"- voluntary (S/D/I/T/t/X/Z/P) total: {voluntary_total} ns"
    )
    lines.append(
        f"- involuntary (R/R+) total:           {involuntary_total} ns"
    )
    if warn_blocks:
        lines.append(
            f"- stat_runtime_check WARN blocks: {warn_blocks} "
            f"({len(warn_blocks)} of 12)"
        )
    else:
        lines.append("- stat_runtime_check: all PASS")
    lines.append("")
    lines.append("## Per-block table")
    lines.append("")
    lines.append("| b | T_D1 (shape[3..=6]) | off_cpu_time_3to6 (ns) | vol | invol | stat |")
    lines.append("|---|----:|----:|----:|----:|:---:|")
    for i, (t, o, ob) in enumerate(zip(T_D1, off_times, off_cpu_blocks)):
        lines.append(
            f"| {i} | {t:.4f} | {o} | {ob.get('voluntary_3to6', 0)} | "
            f"{ob.get('involuntary_3to6', 0)} | "
            f"{ob.get('stat_runtime_check', '?')} |"
        )
    lines.append("")
    lines.append("## Scatter (TSV)")
    lines.append("")
    lines.append("```tsv")
    lines.append("b\tT_D1\toff_cpu_time_3to6")
    for i, (t, o) in enumerate(zip(T_D1, off_times)):
        lines.append(f"{i}\t{t:.6f}\t{o}")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hist-blocks", required=True, type=Path)
    ap.add_argument("--off-cpu", required=True, type=Path)
    ap.add_argument("--cell", required=True, type=str)
    ap.add_argument("--out", required=True, type=Path)
    # HIGH-2: operator hook for out-of-band SUSPECT injection (e.g.
    # capture harness wants to mark a cell SUSPECT for reasons not
    # visible in the reducer JSONL).  Reducer-stamped
    # `suspect_reason` in the JSONL is the primary path.
    ap.add_argument(
        "--drift-halt-marker",
        type=Path,
        default=None,
        help="path to a text file whose presence forces verdict=SUSPECT; "
        "contents (if any) become suspect_reason. Optional.",
    )
    args = ap.parse_args(argv)

    hist_blocks = load_jsonl(args.hist_blocks)
    off_cpu_blocks = load_jsonl(args.off_cpu)

    if len(hist_blocks) != 12:
        print(
            f"HALT: hist-blocks length {len(hist_blocks)} != 12 "
            f"({args.hist_blocks})",
            file=sys.stderr,
        )
        return 2
    if len(off_cpu_blocks) != 12:
        print(
            f"HALT: off-cpu length {len(off_cpu_blocks)} != 12 "
            f"({args.off_cpu})",
            file=sys.stderr,
        )
        return 2

    # Sort both by `b` defensively.
    hist_blocks.sort(key=lambda x: x.get("b", 0))
    off_cpu_blocks.sort(key=lambda x: x.get("b", 0))

    # HIGH-2: detect the reducer-emitted sentinel.  Any block carrying
    # `suspect_reason` short-circuits to SUSPECT.  Fall back to the
    # optional --drift-halt-marker sidecar.
    suspect_reason: str | None = None
    for blk in off_cpu_blocks:
        sr = blk.get(SUSPECT_REASON_KEY)
        if sr:
            suspect_reason = str(sr)
            break
    if suspect_reason is None and args.drift_halt_marker is not None:
        if args.drift_halt_marker.is_file():
            marker_text = args.drift_halt_marker.read_text().strip()
            suspect_reason = marker_text or "drift_halt_marker_present"

    T_D1 = compute_T_D1(hist_blocks)
    off_times = [int(b.get("off_cpu_time_3to6", 0)) for b in off_cpu_blocks]

    rho, pvalue = spearman_rho(T_D1, [float(x) for x in off_times])

    duty_cycle_pct = 100.0 * sum(off_times) / NOMINAL_WINDOW_NS

    verdict, reason = verdict_from(rho, duty_cycle_pct, suspect_reason)

    voluntary_total = sum(int(b.get("voluntary_3to6", 0)) for b in off_cpu_blocks)
    involuntary_total = sum(
        int(b.get("involuntary_3to6", 0)) for b in off_cpu_blocks
    )
    warn_blocks = [
        int(b.get("b", i))
        for i, b in enumerate(off_cpu_blocks)
        if b.get("stat_runtime_check") == "WARN"
    ]

    report = render_report(
        cell=args.cell,
        hist_blocks=hist_blocks,
        off_cpu_blocks=off_cpu_blocks,
        T_D1=T_D1,
        off_times=off_times,
        rho=rho,
        pvalue=pvalue,
        duty_cycle_pct=duty_cycle_pct,
        verdict=verdict,
        reason=reason,
        voluntary_total=voluntary_total,
        involuntary_total=involuntary_total,
        warn_blocks=warn_blocks,
        suspect_reason=suspect_reason,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)

    # LOW-5: meta.json core schema is the plan §3.1 step 11 contract:
    # {verdict, rho, pvalue, duty_cycle_pct, warn_blocks}.  Everything
    # else is packed into a `diagnostic` sub-object so downstream tools
    # with an exact-key contract see the plan shape, while humans and
    # debug tooling still get every intermediate value.
    meta: dict = {
        "verdict": verdict,
        "rho": rho,
        "pvalue": pvalue,
        "duty_cycle_pct": duty_cycle_pct,
        "warn_blocks": warn_blocks,
        "diagnostic": {
            "cell": args.cell,
            "reason": reason,
            "suspect_reason": suspect_reason,  # LOW-5 R3: moved into diagnostic to keep top-level schema exactly {verdict, rho, pvalue, duty_cycle_pct, warn_blocks}
            "T_D1": T_D1,
            "off_cpu_time_3to6": off_times,
            "voluntary_total_ns": voluntary_total,
            "involuntary_total_ns": involuntary_total,
            "n_blocks": 12,
            "rho_in": RHO_IN,
            "rho_out": RHO_OUT,
            "duty_in_pct": DUTY_IN_PCT,
            "duty_out_pct": DUTY_OUT_PCT,
            "nominal_window_ns": NOMINAL_WINDOW_NS,
        },
    }
    # Sibling meta.json: <report>.md -> <report>.meta.json.
    meta_path = args.out.parent / (args.out.stem + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    print(
        f"cell={args.cell} verdict={verdict} rho={rho} "
        f"duty_cycle_pct={duty_cycle_pct:.3f}"
        + (f" suspect_reason={suspect_reason}" if suspect_reason else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
