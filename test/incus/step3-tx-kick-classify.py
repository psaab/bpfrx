#!/usr/bin/env python3
"""#827 P3 classifier — apply T1 (retry + kick latency) on a cell.

Reads the per-block deltas written by `step1-histogram-classify.py`'s
#827 extension in `hist-blocks.jsonl`, then applies #819 §3.2 / §5.3
threshold T1 to the kick counters:

    T_D1,b        = shape[3] + shape[4] + shape[5] + shape[6]
    ElevatedBlocks = top quartile of T_D1 (top 3 of 12, tie-inclusive)

    IN  iff  ∃ b ∈ ElevatedBlocks:
               tx_kick_retry_delta[b] >= 1000  AND
               tx_kick_count_delta[b] > 0      AND
               tx_kick_sum_ns_delta[b] >= 4096 * tx_kick_count_delta[b]
    OUT iff  ∀ b ∈ 0..=11:
               tx_kick_retry_delta[b] < 100    AND
               (tx_kick_count_delta[b] == 0 OR
                tx_kick_sum_ns_delta[b] < 2048 * tx_kick_count_delta[b])
    INCONCLUSIVE otherwise.

Writes:
    <out>                                  markdown report
    <out>.stem.meta.json   (sibling)       machine verdict
    <out>.stem.diag.json   (sibling)       diagnostic table
    tx-kick-by-block.jsonl (sibling)       12-line per-block view

Usage:
    step3-tx-kick-classify.py \\
        --hist-blocks <path>/hist-blocks.jsonl \\
        --cell <slug> \\
        --out <path>/tx-kick/correlation-report.md
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import scipy.stats

# Thresholds per #819 §3.2 / §5.3. 4096 = bucket-3 lower edge for the
# kick-latency histogram per `userspace-dp/src/afxdp/umem.rs:198-202`
# (b = 54 − clz(ns|1); 2^12 = 4096 ns maps to bucket 3). 2048 = bucket-2
# lower edge.
KICK_LAT_IN_NS = 4096
KICK_LAT_OUT_NS = 2048
RETRY_IN = 1000
RETRY_OUT = 100
N_BLOCKS = 12

# Top-quartile size per #819 §3.1 (12 / 4 = 3, rounded).
TOPQ_SIZE = 3

D1_LO, D1_HI = 3, 6  # inclusive


def load_jsonl(path: Path) -> list[dict]:
    out = []
    with path.open() as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            out.append(json.loads(raw))
    return out


def validate_hist_blocks(hist_blocks: list[dict], source: Path) -> None:
    """Enforce the step3-side input contract.

    Step1 is the sole writer of per-block kick deltas (#827 plan R2
    MED-2). Step3 only validates that the fields exist with the right
    shape and length; invariants K0-K3 live in step1.
    """
    if len(hist_blocks) != N_BLOCKS:
        raise ValueError(
            f"{source}: expected {N_BLOCKS} blocks, got {len(hist_blocks)}"
        )
    required_keys = (
        "shape",
        "tx_kick_count_delta",
        "tx_kick_sum_ns_delta",
        "tx_kick_retry_delta",
        "tx_kick_hist_delta",
    )
    for i, blk in enumerate(hist_blocks):
        for key in required_keys:
            if key not in blk:
                raise ValueError(
                    f"{source}: block {i} missing key {key!r} — run "
                    f"step1-histogram-classify.py on post-#826 evidence first"
                )
        shape = blk["shape"]
        if len(shape) != 16:
            raise ValueError(
                f"{source}: block {i} shape length {len(shape)} != 16"
            )
        kick_hist = blk["tx_kick_hist_delta"]
        if len(kick_hist) != 16:
            raise ValueError(
                f"{source}: block {i} tx_kick_hist_delta length "
                f"{len(kick_hist)} != 16"
            )


def compute_T_D1(hist_blocks: list[dict]) -> list[float]:
    return [float(sum(b["shape"][D1_LO : D1_HI + 1])) for b in hist_blocks]


def elevated_blocks(T_D1: list[float]) -> tuple[list[int], float]:
    """Top-quartile with tie-inclusion per plan §4.4.

    Returns (elevated_indices, threshold). Size is >= TOPQ_SIZE and
    ≤ len(T_D1). In the pathological all-tied case (every block has
    the same T_D1 value) the full 12-block set is elevated, which
    makes the IN ∃-quantifier checks against the absolute T1
    thresholds the sole discriminator — still correct by
    construction because T1's absolute thresholds (retry ≥ 1000,
    mean ≥ 4096 ns) are independent of T_D1.
    """
    if len(T_D1) < TOPQ_SIZE:
        return list(range(len(T_D1))), (min(T_D1) if T_D1 else 0.0)
    sorted_desc = sorted(T_D1, reverse=True)
    threshold = sorted_desc[TOPQ_SIZE - 1]
    elevated = [i for i, v in enumerate(T_D1) if v >= threshold]
    return elevated, threshold


def kick_mean_ns_float(sum_ns_delta: int, count_delta: int) -> float:
    """Informational mean for the human-readable report only.

    The T1 verdict itself is derived from integer cross-multiplication
    (§4.3) so f64 precision loss near 2^53 does not affect it. This
    float value is for the markdown table + rho computation only.
    """
    if count_delta <= 0:
        return 0.0
    return sum_ns_delta / count_delta


def t1_in_block(retry_delta: int, count_delta: int, sum_ns_delta: int) -> bool:
    if count_delta <= 0:
        return False
    if retry_delta < RETRY_IN:
        return False
    return sum_ns_delta >= KICK_LAT_IN_NS * count_delta


def t1_out_block(retry_delta: int, count_delta: int, sum_ns_delta: int) -> bool:
    if retry_delta >= RETRY_OUT:
        return False
    if count_delta == 0:
        return True
    return sum_ns_delta < KICK_LAT_OUT_NS * count_delta


def classify(
    hist_blocks: list[dict],
) -> dict:
    """Build the per-block table and apply T1. Returns a diag dict."""
    T_D1 = compute_T_D1(hist_blocks)
    elevated, threshold = elevated_blocks(T_D1)

    per_block = []
    in_witnesses: list[int] = []
    for i, blk in enumerate(hist_blocks):
        retry_d = int(blk["tx_kick_retry_delta"])
        count_d = int(blk["tx_kick_count_delta"])
        sum_ns_d = int(blk["tx_kick_sum_ns_delta"])
        hist_d = [int(x) for x in blk["tx_kick_hist_delta"]]

        is_elevated = i in elevated
        no_kick = count_d == 0

        # IN requires membership in ElevatedBlocks (∃ quantifier in §4.4).
        in_block = is_elevated and t1_in_block(retry_d, count_d, sum_ns_d)
        out_block = t1_out_block(retry_d, count_d, sum_ns_d)

        if in_block:
            in_witnesses.append(i)

        per_block.append(
            {
                "b": i,
                "T_D1": float(T_D1[i]),
                "T_D1_elevated": is_elevated,
                "retry_count_delta": retry_d,
                "kick_count_delta": count_d,
                "kick_sum_ns_delta": sum_ns_d,
                "kick_latency_mean_ns": kick_mean_ns_float(sum_ns_d, count_d),
                "kick_hist_delta": hist_d,
                "no_kick": no_kick,
                "T1_in_sufficient_block": in_block,
                "T1_out_block": out_block,
            }
        )

    t1_in = len(in_witnesses) > 0
    t1_out_holds = all(b["T1_out_block"] for b in per_block)

    if t1_in and t1_out_holds:
        # Impossible by construction — IN requires retry >= 1000 on some
        # block, OUT requires retry < 100 on every block. Guard anyway.
        raise AssertionError(
            "T1 IN and OUT both true — threshold contradiction; "
            f"witnesses={in_witnesses}"
        )

    if t1_in:
        verdict = "IN"
    elif t1_out_holds:
        verdict = "OUT"
    else:
        verdict = "INCONCLUSIVE"

    retry_series = [b["retry_count_delta"] for b in per_block]
    kick_mean_series = [b["kick_latency_mean_ns"] for b in per_block]

    rho_retry, pv_retry = spearman_rho(T_D1, [float(x) for x in retry_series])
    rho_kick, pv_kick = spearman_rho(T_D1, kick_mean_series)

    max_retry_elev = max(
        (b["retry_count_delta"] for b in per_block if b["T_D1_elevated"]),
        default=0,
    )
    # Mean-ns across elevated blocks; treat no-kick as 0 (report only).
    max_kick_mean_elev = max(
        (b["kick_latency_mean_ns"] for b in per_block if b["T_D1_elevated"]),
        default=0.0,
    )
    block_count_no_kick = sum(1 for b in per_block if b["no_kick"])

    return {
        "verdict": verdict,
        "elevated_threshold_T_D1": threshold,
        "elevated_blocks": elevated,
        "T_D1": T_D1,
        "per_block": per_block,
        "rho_retry": rho_retry,
        "pvalue_retry": pv_retry,
        "rho_kick": rho_kick,
        "pvalue_kick": pv_kick,
        "T1_in_witness_block": in_witnesses[0] if in_witnesses else None,
        "T1_out_holds": t1_out_holds,
        "max_retry_count_delta_in_elevated": int(max_retry_elev),
        "max_kick_latency_mean_ns_in_elevated": float(max_kick_mean_elev),
        "block_count_no_kick": block_count_no_kick,
    }


def spearman_rho(xs: list[float], ys: list[float]) -> tuple[float | None, float | None]:
    """Spearman rho with degenerate-input handling. Matches P1 classifier."""
    if len(xs) != len(ys):
        raise ValueError(f"xs/ys length mismatch: {len(xs)} vs {len(ys)}")
    if len(xs) < 2:
        return None, None
    if len(set(xs)) == 1 or len(set(ys)) == 1:
        return None, None
    res = scipy.stats.spearmanr(xs, ys)
    rho = float(res.statistic) if hasattr(res, "statistic") else float(res[0])
    pv = float(res.pvalue) if hasattr(res, "pvalue") else float(res[1])
    if math.isnan(rho):
        rho = None
    if pv is not None and math.isnan(pv):
        pv = None
    return rho, pv


def render_report(cell: str, diag: dict) -> str:
    lines: list[str] = []
    lines.append(f"# step3 tx-kick correlation report — `{cell}`")
    lines.append("")
    lines.append(
        "Threshold-T1 verdict on per-block kick retry count and mean kick "
        "latency (sendto → return) against top-quartile T_D1 blocks. See "
        "#819 §3.2 / §5.3 and #827 plan §4.4 for thresholds."
    )
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    v = diag["verdict"]
    if v == "IN":
        wb = diag["T1_in_witness_block"]
        reason = (
            f"witness block b={wb}: retry_delta="
            f"{diag['per_block'][wb]['retry_count_delta']} >= {RETRY_IN} AND "
            f"mean_kick_ns="
            f"{diag['per_block'][wb]['kick_latency_mean_ns']:.0f} >= "
            f"{KICK_LAT_IN_NS}"
        )
    elif v == "OUT":
        reason = (
            f"all 12 blocks satisfy OUT: retry_delta < {RETRY_OUT} AND "
            f"mean_kick_ns < {KICK_LAT_OUT_NS}"
        )
    else:
        reason = (
            f"max_retry_in_elevated="
            f"{diag['max_retry_count_delta_in_elevated']}, "
            f"max_kick_mean_in_elevated="
            f"{diag['max_kick_latency_mean_ns_in_elevated']:.0f} ns — "
            f"neither IN nor OUT thresholds met"
        )
    lines.append(f"- **{v}** — {reason}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    rr = diag["rho_retry"]
    rk = diag["rho_kick"]
    pr = diag["pvalue_retry"]
    pk = diag["pvalue_kick"]
    lines.append(
        f"- rho(T_D1, retry_count_delta): "
        + ("n/a" if rr is None else f"{rr:.4f}")
        + " (p="
        + ("n/a" if pr is None else f"{pr:.4g}")
        + ")"
    )
    lines.append(
        f"- rho(T_D1, kick_latency_mean_ns): "
        + ("n/a" if rk is None else f"{rk:.4f}")
        + " (p="
        + ("n/a" if pk is None else f"{pk:.4g}")
        + ")"
    )
    lines.append(
        f"- elevated threshold (T_D1 3rd-largest): "
        f"{diag['elevated_threshold_T_D1']:.4f}"
    )
    lines.append(
        f"- elevated blocks: {diag['elevated_blocks']} "
        f"(size {len(diag['elevated_blocks'])})"
    )
    lines.append(
        f"- max retry_count_delta in elevated: "
        f"{diag['max_retry_count_delta_in_elevated']}"
    )
    lines.append(
        f"- max kick_latency_mean_ns in elevated: "
        f"{diag['max_kick_latency_mean_ns_in_elevated']:.1f}"
    )
    lines.append(f"- blocks with no kick activity: {diag['block_count_no_kick']}")
    lines.append("")
    lines.append("## Per-block table")
    lines.append("")
    lines.append(
        "| b | T_D1 | elev | retry_Δ | count_Δ | sum_ns_Δ | mean_ns | in | out |"
    )
    lines.append("|---|----:|:-:|----:|----:|----:|----:|:-:|:-:|")
    for blk in diag["per_block"]:
        lines.append(
            f"| {blk['b']} | {blk['T_D1']:.4f} | "
            f"{'*' if blk['T_D1_elevated'] else ''} | "
            f"{blk['retry_count_delta']} | {blk['kick_count_delta']} | "
            f"{blk['kick_sum_ns_delta']} | "
            f"{blk['kick_latency_mean_ns']:.0f} | "
            f"{'*' if blk['T1_in_sufficient_block'] else ''} | "
            f"{'*' if blk['T1_out_block'] else ''} |"
        )
    lines.append("")
    lines.append("## Scatter (TSV)")
    lines.append("")
    lines.append("```tsv")
    lines.append("b\tT_D1\tretry_count_delta\tkick_latency_mean_ns\televated")
    for blk in diag["per_block"]:
        lines.append(
            f"{blk['b']}\t{blk['T_D1']:.6f}\t{blk['retry_count_delta']}\t"
            f"{blk['kick_latency_mean_ns']:.3f}\t"
            f"{1 if blk['T_D1_elevated'] else 0}"
        )
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hist-blocks", required=True, type=Path)
    ap.add_argument("--cell", required=True, type=str)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    hist_blocks = load_jsonl(args.hist_blocks)
    validate_hist_blocks(hist_blocks, args.hist_blocks)
    hist_blocks.sort(key=lambda x: x.get("b", 0))

    diag = classify(hist_blocks)

    report = render_report(args.cell, diag)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)

    meta = {
        "cell": args.cell,
        "verdict": diag["verdict"],
        "rho_retry": diag["rho_retry"],
        "pvalue_retry": diag["pvalue_retry"],
        "rho_kick": diag["rho_kick"],
        "pvalue_kick": diag["pvalue_kick"],
        "elevated_threshold_T_D1": diag["elevated_threshold_T_D1"],
        "elevated_blocks": diag["elevated_blocks"],
        "max_retry_count_delta_in_elevated": diag[
            "max_retry_count_delta_in_elevated"
        ],
        "max_kick_latency_mean_ns_in_elevated": diag[
            "max_kick_latency_mean_ns_in_elevated"
        ],
        "T1_in_witness_block": diag["T1_in_witness_block"],
        "T1_out_holds": diag["T1_out_holds"],
        "block_count_no_kick": diag["block_count_no_kick"],
    }
    diag_out = {
        "cell": args.cell,
        "verdict": diag["verdict"],
        "T_D1": diag["T_D1"],
        "per_block": diag["per_block"],
        "rho_retry": diag["rho_retry"],
        "rho_kick": diag["rho_kick"],
        "pvalue_retry": diag["pvalue_retry"],
        "pvalue_kick": diag["pvalue_kick"],
        "retry_in_threshold": RETRY_IN,
        "retry_out_threshold": RETRY_OUT,
        "kick_lat_in_ns": KICK_LAT_IN_NS,
        "kick_lat_out_ns": KICK_LAT_OUT_NS,
        "top_quartile_size": TOPQ_SIZE,
        "n_blocks": N_BLOCKS,
    }

    meta_path = args.out.parent / (args.out.stem + ".meta.json")
    diag_path = args.out.parent / (args.out.stem + ".diag.json")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    diag_path.write_text(json.dumps(diag_out, indent=2) + "\n")

    by_block_path = args.out.parent / "tx-kick-by-block.jsonl"
    with by_block_path.open("w") as f:
        for blk in diag["per_block"]:
            f.write(json.dumps(blk) + "\n")

    print(
        f"cell={args.cell} verdict={diag['verdict']} "
        f"rho_retry={diag['rho_retry']} rho_kick={diag['rho_kick']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
