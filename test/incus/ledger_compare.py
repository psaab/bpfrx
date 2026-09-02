#!/usr/bin/env python3
"""Compare the newest gate run against a band over the last K green runs.

Reads ``test/results/ledger.jsonl`` (written by ``test/incus/harness-result.sh``)
and answers ONE question about one gate at one env: is the newest headline
metric inside the distribution of the runs we already trust?

Why a band and not "compare against the previous run"
-----------------------------------------------------
A single prior value cannot tell a regression from a flake, so a comparator
built on it either cries wolf or is tuned until it says nothing. The band is a
robust interval over the last ``MIN_BASELINE_RUNS`` **green** runs at the same
env; a run outside it is reported, a run inside it is not, and the number of
runs that went into the band is printed so a thin baseline is visible rather
than implied.

Three rules carry the whole design, and each one is a mutation cell in
``ledger_compare_test.py`` because a comparator with a broken band is
INDISTINGUISHABLE from a healthy one on every green run -- and a loop is green
almost all the time by construction:

1. **VOID rows never enter the band.** A void is not a data point. It is the
   record of a run that did not measure what it claims to, and letting one into
   a baseline is the direct generalisation of the failure
   ``newflow_ceiling_analyze.py`` documents at length -- a missing input
   degrading into a value that then skips the gate reading it.
2. **``NO-BASELINE`` is not ``PASS``.** "We have no grounds to judge this" and
   "this is fine" are different answers. Collapsing them is how a loop stops
   being able to say anything, and it is the collapse that a green history
   hides best.
3. **Fewer than K green rows is NO-BASELINE, full stop.** K is 3. Two points
   have no dispersion to speak of and a band drawn through them is a number
   with the shape of evidence.

Flake vs. regression without re-running blindly
-----------------------------------------------
Every row carries invariant metrics beside its headline. When the headline
leaves the band, each invariant that has its own baseline is banded too:

* headline moved, every invariant held        -> ``flake-candidate``
* headline moved, some invariant moved too    -> ``regression-candidate``
* headline moved, NO invariant has a baseline -> ``undetermined``

The third is deliberately not folded into the first. "Every invariant held" and
"there were no invariants to check" are the same sentence only if you do not
look, and the empty set is exactly where a check fails to a value
indistinguishable from healthy.

Falsifiability of this module
-----------------------------
If the property is FALSE (the metric really regressed): ``REGRESSION``, with
the value, the band, the K that produced it, and the build sha of the newest
row and of the baseline.
If the measurement did not happen: ``VOID`` (the newest row is void) or
``NO-BASELINE`` (too few greens). Never ``WITHIN-BAND``.
On an empty set (no rows for this gate/env at all): ``NO-BASELINE``, never a
pass.
If the ledger itself is damaged (an unparseable line, a committed conflict
marker): ``LEDGER-CORRUPT`` naming the first bad line -- never a silent skip,
because a skipped row does not count toward K while looking like it does.

Exit status
-----------
Deliberately mirrors ``mouse_latency_aggregate.py``, the one tool in the tree
that got this right, and NOT ``newflow_ceiling_analyze.py``, whose exit 1 means
the opposite:

    0  WITHIN-BAND or IMPROVED, and the newest row is a PASS
    1  REGRESSION, or the newest row is a FAIL -- measured, and bad
    2  VOID / NO-BASELINE / LEDGER-CORRUPT -- undetermined, NOT a pass

The verdict a caller should act on is the ``outcome`` STRING, not this integer;
the integer exists because a shell caller needs one and defaulting it would
repeat the confusion this whole layer was built to end.
"""

from __future__ import annotations

import argparse
import json

import statistics
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: Green runs required before a REGRESSION may be claimed at all. Below this the
#: answer is NO-BASELINE. Three is the floor, not a target: two points have no
#: dispersion and a band through them is a number wearing the shape of evidence.
MIN_BASELINE_RUNS = 3

#: Half-width of the band, in robust standard deviations. 1.4826 * MAD is the
#: consistency constant that makes the median absolute deviation an estimator of
#: sigma for normal data; the median/MAD pair is used rather than mean/stddev so
#: that ONE bad run inside the baseline cannot widen the band enough to hide the
#: next one.
BAND_Z = 3.0

#: Minimum half-width as a fraction of |median|, applied when the baseline is
#: tighter than this. Without it a perfectly repeatable gate gets a zero-width
#: band and every run after it reports REGRESSION on ordinary jitter. With it
#: too large, a real regression fits inside the band and is never reported --
#: which is why "widen the band" is one of the required mutation cells.
BAND_REL_FLOOR = 0.05

VERDICTS = ("PASS", "FAIL", "VOID")
EXE_CHECKS = ("MATCH", "MISMATCH", "UNAVAILABLE", "NOT-APPLICABLE")
REQUIRED_KEYS = (
    "schema",
    "run_id",
    "ts",
    "gate",
    "env",
    "verdict",
    "void_reason",
    "headline_metric",
    "headline_direction",
    "metrics",
    "build_git_sha",
    "exe_check",
)

# Outcomes.
REGRESSION = "REGRESSION"
WITHIN_BAND = "WITHIN-BAND"
IMPROVED = "IMPROVED"
NO_BASELINE = "NO-BASELINE"
VOID = "VOID"
LEDGER_CORRUPT = "LEDGER-CORRUPT"


class LedgerError(Exception):
    """The ledger could not be read as a ledger. Never a comparison result."""


# ---------------------------------------------------------------------------
# Parsing and linting
# ---------------------------------------------------------------------------


def lint_row(row: object, lineno: int) -> List[str]:
    """Return the list of contract violations in one row (empty == clean).

    This is the SAME contract ``harness_result_emit`` enforces at write time.
    Checking it again at read time is not redundant: the ledger is a tracked
    file that a merge, a hand edit, or a committed conflict marker can damage
    after the emitter is done with it.
    """
    errs: List[str] = []
    if not isinstance(row, dict):
        return [f"line {lineno}: not a JSON object"]
    for k in REQUIRED_KEYS:
        if k not in row:
            errs.append(f"line {lineno}: missing required key {k!r}")
    if errs:
        return errs
    verdict = row["verdict"]
    if verdict not in VERDICTS:
        errs.append(f"line {lineno}: verdict {verdict!r} is not one of {VERDICTS}")
    if row["exe_check"] not in EXE_CHECKS:
        errs.append(f"line {lineno}: exe_check {row['exe_check']!r} is not one of {EXE_CHECKS}")
    reason = row.get("void_reason") or ""
    if verdict == "VOID" and not reason:
        errs.append(f"line {lineno}: VOID row with an empty void_reason")
    if verdict in ("PASS", "FAIL") and reason:
        errs.append(f"line {lineno}: {verdict} row carries a void_reason {reason!r}")
    if verdict in ("PASS", "FAIL") and row["exe_check"] in ("MISMATCH", "UNAVAILABLE"):
        errs.append(
            f"line {lineno}: {verdict} row with exe_check={row['exe_check']} — a "
            "measurement of a binary that cannot be named is a VOID (#2176)"
        )
    metrics = row.get("metrics")
    if not isinstance(metrics, dict):
        errs.append(f"line {lineno}: metrics is not an object")
        return errs
    for k, v in metrics.items():
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            errs.append(f"line {lineno}: metric {k!r} has non-numeric value {v!r}")
    if verdict in ("PASS", "FAIL"):
        if not metrics:
            errs.append(f"line {lineno}: {verdict} row with an empty metrics map")
        headline = row.get("headline_metric") or ""
        if headline not in metrics:
            errs.append(
                f"line {lineno}: headline_metric {headline!r} is absent from the row's "
                f"own metrics {sorted(metrics)}"
            )
        if row.get("headline_direction") not in ("higher-better", "lower-better", "neither"):
            errs.append(
                f"line {lineno}: headline_direction {row.get('headline_direction')!r} is "
                "not one of higher-better / lower-better / neither"
            )
    return errs


def _canonical(row: Dict) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def lint_ledger(text: str) -> List[str]:
    """Lint a whole ledger. Returns the list of problems; empty == clean.

    An EMPTY ledger is a problem, not a clean sweep: linting zero rows and
    reporting success is the empty-set pass that ``run-selftests.sh`` already
    guards against in three other places.

    A repeated ``run_id`` whose payload is IDENTICAL is not a problem -- it is
    the benign `merge=union` artifact of both branches carrying the same row,
    and :func:`parse_ledger` dedupes it. A repeat whose payload DIFFERS is
    corruption: two different runs claiming one identity, which would put a
    foreign measurement into a band.
    """
    problems: List[str] = []
    seen = 0
    by_run_id: Dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        seen += 1
        try:
            row = json.loads(line)
        except ValueError as exc:
            problems.append(f"line {lineno}: not parseable as JSON ({exc})")
            continue
        row_errs = lint_row(row, lineno)
        problems.extend(row_errs)
        if row_errs or not isinstance(row, dict):
            continue
        run_id = row.get("run_id")
        canon = _canonical(row)
        if run_id in by_run_id and by_run_id[run_id] != canon:
            problems.append(
                f"line {lineno}: run_id {run_id!r} repeats with DIFFERENT content — "
                "two runs claiming one identity"
            )
        by_run_id.setdefault(run_id, canon)
    if seen == 0:
        problems.append("the ledger has zero rows — linting an empty ledger is not a pass")
    return problems


def parse_ledger(text: str) -> List[Dict]:
    """Parse a ledger into rows, REFUSING on the first damaged line.

    Skipping a bad line would be the worse failure: the skipped row does not
    count toward K, so a corrupt ledger silently produces a thinner baseline
    that still reports WITHIN-BAND.

    A byte-identical repeat of a ``run_id`` IS dropped -- that is the benign
    `merge=union` artifact of both branches carrying one row, and a baseline is
    a count of runs, so counting it twice inflates one. A repeat whose payload
    differs is refused.
    """
    rows: List[Dict] = []
    by_run_id: Dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise LedgerError(f"line {lineno}: not parseable as JSON ({exc})") from exc
        errs = lint_row(row, lineno)
        if errs:
            raise LedgerError(errs[0])
        run_id = row["run_id"]
        canon = _canonical(row)
        if run_id in by_run_id:
            if by_run_id[run_id] != canon:
                raise LedgerError(
                    f"line {lineno}: run_id {run_id!r} repeats with DIFFERENT content — "
                    "two runs claiming one identity"
                )
            # A byte-identical repeat is the `merge=union` artifact of both
            # branches carrying the same row. Dropping it is the whole reason
            # rows carry an identity: counted twice it would inflate a
            # baseline, and a baseline is a count of RUNS.
            continue
        by_run_id[run_id] = canon
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# The band
# ---------------------------------------------------------------------------


def band(values: Sequence[float]) -> Tuple[float, float, float]:
    """Return (median, lo, hi) for a baseline. Requires a non-empty sequence."""
    if not values:
        raise ValueError("band() over an empty baseline")
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    half = max(BAND_Z * 1.4826 * mad, BAND_REL_FLOOR * abs(med))
    return med, med - half, med + half


def classify(value: float, lo: float, hi: float, direction: str) -> str:
    """Place a value against a band, in the metric's own direction."""
    if lo <= value <= hi:
        return WITHIN_BAND
    if direction == "higher-better":
        return IMPROVED if value > hi else REGRESSION
    if direction == "lower-better":
        return IMPROVED if value < lo else REGRESSION
    # direction "neither": a move in either direction is reported, never
    # celebrated. Calling an unattributed move an improvement is a claim the
    # row does not support.
    return REGRESSION


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _sorted_rows(rows: Iterable[Dict]) -> List[Dict]:
    # Sort by ts, keeping file order for equal timestamps. A ledger written by
    # parallel worktrees is not guaranteed to be in ts order on disk.
    return [r for _, _, r in sorted(((r["ts"], i, r) for i, r in enumerate(rows)), key=lambda t: (t[0], t[1]))]


def compare(
    rows: Sequence[Dict],
    gate: str,
    env: Optional[str] = None,
    k: int = MIN_BASELINE_RUNS,
) -> Dict:
    """Compare the newest row for ``gate`` (at ``env``) against its band."""
    matching = [r for r in rows if r.get("gate") == gate]
    if env is not None:
        matching = [r for r in matching if r.get("env") == env]
    matching = _sorted_rows(matching)

    if not matching:
        return {
            "outcome": NO_BASELINE,
            "gate": gate,
            "env": env,
            "k_required": k,
            "baseline_n": 0,
            "note": (
                f"no rows for gate {gate!r}"
                + (f" at env {env!r}" if env is not None else "")
                + " — nothing has been measured, which is not a pass"
            ),
        }

    newest = matching[-1]
    # An env was not given: judge the newest row against its OWN env only.
    # Mixing envs into one band is how a comparator reports a clean history for
    # a gate whose runs never actually compared to each other.
    resolved_env = newest.get("env")
    prior = [r for r in matching[:-1] if r.get("env") == resolved_env]

    result = {
        "outcome": None,
        "gate": gate,
        "env": resolved_env,
        "k_required": k,
        "ts": newest.get("ts"),
        "verdict": newest.get("verdict"),
        "build_git_sha": newest.get("build_git_sha"),
        "running_exe_sha256": newest.get("running_exe_sha256"),
        "exe_check": newest.get("exe_check"),
        "headline_metric": newest.get("headline_metric"),
        "baseline_n": 0,
    }

    if newest.get("verdict") == "VOID":
        result["outcome"] = VOID
        result["void_reason"] = newest.get("void_reason")
        result["note"] = "the newest row is VOID — nothing was measured, so there is nothing to compare"
        return result

    headline = newest.get("headline_metric")
    direction = newest.get("headline_direction")
    value = newest["metrics"][headline]
    result["value"] = value
    result["headline_direction"] = direction

    # The baseline: GREEN rows only (PASS -- never FAIL, never VOID), at the
    # same env, carrying the SAME headline metric. A row measuring something
    # else is not a prior measurement of this.
    greens = [
        r
        for r in prior
        if r.get("verdict") == "PASS" and headline in (r.get("metrics") or {})
    ]
    baseline = greens[-k:] if k > 0 else []
    result["baseline_n"] = len(baseline)
    result["baseline_ts"] = [r.get("ts") for r in baseline]

    if len(baseline) < k:
        result["outcome"] = NO_BASELINE
        result["note"] = (
            f"only {len(baseline)} green run(s) with metric {headline!r} at env "
            f"{resolved_env!r} precede this one; {k} are required before a "
            "regression may be claimed. NO-BASELINE is not a PASS."
        )
        return result

    values = [r["metrics"][headline] for r in baseline]
    med, lo, hi = band(values)
    result.update(
        {
            "baseline_values": values,
            "band_median": med,
            "band_lo": lo,
            "band_hi": hi,
            "outcome": classify(value, lo, hi, direction),
        }
    )

    # Invariants: every other metric the newest row carries that also has a
    # baseline of its own.
    invariants: Dict[str, Dict] = {}
    for name, mvalue in sorted((newest.get("metrics") or {}).items()):
        if name == headline:
            continue
        ivals = [
            r["metrics"][name]
            for r in prior
            if r.get("verdict") == "PASS" and name in (r.get("metrics") or {})
        ][-k:]
        if len(ivals) < k:
            continue
        imed, ilo, ihi = band(ivals)
        invariants[name] = {
            "value": mvalue,
            "band_lo": ilo,
            "band_hi": ihi,
            "held": ilo <= mvalue <= ihi,
            "baseline_n": len(ivals),
        }
    result["invariants"] = invariants

    if result["outcome"] in (REGRESSION, IMPROVED):
        if not invariants:
            # "Every invariant held" and "there were no invariants to check"
            # are the same sentence only if you do not look.
            result["signal"] = "undetermined"
            result["signal_note"] = (
                "no invariant metric has a baseline of its own, so this move cannot "
                "be told from a flake without re-running"
            )
        elif all(i["held"] for i in invariants.values()):
            result["signal"] = "flake-candidate"
            result["signal_note"] = (
                "the headline moved and every invariant with a baseline held — "
                "re-run THIS gate before bisecting"
            )
        else:
            moved = [n for n, i in invariants.items() if not i["held"]]
            result["signal"] = "regression-candidate"
            result["signal_note"] = (
                "the headline moved and so did " + ", ".join(moved) + " — the move came "
                "with a behaviour change"
            )
    return result


def render(result: Dict) -> str:
    out = [f"outcome: {result['outcome']}"]
    out.append(f"gate: {result['gate']}   env: {result['env']}")
    if result.get("ts"):
        out.append(f"newest run: {result['ts']}   verdict: {result.get('verdict')}")
        out.append(
            f"  build_git_sha={result.get('build_git_sha')}  "
            f"exe_check={result.get('exe_check')}  "
            f"running_exe_sha256={result.get('running_exe_sha256') or '-'}"
        )
    if result.get("void_reason"):
        out.append(f"  void reason: {result['void_reason']}")
    if "value" in result:
        out.append(
            f"headline {result['headline_metric']} = {result['value']} "
            f"({result.get('headline_direction')})"
        )
    if result.get("baseline_n"):
        out.append(
            f"band over the last {result['baseline_n']} green run(s): "
            + (
                f"[{result['band_lo']:.6g}, {result['band_hi']:.6g}] "
                f"median {result['band_median']:.6g}"
                if "band_lo" in result
                else "(not computed)"
            )
        )
    if result.get("note"):
        out.append(f"note: {result['note']}")
    inv = result.get("invariants") or {}
    if inv:
        out.append("invariants:")
        for name, i in inv.items():
            mark = "held" if i["held"] else "MOVED"
            out.append(
                f"  {name:<24} {i['value']:<14} [{i['band_lo']:.6g}, {i['band_hi']:.6g}]  {mark}"
            )
    if result.get("signal"):
        out.append(f"signal: {result['signal']} — {result['signal_note']}")
    return "\n".join(out)


def exit_status(result: Dict) -> int:
    """0 = within band / improved and green, 1 = measured bad, 2 = undetermined.

    Mirrors mouse_latency_aggregate.py's mapping on purpose. A FAIL row exits 1
    even when its headline sits inside the band: the band says the metric did
    not move, and the row says the gate was violated, and the second one wins.
    """
    outcome = result.get("outcome")
    if outcome in (VOID, NO_BASELINE, LEDGER_CORRUPT):
        return 2
    if outcome == REGRESSION:
        return 1
    if result.get("verdict") == "FAIL":
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Compare the newest gate run against its band.")
    p.add_argument("--ledger", default=None, help="path to ledger.jsonl")
    p.add_argument("--gate", help="gate name to compare")
    p.add_argument("--env", default=None, help="restrict to this env")
    p.add_argument("--k", type=int, default=MIN_BASELINE_RUNS, help="green runs required")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--lint", action="store_true", help="lint the ledger and exit")
    args = p.parse_args(argv)

    ledger = args.ledger
    if ledger is None:
        import pathlib

        ledger = str(pathlib.Path(__file__).resolve().parents[2] / "test" / "results" / "ledger.jsonl")

    try:
        with open(ledger, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"LEDGER-CORRUPT: cannot read {ledger}: {exc}", file=sys.stderr)
        return 2

    if args.lint:
        problems = lint_ledger(text)
        if problems:
            print(f"ledger-lint: {len(problems)} problem(s) in {ledger}", file=sys.stderr)
            for prob in problems:
                print(f"  {prob}", file=sys.stderr)
            return 1
        rows = len([ln for ln in text.splitlines() if ln.strip()])
        print(f"ledger-lint: OK — {rows} row(s) in {ledger}")
        return 0

    if not args.gate:
        p.error("--gate is required unless --lint is given")

    try:
        rows = parse_ledger(text)
    except LedgerError as exc:
        result = {"outcome": LEDGER_CORRUPT, "gate": args.gate, "env": args.env, "note": str(exc)}
        print(json.dumps(result, indent=2) if args.json else render(result))
        return 2

    result = compare(rows, args.gate, args.env, args.k)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return exit_status(result)


if __name__ == "__main__":
    sys.exit(main())
