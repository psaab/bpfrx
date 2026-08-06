"""Turn two helper counter snapshots into a new-flow rate AND an attribution.

This is the analysis half of the #4800 connection-rate harness. The shell
driver (`newflow-ceiling-harness.sh`) only collects; every derivation lives
here so it can be fed synthetic snapshot pairs and asserted, rather than
buried in shell arithmetic that nothing tests.

Why the attribution matters more than the rate
----------------------------------------------
A number that says "new flows/sec plateaued at N" settles nothing. Three
cross-worker synchronization points sit on every transit install:

* the SNAT pool allocator's residual `live` map mutex (#2852 Phase 1),
* `publish_shared_session` (up to three shared-map mutexes per flow),
* the N-way `replicate_session_upsert` fan-out (one sibling queue mutex per
  worker, per flow).

#2852 Phase-2 sharding targets only the first. If publish and replication
saturate before the allocator does, sharding the allocator alone moves
nothing — which is precisely the conclusion #4800 exists to test. So
`analyze` never reports a single winner: it reports EVERY site over the
saturation threshold, in descending order, plus the full per-site table so a
reader can see the ones that stayed cold.

Why it can report failure
-------------------------
A harness that cannot fail is worse than none. `analyze` returns
`INVALID` when the run did not measure what it claims to (no pool-mode SNAT
allocations at all, a counter that went backwards because the helper
restarted, a non-positive or too-short window) and `INCONCLUSIVE` when
something OTHER than the install path bound first (allocator exhaustion, a
generator that never reached its offered rate, traffic landing on too few RX
queues). Only `VALID` results may be used to argue about the install path,
and even then `saturated=False` with an empty culprit list is a real and
common answer.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Defaults. Every one is overridable; the harness records the values it used
# in the run artifact so a reported ceiling can be re-derived.
# ---------------------------------------------------------------------------

#: A lock site counts as saturated when this fraction of its acquisitions had
#: to block. 10% blocked acquisitions on a mutex held for a map insert is
#: already a serialization regime, not noise; below that the site is reported
#: with its ratio but not named a culprit.
DEFAULT_SATURATION_RATIO = 0.10

#: The sibling replication queue counts as backlogged at this observed depth
#: high-water. Steady-state depth is O(1) — the consuming worker drains every
#: poll — so a triple-digit high-water means the consumer fell behind, which
#: is a different failure from producers colliding on the queue mutex.
DEFAULT_QUEUE_DEPTH_BACKLOG = 64

#: Minimum measurement window. Shorter windows let one status-poll jitter
#: dominate the rate.
DEFAULT_MIN_WINDOW_S = 5.0

#: Accepted new flows must reach this fraction of the offered rate, when the
#: generator reports one. Below it the generator (or the client NIC, or the
#: target) bound first and the firewall was never the constraint.
DEFAULT_MIN_ACCEPT_RATIO = 0.95

#: The loss userspace cluster's mlx5 VFs expose 6 combined RX queues -> 6
#: workers (docs/fairness-regimes.md). A cross-worker contention claim needs
#: traffic on more than a couple of them.
DEFAULT_MIN_ACTIVE_WORKERS = 3

#: A single worker taking more than this share of installs means RSS steered
#: the load onto one queue: the ceiling is that worker's core, not a
#: cross-worker lock.
DEFAULT_MAX_WORKER_SHARE = 0.60

VALID = "VALID"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"


class SnapshotError(ValueError):
    """A snapshot is structurally unusable (missing series, unparseable)."""


# ---------------------------------------------------------------------------
# Snapshot model
# ---------------------------------------------------------------------------

#: (site name, contended series, acquisitions series). The acquisition series
#: is the DENOMINATOR; a site whose denominator is missing cannot be
#: attributed and is reported as such rather than silently scored 0.
LOCK_SITES = (
    (
        "nat_allocator_live_mutex",
        "pool.live_lock_contended_total",
        "pool.live_lock_acquisitions_total",
    ),
    (
        "publish_shared_session",
        "publish.lock_contended_total",
        "publish.lock_acquisitions_total",
    ),
    (
        "replicate_session_upsert",
        "replicate.lock_contended_total",
        "replicate.enqueued_total",
    ),
)

#: Every counter that must never go backwards. A decrease means the helper
#: restarted mid-run (counters are process-lifetime), which invalidates the
#: window regardless of how healthy the numbers look.
MONOTONIC_FIELDS = (
    "pool.allocations_total",
    "pool.exhaustion_total",
    "pool.live_lock_acquisitions_total",
    "pool.live_lock_contended_total",
    "publish.publishes_total",
    "publish.lock_acquisitions_total",
    "publish.lock_contended_total",
    "replicate.upserts_total",
    "replicate.enqueued_total",
    "replicate.lock_contended_total",
    "replicate.queue_depth_max",
)


def _get(snapshot: Mapping, dotted: str) -> int:
    """Read a dotted path out of a snapshot, raising if absent.

    Absent is an ERROR, not a zero: a missing series means the scrape did not
    see the helper (or the helper predates the counter), and scoring that as
    "no contention" would report a clean result for a run that measured
    nothing.
    """
    node = snapshot
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            raise SnapshotError(f"snapshot missing required series {dotted!r}")
        node = node[part]
    if not isinstance(node, (int, float)) or isinstance(node, bool):
        raise SnapshotError(f"series {dotted!r} is not numeric: {node!r}")
    return int(node)


@dataclass
class SiteAttribution:
    """One synchronization site's blocked-acquisition share over the window."""

    name: str
    contended_delta: int
    acquisitions_delta: int
    #: contended/acquisitions over the window, or None when the site was not
    #: exercised at all (zero acquisitions). None is NOT 0.0: "never taken"
    #: and "taken and never blocked" are different findings.
    ratio: Optional[float]
    saturated: bool

    def as_dict(self) -> Dict:
        return {
            "site": self.name,
            "contended_delta": self.contended_delta,
            "acquisitions_delta": self.acquisitions_delta,
            "ratio": self.ratio,
            "saturated": self.saturated,
        }


@dataclass
class Analysis:
    verdict: str
    reasons: List[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    new_flows_per_sec: float = 0.0
    offered_flows_per_sec: Optional[float] = None
    accept_ratio: Optional[float] = None
    sites: List[SiteAttribution] = field(default_factory=list)
    #: EVERY saturated site, ratio-descending. A list, not a winner: the
    #: interesting real-world answer is "publish and replicate both saturated
    #: before NAT did", and a single-winner report would hide half of it.
    culprits: List[str] = field(default_factory=list)
    replication_queue_depth_max: int = 0
    replication_fanout: Optional[float] = None
    worker_installs: Dict[str, int] = field(default_factory=dict)
    active_workers: int = 0
    max_worker_share: Optional[float] = None

    @property
    def saturated(self) -> bool:
        return bool(self.culprits)

    def as_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "elapsed_s": self.elapsed_s,
            "new_flows_per_sec": self.new_flows_per_sec,
            "offered_flows_per_sec": self.offered_flows_per_sec,
            "accept_ratio": self.accept_ratio,
            "saturated": self.saturated,
            "culprits": list(self.culprits),
            "sites": [s.as_dict() for s in self.sites],
            "replication_queue_depth_max": self.replication_queue_depth_max,
            "replication_fanout": self.replication_fanout,
            "worker_installs": dict(self.worker_installs),
            "active_workers": self.active_workers,
            "max_worker_share": self.max_worker_share,
        }


def analyze(
    before: Mapping,
    after: Mapping,
    *,
    offered_flows_per_sec: Optional[float] = None,
    saturation_ratio: float = DEFAULT_SATURATION_RATIO,
    queue_depth_backlog: int = DEFAULT_QUEUE_DEPTH_BACKLOG,
    min_window_s: float = DEFAULT_MIN_WINDOW_S,
    min_accept_ratio: float = DEFAULT_MIN_ACCEPT_RATIO,
    min_active_workers: int = DEFAULT_MIN_ACTIVE_WORKERS,
    max_worker_share: float = DEFAULT_MAX_WORKER_SHARE,
) -> Analysis:
    """Derive the new-flow rate and the bottleneck attribution for one cell.

    ``before``/``after`` are normalized snapshots (see
    :func:`parse_prometheus_text`). Returns an :class:`Analysis` whose
    ``verdict`` is the first thing a caller must read: only ``VALID`` results
    describe the install path.
    """
    elapsed = float(after.get("t", 0.0)) - float(before.get("t", 0.0))

    # --- structural validity ------------------------------------------------
    # Checked before any rate is computed, so an invalid run never gets to
    # print a plausible-looking number.
    if elapsed <= 0:
        return Analysis(
            verdict=INVALID,
            reasons=[f"non-positive measurement window ({elapsed:.3f}s)"],
            elapsed_s=elapsed,
        )

    before_pid = before.get("helper_pid")
    after_pid = after.get("helper_pid")
    if before_pid is not None and after_pid is not None and before_pid != after_pid:
        return Analysis(
            verdict=INVALID,
            reasons=[
                f"helper restarted mid-window (pid {before_pid} -> {after_pid}); "
                "counters are process-lifetime and the deltas are meaningless"
            ],
            elapsed_s=elapsed,
        )

    regressions = []
    for f in MONOTONIC_FIELDS:
        if _get(after, f) < _get(before, f):
            regressions.append(f)
    if regressions:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "counter(s) went backwards, so the helper restarted or the "
                "scrape crossed processes: " + ", ".join(sorted(regressions))
            ],
            elapsed_s=elapsed,
        )

    allocations = _get(after, "pool.allocations_total") - _get(
        before, "pool.allocations_total"
    )
    if allocations <= 0:
        return Analysis(
            verdict=INVALID,
            reasons=[
                "zero pool-mode SNAT allocations over the window: either the "
                "pool-mode source-NAT rule was not in effect, or no new flows "
                "reached it. This is NOT a measured rate of 0"
            ],
            elapsed_s=elapsed,
        )

    if elapsed < min_window_s:
        return Analysis(
            verdict=INVALID,
            reasons=[
                f"measurement window {elapsed:.3f}s is below the {min_window_s}s "
                "floor; status-poll jitter would dominate the rate"
            ],
            elapsed_s=elapsed,
        )

    # --- rate + attribution -------------------------------------------------
    result = Analysis(verdict=VALID, elapsed_s=elapsed)
    result.new_flows_per_sec = allocations / elapsed
    result.offered_flows_per_sec = offered_flows_per_sec
    if offered_flows_per_sec:
        result.accept_ratio = result.new_flows_per_sec / offered_flows_per_sec

    deltas = {
        f: _get(after, f) - _get(before, f) for f in MONOTONIC_FIELDS
    }

    for name, contended_key, acq_key in LOCK_SITES:
        contended = deltas[contended_key]
        acquisitions = deltas[acq_key]
        ratio = (contended / acquisitions) if acquisitions > 0 else None
        result.sites.append(
            SiteAttribution(
                name=name,
                contended_delta=contended,
                acquisitions_delta=acquisitions,
                ratio=ratio,
                saturated=ratio is not None and ratio >= saturation_ratio,
            )
        )

    # Depth is a monotonic high-water GAUGE, so the meaningful reading is the
    # absolute `after` value, not the delta. It is reported alongside the
    # replication lock ratio because the two say different things: contention
    # means producers collided, depth means the consumer never caught up.
    result.replication_queue_depth_max = _get(after, "replicate.queue_depth_max")

    upserts = deltas["replicate.upserts_total"]
    if upserts > 0:
        result.replication_fanout = deltas["replicate.enqueued_total"] / upserts

    # Culprits: every saturated site, ratio-descending. Ties keep LOCK_SITES
    # order so the output is deterministic.
    ordered = sorted(
        (s for s in result.sites if s.saturated),
        key=lambda s: (-(s.ratio or 0.0), [n for n, _, _ in LOCK_SITES].index(s.name)),
    )
    result.culprits = [s.name for s in ordered]
    if result.replication_queue_depth_max >= queue_depth_backlog:
        # A distinct culprit from the replication MUTEX: same subsystem,
        # different remedy (drain rate vs. lock sharding).
        result.culprits.append("replicate_session_upsert_queue_backlog")

    # --- worker distribution -------------------------------------------------
    before_workers = before.get("workers", {}) or {}
    after_workers = after.get("workers", {}) or {}
    installs: Dict[str, int] = {}
    for worker in sorted(set(before_workers) | set(after_workers), key=str):
        delta = int(after_workers.get(worker, 0)) - int(before_workers.get(worker, 0))
        if delta < 0:
            result.verdict = INVALID
            result.reasons.append(
                f"worker {worker} new-flow install counter went backwards; "
                "the helper restarted mid-window"
            )
            return result
        installs[str(worker)] = delta
    result.worker_installs = installs
    total_installs = sum(installs.values())
    result.active_workers = sum(1 for v in installs.values() if v > 0)
    if total_installs > 0:
        result.max_worker_share = max(installs.values()) / total_installs

    # --- things that bound BEFORE the install path did -----------------------
    # These downgrade to INCONCLUSIVE rather than INVALID: the run happened
    # and its numbers are real, they just do not describe the install path.
    if deltas["pool.exhaustion_total"] > 0:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"{deltas['pool.exhaustion_total']} allocator exhaustion events: the "
            "pool ran out of ports, so this is a pool-capacity ceiling, not a "
            "lock ceiling"
        )
    if result.accept_ratio is not None and result.accept_ratio < min_accept_ratio:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"accepted {result.new_flows_per_sec:.0f}/s of an offered "
            f"{offered_flows_per_sec:.0f}/s ({result.accept_ratio:.1%} < "
            f"{min_accept_ratio:.0%}): the generator, client NIC or target bound "
            "first, so the firewall was not the constraint"
        )
    if installs and result.active_workers < min_active_workers:
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"only {result.active_workers} of {len(installs)} workers installed "
            f"flows (minimum {min_active_workers}): RSS-distribution-limited, so "
            "a cross-worker contention claim is not supported"
        )
    if (
        result.max_worker_share is not None
        and result.max_worker_share > max_worker_share
    ):
        result.verdict = INCONCLUSIVE
        result.reasons.append(
            f"one worker took {result.max_worker_share:.1%} of installs (ceiling "
            f"{max_worker_share:.0%}): single-worker-bound, so the ceiling is one "
            "core rather than a cross-worker lock"
        )

    return result


# ---------------------------------------------------------------------------
# Prometheus scrape -> normalized snapshot
# ---------------------------------------------------------------------------

_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)\s*$"
)
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _samples(text: str, metric: str) -> List[tuple]:
    """Return [(labels_dict, value)] for one metric family in a scrape."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if not m or m.group("name") != metric:
            continue
        labels = dict(_LABEL.findall(m.group("labels") or ""))
        try:
            value = float(m.group("value"))
        except ValueError:
            continue
        out.append((labels, value))
    return out


def _scalar(text: str, metric: str) -> int:
    rows = _samples(text, metric)
    if not rows:
        raise SnapshotError(f"scrape has no series {metric!r}")
    if len(rows) > 1:
        raise SnapshotError(f"expected one {metric!r} series, saw {len(rows)}")
    return int(rows[0][1])


def parse_prometheus_text(
    text: str,
    *,
    timestamp: float,
    pool_name: Optional[str] = None,
    rule_name: Optional[str] = None,
    helper_pid: Optional[int] = None,
) -> Dict:
    """Normalize one `/metrics` scrape into the snapshot `analyze` consumes.

    ``pool_name``/``rule_name`` select the pool under test. Selecting it here
    rather than summing every pool is deliberate: a firewall with a second,
    idle pool would otherwise contribute a huge uncontended acquisition count
    and dilute the ratio of the pool actually carrying the load.
    """

    def pool_metric(metric: str) -> int:
        rows = _samples(text, metric)
        if pool_name is not None:
            rows = [r for r in rows if r[0].get("pool") == pool_name]
        if rule_name is not None:
            rows = [r for r in rows if r[0].get("rule") == rule_name]
        if not rows:
            raise SnapshotError(
                f"scrape has no {metric!r} series for pool={pool_name!r} "
                f"rule={rule_name!r} — the pool-mode SNAT rule is not in effect"
            )
        if len(rows) > 1:
            raise SnapshotError(
                f"{metric!r} matched {len(rows)} pools; pass pool/rule to select one"
            )
        return int(rows[0][1])

    workers = {
        labels.get("worker_id", "?"): int(value)
        for labels, value in _samples(text, "xpf_userspace_worker_new_flow_installs_total")
    }

    return {
        "t": float(timestamp),
        "helper_pid": helper_pid,
        "pool": {
            "name": pool_name,
            "rule": rule_name,
            "allocations_total": pool_metric(
                "xpf_userspace_source_nat_pool_allocations_total"
            ),
            "exhaustion_total": pool_metric(
                "xpf_userspace_source_nat_pool_exhaustions_total"
            ),
            "live_lock_acquisitions_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_lock_acquisitions_total"
            ),
            "live_lock_contended_total": pool_metric(
                "xpf_userspace_source_nat_pool_live_lock_contended_total"
            ),
        },
        "publish": {
            "publishes_total": _scalar(text, "xpf_userspace_shared_session_publishes_total"),
            "lock_acquisitions_total": _scalar(
                text, "xpf_userspace_shared_session_publish_lock_acquisitions_total"
            ),
            "lock_contended_total": _scalar(
                text, "xpf_userspace_shared_session_publish_lock_contended_total"
            ),
        },
        "replicate": {
            "upserts_total": _scalar(
                text, "xpf_userspace_session_replication_upserts_total"
            ),
            "enqueued_total": _scalar(
                text, "xpf_userspace_session_replication_enqueued_total"
            ),
            "lock_contended_total": _scalar(
                text, "xpf_userspace_session_replication_lock_contended_total"
            ),
            "queue_depth_max": _scalar(
                text, "xpf_userspace_session_replication_queue_depth_max"
            ),
        },
        "workers": workers,
    }


# ---------------------------------------------------------------------------
# Human report
# ---------------------------------------------------------------------------


def render(a: Analysis) -> str:
    lines = [f"verdict: {a.verdict}"]
    for r in a.reasons:
        lines.append(f"  ! {r}")
    lines.append(f"window: {a.elapsed_s:.2f}s")
    lines.append(f"new flows/sec (accepted pool allocations): {a.new_flows_per_sec:.0f}")
    if a.offered_flows_per_sec:
        lines.append(
            f"offered flows/sec: {a.offered_flows_per_sec:.0f} "
            f"(accepted {a.accept_ratio:.1%})"
        )
    lines.append("")
    lines.append("contention by site (blocked / acquisitions):")
    for s in a.sites:
        ratio = "n/a (never taken)" if s.ratio is None else f"{s.ratio:.2%}"
        flag = "  <-- SATURATED" if s.saturated else ""
        lines.append(
            f"  {s.name:<26} {s.contended_delta:>12} / {s.acquisitions_delta:<14} {ratio}{flag}"
        )
    lines.append(
        f"  replication queue depth high-water: {a.replication_queue_depth_max}"
    )
    if a.replication_fanout is not None:
        lines.append(f"  replication fan-out (enqueued/upserts): {a.replication_fanout:.2f}")
    lines.append("")
    if a.culprits:
        lines.append("saturated: " + ", ".join(a.culprits))
    else:
        lines.append("saturated: none — no site reached the saturation threshold")
    if a.worker_installs:
        spread = " ".join(f"{w}={n}" for w, n in sorted(a.worker_installs.items()))
        lines.append(f"per-worker installs: {spread}")
        lines.append(
            f"  active workers: {a.active_workers}  max share: "
            f"{a.max_worker_share:.1%}"
            if a.max_worker_share is not None
            else f"  active workers: {a.active_workers}"
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("before", help="JSON snapshot taken before the traffic cell")
    p.add_argument("after", help="JSON snapshot taken after the traffic cell")
    p.add_argument(
        "--offered-rate",
        type=float,
        default=None,
        help="generator-reported offered new flows/sec, if known",
    )
    p.add_argument("--saturation-ratio", type=float, default=DEFAULT_SATURATION_RATIO)
    p.add_argument("--queue-depth-backlog", type=int, default=DEFAULT_QUEUE_DEPTH_BACKLOG)
    p.add_argument("--min-window", type=float, default=DEFAULT_MIN_WINDOW_S)
    p.add_argument("--min-accept-ratio", type=float, default=DEFAULT_MIN_ACCEPT_RATIO)
    p.add_argument("--min-active-workers", type=int, default=DEFAULT_MIN_ACTIVE_WORKERS)
    p.add_argument("--max-worker-share", type=float, default=DEFAULT_MAX_WORKER_SHARE)
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = p.parse_args(argv)

    with open(args.before, encoding="utf-8") as f:
        before = json.load(f)
    with open(args.after, encoding="utf-8") as f:
        after = json.load(f)

    a = analyze(
        before,
        after,
        offered_flows_per_sec=args.offered_rate,
        saturation_ratio=args.saturation_ratio,
        queue_depth_backlog=args.queue_depth_backlog,
        min_window_s=args.min_window,
        min_accept_ratio=args.min_accept_ratio,
        min_active_workers=args.min_active_workers,
        max_worker_share=args.max_worker_share,
    )
    print(json.dumps(a.as_dict(), indent=2) if args.json else render(a))
    # Exit codes are the harness's fail gate: 0 only for a run that measured
    # the install path, 2 for a run that measured something else, 1 for a run
    # that measured nothing.
    return {VALID: 0, INCONCLUSIVE: 2}.get(a.verdict, 1)


if __name__ == "__main__":
    sys.exit(main())
