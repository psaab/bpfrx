"""Tests for the #4800 new-flow-ceiling attribution layer.

Two properties carry the value and are asserted hardest:

1. **The classifier must be able to name MORE THAN ONE culprit.** The
   interesting real-world answer to #4800 is "publish and replicate saturate
   before NAT does". A classifier that reports a single winner would let a
   reader conclude "publish is the bottleneck, shard publish" and miss that
   sharding the NAT allocator alone (#2852 Phase 2) was never going to help.

2. **A quiet run must name NOTHING.** The negative control: a snapshot pair
   where every ratio is below threshold must come back VALID with an empty
   culprit list, not with the least-cold site nominated by default.

The validity gates get their own tests because a harness that cannot fail is
worse than none: a run with no pool allocations, a restarted helper, a
backwards counter, an exhausted pool, an under-driving generator or traffic
landing on one RX queue must each be refused rather than reported as a
number.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from newflow_ceiling_analyze import (  # noqa: E402
    INCONCLUSIVE,
    INVALID,
    VALID,
    SnapshotError,
    analyze,
    parse_prometheus_text,
)


def snap(
    t,
    *,
    allocations=0,
    exhaustion=0,
    nat_acq=0,
    nat_blocked=0,
    pub_calls=0,
    pub_acq=0,
    pub_blocked=0,
    rep_upserts=0,
    rep_enqueued=0,
    rep_blocked=0,
    rep_depth=0,
    workers=None,
    helper_pid=4242,
):
    return {
        "t": t,
        "helper_pid": helper_pid,
        "pool": {
            "allocations_total": allocations,
            "exhaustion_total": exhaustion,
            "live_lock_acquisitions_total": nat_acq,
            "live_lock_contended_total": nat_blocked,
        },
        "publish": {
            "publishes_total": pub_calls,
            "lock_acquisitions_total": pub_acq,
            "lock_contended_total": pub_blocked,
        },
        "replicate": {
            "upserts_total": rep_upserts,
            "enqueued_total": rep_enqueued,
            "lock_contended_total": rep_blocked,
            "queue_depth_max": rep_depth,
        },
        "workers": workers if workers is not None else {},
    }


def six_even_workers(total):
    """Six workers sharing `total` installs evenly — the loss cluster's 6 RX
    queues, distributed as a healthy multi-worker run would be."""
    per = total // 6
    return {str(i): per for i in range(6)}


class AttributionNamesEverySaturatedSite(unittest.TestCase):
    def test_publish_and_replicate_both_named_when_both_saturate(self):
        """The load-bearing case for #4800.

        NAT stays cold (1% blocked), publish runs hot (40%), replication runs
        hotter (60%). A single-winner classifier would report only
        replication and a reader would shard the wrong thing; both must be
        named, replication first.
        """
        before = snap(
            0.0,
            allocations=0,
            nat_acq=0,
            nat_blocked=0,
            pub_acq=0,
            pub_blocked=0,
            rep_enqueued=0,
            rep_blocked=0,
            rep_upserts=0,
            workers=six_even_workers(0),
        )
        after = snap(
            10.0,
            allocations=600_000,
            nat_acq=1_200_000,
            nat_blocked=12_000,  # 1.0%
            pub_acq=1_800_000,
            pub_blocked=720_000,  # 40%
            rep_upserts=600_000,
            rep_enqueued=3_600_000,
            rep_blocked=2_160_000,  # 60%
            rep_depth=8,
            workers=six_even_workers(600_000),
        )
        a = analyze(before, after)

        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.new_flows_per_sec, 60_000.0)
        self.assertTrue(a.saturated)
        # BOTH, not one.
        self.assertIn("publish_shared_session", a.culprits)
        self.assertIn("replicate_session_upsert", a.culprits)
        # And NAT must not be swept in with them — that is the whole #2852
        # Phase-2 question.
        self.assertNotIn("nat_allocator_live_mutex", a.culprits)
        # Ratio-descending, so the reader sees the worse one first.
        self.assertEqual(
            a.culprits[:2], ["replicate_session_upsert", "publish_shared_session"]
        )

    def test_cold_sites_are_still_reported_with_their_ratios(self):
        """A site that did not saturate must still appear in the table.

        Omitting cold sites would make "NAT never blocked" indistinguishable
        from "NAT was not measured", which is exactly the distinction the
        Phase-2 decision needs.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=600_000,
                nat_acq=1_200_000,
                nat_blocked=12_000,
                pub_acq=1_800_000,
                pub_blocked=720_000,
                rep_upserts=600_000,
                rep_enqueued=3_600_000,
                rep_blocked=2_160_000,
                workers=six_even_workers(600_000),
            ),
        )
        names = [s.name for s in a.sites]
        self.assertEqual(
            names,
            [
                "nat_allocator_live_mutex",
                "publish_shared_session",
                "replicate_session_upsert",
            ],
        )
        nat = next(s for s in a.sites if s.name == "nat_allocator_live_mutex")
        self.assertAlmostEqual(nat.ratio, 0.01)
        self.assertFalse(nat.saturated)

    def test_all_three_can_be_named_together(self):
        """Nothing structurally caps the culprit list at two."""
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                nat_blocked=100_000,
                pub_acq=300_000,
                pub_blocked=150_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                rep_blocked=300_000,
                workers=six_even_workers(100_000),
            ),
        )
        self.assertEqual(
            sorted(a.culprits),
            sorted(
                [
                    "nat_allocator_live_mutex",
                    "publish_shared_session",
                    "replicate_session_upsert",
                ]
            ),
        )


class NegativeControl(unittest.TestCase):
    def test_nothing_saturated_names_no_culprit(self):
        """A healthy, unsaturated run must nominate nobody.

        Every site is exercised heavily but blocks on well under 1% of
        acquisitions. If this named a culprit, every run would produce one and
        the attribution would carry no information.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                30.0,
                allocations=300_000,
                nat_acq=600_000,
                nat_blocked=600,  # 0.1%
                pub_acq=900_000,
                pub_blocked=450,  # 0.05%
                rep_upserts=300_000,
                rep_enqueued=1_800_000,
                rep_blocked=1_800,  # 0.1%
                rep_depth=3,
                workers=six_even_workers(300_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.culprits, [])
        self.assertFalse(a.saturated)
        self.assertEqual(a.new_flows_per_sec, 10_000.0)
        # ...and it still reports the real ratios, so "quiet" is evidenced
        # rather than merely asserted.
        for s in a.sites:
            self.assertIsNotNone(s.ratio)
            self.assertLess(s.ratio, 0.01)

    def test_untouched_site_reports_none_not_zero(self):
        """A site with zero acquisitions has NO ratio.

        Scoring it 0.0 would read as "measured, never blocked" — a positive
        finding about a site that was never on the path at all.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=1_000,
                nat_acq=2_000,
                nat_blocked=0,
                pub_acq=0,
                pub_blocked=0,
                rep_upserts=0,
                rep_enqueued=0,
                rep_blocked=0,
                workers=six_even_workers(1_000),
            ),
        )
        pub = next(s for s in a.sites if s.name == "publish_shared_session")
        self.assertIsNone(pub.ratio)
        self.assertFalse(pub.saturated)


class QueueDepthIsItsOwnFinding(unittest.TestCase):
    def test_backlogged_queue_is_named_even_when_the_mutex_is_cold(self):
        """Depth and contention are different failures.

        Producers never collide (0 blocked enqueues) but the consuming worker
        is 4000 commands behind. Reporting only the mutex ratio would call
        this run clean.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                nat_blocked=40,
                pub_acq=600_000,
                pub_blocked=60,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_blocked=0,
                rep_depth=4_000,
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertIn("replicate_session_upsert_queue_backlog", a.culprits)
        self.assertNotIn("replicate_session_upsert", a.culprits)

    def test_shallow_queue_is_not_a_backlog(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                nat_blocked=40,
                pub_acq=600_000,
                pub_blocked=60,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_blocked=0,
                rep_depth=6,
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.culprits, [])

    def test_fanout_multiplier_is_recovered_from_the_counter_pair(self):
        """enqueued/upserts must reproduce the sibling worker count.

        The analysis layer never learns the worker count out of band; it
        divides. Six workers must read back as 6.0.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                pub_acq=300_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                workers=six_even_workers(100_000),
            ),
        )
        self.assertAlmostEqual(a.replication_fanout, 6.0)


class ValidityGates(unittest.TestCase):
    def test_no_pool_allocations_is_invalid_not_a_rate_of_zero(self):
        """The SNAT-rule-not-in-effect gate.

        Without this, a run where the pool-mode rule failed to commit reports
        "0 new flows/sec, nothing saturated" — a clean-looking result for a
        run that measured nothing at all.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(30.0, allocations=0, workers=six_even_workers(0)),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertEqual(a.new_flows_per_sec, 0.0)
        self.assertTrue(any("zero pool-mode SNAT allocations" in r for r in a.reasons))

    def test_helper_restart_is_invalid(self):
        a = analyze(
            snap(0.0, helper_pid=100, workers=six_even_workers(0)),
            snap(
                10.0,
                helper_pid=200,
                allocations=500_000,
                nat_acq=1_000_000,
                workers=six_even_workers(500_000),
            ),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("helper restarted" in r for r in a.reasons))

    def test_counter_regression_is_invalid(self):
        """A backwards counter means the scrape crossed helper processes even
        if the pid happened to be unavailable."""
        before = snap(
            0.0, helper_pid=None, allocations=900_000, nat_acq=2_000_000,
            workers=six_even_workers(0),
        )
        after = snap(
            10.0, helper_pid=None, allocations=1_000, nat_acq=2_000,
            workers=six_even_workers(1_000),
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("went backwards" in r for r in a.reasons))

    def test_non_positive_window_is_invalid(self):
        a = analyze(
            snap(10.0, allocations=0, workers=six_even_workers(0)),
            snap(10.0, allocations=500_000, workers=six_even_workers(500_000)),
        )
        self.assertEqual(a.verdict, INVALID)

    def test_short_window_is_invalid(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                1.0,
                allocations=50_000,
                nat_acq=100_000,
                pub_acq=150_000,
                rep_upserts=50_000,
                rep_enqueued=300_000,
                workers=six_even_workers(50_000),
            ),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("below the" in r for r in a.reasons))

    def test_pool_exhaustion_is_inconclusive_not_a_lock_ceiling(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=600_000,
                exhaustion=12_345,
                nat_acq=1_200_000,
                nat_blocked=600_000,
                pub_acq=1_800_000,
                rep_upserts=600_000,
                rep_enqueued=3_600_000,
                workers=six_even_workers(600_000),
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertTrue(any("exhaustion" in r for r in a.reasons))

    def test_generator_underdrive_is_inconclusive(self):
        """Accepting 20k/s of an offered 100k/s means something upstream of
        the firewall bound first."""
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                pub_acq=600_000,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                workers=six_even_workers(200_000),
            ),
            offered_flows_per_sec=100_000.0,
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertAlmostEqual(a.accept_ratio, 0.2)
        self.assertTrue(any("bound first" in r for r in a.reasons))

    def test_generator_at_rate_is_valid(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=1_000_000,
                nat_acq=2_000_000,
                pub_acq=3_000_000,
                rep_upserts=1_000_000,
                rep_enqueued=6_000_000,
                workers=six_even_workers(1_000_000),
            ),
            offered_flows_per_sec=100_000.0,
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertAlmostEqual(a.accept_ratio, 1.0)

    def test_single_rx_queue_is_inconclusive(self):
        """One worker carrying everything is a core ceiling, not a lock one.

        Without this gate a run steered onto a single RX queue would report a
        high replication contention ratio and read as a cross-worker lock
        bound — the exact mis-attribution #4800 must avoid.
        """
        a = analyze(
            snap(0.0, workers={str(i): 0 for i in range(6)}),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                nat_blocked=100_000,
                pub_acq=300_000,
                pub_blocked=150_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                rep_blocked=300_000,
                workers={"0": 100_000, "1": 0, "2": 0, "3": 0, "4": 0, "5": 0},
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertEqual(a.active_workers, 1)
        self.assertTrue(any("RSS-distribution-limited" in r for r in a.reasons))

    def test_worker_skew_is_inconclusive_even_when_all_workers_are_active(self):
        """Three active workers passes the count gate; 80% on one does not
        pass the share gate."""
        a = analyze(
            snap(0.0, workers={str(i): 0 for i in range(6)}),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                pub_acq=300_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                workers={"0": 80_000, "1": 10_000, "2": 10_000, "3": 0, "4": 0, "5": 0},
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertAlmostEqual(a.max_worker_share, 0.8)
        self.assertTrue(any("single-worker-bound" in r for r in a.reasons))

    def test_missing_series_raises_rather_than_scoring_zero(self):
        before = snap(0.0)
        after = snap(10.0, allocations=1_000)
        del after["publish"]["lock_contended_total"]
        with self.assertRaises(SnapshotError):
            analyze(before, after)


SCRAPE = """\
# HELP xpf_userspace_source_nat_pool_allocations_total allocations
# TYPE xpf_userspace_source_nat_pool_allocations_total counter
xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 987654
xpf_userspace_source_nat_pool_allocations_total{pool="idle-pool",rule="other"} 3
xpf_userspace_source_nat_pool_exhaustions_total{pool="lab-pool",rule="snat"} 0
xpf_userspace_source_nat_pool_exhaustions_total{pool="idle-pool",rule="other"} 0
xpf_userspace_source_nat_pool_live_lock_acquisitions_total{pool="lab-pool",rule="snat"} 2000000
xpf_userspace_source_nat_pool_live_lock_acquisitions_total{pool="idle-pool",rule="other"} 9
xpf_userspace_source_nat_pool_live_lock_contended_total{pool="lab-pool",rule="snat"} 40000
xpf_userspace_source_nat_pool_live_lock_contended_total{pool="idle-pool",rule="other"} 0
xpf_userspace_shared_session_publishes_total 1000000
xpf_userspace_shared_session_publish_lock_acquisitions_total 3000000
xpf_userspace_shared_session_publish_lock_contended_total 900000
xpf_userspace_session_replication_upserts_total 1000000
xpf_userspace_session_replication_enqueued_total 6000000
xpf_userspace_session_replication_lock_contended_total 1200000
xpf_userspace_session_replication_queue_depth_max 17
xpf_userspace_worker_new_flow_installs_total{worker_id="0"} 170000
xpf_userspace_worker_new_flow_installs_total{worker_id="1"} 166000
xpf_userspace_worker_new_flow_installs_total{worker_id="2"} 164000
"""


class ScrapeParsing(unittest.TestCase):
    def test_selects_the_pool_under_test(self):
        """A second idle pool must not dilute the ratio.

        Summing both pools' acquisitions would add the idle pool's cold
        denominator to the loaded pool's numerator and understate contention.
        """
        s = parse_prometheus_text(
            SCRAPE, timestamp=100.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        self.assertEqual(s["pool"]["allocations_total"], 987654)
        self.assertEqual(s["pool"]["live_lock_acquisitions_total"], 2_000_000)
        self.assertEqual(s["pool"]["live_lock_contended_total"], 40_000)
        self.assertEqual(s["publish"]["lock_contended_total"], 900_000)
        self.assertEqual(s["replicate"]["queue_depth_max"], 17)
        self.assertEqual(s["workers"], {"0": 170000, "1": 166000, "2": 164000})
        self.assertEqual(s["helper_pid"], 7)

    def test_unknown_pool_raises(self):
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(
                SCRAPE, timestamp=1.0, pool_name="does-not-exist", rule_name="snat"
            )

    def test_ambiguous_pool_selection_raises(self):
        """Refusing to guess is the point: silently picking the first pool
        would attribute another rule's contention to this one."""
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(SCRAPE, timestamp=1.0)

    def test_missing_global_series_raises(self):
        trimmed = "\n".join(
            l
            for l in SCRAPE.splitlines()
            if not l.startswith("xpf_userspace_session_replication_queue_depth_max")
        )
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(
                trimmed, timestamp=1.0, pool_name="lab-pool", rule_name="snat"
            )

    def test_end_to_end_two_scrapes(self):
        """Parse -> analyze, the path the harness actually takes."""
        before = parse_prometheus_text(
            SCRAPE, timestamp=0.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        # Advance the pool allocations AND the per-worker installs: a scrape
        # pair where the workers did not move is a run in which no worker
        # installed anything, and the RSS gate is right to refuse it.
        later = SCRAPE.replace(
            'xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 987654',
            'xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 1587654',
        )
        for worker, before_n, after_n in (
            ("0", 170000, 370000),
            ("1", 166000, 366000),
            ("2", 164000, 364000),
        ):
            later = later.replace(
                f'xpf_userspace_worker_new_flow_installs_total{{worker_id="{worker}"}} {before_n}',
                f'xpf_userspace_worker_new_flow_installs_total{{worker_id="{worker}"}} {after_n}',
            )
        after = parse_prometheus_text(
            later, timestamp=10.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.new_flows_per_sec, 60_000.0)
        # No counter moved besides allocations, so no site can be saturated.
        self.assertEqual(a.culprits, [])


if __name__ == "__main__":
    unittest.main()
