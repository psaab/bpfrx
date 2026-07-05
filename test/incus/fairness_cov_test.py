"""Cross-check the Python CoV mirror against the Rust fairness SSOT.

The expected values are the SAME ones asserted by
`userspace-dp/src/fairness.rs` unit tests (`observed_cov_balanced`,
`observed_cov_skewed`, `observed_cov_empty`, `observed_cov_zero_mean`).
If `population_cov` ever drifts from that estimator — e.g. reverts to a
sample stddev or re-introduces zero-flow filtering — these tests go RED.
"""

import statistics
import unittest

from fairness_cov import population_cov


class PopulationCovMatchesRustSSOT(unittest.TestCase):
    def test_balanced_is_zero(self):
        # fairness.rs observed_cov_balanced: {1000,1000,1000,1000} -> 0.0
        self.assertAlmostEqual(population_cov([1000, 1000, 1000, 1000]), 0.0)

    def test_skewed_is_half(self):
        # fairness.rs observed_cov_skewed: {500,500,1500,1500}
        # mean=1000, var=250000, stddev=500, CoV=0.5 (POPULATION).
        self.assertAlmostEqual(population_cov([500, 500, 1500, 1500]), 0.5)

    def test_empty_is_zero(self):
        # fairness.rs observed_cov_empty
        self.assertEqual(population_cov([]), 0.0)

    def test_zero_mean_is_zero(self):
        # fairness.rs observed_cov_zero_mean: {0,0,0} -> 0.0
        self.assertEqual(population_cov([0, 0, 0]), 0.0)

    def test_population_not_sample_stddev(self):
        # The distinction that motivated hb166 V-10: the SSOT is the
        # population estimator. The sample estimator (statistics.stdev,
        # N-1) gives 0.5774 for the same input — a value the printed CoV
        # must NOT report.
        skewed = [500, 500, 1500, 1500]
        sample_cov = statistics.stdev(skewed) / statistics.mean(skewed)
        self.assertAlmostEqual(sample_cov, 0.5773502691896257)
        self.assertNotAlmostEqual(population_cov(skewed), sample_cov, places=3)

    def test_starved_flow_is_not_filtered(self):
        # A starved (0 bps) flow must RAISE CoV, not vanish. The old
        # reducer filtered zeros and printed CoV 0 (perfectly fair) for
        # exactly this vector — the inverted signal V-10 flags.
        with_starved = [0, 1000, 1000, 1000]
        # mean=750, var=187500, stddev=433.0127, CoV=0.57735.
        self.assertAlmostEqual(population_cov(with_starved), 0.5773502691896257)
        # Filtering the zero (the old behaviour) would collapse to CoV 0.
        filtered = [v for v in with_starved if v > 0]
        self.assertAlmostEqual(population_cov(filtered), 0.0)


if __name__ == "__main__":
    unittest.main()
