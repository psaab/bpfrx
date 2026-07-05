"""Population coefficient-of-variation — the single Python mirror of the Rust
fairness SSOT.

`population_cov` computes the SAME estimator as `compute_observed_cov` in
`userspace-dp/src/fairness.rs` (the authoritative fairness verdict):

    CoV = population_stddev / mean

over the FULL per-flow throughput vector. Two properties are load-bearing
for parity with the Rust SSOT and MUST NOT drift:

* **Population stddev (denominator N), not sample stddev (N-1).**
  `statistics.stdev` is the *sample* estimator and diverges from the Rust
  value — e.g. for {500,500,1500,1500} the population CoV is 0.5 while the
  sample CoV is 0.5774. The smoke reducer previously used
  `statistics.stdev`, so its printed CoV could not reproduce a
  fairness-eval verdict on identical traffic (hb166 V-10).

* **Zero-throughput (starved) flows are NOT filtered.** A fully starved
  flow must RAISE the CoV (it is maximally unfair), not silently vanish.
  The old reducer dropped `bits_per_second == 0` streams, so a class with
  one starved flow printed CoV 0 — the "perfectly fair" value — exactly
  inverting the signal. `compute_observed_cov` takes the whole vector
  including zeros; this mirror does too.

Returns 0.0 for an empty vector or a zero mean, matching the Rust
reference exactly (see `fairness.rs` `observed_cov_empty` /
`observed_cov_zero_mean`).
"""

from __future__ import annotations

from typing import Sequence


def population_cov(values: Sequence[float]) -> float:
    """Return the population CoV (stddev/mean) over ``values``.

    Mirrors ``userspace-dp/src/fairness.rs::compute_observed_cov``:
    population stddev over the full vector, no zero filtering, 0.0 for an
    empty vector or a zero mean.
    """
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    if mean == 0.0:
        return 0.0
    var = sum((float(v) - mean) ** 2 for v in values) / n
    return (var ** 0.5) / mean
