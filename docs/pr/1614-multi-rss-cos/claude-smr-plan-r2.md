# Claude SMR plan-review r2 — #1614 v3

Reviewer: Claude (SMR — network scheduling / shaper semantics / AF_XDP
queue physics / CPU microarchitecture / Junos CoS contract).

Method: hostile-verify against my own r1 + AGY r1 + Codex r1, and
against the new v3 design.

Verdict: **NEEDS-MAJOR (one fatal, two substantive)**.

Plan v3 is significantly closer to PLAN-READY than v2; the
convergent findings from r1 are addressed correctly. But the v3
core algorithm has a new internal inconsistency, the R8
BLOCKING-gate phrasing isn't operationally actionable, and the
acceptance gates need tightening on what "strict-exact" actually
delivers.

## Fatal: F4 — §4 A1.4 weighted-honor algorithm is unstable across drain passes

The v3 §4 A1.4 algorithm rule is "honor each ascending class up
to its rate OR proportional-share, whichever is larger, until
cumulative reaches cap; then break".

Walk it across drain passes on the 109/18 fixture in
`strict-exact` mode:

- Pass 0 (cold cap = 18 G): honor 100m (100M), 1g (1G), 3g (3G),
  6g (6G). Cumulative = 10.1 G. Next is 9g at honor_target =
  max(rate=9G, proportional=1.54G) = 9 G. Cumulative would be
  19.1 G — exceeds cap. **Break**. 9g gets ZERO from Pass 1;
  Pass 2 has 18 − 10.1 = 7.9 G to distribute across 9g/12g/.../24g.

- Pass 2 proportional across {9g, 12g, 15g, 18g, 21g, 24g}:
  cumulative Q = 225+300+375+450+512+512 = 2374 KB ⇒
  9g gets 7.9 × 225/2374 = 750 Mbps
  12g gets 7.9 × 300/2374 = 1.0 G
  15g gets 7.9 × 375/2374 = 1.25 G
  18g gets 1.50 G
  21g gets 1.70 G (clamp)
  24g gets 1.70 G (clamp)

So v3's A1.4 actually gives 9g class 0.75 G (REGRESSION from 2.32
G), 12g 1.0 G (REGRESSION from 2.84 G), but small classes win.

The §4 A1.4 prediction table in the plan says:
> 9g: 1.54 G (was 2.32 G — REGRESSION)

But the actual algorithm-walk gives 9g = 750 M, not 1.54 G. The
plan's prediction table is WRONG because it inconsistently
applies "honor 9g at proportional 1.54 G" in Pass 1, then ALSO
gives 9g a Pass 2 share. The algorithm says "9g is in `unhonored`
set after Pass 1 break" so 9g gets ONLY Pass 2 — not 1.54 G + Pass 2.

This is a fatal internal inconsistency in the v3 plan
description. Either:
- The algorithm is "honor in order up to cap, then proportional
  distribute residual across NOT-HONORED only" — gives the
  walk I just did (9g=750M).
- OR the algorithm is "honor each class up to floor(rate,
  proportional), then proportional residual across ALL" — needs
  re-stating.

Plan v3 must fix this. The cleaner algorithm I'd suggest:

```
sorted = exact queues by rate ASC
remaining = cap
for q in sorted:
    target = R_q
    if remaining >= target:
        q.alloc = target
        remaining -= target
    else:
        q.alloc = remaining
        remaining = 0
        break
# All NOT-honored queues (including the partial-honor q) plus
# ALL honored queues with rate < their proportional_share get a
# proportional residual round:
total_residual = remaining  # 0 in pure-saturation case
```

OR (charitable but stable):

```
sorted = exact queues by rate ASC
honor_set = []
remaining = cap × (1 - residual_fraction)  // e.g. 0.7 × cap
for q in sorted:
    if remaining >= R_q:
        q.alloc = R_q
        remaining -= R_q
        honor_set.append(q)
    else:
        break
total_residual = cap - sum(q.alloc)
total_residual_quantum = sum(Q_q for q NOT in honor_set)
for q NOT in honor_set:
    q.alloc = total_residual × Q_q / total_residual_quantum
```

With `residual_fraction = 0.3` (70% Pass 1, 30% Pass 2) on
109/18:
- Pass 1 cap = 12.6 G
- Honor 100m, 1g, 3g, 6g (cumulative 10.1 G); next 9g (need 9 G)
  cumulative 19.1 > 12.6, break. So honor 100m+1g+3g+6g fully.
- Residual = 18 − 10.1 = 7.9 G distributed across {9g, 12g, ...,
  24g}.

That gives exactly my walk above (9g 750M, etc.) and is what
the plan SHOULD say.

**Fix**: rewrite §4 A1.4 with the explicit two-step algorithm
above, with `residual_fraction` as an operator-tunable
parameter (default 0.3 = 30% Pass 2 reservation). Then re-run
the prediction table.

Severity: HIGH (algorithm inconsistency is fatal for
plan-review).

## Substantive findings

### S8 — Gate 8 (R8) phrasing isn't actionable

The plan §7 gate 8 says "If reverse-simul also caps at ~18 G,
the firewall ISN'T the bottleneck and the entire baseline
needs remeasurement on a beefier generator (BLOCKED, file
follow-up)."

But that's an outcome-conditional gate. Operationally, what
does the implementer do FIRST? The plan should be explicit:
implementer MUST run gate 8 BEFORE writing any A1 code AND
file an early follow-up issue if it caps. Without this
sequencing the implementer might write A1 + A2 + A3 first then
discover the baseline is wrong, wasting hours.

**Fix**: §7 gate 8 should move to a separate "phase 0"
verification step before "phase 1 implementation".

### S9 — `strict-exact` is sloppily named vs the actual mechanism

The opt-in mode is called `strict-exact` but the algorithm
**doesn't** strictly honor exact rates — it honors them
**only** when cumulative ≤ cap, then degrades to proportional
residual. A truly strict-exact mode would either error on
overcommit OR cause large classes to starve.

The plan as written is more accurately
`small-class-priority` or `juniper-like-oversubscription` than
`strict-exact`. Junos vSRX docs use the term "guaranteed-rate"
for this behaviour. Suggest renaming.

**Fix**: rename the mode to `guaranteed-rate` (matches Junos
documentation), or `small-class-priority` (matches actual
mechanism). Keep `proportional` as default.

### S10 — CoDel target uniformity vs per-queue tuning interaction with Pass 1 honoring

CoDel target 5 ms is per-queue tunable. But during Pass 1
honoring, a small class might fill its queue rapidly (100m
class buffer is 500 KB = 40 ms at 100 M sustained = 40 ms of
queue residence). If the iperf3 generator pushes 2 G at the
100m class for a brief burst, the queue depth fills 500 KB in
2 ms and CoDel never fires; the rate-limit drops the burst.

For larger classes the 5 ms target may fire EVEN under
`strict-exact` Pass 1 honoring if the queue depth grows
because the Pass-1 drain rate equals the configured rate
(not faster). So CoDel may be too aggressive on large classes
in `strict-exact` mode where their drain rate matches their
arrival rate.

**Fix**: document that the CoDel target should scale with the
class's `transmit-rate` (e.g. `codel-target = max(5ms,
buffer_size / rate × 0.5)`). Or just make it default 5ms with
explicit per-queue tuning advice in `docs/cos-traffic-shaping.md`.

Severity: LOW-MEDIUM (tuning guidance, not algorithmic fatal).

## What v3 got right

- Correctly converged on rate-proportional via quantum framing
  per Codex/AGY math.
- Correctly removed B3.
- Correctly demoted B1 to BLOCKED.
- Correctly preserved `proportional` as default to avoid upgrade
  surprise.
- Correctly replaced ECN-WRED with CoDel.
- Correctly added gate 8 R8 BLOCKING check.
- Correctly added §4 A4 operator warning.
- Correctly tested both modes in the smoke matrix (C1
  proportional regression + C2 strict-exact gate).

## Decision

NEEDS-MAJOR. F4 + S8 + S9 must be addressed in plan v4 before
implementation. F4 is fatal (algorithm inconsistency); S8 and S9
are substantive but small fixes.

If plan v4 addresses these, PLAN-READY should be reachable on
round 3.

Author: address F4 (algorithm rewrite), S8 (phase 0 sequencing),
S9 (mode renaming). S10 (CoDel + Pass 1 interaction) deserves a
paragraph in §9 risks but isn't blocking.
