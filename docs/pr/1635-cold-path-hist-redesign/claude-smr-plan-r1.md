# Claude SMR plan-review r1 — #1635 cold-path histogram redesign

**Reviewer role**: domain SMR — histogram design (log-linear / HDR / pow-of-2 trade
space), hash collision analysis (birthday paradox + alias detection semantics),
aggregation semantics under packet-mix-ratio variability, wire-protocol versioning
(forward + backward compat across the Go/Rust boundary).

**Plan under review**: `docs/pr/1635-cold-path-hist-redesign/plan.md` v1.

**Self-bias check**: I authored the plan. I MUST find issues an independent reviewer
would find; otherwise this seat is performative. Hostile.

## Verdict: **PLAN-NEEDS-MAJOR**

Three structural defects in the plan that must be fixed before PLAN-READY. Listed in
descending severity.

---

### F1 (HIGH, fatal): The "≤2× error" claim is half-correct and the plan §2.1 math
contradicts itself

Plan §2.1 says:
> Worst-case error = 64 / 32 = **2× at the leftmost edge** (sample at ns=1 lands in
> bucket 0 midpoint=32 → 32× error)

This is the actual problem. The plan acknowledges the bucket-0 problem in the same
sentence as it dismisses it. A sample at ns=1 reads as bucket-0 midpoint=32 ns → 32×
error. The 10-rule cell's target range starts at **~50 ns**, but the plan provides no
evidence the production samples are bounded away from the lower edge of bucket 0
([0, 64) ns). If TSC calibration leaves residual <50 ns drift, half the samples land
in bucket 0 and the reported p50 is 32 ns regardless of truth.

**The "≤2× error" criterion as stated in the acceptance gate is not what the operator
actually needs.** What the operator needs is "p50 of the reported distribution is
within 2× of p50 of the true distribution". For a tight distribution at the bucket
edge, the bucket midpoint can be arbitrarily far from the truth in the limit. This is
the same class of error the v1 layout has, just at a finer granularity.

**Required remediation options** (pick one in v2):

(a) **Linear band stride = 16 ns** (not 64 ns), with 64 buckets covering [0, 1024) ns.
Then exponential band 16 buckets covering [1024, 2^24) ns. Total: **80 buckets** vs
plan v1's 32. Memory grows 2.5×.

(b) **Subtract baseline EXPLICITLY in the layout**: bucket 0 is `[0, baseline)` and
bucket 1 is `[baseline, baseline + 16) ns`. This pins bucket 0 = "sub-baseline noise,
discard" and the layout is calibrated relative to the wrapper baseline. Operator
reads quantiles from bucket 1 onward.

(c) **Acknowledge the limit honestly** in the acceptance gate: "≤2× error provided
the true p50 is at least 1.5× the bucket width at that magnitude". For 64-ns stride,
this means the layout is trustworthy when p50 ≥ 96 ns. For 16-ns stride, p50 ≥ 24 ns.
The 10-rule target at ~50-150 ns is covered by 16-ns stride but borderline at 64-ns.

I recommend (a) or (b). The acceptance criterion as currently written gives a false
sense of security; the plan §X gate "10-rule cell publishes a meaningful p50" is met
only if production samples are bounded away from 0.

### F2 (HIGH, structural): Slot 63 overflow is silently bias-inducing — same problem
as v1's alias_seen exclusion

Plan §2.2 says:
> if a deployment exceeds 64 active zone-pairs, the build assigns slot 63 to all
> overflow pairs

This recreates the v1 problem at the boundary. The 65th, 66th, ... pairs all collide
into slot 63 and the `alias_seen` defense-in-depth fires. The harness side's "should
always be 0" assertion becomes "is non-zero in any deployment with >63 pairs" and the
slot-63 row is published as a meaningless aggregate of disjoint distributions — F3 of
the consumer's complaint reappears inside slot 63.

**The Claude SMR consumer of #1622 explicitly called out F3 (bimodal aggregate
corruption) as structural.** Allowing it to reappear in slot 63 reintroduces the same
bug class the redesign exists to eliminate.

**Required remediation**: when `overflow_active == true`, the publisher emits NO data
for slot 63 (empty Vec / zero counts) and the operator sees a clear gap in the
table. The clear-gap is the right operator signal — "you have too many pairs; bump
the slot count and redeploy".

OR — make slot count 128 (memory cost ~6.5 KB local + ~6.5 KB atomics; wire payload
~36 KB) so the truncation case requires >127 active pairs (>10× the largest observed
deployment). Plan §7 Q2 considered this; I now think we should pick it.

### F3 (MED, soundness): Wire-protocol version-tag forward-compat scenario is wrong

Plan §3 claims:
> Older Go reading newer Rust: ... Older Rust on newer Go: Go validates array lengths
> at parse time and degrades to "no data this scrape" if shapes don't match expected.

This isn't quite what `feedback_wire_protocol_both_sides` mandates. The Go side
currently has shape-agnostic reads (it just iterates `len(w.ColdPathHist)` and
`len(w.ColdPathHist[slot])`). The current `pkg/api/metrics_userspace.go:570-580` is
shape-agnostic. So **older Go on newer Rust ACTUALLY DOES NOT crash** — it just emits
v2 bucket counts under v1 `le` labels, producing wrong `histogram_quantile()`.

This is **worse** than a hard failure: the consumer Prometheus emits structurally
wrong numbers under what looks like a normal scrape. Plan v1 misses this.

**Required remediation**: the Go side MUST read `cold_path_layout_version` and switch
the `le` boundary computation accordingly. The plan §4.8 already says this, but the
§3 narrative implies the old Go "doesn't crash" is sufficient — it's not, because
graceful-degrade-to-wrong-numbers is worse than hard-error. Strengthen the §3
contract: "older Go on newer Rust MUST EITHER produce v2-correct labels (preferred)
OR refuse to emit cold-path metrics entirely (acceptable fallback)".

### N1 (NIT): "ColdPathSlotMap" inverse table inconsistency

Plan §4.2 defines:
```rust
pub map: FastMap<u32, u8>,
pub inverse: [(u16, u16); POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
```

The inverse uses fixed-size array indexed by slot; the forward uses a FastMap. Fine,
but the (0, 0) entry in `inverse` is ambiguous — is slot 0 unassigned, or assigned to
zone-pair (0, 0)? Per the existing `zone_pair_packed_key` convention, (0, 0) is a
valid pair (packed key = 1). Use `Option<(u16, u16)>` for the inverse, or add an
explicit `slot_in_use: [bool; 64]` bitmap.

### N2 (NIT): Snapshot generation invalidation gap (plan §7 Q5)

Plan §7 Q5 acknowledges this but defers. I think the plan should commit to a position
in v2: a stale sample lands in the wrong slot at most for ~1 publish window (~1 s).
This is acceptable because: (1) at 1-in-256 sampling the per-second sample volume is
already noisy; (2) the publish-tick clears `samples`/`buckets` arrays anyway in the
local→atomics path. ACTUALLY — wait — does it? Let me trace:

Looking at the existing code: the local `WorkerColdPathCounters` is **NOT cleared**
on publish (`worker/loop_body/mod.rs:349 cph::WorkerColdPathCounters::default()` is
the merge accumulator, not a clear of the per-binding local). The per-binding
`binding.cold_path` accumulates forever. So a config-apply that changes the slot map
will leave **stale per-binding accumulator counts** in the wrong slots, and the next
publish will publish those stale counts under the NEW slot-map labels.

**This is a real bug in the redesign that the plan does not address.** When the slot
map changes, the per-binding `binding.cold_path` needs to be reset (or the new map
needs to validate that the existing accumulator slots still match the new
`(from_zone_id, to_zone_id)` keys for those slots).

I'm escalating this from N2 (NIT) to **F4 (HIGH)**.

### F4 (HIGH, soundness — promoted from N2): Stale per-binding accumulator on
slot-map change

When config-apply mints a new `cold_path_slot_map`:
- Slot 5 used to be `(trust, untrust)` → bucket counts reflect trust→untrust samples.
- Slot 5 now means `(dmz, wan)` → next publish includes the stale trust→untrust
  counts under dmz→wan labels.

This corrupts the consumer table on every snapshot generation bump.

**Required remediation** (pick one):

(a) Reset `binding.cold_path` to default on snapshot generation bump (the existing
    `arc_swap::Cache` already exposes generation; tie the cold_path reset to the
    cache flush).

(b) Generation-tag each slot: per-slot generation u32, sampled slot stamps the
    generation; on publish, the merge filters out slots whose generation doesn't
    match the current map.

(c) Disallow slot remapping — once a slot is assigned to a (from, to) pair, it stays
    assigned for the worker's lifetime. Snapshot apply rebuilds the map only by
    appending NEW pairs to unused slots; existing assignments are preserved.

I recommend (c) — it preserves the publisher contract (slot index is stable across
snapshots) AND avoids both the reset overhead and the generation-tag complexity. The
operator-facing semantics: "a zone-pair maps to the same slot for the daemon's
lifetime; restarting the daemon may remap." This matches `feedback_smoke_v4_and_v6`
contract style.

---

## Other concerns (NIT — not gating)

### N3: F4 affects the alias_seen "defense-in-depth" pitch

With (c) above, alias_seen should be **kept and enforced** as a hard error — a
duplicate (from, to) packed key in the same slot post-redesign means the builder is
broken. The plan §2.2 says "alias_seen is no longer needed for collision detection";
correct, but it's still useful as a builder invariant assertion. Plan §2.2 already
says this.

### N4: Plan §X consumer success criteria — F3 alternative for #1622

"Aggregate row is replaced with per-zone-pair rows" — the per-zone-pair rows make
the labeled PromQL aggregation the operator's choice. But #1622's STAGED-fallback
that AGY r1 #6 rejected (ship empty tables) ... is the per-zone-pair publication
that this plan delivers actually populated enough to write the operator-facing tables?
At 10 zone-pairs × 4 cohort × 2 CoS × ... the table cells are populated, but #1622's
"populated Tables A1/A2/B1/B2" deliverable required AGGREGATE per-cohort numbers.

**This is the consumer-side question that should be settled before #1635 ships:**
does #1622's eventual rewrite use the per-zone-pair rows AS-IS (PromQL aggregates
chosen per-cell) or does it still try to publish an aggregate row that this redesign
intentionally suppresses? The plan should commit to one path so #1622's reopen
template is determined.

Plan §X currently says "Aggregate row is replaced with per-zone-pair rows" — pin
this as the consumer contract. If #1622's reopen wants a different aggregation, it
proposes that aggregation in its own plan, not this PR.

---

## Decisive summary

Plan v1 has the right shape but three structural defects (F1 / F2 / F4) and one
soundness gap (F3) that I would NOT pass through plan-review.

**v2 must:**

1. Pick a narrower bucket stride (16 ns linear, 80 buckets total) OR pin the
   trustworthy-p50-region floor honestly in the acceptance gate.
2. Reject overflow with empty-row publication (NOT silent slot-63 alias) OR grow to
   128 slots.
3. Strengthen §3 wire-protocol forward-compat — older Go MUST switch on
   `cold_path_layout_version`, not silently emit wrong-labeled buckets.
4. Resolve F4 (stale slot-map remapping) — recommend "stable-slot-assignment" policy
   (option (c) above).

If v2 addresses all four, **PLAN-READY** is the next state from my seat. I'll
hostile-verify the v2 fix patches against the F1/F2/F4 escalation paths above.

---

## Self-bias retraction

I authored the plan. My r1 review surfaced four findings I missed when authoring. I
ascribe this to the difference between author-mode (defending the path-of-least-
resistance choices) and review-mode (testing the choices against the consumer's
declared needs). The author-mode oversight that produced F4 is exactly the bug
pattern `feedback_review_scaffolding_against_consumer` warns against — I scaffolded
correctness of the new bucket / new slot map in isolation without re-validating
against the consumer's stale-data exposure.

This is a strong signal that the v1 plan needs the v2 iteration, not a self-pass.
