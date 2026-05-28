# Claude SMR plan-review r1 — #1630 CoS scheduler equalize-bug

**Reviewer role**: domain SMR (CoS scheduler, waterfill allocator,
per-class lease coordination, root-shaper interaction, cache-line
behaviour, software-design patterns).

**Verdict**: **PLAN-NEEDS-MINOR**. Plan is dispositive on root
cause and proposed fix; needs sharper tests + one clarifying
edge case.

## §1 Root-cause analysis (sharper)

I traced the dataflow end-to-end and confirm plan §4's diagnosis:

**The pass1 budget formula is structurally wrong for any config
where `Σ R_i > shaping_rate`** (i.e., any oversubscription
scenario — which is the whole point of the knob).

Walking the numbers for the smoke fixture:

- `quantum_sum = Σ (R_i × 200µs)` over 10 exact queues with
  `R_i = {100M, 1G, 3G, 6G, 9G, 12G, 15G, 18G, 21G, 24G} bps`:
  `Σ R_i ≈ 109 Gbps`. Sum of quanta ≈ `13.6 GB/s × 200µs =
  2.725 MB`. With fraction 0.7, pass1 = 1.9 MB.

- Root tokens delivered per 200µs at shaper 25 Gbps:
  `3.125 GB/s × 200µs = 625 KB`.

**Ratio**: pass1 budget is **3.05× the bytes the shaper can
actually deliver per epoch**.

Phase 2 never fires. Selector lives in Phase 1 ascending-RR.
All classes get per-class-lease-throttled, root-shaper-bottlenecked,
rate-proportional distribution — i.e., the default proportional
mode behaviour, not the guarantee-rate behaviour.

## §2 Why the plan's fix is correct

`pass1 = (shaping_rate × VISIT_NS / 1e9) × fraction` makes pass1
a **fraction of what the shaper actually delivers per epoch**.
Under the smoke fixture: 625 KB × 0.7 = 437.5 KB. After honoring
{100m, 1g, 3g, 6g} (cumulative quantum = 252.5 KB), remaining
= 185 KB. iperf-9g's quantum = 225 KB > 185 KB → Phase 2.

This matches the documented contract verbatim:
`docs/fairness-regimes.md:848-855` — "ascending up to `fraction × cap`"
where `cap` is the shaper-delivered budget.

## §3 Cross-cutting verification

I verified the suspects #1625 raised:

- **worker_fair_share at rotate_epoch_v8.rs:230-235**: NOT the
  bug. The lease is per-class (coordinator/mod.rs:1118-1126),
  so `new_cap` here = class-rate-aware. Plan §6 captures this
  correctly.

- **Phase-2 lock-in at queue_service:889-893**: NOT the
  bug. The `break` is correct in principle but UNREACHABLE
  under realistic configs because pass1 budget is over-provisioned.
  Plan §7 captures this.

- **Phase-1 honored_mask local-not-persistent** (a third
  suspect I considered): NOT the primary bug. The per-class
  lease's `acquire_v8` naturally throttles each class to its
  configured rate per epoch, so even though `honored_mask` is
  reset per call, a queue cannot consume more than its
  class-rate-bound grant. The selector skips it on
  `queue.hot.tokens < head_len`.

## §4 Concerns I want addressed before PLAN-READY

### Concern A (open question #4 in plan): post-fix gate-1 validation

Under the fix, **iperf-100m must reach ≥ 95 Mbps**. The
per-class lease at iperf-100m grants 12.5 MB/s = 100 Mbps.
But TX_BATCH_SIZE caps each visit to 64 packets ≈ 96 KB. At
1500-byte MTU each visit = 1-2 packets for iperf-100m
(because per-visit quantum = 2500 B = 1.6 packets).

Per-class lease grants 2500 B per 200µs epoch. So iperf-100m
can drain 1.6 packets per epoch ≈ 8000 packets/sec ≈
12 Mbps of useful bytes. **Wait — that's LOWER than the
observed 19 Mbps in the broken mode.**

Let me recompute: per-class lease grant rate = 100 Mbps =
12.5 MB/s. Per second, iperf-100m's lease should grant
12.5 MB of bytes. The lease cap is `R × elapsed`, not
`R × VISIT_NS`. Over 1 second, iperf-100m's lease delivers
12.5 MB worth of grants. Selector visits drain it as fast
as packets are queued. **So 12.5 MB/s ≈ 100 Mbps is
achievable.**

But the existing measurement shows iperf-100m at 19 Mbps
(broken mode). That's BELOW 100 Mbps, suggesting the
selector is also a bottleneck somewhere. **The fix may
need to also unblock the per-visit cap.**

**Ask**: plan should add an explicit worked example for
iperf-100m drainage rate under the fix, showing 100 Mbps
is actually reachable (not blocked by TX_BATCH_SIZE or
quantum or per-visit budget). If it ISN'T reachable, the
fix needs to also widen the per-visit budget.

### Concern B: transparent-root fallback is dead code in
production

Plan §10 keeps a transparent-root fallback for
`shaping_rate_bytes == 0`. In production, GuaranteeRate mode
is meaningful only WITH a configured shaping-rate (otherwise
there's no oversubscription to manage). Audit:
`pkg/config/compiler_class_of_service.go:331+` — is there a
config validator that prevents
`oversubscription-policy guarantee-rate` from being applied
when `shaping-rate` is unset?

If yes, the transparent-root fallback is unreachable in
production; consider asserting unreachable instead of silently
falling back. If no, the fallback is a defensive guard worth
keeping but should also emit a warning.

### Concern C: AGY r1's jumbo-frame Phase-1 starvation
(open question #5)

Under the corrected (smaller) pass1 budget, the `break` at
line 893 is more likely to fire. If a single mid-rate queue's
quantum is the first to exceed remaining pass1, ALL
subsequent smaller queues starve. With 9 ascending queues at
{2.5K, 25K, 75K, 150K, ...} and pass1 = 437.5 KB, the break
fires after 6G (cumulative 252.5K) — but at that point all
small classes ARE honored. So smoke fixture is safe.

Edge case: pre-existing config with R_i = {100M, 25G, 50G}
and shaper 30G, fraction 0.5: pass1 = (30G × 200µs × 0.5)/8
= 375 KB. iperf-100m quantum = 2500. iperf-25g quantum =
clamped 512 KB > 375 KB → break. iperf-50g never reached.
iperf-100m honored. iperf-25g and iperf-50g go to Phase 2.
**This is correct behaviour** — small class served, larger
classes share residual. Confirmed safe.

### Concern D: tests need a "fraction matters" boundary case

Plan §11 adds 3 unit tests. Add a 4th: with
`shaping_rate_bytes = 3_125_000_000`, run pass1-refill for
`fraction ∈ {0.2, 0.5, 0.7, 1.0}` and assert
`pass1_remaining` is exactly proportional to fraction.
This is the boundary the existing
`waterfill_guarantee_rate_fraction_consulted_by_selector`
test in tests.rs:2278 was trying to cover but had to defer
the visible-distribution check.

## §5 Test discipline (Concern E)

Plan §11 names cargo + 5×loop + smoke. Add:
- `cargo test --release` (release builds sometimes catch
  arithmetic overflow that debug builds mask).
- Explicit `make test-failover` (already mentioned but
  call out the success criterion: zero packet drops).
- A negative test: with fraction = 0.0 the selector must NOT
  call the waterfill at all (dispatch gate at mod.rs:603-606).
  Existing test
  `waterfill_default_proportional_mode_uses_legacy_rr` covers
  this for `Proportional`; add equivalent for
  `GuaranteeRate + fraction = 0.0`.

## §6 What I'd block on

Nothing. Concerns A-E are minor; the plan is fundamentally
correct and the fix is small. I'd request a v2 that:

1. Adds the iperf-100m drainage-rate worked example (Concern A).
2. Notes whether config-validator prevents transparent-root +
   GuaranteeRate (Concern B); leaves fallback or asserts as
   appropriate.
3. Adds the fraction-proportionality test (Concern D).
4. Adds the cargo --release + zero-drop failover criteria
   (Concern E).

If reviewers Codex / AGY converge with these or sharper, sign off.

## §7 Recommended verdict for cross-reviewer convergence

**Claude SMR**: **PLAN-NEEDS-MINOR**. Root-cause analysis
is dispositive. Fix is correct and minimal. v2 adds 4 sharp
clarifications; expect PLAN-READY after v2.
