# Codex hostile plan review r3 - #1614 v5.1

Reviewer: Codex (hostile scheduler / AF_XDP / CoS plan reviewer)

Target: `docs/pr/1614-multi-rss-cos/plan.md` v5.1, branch
`refactor/1614-multi-rss-cos`, HEAD `c7561be43`.

Verdict: **NEEDS-MINOR**

No PLAN-KILL. I do not have a verified counter-example that
invalidates Axis A, revives B3, or breaks the Phase 0 premise. Phase 0
is accepted as PASSED on 2026-05-27: reverse-simul received 22.72 G
with all 11 classes, generator CPU idle headroom, firewall confirmed as
the bottleneck.

The A1.1 executable algorithm now has the right shape: reserve
priority-low first with `saturating_sub`, branch to the legacy selector
for proportional / fraction-zero mode, and use remaining quantum in
Phase 2. That is the right design. The remaining blockers are stale or
inconsistent plan text that implementors could reasonably follow.

## Required minor fixes

### F1. A1/A2 still have stale `cap` / subtraction text

Severity: **NEEDS-MINOR**

A1.1 correctly states:

```text
let cap_eff = root.tokens.saturating_sub(priority_low_min_share_pass);
...
return select_exact_cos_guarantee_queue_with_lease_telemetry(root, cap_eff, ...)
// else: run the new waterfill allocator below over cap_eff.
```

That closes AGY r3 B and E1 in the main algorithm. It also makes
proportional mode with `priority_low_min_share_pass > 0` coherent: the
legacy exact selector still runs, but against `cap_eff`; Phase 3 can
admit priority-low against the reserved share.

However, the later pseudocode still defines `cap` as `root.tokens` and
computes `pass1_budget = cap * guarantee_fraction`, while Phase 2 uses
`cap_eff`. A2 also still says:

```text
cap_eff = root.tokens - priority_low_min_share_pass
```

Those lines should be changed to one invariant everywhere:

```text
let cap_eff = root.tokens.saturating_sub(priority_low_min_share_pass);
pass1_budget = (cap_eff * guarantee_fraction).floor()
pass2_budget = cap_eff - actual_phase1_alloc
```

Without that cleanup, a literal implementation can either reintroduce
unsigned underflow or let Phase 1 allocate against the unreserved root
token budget, violating the priority-low reserve in guarantee-rate mode.

### F2. A1.2 prediction tables still use full quantum for the partial queue

Severity: **NEEDS-MINOR**

The A1.1 algorithm correctly fixes AGY r3 E2:

```text
remaining_quantum_i = Q_i - alloc[queue_idx]
```

That bounds each queue's total allocation by `Q_i` in the oversubscribed
regime. Proof: after Phase 1, the denominator is
`sum(Q_i - alloc[i])` over queues not in `honor_set`. Since
`cap_eff <= sum(Q_i)` under oversubscription,
`pass2_budget <= unhonored_remaining_quantum`, so every Phase 2 share
is `<= remaining_quantum_i`; therefore `alloc[i] <= Q_i`.

But A1.2 still computes the `0.4` and `0.7` examples with the partial
queue's full quantum in Phase 2. The examples should be updated to the
remaining-quantum math below, or removed to avoid encoding wrong test
expectations.

## Fraction walk

Assume the documented 109/18 fixture, exact rates
`0.1, 1, 3, 6, 9, 12, 15, 18, 21, 24 G`, and quantums
`2.5, 25, 75, 150, 225, 300, 375, 450, 512, 512 KB`.

### `fraction = 0.0`, `priority_low_min_share = 0`

`cap_eff == root.tokens`. The explicit branch calls the existing
`select_exact_cos_guarantee_queue_with_lease_telemetry` path with the
same capacity. This preserves the exact-class current behavior.

### `fraction = 0.0`, `priority_low_min_share > 0`

`cap_eff = root.tokens.saturating_sub(priority_low_min_share_pass)`.
The explicit branch still calls the legacy selector, but on the reduced
exact-class budget. That is not bit-for-bit identical to the no-minshare
default, but it is the intended behavior: exact-class scheduling remains
the legacy algorithm under `cap_eff`, while priority-low keeps its
reserve.

The `saturating_sub` is the right Rust guard. If transient depletion
makes `root.tokens < priority_low_min_share_pass`, `cap_eff` becomes
zero instead of panicking in debug or wrapping in release.

### `fraction = 0.4`

Phase 1 budget is `7.2 G`. It fully honors 100m, 1g, and 3g
(`4.1 G` cumulative), then partially honors 6g with `3.1 G`.

The 6g class consumed `3.1 / 6.0 * 150 = 77.5 KB` of its quantum, so
its Phase 2 remaining weight is `72.5 KB`, not `150 KB`.

Phase 2 budget is `10.8 G`; denominator is
`72.5 + 225 + 300 + 375 + 450 + 512 + 512 = 2446.5 KB`.

Approximate final totals:

| Class | Total |
|-------|------:|
| 100m | 0.10 G |
| 1g | 1.00 G |
| 3g | 3.00 G |
| 6g | 3.42 G |
| 9g | 0.99 G |
| 12g | 1.32 G |
| 15g | 1.66 G |
| 18g | 1.99 G |
| 21g | 2.26 G |
| 24g | 2.26 G |
| Sum | 18.00 G |

### `fraction = 0.7`

Phase 1 budget is `12.6 G`. It fully honors 100m, 1g, 3g, and 6g
(`10.1 G` cumulative), then partially honors 9g with `2.5 G`.

The 9g class consumed `2.5 / 9.0 * 225 = 62.5 KB` of its quantum, so
its Phase 2 remaining weight is `162.5 KB`, not `225 KB`.

Phase 2 budget is `5.4 G`; denominator is
`162.5 + 300 + 375 + 450 + 512 + 512 = 2311.5 KB`.

Approximate final totals:

| Class | Total |
|-------|------:|
| 100m | 0.10 G |
| 1g | 1.00 G |
| 3g | 3.00 G |
| 6g | 6.00 G |
| 9g | 2.88 G |
| 12g | 0.70 G |
| 15g | 0.88 G |
| 18g | 1.05 G |
| 21g | 1.20 G |
| 24g | 1.20 G |
| Sum | 18.00 G |

### `fraction = 1.0`

Phase 1 budget is `18.0 G`. It fully honors 100m, 1g, 3g, and 6g
(`10.1 G` cumulative), then partially honors 9g with the remaining
`7.9 G`. Phase 2 budget is zero.

Approximate final totals:

| Class | Total |
|-------|------:|
| 100m | 0.10 G |
| 1g | 1.00 G |
| 3g | 3.00 G |
| 6g | 6.00 G |
| 9g | 7.90 G |
| 12g | 0.00 G |
| 15g | 0.00 G |
| 18g | 0.00 G |
| 21g | 0.00 G |
| 24g | 0.00 G |
| Sum | 18.00 G |

## CoDel disposition check

The r2 CoDel concern is closed enough for plan purposes: A3 is now an
experimental smoke-driven gate with an explicit fallback to ship A1,
A2, and A4 if CoDel regresses. That is acceptable.

One wording cleanup is still advisable while touching the minor fixes:
the plan says PR-1 is mergeable only with gate 3 PASSING, while A3 says
200-500 retrans/class/30s can merge as a partial gain. Make the §7 gate
3 wording point to the A3 disposition tiers so reviewers do not treat
the partial-gain path as contradictory.

## Decision

**NEEDS-MINOR.**

Do not reopen Axis B. Do not KILL. Fix the stale `cap_eff` /
`saturating_sub` text and update the A1.2 fraction examples to
remaining-quantum math. After those edits, I would attest
**PLAN-READY** for implementation.
