# Claude SMR plan-review r2 — #1630

**Verdict**: **PLAN-READY**.

## §1 What changed in v2

After reading Codex r1 (PLAN-NEEDS-MAJOR, 8 findings) and AGY r1
(PLAN-NEEDS-MINOR, 3 findings), v2:

1. Adds **Hunk B**: persistent `waterfill_honored_mask` on
   `CoSInterfaceRuntime`, reset only on Phase-1 refill, used by
   Phase-2 to skip already-honored queues. Addresses Codex r1
   #2 + AGY r1 #1 (dead-local bypass defect).

2. **Demotes Gate 2** to informational. The waterfill selector
   only iterates exact queues; priority-low (iperf-uncapped) is
   non-exact and is serviced by a separate selector. This fix
   cannot, by itself, fix Gate 2 — Codex r1 #3 dispositive.

3. **Corrects §11.3** unit test to account for TX_BATCH_SIZE
   truncation of the 6 Gbps class (Codex r1 #4). The 5th call
   still returns Phase-1; Phase-2 first engages on the 7th-ish
   call depending on draining pattern.

4. **Adds 3 new tests** (Codex r1 #5, AGY r1 #3, SMR D):
   fraction-proportionality boundary, persistent-mask Phase-2
   exclusion, proportional-mode bypass under zero fraction.

5. **Drops cap_eff aside** (Codex r1 #8); confirmed wire-only.

6. **Adds §8.5 drainage worked example** (SMR concern A)
   confirming iperf-100m reaches 100 Mbps under fix.

## §2 Why v2 is PLAN-READY (Claude SMR)

The plan now has:

- **Right diagnosis**: pass1 refill formula uses sum-of-quanta,
  documented contract is `fraction × cap` where cap = shaper
  per-epoch budget. Both Codex and AGY independently confirm.

- **Right primary fix**: anchor pass1 to
  `shaping_rate × VISIT_NS × fraction`. Codex r1 #1 +
  AGY r1 worked counter-example arithmetic both verify.

- **Right secondary fix**: persist honored_mask to avoid
  Phase-2 re-honoring small queues that already got their
  Phase-1 share. Codex r1 #2 + AGY r1 #1 + a static
  `debug_assert!(queues.len() <= 64)` codify the 64-queue
  invariant the bitmask depends on.

- **Scoped contract**: Gate 1 + Gate 3 blocking; Gate 2
  informational (non-exact selector out of scope). Honest
  about what this PR can and cannot achieve.

- **Tests prove the contract**:
  - Test 1 pins pass1 formula
  - Test 3 confirms Phase-2 engages after correct break boundary
  - Test 5 confirms persistent-mask exclusion of already-honored
  - Test 6 confirms proportional-mode bit-for-bit preservation
  - Smoke gate 1 confirms small classes ≥ 95 % of shape under
    live traffic — the real contract from #1630 issue body.

- **Right risk surface**: GuaranteeRate-mode-only changes
  (default off, opt-in). Proportional mode bit-for-bit. Single
  new u64 field. Smoke covers Phase-2 first activation.

## §3 Hostile checks I ran

### Will the persistent honored_mask itself create a new bug?

Phase-1 refill clears mask. Phase-1 honor sets mask. Phase-2 walk
reads mask (only for `queue_idx < 64`). When pass1_remaining hits
0, refill clears mask. **Race**: are pass1 and mask updates
ordered correctly?

Selector is single-threaded per worker (per `CoSInterfaceRuntime`,
which is `&mut` accessed). No race. ✓

### What if `queues.len() > 64`?

The `debug_assert!` codifies the invariant. Release builds skip
the assert; queues at idx >= 64 fall through the bitmask check
`if queue_idx < 64` (mod.rs:899). Those queues are NEVER masked
as honored, so Phase-2 may pick them again. In practice, deployments
have ≤ 8-16 queues per interface (Junos hardware ceiling), so this
is purely defensive. Document the invariant.

### Does Phase-2 ever pick queues idx ≥ 64?

The Phase-2 walk doesn't filter by idx — it walks all queues in
`exact_queues_by_rate_ascending`, skips on the mask check. So
queues at idx ≥ 64 will be visited by Phase-2 — and may be picked
even if "honored" in Phase-1 (because the mask can't mark them).
**Codified by the debug_assert; if Junos ever exceeds 64 exact
classes, the assert fires in debug builds and forces a re-design
to a Vec<bool> or HashSet.**

### Does the fix actually achieve gate 1 under live load?

§8.5 walks the arithmetic. iperf-100m's 12.5 MB/s lease-grant
rate dominates; under the fix it gets ascending priority and
its per-class lease drains naturally. The corrected pass1
budget ensures Phase-2 fires before iperf-9g+ steal small-class
shaper allocation.

### Does the fix regress transparent-root configs?

§10.1 keeps the `shaping_rate_bytes == 0 → quantum_sum × fraction`
fallback. Existing test
`waterfill_guarantee_rate_fraction_consulted_by_selector`
covers this (transparent-root by default in
`test_mixed_class_root_with_primed_queues` fixture).
New test 4 adds explicit shaper-anchored variant.

## §4 Sign-off

**PLAN-READY**. v2 addresses every r1 finding from Codex and AGY
with explicit hunks, corrected arithmetic, and tightened tests.
Risk is low: opt-in mode, one new u64 field, single arithmetic
change in pass1 formula, single bypass-defect fix in Phase-2.

Recommend dispatching Codex r2 + AGY r2 for confirmation. If
both converge PLAN-READY, proceed to implementation.
