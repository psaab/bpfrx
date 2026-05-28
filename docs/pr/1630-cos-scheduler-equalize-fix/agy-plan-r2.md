## Verdict: PLAN-READY
## Confidence: 1.0

### r1→r2 addressing

#### Finding 1: Refill scalar is wrong (primary bug at refill formula)
- **Quote in v2**: 
  > *`§10.1 Hunk A Skeleton diff:`*
  > ```rust
  > +        } else {
  > +            let cap_per_epoch = ((root.shaping_rate_bytes as u128)
  > +                * (COS_GUARANTEE_VISIT_NS as u128)
  > +                / 1_000_000_000u128) as u64;
  > +            ((cap_per_epoch as f64) * frac).floor() as u64
  > +        };
  > ```
- **Disposition**: Fully Addressed. The budget formula is correctly anchored to the actual shaper-delivered epoch capacity `cap_per_epoch` instead of the sum of configured queue quanta.

#### Finding 2: The break / Phase-2 suspect is ruled out too aggressively, `honored_mask` is a dead local, and state tracking is inconsistent
- **Quote in v2**:
  > *`§10.2 Hunk B: persistent honored mask`*
  > - "Add a `waterfill_honored_mask: u64` field to `CoSInterfaceRuntime` ... Replace the local `let mut honored_mask: u64 = 0;` (mod.rs:806) with reading `root.waterfill_honored_mask` ... At Phase-1 refill (mod.rs:787-800), reset `root.waterfill_honored_mask = 0` ... Phase-2's `(honored_mask & (1u64 << queue_idx)) != 0` check now reads the persistent field."
- **Disposition**: Fully Addressed. Turning `honored_mask` into a persistent field on `CoSInterfaceRuntime` that resets only on a Phase-1 refill completely fixes the dead-local bypass defect, preventing Phase 2 from double-servicing queues already honored in Phase 1.

#### Finding 3: Gate 2 in the test plan is wrong on the code path
- **Quote in v2**:
  > *`§11 Smoke / Gate 2 (INFORMATIONAL):`*
  > - "Gate 2 (priority-low ≥ 5 % of ceiling) is DEMOTED to informational, not blocking ... The waterfill selector iterates exact queues ONLY (mod.rs:945-950); iperf-uncapped is a non-exact class serviced by `select_nonexact_cos_guarantee_batch` (mod.rs:1014-1069)."
- **Disposition**: Fully Addressed. The author correctly identifies that `iperf-uncapped` is serviced by a separate selector (`select_nonexact_cos_guarantee_batch`) that is untouched by this exact-waterfill change. Demoting Gate 2 to informational is correct and keeps the PR's contract honest.

#### Finding 4: Unit test §11.3 has the wrong model of a “call” due to `TX_BATCH_SIZE` truncation
- **Quote in v2**:
  > *`§11.3 unit test corrected for TX_BATCH_SIZE truncation:`*
  > - "...6 Gbps quantum is split 96 KB + 54 KB so the break boundary fires after the 6th selection, not the 5th."
- **Disposition**: Fully Addressed. The unit test model in §11.3 now correctly accounts for `TX_BATCH_SIZE` (64 packets ≈ 96 KB) capping a single queue visit, splitting the 150 KB quantum of the 6G class across two exact selections.

#### Finding 5: The tests do not prove the documented contract
- **Quote in v2**:
  > *`§11 Unit tests:`*
  > - "Add 6 tests in `userspace-dp/src/afxdp/cos/queue_service/tests.rs`: ... `waterfill_pass1_budget_fraction_proportional`, `waterfill_persistent_honored_mask_excludes_phase2`, `waterfill_proportional_mode_bypass_under_zero_fraction`."
- **Disposition**: Fully Addressed. The test suite has been drastically improved. It now pins the fraction-proportionality boundaries, verifies the persistent mask Phase-2 exclusion, and asserts bit-for-bit bypass correctness under proportional/zero-fraction configurations.

#### Finding 6: The worker-fair-share suspect is correctly ruled out
- **Quote in v2**:
  > *`§6 Why #1625's worker_fair_share suspect is NOT the bug:`*
  > - "The lease is per-class (one lease per (ifindex, queue_id)), so `cap` here = `class_rate × elapsed` ... `my_share` is derived from the per-class `new_cap`, not a class-agnostic pool. That is not the smoke-fixture equalize bug."
- **Disposition**: Fully Addressed. The analysis correctly reinforces that `rotate_epoch_v8.rs` is class-rate-aware and plays no part in the rate-equalization symptom.

#### Finding 7: Transparent-root fallback is compatible
- **Quote in v2**:
  > *`§10.1 Hunk A Skeleton diff:`*
  > - "Transparent-root (shaping_rate_bytes == 0) preserves the legacy quantum_sum behaviour because there is no root-shaper budget to anchor against — the per-class leases still throttle each class to its own rate."
- **Disposition**: Fully Addressed. Keeping the `quantum_sum` fallback for transparent-root configurations is safe and ensures no compile-time or config regressions when root shaping rates are omitted.

#### Finding 8: The plan’s `cap_eff` discussion is sloppy because that mechanism does not exist yet
- **Quote in v2**:
  > *`§12 Open Questions:`*
  > - "1. `priority_low_min_share_bytes` subtraction — confirmed out of scope. Per Codex r1 #8 ... this field is wire-only ... Tracked separately."
- **Disposition**: Fully Addressed. The plan dropped the sloppy `cap_eff` / `min_share_bytes` reasoning in favor of a clean wire-only boundary, tracking follow-ups separately.

---

### New concerns

No new concerns have been identified. The v2 plan is extremely thorough, arithmetically solid, and low-risk.

---

### Verdict rationale

All 8 of the findings from the `r1` review have been fully addressed with high precision:

1. **Arithmetically sound**: The core fix anchors Phase 1 budget to `cap_per_epoch * fraction`. §8 and §8.5 demonstrate via rigorous math that `iperf-100m` will achieve exactly its 100 Mbps (12.5 MB/s) contract by executing a 3-epoch pattern of MTU 1500 packets (Epoch A: 1500B, Epoch B: 3000B, Epoch C: 3000B).
2. **Defect-free state tracking**: Adding `waterfill_honored_mask` as a persistent field on `CoSInterfaceRuntime` eliminates the compiler warning and prevents double-servicing in Phase 2. The reset logic inside `waterfill_pass1_remaining_bytes == 0` is correctly ordered.
3. **Robust invariants**: The `debug_assert!(root.queues.len() <= 64)` safely protects the bitwise operations on `honored_mask`. Since Junos hardware CoS is capped at 8-16 queues, this is completely sufficient and doesn't clutter the production hot path.
4. **Honest contract limits**: Correctly demoting Gate 2 to informational and fixing the `TX_BATCH_SIZE` selection counting model ensures that unit tests and smoke tests align perfectly with reality.
5. **No Regressions**: Bit-for-bit default-off preservation is guaranteed since Proportional mode (or GuaranteeRate with zero fraction) skips the waterfill path entirely.

The plan is fully ready for implementation.
