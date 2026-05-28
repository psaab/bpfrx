# Codex plan-r2 — task-mppoz0st-2hsrwp (verbatim)

## Verdict: PLAN-NEEDS-MAJOR
## Confidence: 0.86

### r1→r2 addressing
1. r1 #1, refill scalar anchored to the wrong base: v2 now states `Phase 1 honours small-rate exact classes ascending by R_i up to fraction × cap` and `Here cap means the per-epoch budget the root shaper actually delivers` (§3), then proposes `direct shaping_rate × VISIT_NS × fraction budget` in `§10.1 Hunk A`. Disposition: ADDRESSED.

2. r1 #2, dead-local `honored_mask` / Phase-2 exclusion bug: v2 adds `waterfill_honored_mask: u64` as a persistent runtime field and says `At Phase-1 refill ... reset root.waterfill_honored_mask = 0` and `At Phase-1 honor ... root.waterfill_honored_mask |= 1u64 << queue_idx` and `Phase-2's ... check now reads the persistent field` (§10.2). Disposition: ADDRESSED on design; test coverage is still weak, see New concern 1.

3. r1 #3, Gate 2 was on the wrong code path: v2 says `Gate 2 (priority-low ≥ 5 % of ceiling) is DEMOTED to informational` (top summary), then `The waterfill selector iterates exact queues ONLY ... iperf-uncapped is a non-exact class serviced by select_nonexact_cos_guarantee_batch` (§11, informational gates). Disposition: ADDRESSED.

4. r1 #4, §11.3 had the wrong call-count model under `TX_BATCH_SIZE`: v2 now says `TX_BATCH_SIZE truncation of the 6G class into 96 KB + 54 KB selections — total 6 ascending exact selections` and `the 5th call still returns a Phase-1 honor of the 6G remainder, not a Phase-2 pick` (§11.3). Disposition: ADDRESSED.

5. r1 #5, tests did not prove the documented contract: v2 adds `waterfill_pass1_budget_fraction_proportional` and `waterfill_persistent_honored_mask_excludes_phase2` plus a zero-fraction bypass test (§11.4-§11.6). Disposition: PARTIAL. Coverage is better, but v2 still does not deterministically prove the documented Phase-2 proportional-residual contract, and test 5 is underspecified enough to miss the bug.

6. r1 #6, `worker_fair_share` was not the primary bug: v2 keeps a dedicated section. Disposition: ADDRESSED.

7. r1 #7, transparent-root fallback remained compatible with current config semantics: ADDRESSED.

8. r1 #8, `cap_eff` discussion was sloppy: ADDRESSED.

### New concerns

1. [HIGH] `waterfill_persistent_honored_mask_excludes_phase2` is still underspecified enough to miss the bug. The plan says `construct a 4-queue runtime where pass1 is small enough that ALL four queues are honored in Phase 1. Drive selections until pass1 < smallest quantum so Phase-2 engages` (§11.5). That only works if the test chooses concrete rates/shaper/fraction such that after honoring all four queues, `0 < pass1_remaining < smallest_quantum`. If the remainder is exactly `0`, the next call refills and clears the mask before Phase 2 runs.

2. [HIGH] The `queue_idx >= 64` case is still not safely handled. v2's answer is only `debug_assert!(root.queues.len() <= 64, "waterfill assumes ≤ 64 queues")` (§10.2). That is not compile-time, and it disappears in release builds. The control plane/runtime surface still allows `queue_id` across `0..=u8::MAX`, and I found no `<= 64` queue-count validator. In release, `>64` exact queues would silently produce incorrect Phase-2 exclusion semantics. Needs either a real config/runtime invariant, or a hard fallback such as disabling waterfill and using legacy RR when exact-queue count exceeds 64.

3. [MEDIUM] r1 #5 is not fully closed because v2 still does not test the documented Phase-2 proportional-residual contract.

4. [LOW] Gate accounting is still internally inconsistent. v2 correctly demotes Gate 2 to informational, but `Pass B` still ends with `All 3 gates PASS.` That wording reintroduces the demoted gate as an implied blocker.

### Verdict rationale

v2 fixes the main arithmetic diagnosis and it correctly retracts the bad Gate 2 claim. The new persistent-mask design is directionally correct. The plan is still not ready: test 5 not tight enough; `>64` exact-queue case still a correctness hole in release builds; Phase-2 proportional residual contract still not directly tested.

On the specific hostile checks: Gate 2 demotion is correct on the current code path, and the §8.5 `iperf-100m` arithmetic is sound (`7500 B / 600 us = 12.5 MB/s = 100 Mbps`). I do not see a new mask-reset ordering bug, and I do not see an obvious arithmetic hole that would by itself prevent Gate 1 from passing on the existing 11-queue, 1500-byte live smoke. The blockers are proof and safety around the newly-hot Phase-2 path, not the refill formula itself.
