# Codex plan-r3 — task-mpppgrof-tsveor (verbatim)

## Verdict: PLAN-NEEDS-MAJOR
## Confidence: 0.84

### r2→r3 addressing

1. r2 #1 (test 5 underspecified): v3 reworks §11.5 with concrete arithmetic and notes the mask must also gate Phase 1. Disposition: PARTIAL — the new Phase-1 mask design introduces a worse bug; see new concern 1.

2. r2 #2 (>64 release-build hole): v3 identifies the right failure mode but §10.2 is internally inconsistent (prose says `queues.len() > 64` while code uses `exact_queues_by_rate_ascending.len() <= 64`). Mask bits are keyed by `queue_idx`; guarding only exact-count does not protect the `queue_idx >= 64` case when total queues exceed 64 but exact count does not. Disposition: PARTIAL.

3. r2 #3 (Phase-2 proportional-residual contract untested): v3 adds §11.7 multi-epoch tally test. Disposition: ADDRESSED.

4. r2 #4 (Pass B wording): v3 corrects to "Gate 1 + Gate 3 PASS; Gate 2 logged but not blocking". Disposition: ADDRESSED.

### New concerns

1. [HIGH] The new v3 fix for r2 #1, mask-gating the Phase-1 ascending walk, breaks the scheduler under the actual epoch/reset semantics. The current selector resets the epoch only when Phase-2 makes no selection and falls out to the reset at `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1002-1005`. In the smoke fixture, Phase 1 would honor 100m, 1g, 3g, 6g once, leaving `pass1_remaining = 185_000` per §8; then Phase 1 would skip those four forever, break at 9g (`225_000 > 185_000`), and Phase 2 would keep successfully selecting 24g/21g/18g/... on every call. Because Phase 2 is making progress, the epoch never resets, so the small queues remain masked indefinitely. This is a direct starvation regression induced by the new v3 design.

2. [HIGH] The same Phase-1 mask also regresses the existing multi-visit lease behavior that the code and tests rely on for quanta above a single `TX_BATCH_SIZE` visit. Under v3, a 6 Gbps queue is masked after one Phase-1 selection even though one visit can ship only about 96 KB, not its 150 KB quantum. So the proposed design caps that queue at roughly `96_000 B / 200 us * 8 = 3.84 Gbps`, which directly contradicts Gate 1's `>= 95% of 6 Gbps` target and also contradicts v3's own §11.3 expectation that 6g needs two selections.

3. [MEDIUM] The `>64` fallback test in §11.8 still does not pin the actual mask-index hazard described in §10.2. A test with 65 exact queues would catch an exact-count guard, but it would not catch the sparse case where `root.queues.len() > 64`, `exact_queues_by_rate_ascending.len() <= 64`, and one exact queue has `queue_idx >= 64`.

### Verdict rationale

v3 closes two of the four r2 concerns cleanly and improves the arithmetic specificity around test 5. The plan is still not ready because the new Phase-1 mask is not a safe refinement of the current algorithm. It changes the meaning of an epoch without changing the actual reset condition, and that creates a production-visible starvation path. It also breaks the existing multi-visit behavior that large "small-class" quanta need under `TX_BATCH_SIZE`.

The decisive blocker is the new Phase-1 mask. Under the actual control flow in mod.rs:740, it does not just make test 5 deterministic; it changes the live scheduler into "small queues get one shot, then large queues drain forever until Phase-2 exhausts," which a saturated smoke run will not allow.
