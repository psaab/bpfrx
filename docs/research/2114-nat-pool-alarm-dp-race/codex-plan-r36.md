# Codex hostile plan-review — round 36 (plan v36 @ c0cf0b687)

Task: task-ms21wapb-rlr4h9 (session 019f9f65-2a30-7f62-81ba-c9736b671a19).
Verdict: NEEDS-REVISION (1 MAJOR, 1 MINOR; fold verification 2 FOLDED / 1 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — v36 explicitly requires `ConfirmDebtKindMask == 0`, routes live debt to running removal, and distinguishes successful-active recovery from absent/compile-failed orphan seeding (`plan.md:3304-3325,5136-5145`); the consequences are confirmed at `pkg/configstore/store_persist.go:36-42,81-114,149-165,171-255,397-401`.
2. FOLDED — the staged API, hook ordering under `s.mu`, reclassification, test seam, and rejection of post-write read-back are pinned (`plan.md:3333-3351,4119-4125,5147-5152`) against the current monolithic path (`pkg/configstore/db.go:207-218`; `pkg/fsatomic/fsatomic.go:310-355`).
3. PARTIAL — corrected copies exist (`plan.md:4237-4239,4420-4427`), but `plan.md:3497-3501` still says “ALL THREE,” and `plan.md:4410-4416` still enumerates only active-persist, confirm debt, and terminal corruption, omitting `ConfigWriteUnverified`.

New findings:

MAJOR 1 — The zero-mask check is TOCTOU, not a safe stopped-repair precondition. The mask is derived only “at snapshot time” (`plan.md:3411-3413`), while the plan admits a later confirmed commit can create W debt (`plan.md:2722-2725`). Asynchronous demotion can likewise resolve a window (`pkg/daemon/daemon_ha.go:466-474`), with failed removal raising process-local debt (`pkg/configstore/store_commit.go:575-608,652-702,780-792`). Thus mask-zero observation → debt raise → stop abandons debt → offline repair can still reach re-arm/revert on boot (`pkg/configstore/store_persist.go:149-165,171-255,397-401`). No producer-quiesce fence, shutdown-final check, persisted safe-stop proof, or explicit acceptance exists. Post-restart health is too late because recovery runs inside `Load` before service (`pkg/configstore/store_persist.go:110-114`), and on-disk presence cannot reconstruct process-local debt.

MINOR 1 — Hook-veto cleanup is ambiguous. Every copy merely says the hook “abandons” the temp (`plan.md:3342-3343,4122-4124,5149-5150`), whereas fsatomic requires unlink on every pre-rename failure and implements that with deferred removal (`pkg/fsatomic/fsatomic.go:40-43,315-321`). `NewDB` sweeps only at construction (`pkg/configstore/db.go:61-68`); later attempts create new unique temps, so literal abandonment accumulates files. Require unlink-on-hook-error plus target-unchanged/no-temp regression coverage matching `pkg/fsatomic/fsatomic_test.go:297-347`.

Structure confirmation: CONFIRMED — HEAD `c0cf0b687` has merge-base `ed6999000`; committed branch changes remain confined to `docs/research/2114-nat-pool-alarm-dp-race/`, and §4.7 retains PR-1 core plus combined G+H+H2 follow-up (`plan.md:4035-4079`).

NEEDS-REVISION

Codex session ID: 019f9f65-2a30-7f62-81ba-c9736b671a19
Resume in Codex: codex resume 019f9f65-2a30-7f62-81ba-c9736b671a19
