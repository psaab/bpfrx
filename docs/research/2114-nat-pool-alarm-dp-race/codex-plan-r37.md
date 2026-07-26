# Codex hostile plan-review — round 37 (plan v37 @ 68a1b1376)

Task: task-ms22y3m4-bidkyu (session 019f9f80-1365-72a1-896b-dd32481233e3).
Verdict: NEEDS-REVISION (2 MAJOR, 2 MINOR; fold verification 2 FOLDED / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. NOT-FOLDED — One completed pass does finalize healing and re-raise removal debt before backoff doubles (`pkg/configstore/store_persist.go:419-465`), but the protocol never gates peer-driven SyncApply after the re-check (`plan.md:3377-3385`; `pkg/daemon/daemon_ha_sync.go:417-430,500-522,909-912`), which can raise process-local D debt (`plan.md:3214-3219,3231-3234`).
2. FOLDED — Hook failure unlinks the temp, crash leftovers are swept, and target-unchanged/no-temp is pinned (`plan.md:3408-3420`; `pkg/fsatomic/fsatomic.go:40-43,310-321`; `pkg/configstore/db.go:61-68`; `pkg/fsatomic/fsatomic_test.go:297-347`).
3. FOLDED — Both stale copies now include per-state key-class causes and `ConfigWriteUnverified` (`plan.md:3569-3579,4302-4322,4493-4513`).

New findings:

MAJOR 1 — “PRODUCER-QUIESCE” does not quiesce its only non-operator producer. Peer reconnect, promotion, or the 30-second reconciler can initiate SyncApply independently of operator commits (`pkg/daemon/daemon_ha_sync.go:417-430,500-522,926-956`), and ingress remains live through `handleConfigSync`/`SyncApply` (`:534-578,909-912`; `pkg/configstore/store.go:630-643`). A post-check SyncApply under the BOOT latch can fail synthesized tombstone/delete and raise process-local D debt (`plan.md:3071-3080,3132-3137,3231-3234`), which stop abandons (`pkg/configstore/store_persist.go:397-401`). The plan names only “ONE debt-pass interval,” not an observable completion barrier; runtime backoff is dynamic from 1 to 60 seconds (`pkg/configstore/store_commit.go:620-628`). Backoff doubling occurs after a completed pass, so one completed pass is internally sufficient, but neither elapsed time nor the mask re-check joins or fences later SyncApply.

MAJOR 2 — The named post-restart escape is not generally available. Recovery re-arms only for the original remaining interval, which may be arbitrarily short—not a fresh default ten minutes (`plan.md:1437-1442`; `pkg/configstore/store_persist.go:231-253`). More critically, H intercepts an unexpired FirstCommit+cluster record before re-arm and immediately reverts it during Load (`plan.md:1849-1858,1883-1888,3626-3633`), so there is no service-time confirmation opportunity. Manual removal is also not timer cancellation: the timer remains in memory until `ConfirmCommit` cancels it (`pkg/configstore/store_commit.go:729-748,796-823`). The write-unverified precheck itself is not contradictory for ordinary re-arm—re-arm follows a clean successful read (`plan.md:2929-2953`; `pkg/configstore/store_persist.go:140-171,231-253`)—but it does not rescue these H and short-deadline cases.

MINOR 1 — “`commit check`-style confirmation” is incorrect operator guidance (`plan.md:3390-3393`). `commit check` only validates (`pkg/cli/cli_config.go:177-185`); bare `commit` confirms an unchanged pending window (`:257-271`).

MINOR 2 — The plan adds exported `WriteFileDurableStaged` (`plan.md:4198-4208`) but omits the fsatomic package documentation from its inventory; both the package comment and README still claim there are exactly two writers (`pkg/fsatomic/fsatomic.go:1-4`; `pkg/fsatomic/README.md:3-12`).

Structure confirmation: CONFIRMED — §4.7 retains the PR-1 core and the combined G+H+H2 follow-up (`plan.md:4114-4149`); the tracked plan commit remains research-documentation-only.

NEEDS-REVISION

Codex session ID: 019f9f80-1365-72a1-896b-dd32481233e3
Resume in Codex: codex resume 019f9f80-1365-72a1-896b-dd32481233e3
