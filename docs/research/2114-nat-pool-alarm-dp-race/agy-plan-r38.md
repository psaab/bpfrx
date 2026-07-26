# AGY adversarial plan-review — round 38 (plan v38 @ 95866d9c3)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (3/3 folds FOLDED; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED: `daemon_ha_sync.go:417-430,500-522,926-956` (reconciler and peer-connect sync paths), `store_persist.go:149-165` (#5835 stale-confirm recovery removes readable dead records without re-arming/reverting), `store_persist.go:231-255` (recovery re-arm path), and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3422-3449` (quiescence protocol step (2) and benign D-kind residual rules).
2. FOLDED: `store_persist.go:231-253` (timer re-arms for `remaining := time.Until(rec.Deadline)`), `store_commit.go:729-748,796-823` (`ConfirmCommit` clears pending confirm state and cancels timer), `cli_config.go:177-185` (`CommitCheck` validates only), `cli_config.go:257-271` (bare `commit` invokes `ConfirmCommit`), and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3449-3471` (recovery guidance and confirm-away path).
3. FOLDED: `fsatomic.go:1-4` (claims two file-replacement writers), `pkg/fsatomic/README.md:3-12` (claims two writers), and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:4284-4285` (documents the sweep update for `WriteFileDurableStaged`).

(B) Fresh attacks:
- Quiescence check observability: Hypothesis: Operator cannot observe cluster-sync quiescence, rendering step (2) unactionable. Outcome: FAILED. `status.go:10-60` and `cluster_cli.go:156-167` expose cluster status, peer health, and `CF` (Config Sync) monitoring flags via `show chassis cluster status`. Moreover, per `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3440-3449`, even if a peer SyncApply occurs post-re-check, the D-kind target is a dead record by construction and its abandonment cannot trigger a live-window replay.
- Benign-D readable-dead-record revert hazard: Hypothesis: An abandoned D-kind debt leaving a readable dead record on disk after a SyncApply will cause boot recovery to revert the active config. Outcome: FAILED. On boot with a healthy active load, `store_persist.go:149-165` (#5835) matches `rec.GuardedHash != journalConfigHash(s.active)`, logging a warning and removing the record via `resolveConfirmRemovalLocked("stale_confirm_recovery")` without re-arming or reverting. If active load is absent/compile-failed, the seeded-orphan machinery (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:2255-2272`) resolves the record by removal or overwrite on the next commit without reverting.

(C) Structure confirmation:
The §4.7 delivery structure (PR-1 = `d.dp` core + conversion + canaries + sampler; Follow-up = G+H+H2) stands; r28 (A) dissent remains recorded.

PLAN-READY
