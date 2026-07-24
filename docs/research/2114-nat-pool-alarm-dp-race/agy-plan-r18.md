# AGY adversarial plan-review — round 18 (plan v18 @ df04e2598)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim. NOTE (claude-smr-plan-r18.md §C): AGY's attack-2 and attack-3 rationales are factually wrong (loadOtherError proceeds, and the probe re-arm is origin-keyed) — the PLAN-READY stands on the folds, not on those rationales.

---

(A) Verification of each fold 1-7:

1. Replacement-path failure-phase classification: FOLDED
   - Evidence: `pkg/configstore/store.go:738-760` (SyncApply), `pkg/configstore/store_commit.go:867-937` (PromoteRollback), `pkg/configstore/store_persist.go:171-227` (boot-recovery revert), `pkg/configstore/confirm_rollback_durable_5473_test.go:334-349`.
   - All three replacement paths classify `writeActive` failures via `isPostRenameDurabilityFailure`. PRE-rename failures retain the confirm record without attempting a tombstone because the replacement is invisible on disk. POST-rename failures execute an immediate tombstone barrier attempt via `resolveConfirmRemovalLocked`; success proves the replacement durable (its directory fsync covers `active.json`), while failure retains both debts (`persistDegraded` + keyed removal debt). The single-failure restart hole is closed without violating #5473 durable-intent semantics.

2. Load seeding on EVERY outcome: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:26-42` (absent-DB path), `:81-113` (compile-failed path), `:113` (success path), `pkg/configstore/store_commit.go:678-682` (plain commit).
   - `Load` reads `confirm.json` on all outcomes to seed the three-state identity `Present(ArmID) / Absent / unreadable->latch`. An un-resolved orphan record A remains keyed on A across plain commits and subsequent PRE-rename arm failures. On a transient read error on the absent-DB path, `Load` retries boundedly and then fails `Load` closed (`daemon_run_bringup.go:278-286`), preserving fail-closed behavior.

3. Debt set corrected: FOLDED
   - Evidence: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:385-390,1308-1322`, `pkg/configstore/store_persist.go:402-465`.
   - The falsified `≤1+1` debt bound is deleted. The retry loop carries a keyed debt SET (multiple removal debts + at most one rewrite debt re-keyed by the latest arm outcome). Under adversarial interleaving, each pass processes debts by the four-state machine, achieving strict per-pass set reduction. Rewrite debts clear safely when another write (e.g. tombstone or new arm) makes the record durable on disk.

4. Terminal machine mechanical sentinel + live probe observer: FOLDED
   - Evidence: `pkg/configstore/crypto.go:446-461`, `pkg/configstore/db.go:251-253,271-280`, `pkg/configstore/store_persist.go:396-412`.
   - `readMasterKey` IO errors (`crypto.go:446-449`) are classified TRANSIENT, while invalid observed key length (`:452,:461`) and semantic gates (`db.go:271-280`) wrap `ConfirmRecordPermanentError`. Errors wrapped with `%w` at `db.go:251-253` survive `errors.As`. The terminal latch keeps `persistRetryLoop` alive in probe-only mode (`store_persist.go:405-412`), where clean reads clear the latch and re-arm from `rec` fields (`ArmID`, `Deadline`, `PrevTree`), and confirmed absence clears and drops the debt without breaking shutdown safety (`:396-401`).

5. Transient boot fail-closed: FOLDED
   - Evidence: `pkg/configstore/store_persist.go:140-145`, `pkg/daemon/daemon_run_bringup.go:277-306`.
   - Bounded retries inside `Load` fail `Load` closed on persistent transient read errors, causing `daemon_run_bringup.go:278-286` to return `loadFatalUnreadable` and abort daemon startup so systemd `RestartSec=1` re-drives startup. Deterministic PERMANENT-class errors proceed degraded with the terminal latch set, exposing 503 while avoiding node bricking.

6. Cause-bearing health channel: FOLDED
   - Evidence: `pkg/api/server.go:130-145`, `pkg/api/health.go:65-71`, `pkg/daemon/daemon_run_servers.go:370-374`.
   - `ConfigPersistDegradedState()` returns `{ActivePersistDegraded, ConfirmRecordTerminal}` and is option-wired through `server.go:130-145`. `api/health.go:65-71` enforces precedence (`ConfirmRecordTerminal` > `ActivePersistDegraded`) to output specific error messages, while Prometheus gauges (`metrics.go:951-957`) maintain aggregate OR behavior.

7. Residual broadened + sweeps: FOLDED
   - Evidence: `pkg/configstore/store.go:716-717`, `pkg/configstore/README.md:663-672`, `pkg/api/metrics_descriptors.go:625-630`.
   - The residual is broadened to `replacement-POST ∧ tombstone-failure-ANY-phase ∧ restart-before-barrier`. `SyncApply` source comments (`store.go:716-717`) and `README.md:663-672` prose reflect replacement-class framing, and metrics descriptors reflect aggregate degradation.

---

(B) Fresh attacks with outcomes:

1. Post-rename immediate tombstone's READ-MUTATE-WRITE on SyncApply: FAILED
   - Attack: `resolveConfirmRemovalLocked` during `SyncApply` reads and tombstones `confirm.json` from disk, which could target the wrong record if a nested arm replaced A's.
   - Outcome: All store mutations (`SyncApply`, `Commit`, `CommitConfirmedGen`) run under `s.mu` (`pkg/configstore/store.go:697-760`). `confirm.json` on disk at the time of `SyncApply` is either the active pending record B or legacy record A. Tombstoning `confirm.json` (`Resolved: true`) ensures that whatever record is currently visible on disk is marked resolved, preventing post-crash re-arming.

2. Load-failure fixture migration & fail-closed daemon handling: FAILED
   - Attack: Failing `Load()` on transient `confirm.json` read errors breaks daemon startup error classification.
   - Outcome: `daemon_run_bringup.go:277-306` routes errors from `d.store.Load()` through `classifyLoadError`. Any unhandled transient IO error falling out of `Load` after bounded retries matches `loadFatalUnreadable` or `loadOtherError`, returning a non-nil startup error and aborting bringup cleanly.

3. Probe-only re-arm vs tombstone execution: FAILED
   - Attack: Probe-only mode observing a repaired file might wrongly re-arm a record that should have been tombstoned.
   - Outcome: `ReadConfirm()` returns the repaired `confirmRecord`. If `Resolved` is `true` or the file is unlinked (confirmed absence), the probe clears the latch and drops the debt. If the operator repaired `confirm.json` into a valid pending record, re-arming `rec.Deadline` and `rec.PrevTree` is the intended recovery behavior.

4. Absent -> Present(ArmID) transition on arming paths: FAILED
   - Attack: Transitioning from `Absent` to `Present(ArmID)` during `writeConfirmState` could leave `s.onDiskArmID` in an inconsistent state on write failure.
   - Outcome: On PRE-rename write failure, `confirm.json` is not written and `s.onDiskArmID` remains `Absent` (`""`). On POST-rename failure, `confirm.json` is visible on disk and `s.onDiskArmID` updates to `ArmID`, raising a rewrite debt keyed on `ArmID`. `s.onDiskArmID` strictly reflects the on-disk state.

---

PLAN-READY
