# AGY adversarial plan-review — round 58 (plan v58 @ 77720748d)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 4 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. Item 1 (r57 M5: OnXSKBound stale closure): FOLDED — Re-deriving `deferredOverlays` under `applySem` at fire time (`daemon_apply_interfaces.go:98-109`, `maps_sync.go:451-456`, `daemon_ha_fabric.go:41-54,99-148`) eliminates stale state execution and guarantees zero residual window by serializing against every config apply.
2. Item 2 (r57 M4: Rollback health fork): FOLDED — Every branch in `executeConfirmedRollback` (`daemon_apply_commit.go:630-708`) publishes an explicit NEUTRAL (`!ok` no-op:646), SUCCESS, or FAILURE (`enterBootstrapMode` failure:671, `applyConfigLocked` failure:697, `clearSessionsForPolicyChanges` failure:706) outcome, closing the health fork.
3. Item 3 (M1: Receiver rejection / dual-primary marker suppression): FOLDED — Rejection at `daemon_ha_sync.go:547` leaves peer store unchanged, producing text or applied-digest divergence on the interval-bracketed double read (`daemon_ha_sync.go:550-569`), recovered by operator re-drive.
4. Item 4 (M2/M3: Provider replacement after check / authority invalidation): FOLDED — Stale or rejected pushes fail to update peer state (`daemon_ha_sync.go:544-585`), producing digest divergence caught at bracketing reads and recovered by re-drive.
5. Item 5 (M6: Debt-transfer transaction): FOLDED — A mis-registered or stranded arm token remains registered in the pending arm set, keeping `no pending arm outstanding` false (`daemon_health.go:79-125`), leaving the predicate unblessed (fail-closed).

(B) Fresh attacks:
1. Attack on M1 (Non-digest-visible rejection): FAILED — Rejection at `daemon_ha_sync.go:547` aborts store mutation; if peer active text differs, text digest diverges; if peer active text matches but apply failed, `ActiveApplied()` (`daemon_ha_sync.go:563`) is false and captured in the versioned snapshot (`store.go:781-809`).
2. Attack on M2/M3 (Non-digest-visible publication race): FAILED — Any stale or rejected push fails to update peer store and enforcement, producing digest or snapshot divergence caught by the double read.
3. Attack on M6 (Stranded arm false green): FAILED — A stranded arm never calls completion (`finishArm`), keeping `no pending arm outstanding` false (`daemon_health.go:79-125`) and leaving the predicate unblessed (fail-closed).
4. Attack on OnXSKBound window (Race between fire-time read and IPVLAN creation): FAILED — Fire-time read of `d.ActiveConfig()` and `ensureFabricIPVLAN` both execute while holding `applySem` (`daemon_apply_interfaces.go:98-109`), serializing against any config apply.

(C) New findings:
None.

(D) Structure confirmation:
Structure confirmed: §4.7 split delivery stands (PR-1 core `d.dp` accessor + follow-up G+H+H2 unit); AGY r28 dissent (A) CONVERGE remains recorded (`plan.md:6180-6188,8563-8579`).

(E) PLAN-READY
