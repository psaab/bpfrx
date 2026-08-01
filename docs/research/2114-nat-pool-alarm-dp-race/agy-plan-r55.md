# AGY adversarial plan-review — round 55 (plan v55 @ f437e4dd6)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). First dispatch timed out at the 9m print-timeout (infra); retried at 12m per the infra-retry rule. Verdict: PLAN-READY (5/5 folds FOLDED; 3 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

(A) Fold verification:
1. FOLDED — [daemon_apply_commit.go:274-285](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L274-L285), [daemon_ha_sync.go:336-370,474-489](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L336-L370), [sync_conn_config.go:234-250](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/sync_conn_config.go#L234-L250): holding `configSyncMu` from validation through send completion serializes commit pushes and reconciler pushes, revalidates all 5 gates (`syncPeerConnected`, `rg0ConfigSyncAuthority`, uptime, `ConfigSync`, generation hash mismatch), and claims the marker strictly at the send boundary.
2. FOLDED — [daemon_apply_commit.go:98-126,194-222,551-575](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go#L98-L126), [daemon_apply.go:50-56,83-86](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go#L50-L56): all apply paths (`commitAndApply`, `commitConfirmedAndApply`, `applyConfig`, `applyConfigResult`, `syncAndApply`) wrap `applyConfigLocked` via outer entry points where the token mints before preflight/compile.
3. FOLDED — [daemon_apply_interfaces.go:98-109](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_interfaces.go#L98-L109), [maps_sync.go:451-457](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L451-L457): `SetOnXSKBound` is registered on the daemon side during apply before manager map sync can execute and launch `m.OnXSKBound()`, satisfying registration-before-launch.
4. FOLDED — [manager_worker_arm_5134.go:18-38](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_worker_arm_5134.go#L18-L38), [process_status.go:183-198](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_status.go#L183-L198), [maps_sync.go:451-480](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go#L451-L480), [process_linkcycle.go:145-184](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_linkcycle.go#L145-L184), [daemon_apply_dataplane.go:289-296](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go#L289-L296): exactly six asynchronous apply-time arms exist; no seventh void or nil-with-deferral path exists.
5. FOLDED — [process_status.go:168-172](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process_status.go#L168-L172), [manager_worker_arm_5134.go:18-38](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_worker_arm_5134.go#L18-L38), [protocol_status.go:73-84](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/protocol_status.go#L73-L84): verified `#6034` seed is neighbor-replace generation, deferred-MAC is PENDING, status rendering includes token + pending-set, and OBSERVED-complete is struck.

(B) Fresh attacks:
- Mutex-across-send 5s deadline: FAILED — holding `configSyncMu` across `QueueConfig`'s 5s write deadline ([sync_conn_config.go:241-244](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/cluster/sync_conn_config.go#L241-L244)) stalls background reconciler claim checks ([daemon_ha_sync.go:474-489](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go#L474-L489)) harmlessly for up to 5s (reconciler interval is 30s), while commit pushes remain serialized under `applySem`.
- Per-arm-ID set lifecycle across attempts: FAILED — registrations are explicitly keyed by `(token, arm-ID)`; when a new attempt mints a fresh token at outer entry, status reporting checks readiness for the new active token, preventing leaked arms from prior attempts from blocking current attempt readiness.
- v55 delta regression audit: FAILED — no regressions found; send-boundary revalidation protocol and outer mint tokening hold without side-effects.

(C) New findings:
None.

(D) Structure confirmation:
Confirmed: §4.7 delivery structure (two units: #2114 core PR + G+H+H2 follow-up unit) stands.

(E) Verdict:
PLAN-READY
