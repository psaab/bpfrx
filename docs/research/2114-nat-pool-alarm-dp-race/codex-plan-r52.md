# Codex hostile plan-review — round 52 (plan v52 @ 5e6483dd0)

Task: task-msa45uoa-2vkcjv (session 019fbc74-5826-7622-b680-7b94f8a2ea9c).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 2 PARTIAL / 2 NOT-FOLDED / 1 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — CONFIGSTORE is named owner (plan.md:5780-5784), but the inventory still places the fields in daemon and says daemon tracks them (plan.md:5758-5768,5945-5953), with no Store transition API. Daemon→Store publication is cycle-free (pkg/daemon/daemon.go:21,72; daemon_apply.go:69-70), but writers at store_persist.go:105,110,175, store.go:687-689,787-848, and store_commit.go:221-225,488-492,856-868 are not concretely folded. Pre-promotion failure changes no active state (daemon_apply_commit.go:194-220); post-promotion/pre-entry failure does (daemon_apply_commit.go:354,381-402), yet its outcome transition is undefined.
2. PARTIAL — The retry discipline and stale/mid-render legs exist (plan.md:5781-5787,7357-7365), but v52 does not pin immutable atomic publication or version allocation under Store.mu. One atomic.Pointer swap of a fully initialized immutable versioned struct is sufficient; no separate version atomic/fence is required.
3. NOT-FOLDED — v52 asserts a pending-XSK feed (plan.md:5802-5812) but defines no callback, result state, Store method, or generation token. Compile still records the deferred snapshot and returns nil (manager_compile.go:257-298; manager.go:348-357), while the status loop only logs rejection (process_status.go:183-186). The H2 runbook and formal acceptance remain synchronous-only (plan.md:4851-4865,7245-7262).
4. NOT-FOLDED — A claimant can pause after releasing configSyncMu and before QueueConfig (pkg/daemon/daemon_ha_sync.go:474-497); neither reconnect’s epoch bump nor the 30-second loop cancels or joins it (daemon_ha_sync.go:51-57,506-523). QueueConfig assigns its newer wire generation only when that stale pass resumes (pkg/cluster/sync_conn_config.go:234-243), including after both verification reads. The two-interval “stuck-lock” declaration therefore has no bounded-pause or termination proof (plan.md:4747-4755).
5. PARTIAL — All six named legs exist (plan.md:7357-7377), but the publication-order leg merely repeats the invariant (plan.md:7364-7365), pending-XSK omits its feed/state-machine schedules (plan.md:7366-7369), and the claimant leg releases only early enough for the bracket to catch it (plan.md:7370-7375). It does not exercise release after the second verification; marker-no-op rejection also contradicts plan.md:4725-4730.

New findings:
MAJOR — handleConfigSync remains outside the coherent-snapshot discipline: it reads ShowActive and ActiveApplied in separate Store lock transactions (pkg/daemon/daemon_ha_sync.go:544-568; pkg/configstore/store_format.go:31-36; pkg/configstore/store.go:803-809). An A→B promotion/apply between those reads combines cached text A with ActiveApplied(B)==true, returns success for incoming A, and advances the receiver high-water (pkg/cluster/sync_conn_config.go:319-324,390-395). No §9 leg covers this composite reader.

MAJOR — The pending-XSK feed is neither terminal-path complete nor ordered against the enclosing apply. Deferred completion can occur through helper catch-up or content dedup (pkg/dataplane/userspace/process_status.go:19-38,73-81), while failure can occur during restart/protocol/disarm, publication, or post-publication status handling (process_status.go:61-71,87-100,118-136). That status loop runs outside applySem (process_status.go:150-186); without an attempt/generation token and a two-phase “pipeline complete AND publication complete” join, an old or early completion can stamp lastOK=true during a newer apply.

MAJOR — Pending publication is not the only nil/void asynchronous userspace outcome. Normal Compile publishes and returns nil before XSK liveness is resolved (pkg/dataplane/userspace/manager_compile.go:338-402); the later probe can fail closed while merely logging (pkg/dataplane/userspace/maps_sync.go:461-545). The link-cycle path similarly invokes void NotifyLinkCycle (pkg/daemon/daemon_apply_dataplane.go:390-401), whose rebind failure is swallowed (pkg/dataplane/userspace/process_linkcycle.go:184-224). These can leave H2 green despite non-converged forwarding.

MAJOR — The obsolete witness gate was not removed: H2 still requires observing ConfigsSent or marker no-op before committing (plan.md:4725-4730), immediately before v52 admits neither is faithful (plan.md:4734-4749). The marker is private (pkg/daemon/daemon.go:420-424), while status exposes only counters (pkg/cluster/status.go:340-356); §9 simultaneously says no runbook step may wait on that tick (plan.md:7375-7377).

MINOR — Pending/retry semantics contradict the sticky predicate. Pending is “NOT-converged” (plan.md:5802-5812) and every non-converged return increments the process-lifetime count (plan.md:5818-5822), while acceptance requires count==0 (plan.md:7245-7247). Thus even clean completion—or success after a rejection—cannot rehabilitate the predicate. The plan must distinguish pending from failed and state whether retry requires a process restart.

Structure confirmation: §4.7 stands—PR-1 remains A1 core/conversion/canaries/sampler; G+H+H2 remain together in the follow-up; dissent remains recorded (plan.md:5703-5746).

NEEDS-REVISION

Codex session ID: 019fbc74-5826-7622-b680-7b94f8a2ea9c
Resume in Codex: codex resume 019fbc74-5826-7622-b680-7b94f8a2ea9c
