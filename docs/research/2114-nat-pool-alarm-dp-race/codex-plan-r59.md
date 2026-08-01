# Codex hostile plan-review — round 59 (plan v59 @ 5a0df2b2c)

Task: task-msac7cbq-0d4e5j (session 019fbd42-70bc-7b42-b263-19e4771e8954).
Verdict: NEEDS-REVISION (5 MAJOR, 2 MINOR; fold verification 1 FOLDED / 3 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. NOT-FOLDED — The added check observes election intent, not applied forwarding ownership. Cluster status prints separately captured local and cached-peer election states (pkg/cluster/status.go:12-25,91-103); election changes state before asynchronous VRRP/rg_active actuation, whose failure is retried later (pkg/cluster/election.go:337-395; pkg/daemon/daemon_ha.go:340-371,809-848). Thus exact-one can coexist with dual live forwarding, and “SETTLED” has no observable epoch or stability interval (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5325-5334,8019-8023).

2. PARTIAL — Checking stopping after acquiring applySem closes the original post-drain waiter window (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6662-6674). It does not use work item G’s runCtx-or-stopping fence, does not cover an already-admitted callback beyond the five-second drain, and does not specify total propagation of ensureFabricIPVLAN’s swallowed failures (docs/research/2114-nat-pool-alarm-dp-race/plan.md:2966-2998,7100-7105; pkg/daemon/daemon_ha_fabric.go:29-53,72-93,102-148).

3. NOT-FOLDED — QUEUED appears only in v59’s revision-history prose (docs/research/2114-nat-pool-alarm-dp-race/plan.md:2616-2624). Normative §5.1 still mints after applySem admission and has no queued reservation in the coherent snapshot (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6407-6417,6485-6497); formal acceptance and §9 likewise omit it (docs/research/2114-nat-pool-alarm-dp-race/plan.md:7993-8012,8107-8112).

4. PARTIAL — §5.1 now makes same-manager registration, completion, and supersession serialize through m.mu, consistent with current manager paths (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6385-6399,6458-6474; pkg/dataplane/userspace/process_status.go:160-198; pkg/dataplane/userspace/maps_sync.go:451-456). But the normative runbook still defers “the single-retoken transaction” and claims mis-registration is necessarily pending/fail-closed (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5389-5394), directly contradicting §5.1.

5. FOLDED — §9 now contains the rollback-fork and stale-callback h2k legs (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8136-8144); formal acceptance contains the authority check and explicitly imports residuals (iv)-(vi), defined in the normative runbook (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8019-8026,5367-5394). The JOIN-COHERENCE legs remain present and internally aligned (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8052-8101,8194-8208).

New findings:

MAJOR 1 — Election green remains a live-forwarding false green. runElection publishes the new state before the daemon consumes its event; userspace desired activity is cluster-primary OR VRRP-master, so a demoted election state can retain rg_active while VRRP is still MASTER, and SetRGActive failure leaves that state live until a later retry (pkg/cluster/election.go:337-395; pkg/daemon/rg_state.go:250-263; pkg/daemon/daemon_ha.go:340-371,809-848). The proposed apply-health counter covers full applies, not HA actuation (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6262-6271). Moreover, status combines local and peer snapshots from different instants, and heartbeat processing can immediately rerun election (pkg/cluster/status.go:12-25; pkg/cluster/heartbeat_manager.go:306-355). A pre-settlement miss is safely red, but a transient exact-one read can fail open; authority is also absent from the final post-reactivation predicate (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8034-8042).

MAJOR 2 — The callback fence is admission-only, not lifecycle-total. Work item G requires runCtx.Err() OR stopping because signal-driven teardown begins before runShutdownSequence publishes stopping; v59’s callback checks only stopping (docs/research/2114-nat-pool-alarm-dp-race/plan.md:2966-2994,6670-6674). A callback that passes immediately before publication can continue, and shutdown explicitly proceeds after the five-second applySem drain timeout (pkg/daemon/daemon_run_shutdown.go:50-64,214-230; docs/research/2114-nat-pool-alarm-dp-race/plan.md:7100-7105). Therefore “never mutating live state during teardown” is not established.

MAJOR 3 — Callback outcome reporting is not specified deeply enough to be truthful. The current helper ignores parent-up errors, logs MTU/address errors, discards existing-child MTU/up errors, calls a void reconciliation that suppresses list/delete/add failures, and accepts any existing link type when ParentIndex matches (pkg/daemon/daemon_ha_fabric.go:29-53,72-93,102-148). V59 requires only a generic “creation or reconciliation failure” outcome and one generic test leg; it never mandates returned/aggregated errors for each operation (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6674-6681,8136-8144). An implementation can therefore still retire SUCCESS on partial or wrong-kind reconciliation.

MAJOR 4 — QUEUED has no ordering or retirement model. If waiter B publishes scalar QUEUED while A runs, A’s later SUCCESS can overwrite it and expose stale enforcement as green; multiple waiters require additive reservations, not one state value. Conversely, a request whose semaphore acquisition is canceled returns directly, so its QUEUED publication can remain false-red indefinitely (pkg/daemon/daemon_apply_commit.go:172-175). The normative snapshot contains no queued count/token or atomic queued-to-running transition (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6284-6302,6485-6491). A prior incarnation should not leak if QUEUED joins the promised process-lifetime state because restart constructs a fresh Store (pkg/configstore/store.go:302-319; pkg/daemon/daemon.go:1046-1054), but v59 never actually places QUEUED there.

MAJOR 5 — Residual (vi) is not honestly fail-closed. A cross-incarnation arm omitted from the current registration set is not pending, and its unregistered completion is ignored; that is precisely a possible false green, contrary to the runbook’s claim (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5389-5394,6438-6452). If the mandatory serialized supersession re-registers every live debt, the single-retoken transaction is implemented rather than residual; if it does not, residual (vi) remains unsafe.

MINOR 1 — §5.1 places the callback work under pkg/dataplane/userspace but omits the necessarily modified pkg/daemon/daemon_apply_interfaces.go and pkg/daemon/daemon_ha_fabric.go from the changed-file inventory (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6638-6681).

MINOR 2 — Formal acceptance calls the post-reactivation predicate “COMPLETE” but its explicit enumeration omits the no-pending term present in the normative copy (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5343-5348,8034-8038).

Structure confirmation: CONFIRMED — §4.7 still ships the accessor core as PR-1 and keeps G+H+H2 together in the follow-up (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6200-6243).

NEEDS-REVISION

Codex session ID: 019fbd42-70bc-7b42-b263-19e4771e8954
Resume in Codex: codex resume 019fbd42-70bc-7b42-b263-19e4771e8954
