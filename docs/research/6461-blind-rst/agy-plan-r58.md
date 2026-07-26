VERDICT: PLAN YES

### Q1 (Election Hold) — SOUND
* **Plan Evidence**: `plan.md:L4213-4265`
* **Code Evidence**: `pkg/daemon/daemon_run_bringup.go:226-233`, `pkg/daemon/daemon_ha_sync.go:90-100`, `pkg/vrrp/manager.go:389-404`, `pkg/cluster/manager.go:289-293`
* **Analysis**: The design specifies that the hold is an automatic-election fence designed to block spontaneous priority-driven preemption. Planned/manual failover requests (`request mastership`, `ForceRGMaster`) and priority-0 takeovers are operator-authoritative and explicitly bypass the hold via a post-barrier override (`vrrp/manager.go:761`, `daemon_ha_userspace_readiness.go:155`) without clearing the underlying repair obligation. Thus, spontaneous preemption is gated while manual failover paths remain unblocked and sound.

---

### Q2 (CAS Order + Bundle Serialization) — SOUND
* **Plan Evidence**: `plan.md:L4334-4363`
* **Code Evidence**: `pkg/vrrp/manager.go:389`, `pkg/vrrp/manager.go:432`, `pkg/vrrp/instance.go:1382`
* **Analysis**: A live writer hanging inside the bundle (e.g., `ReleaseSyncHold` blocking on `vrrp.Manager.mu` during `vi.stop()`) cannot hang future activations indefinitely. The activation state transition is committed first via CAS, and external side effects execute outside the packed word's critical section as generation-tagged idempotent follow-ups under a recoverable `Completing(g, ticket)` state with explicit deadlines. If an effect hangs, its ticket is abandoned, allowing subsequent activations to retry or override.

---

### Q3 (Authenticated Reader + Byte Rules + Owner Totality) — SOUND
* **Plan Evidence**: `plan.md:L4148-4192`
* **Code Evidence**: `sync_auth.go:345`, `sync_conn_read.go:71-94`
* **Analysis**: A complete late `CONFIRM` is not blindly discarded by value. It is schema-validated, provenance-bound, and evaluated against the connection's negotiated tuple. If the late `CONFIRM` tuple matches the negotiated tuple, it is consumed and ignored for feature activation while preserving owner calculation. If the tuple mismatches, it is treated as a protocol violation and immediately closes the connection.

---

### NEW Traces Folded Open by v9.9.54.9 / v9.9.54.10

1. **Preemption Exposure Between Legacy Sync Release and Repair-vN Activation**
   * **Trace**: A legacy bulk sync completion releases the VRRP sync hold (`pkg/daemon/daemon_ha_sync.go:90-100`, `pkg/vrrp/manager.go:389-404`), but `syncReady` gates only private RG elections (`pkg/cluster/manager.go:289-293`). If a subsequent connection activates `repair-vN` and transitions to `not-ready`, standard VRRP preemption remains enabled prior to receiving `JOURNAL_END`, allowing a priority event to trigger mid-repair failover (`plan.md:L4213-4240`).
   * **Resolution**: The activation transaction acquires a generation-scoped hold prior to exposing `repair-vN`, requiring current-generation inbound `JOURNAL_END` application to release it.

2. **Indefinite Activation Hang on Unbounded Bundle Execution (`ReleaseSyncHold`)**
   * **Trace**: Executing completion bundle side effects directly within the packed word critical section allows a writer blocked on `vrrp.Manager.mu` (`pkg/vrrp/manager.go:389`, `:432`, `vi.stop()` at `instance.go:1382`) to block all subsequent activation attempts indefinitely (`plan.md:L4344-4358`).
   * **Resolution**: External follow-up effects run outside the packed word critical section using generation-tagged idempotent operations under a recoverable `Completing(g, ticket)` state backed by execution deadlines.

3. **Allowlisted Reader Rejection of Baseline `ClockSync`**
   * **Trace**: A baseline authenticated peer sends `ClockSync` (`sync_conn.go:137`, `sync_conn_write.go:256`) immediately post-authentication. An allowlisted-only decision reader drops non-decision frames, causing a connection loop that breaks legacy latching (`plan.md:L4161-4172`).
   * **Resolution**: Entry into the decision phase is gated on explicit capability advertisement; baseline peer frames are buffered, legacy mode is latched, and buffered frames are dispatched sequentially.
AGY EXIT: 0
