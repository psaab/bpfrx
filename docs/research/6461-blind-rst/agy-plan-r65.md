VERDICT: PLAN NO


### Q1 (class-commit soundness + reset independence)
**UNSOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:4242-4247`, `4291-4301`, `6029-6035`.
- **Analysis**:
  1. *Explicit authenticated v0 declaration*: At line 4296–4297, the plan states that "v0 commits ONLY on a complete ordinary frame with no record, or an explicit authenticated v0 declaration". However, existing baseline code sends no capability record and no "v0 declaration" frame exists in the protocol or plan schema. It is dead text referencing a non-existent wire message.
  2. *Discharge predicate*: Line 4242–4245 specifies that `reset-vN` is an independent state machine from `repair-vN` and that a peer without reset support selects the legacy time-barrier path. However, the completion matrix (lines 5255–5340) names discharge criteria only for `repair-vN` (`JOURNAL_END`/`JOURNAL_ACK`), leaving the `reset-vN` discharge/timeout predicate omitted when `reset-vN` is absent/unnegotiated.

---

### Q2 (cutoff watermark + CommitUncertain)
**UNSOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:4585-4601`, `4683-4717`, `6036-6045`; `pkg/ha/failover.go:471`, `pkg/ha/daemon_ha_sync.go:1045`.
- **Analysis**:
  1. *CommitUncertain with Volatile Record*: Line 4683 acknowledges that the peer's stage ledger is "VOLATILE BY DESIGN". If peer B crashes after applying a failover commit and clearing its restore lease (`failover.go:471`, `daemon_ha_sync.go:1045`), B restarts in a quiesced sync-hold state with its volatile ledger lost.
  2. *Dual-Secondary Deadlock*: When A queries B upon reconnect, B responds `not-applied` (due to memory wipe on restart). A then aborts pre-PONR to a secondary state. Because B had already cleared its restore lease prior to crashing and restarted secondary, both nodes end up secondary (dual-secondary availability loss), with no mechanism in the plan to re-arm B's lease automatically.

---

### Q3 (reconciliation epoch + cancellable publication)
**UNSOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:4406-4444`, `4458-4476`, `4495-4503`, `6046-6052`; `pkg/vrrp/manager.go:432`, `pkg/vrrp/instance.go:1296`, `:1382`.
- **Analysis**:
  1. *Unstated Epoch / Permit Ordering*: Line 4440 defines `PromotionPermit` as the outermost lock before `Manager.mu`/`vipMu`/`directVIPMu` and instance locks. `UpdateInstances` (`vrrp/manager.go:432`) holds the single reconciliation epoch across stop-set collection and joins instance run loops (`instance.go:1382`). An instance run loop mid-`becomeMaster` (`instance.go:1296`) holds `PromotionPermit`. The plan fails to specify a strict acquisition hierarchy between the reconciliation epoch and `PromotionPermit`, allowing a deadlock cycle if `UpdateInstances` joins a run loop holding `PromotionPermit` while a thread inside the run loop or config apply path attempts to acquire the reconciliation epoch.
  2. *Multi-VIP Bound*: Line 4499 correctly specifies a single per-operation bound ("the whole publication is one cancellable token-fenced operation bounded below masterDownInterval"), but this does not remedy the epoch/permit lock inversion risk.

---

### Q4 (DisruptiveTransfer lifecycle)
**UNSOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:4708-4713`, `4807-4815`, `4822-4828`, `6052-6055`.
- **Analysis**:
  1. *CommitUncertain Deadlock on Down Peer*: Lines 4807–4814 state that `DisruptiveTransfer` enters the exact same `CommitUncertain` lifecycle as an ordinary transfer, with only the admission predicate differing.
  2. *No Fenced Resolution*: A disruptive transfer is invoked specifically when the peer node is down or degraded. If a commit sent during `DisruptiveTransfer` goes unACKed, it enters `CommitUncertain`, which line 4712 specifies "clears ONLY on a definitive answer" from the peer. Because the peer is down, it can never answer the status query. The plan provides no operator-fenced override mechanism to resolve a `CommitUncertain` claim when the peer is dead, causing the claim to retain indefinitely.

---

### NEW Traces Folded Open by v9.9.54.19

1. **CONFIRM-Timeout Class Reversal Race** (`docs/research/6461-blind-rst/plan.md:4075-4115`, `4291-4301`, `6029-6035`):
   When Node A experiences a CONFIRM timeout and latches `v1-extras-inactive`, but Node B receives A's CONFIRM and latches `v1-extras-active`, they exchange declarations resulting in a shared decision of `v1` (legacy). If Node B sent `reset-vN` control frames on the reset lane prior to receiving `CAPABILITY_DECISION`, Node A drops or aborts the transport (`pkg/ha/sync_auth.go:289`, `pkg/ha/sync_conn_read.go:205`) because its local class engine was latched inactive during the frame arrival window.

2. **Continue-and-Journal Buffer Divergence Under High Churn** (`docs/research/6461-blind-rst/plan.md:4576-4601`, `6036-6045`; `pkg/ha/daemon_ha_sync.go:1045`, `pkg/ha/sync_conn.go:244`):
   Under the continue-and-journal policy, new admissions continue into the Go journal buffer while the cutoff watermark drains. Under high deltas generation, if peer B's socket buffer overflows before peer-ACKing up to the watermark, B drops packets and closes the connection. Node A aborts the transfer and releases the non-journaled freeze (`plan.md:4599`), but B retains partial unACKed journal mutations applied prior to the disconnect, creating session table state divergence without triggering a full repair until reconnect.

3. **Volatile Record Loss Leads to Dual-Secondary State** (`docs/research/6461-blind-rst/plan.md:4683-4717`, `6041-6045`; `pkg/ha/failover.go:471`, `pkg/ha/daemon_ha_sync.go:999`, `:1045`):
   When Node B applies a failover commit, becomes secondary, and clears its restore lease, B's crash wipes its volatile stage ledger. Upon reconnect, A's `CommitUncertain` query receives `not-applied` from B, forcing A to abort pre-PONR and remain secondary (`plan.md:4711`). Since B also restarted secondary in sync-hold with a cleared restore lease, both cluster nodes lock into secondary state simultaneously.

4. **Reconciliation Epoch vs PromotionPermit Lock Cycle** (`docs/research/6461-blind-rst/plan.md:4440-4476`, `6046-6052`; `pkg/vrrp/manager.go:432`, `pkg/vrrp/instance.go:1296`, `:1382`):
   `UpdateInstances` (`pkg/vrrp/manager.go:432`) acquires the single reconciliation epoch, extracts stop-sets under `Manager.mu`, and releases `Manager.mu` to join instance run loops (`pkg/vrrp/instance.go:1382`). If an instance run loop is concurrently executing `becomeMaster` (`pkg/vrrp/instance.go:1296`) while holding `PromotionPermit`, `UpdateInstances` blocks on the run loop join. Any concurrent code path inside the run loop or config tail (`pkg/ha/daemon_apply_tail.go:50`) that attempts to acquire the reconciliation epoch while holding `PromotionPermit` triggers an unrecoverable deadlock.

5. **Indefinite CommitUncertain Lockup on Disruptive Failover** (`docs/research/6461-blind-rst/plan.md:4708-4713`, `4807-4815`, `6052-6055`):
   When `DisruptiveTransfer` is executed against an unreachable peer, an unacknowledged commit places the claim into `CommitUncertain`. Because `CommitUncertain` resolution strictly requires a definitive peer answer (`plan.md:4712`) and the peer is dead, the claim remains locked indefinitely. Subsequent failover or ownership operations are fenced without an operator-driven mechanism to clear `CommitUncertain` on dead peers.
