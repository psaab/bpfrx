# AGY hostile plan-review — round 97 (v10.14.0)

Reviewer: AGY (direct binary; one RESOURCE_EXHAUSTED 429, then success after a 4-minute backoff). Verdict: SOUND. The marker-lifecycle attack analysis is the highlight: a stale-positive marker under tuple reuse suppresses exactly ONE purging packet (the stale row is deleted by that purge, and the new flow's second packet installs/caches normally); materialize-through clears the marker via ordinary republication. The overdue skip+guard and the D==now boundary semantics verified against expire.rs:166-168.

## Verbatim review

SOUND

### Executive Summary: v10.14.0 Consistency Review

This review completes the round-97 design-document consistency audit for `docs/research/6461-blind-rst/plan.md` (v10.14.0, commit `2008089d2810`). The round-97 folds — specifically the close-retained marker on `SyncedSessionEntry` conditioning flow-cache insertion suppression during purging dispatches, the overdue-probation skip-wholesale rule paired with the commit-hook never-refresh-on-overdue guard, and the dual reachability of the conflicted reservation state via #6522 or #6600 — have been thoroughly analyzed against the codebase (`userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, `userspace-dp/src/afxdp/shared_ops.rs`, `userspace-dp/src/afxdp/session_glue/promote.rs`, and `userspace-dp/src/session/expire.rs`).

The plan is **SOUND**. Below is the detailed analysis addressing each item of your review checklist.

---

### (a) Marker Mechanics & Lifecycle Attack Verification

#### 1. Setting at the Gate
* **Location:** `userspace-dp/src/afxdp/session_glue/mod.rs:1178-1223` / `promote.rs:48-59`.
* **Mechanism:** When a closing segment (FIN/RST) arrives on a non-owner node for a translated forward key, `should_keep_synced_hit_transient` evaluates to `true`. The close-aware purge gate intercepts the close, skips the destructive purge from `shared_sessions`, retains the shared entry, and marks `close_retained = true` on the `SyncedSessionEntry` stored in the shared maps (`userspace-dp/src/afxdp/worker/mod.rs:375-401`).
* **Verification:** `SyncedSessionEntry` carries internal shared-map metadata that is never transmitted on the HA wire. Setting this flag on retention provides the exact historical observation context that the stateless `should_keep_synced_hit_transient` predicate previously lacked.

#### 2. Consultation at Purging Dispatch
* **Location:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959`.
* **Mechanism:** When a subsequent non-closing packet (e.g. ACK) arrives on the non-owner node for that same tuple, `should_keep_synced_hit_transient` evaluates to `true` (it is a non-close packet). The purging dispatch purges the shared row and forwards the packet using the retained decision. At line 3900 (`FlowCacheEntry::from_forward_decision`), flow-cache insertion is conditioned on `!purged_row_had_close_retained_marker`.
* **Verification:** ACK-first flows (no close ever retained, `close_retained == false`) purge and populate the flow cache exactly as master does. Close-then-ACK sequences (marker set) purge the shared row while suppressing flow-cache insertion, forcing the subsequent packet to clean-miss and install a fresh local entry with an owned $P_2$ allocation.

#### 3. Marker Lifecycle & Attack Analysis
* **Who clears the marker?**
  1. *Purging Removal:* The purging dispatch itself removes the marker-bearing row from `shared_sessions` (`shared_sessions.remove(&key)`). Once purged, the shared row no longer exists.
  2. *Republication:* `publish_shared_session` (`userspace-dp/src/afxdp/shared_ops.rs:897-916`) overwrites the shared map entry with a freshly constructed `SyncedSessionEntry`, which defaults `close_retained = false`.
* **Can it go stale-positive and wrongly suppress a later legitimate flow's cache insert under tuple reuse?**
  * *Analysis:* Suppose Flow 1 receives a FIN/RST, setting `close_retained = true`, but no follow-up ACK arrives to trigger the purging dispatch. The marker-bearing row remains in `shared_sessions`. If a new Flow 2 reuses the same 5-tuple 10 minutes later and its first non-closing packet hits this non-owner node:
  * The non-closing packet of Flow 2 hits the retained row and triggers the purging dispatch.
  * Flow 2's *first* packet purges the stale row from `shared_sessions` and has its flow-cache insertion suppressed.
  * Crucially, the stale row is now **deleted** from `shared_sessions`.
  * Flow 2's *second* packet clean-misses in `shared_sessions`, installs a fresh local session, and populates the flow cache normally.
  * *Verdict:* The suppression is strictly one-shot (confined to the single purging packet that evicts the stale row). Tuple reuse cannot cause ongoing or permanent cache insertion suppression.
* **Should a non-close materialize-through clear it?**
  * *Analysis:* If RG active-owner status changes such that a non-closing packet materializes-through (`materialize_shared_session_hit`), `should_keep_synced_hit_transient` returns `false` (it is not a purging dispatch). The local session is installed, and subsequent promotion/re-publication calls `publish_shared_session`, which replaces the shared entry with a fresh `close_retained = false` record. Thus, materialize-through naturally resets the marker via ordinary republication.

---

### (b) Overdue Probation Skip & Guard Verification

#### 1. Mechanics vs. `expire.rs:166-168` Expiry Boundary
* **Expiry predicate in `expire.rs:168`:**
  `now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns` (equivalent to `now_ns > D`).
* **Overdue condition:** $D \le \text{now\_ns}$ (where $D = \text{last\_seen\_ns} + \text{expires\_after\_ns}$).
* **At $D = \text{now\_ns}$:** Strict expiry has not yet fired in `expire.rs:168` (`>` is false). Treating $D = \text{now\_ns}$ as overdue for skipping upsert and guarding commit-hook refresh is a deliberate one-instant shortening that guarantees an entry sitting at its exact expiration instant is not resurrected for a full 300 s timeout by a racing packet before the wheel GC processes it.

#### 2. Re-materialization Skip-Wholesale
* **Rule:** A `materialize_shared_session_hit` probe against an existing local probation entry $K$ where $D \le \text{now\_ns}$ skips the upsert entirely.
* **Verification:** No `remove_entry`, no reinstall, no restamp of `last_seen_ns`/`expires_after_ns`, no wheel re-queue, and no local removal (avoiding the pre-admission removal bug of v10.13.0). $K$ remains in its existing wheel slot, the packet is forwarded using the materialized $S_2$ decision, and $K$ reaps on schedule during the next wheel GC pass.

#### 3. Commit-Hook Guard
* **Rule:** When a non-closing packet reaches final admission (commit hook), if the matched entry is a probation entry with $D \le \text{now\_ns}$, the clear+refresh logic (`probation = false`, `last_seen_ns = now_ns`, `expires_after_ns = ESTABLISHED_TIMEOUT`) is skipped wholesale.
* **Verification:** Prevents a stale decision from being resurrected for a full established timeout by a packet that arrives at or after the probation deadline.

---

### (c) End-State Stress Analysis

1. **Blind Demote DoS Defeated:**
   * Sequence validation (`close_seq_plausible`) gates all FIN/RST demotions on the canonical forward entry's anchor. Implausible or unanchored closes are refused demotion while maintaining non-blocking packet delivery to endpoints.
   * Blind attack difficulty is elevated from a single packet anytime to continuous spraying at $\sim 1/6,554$ to $1/10,923$ probability per packet.
2. **HA Wire Parity & Zero Wire Format Changes:**
   * Part A operates entirely on worker-local state (`TcpSeqAnchor` POD on `SessionEntry`). No HA wire schema modifications, version negotiation, or sidecar changes are introduced.
   * Standby nodes refuse demotion on untrusted baselines, preventing blind remote cluster-wide deletes.
3. **Clean Decoupling:**
   * The pre-existing NAT release bug (#6522) is correctly isolated to its own tracking issue.
   * Phase 2 HA-wire anchor carriage is properly partitioned into `phase2-brief.md`.
   * Pre-existing race conditions (#6599, #6600) are documented as master-parity behaviors without widening blast radius.

---

### (d) Full-Document Consistency Sweep & Citation Audit

A complete line-by-line sweep of `docs/research/6461-blind-rst/plan.md` (v10.14.0) confirms full structural and technical internal consistency:

1. **`userspace-dp/src/afxdp/worker/mod.rs:375-401`**: `SyncedSessionEntry` struct definition and field additions match the text.
2. **`userspace-dp/src/afxdp/session_glue/promote.rs:48-59`**: `should_keep_synced_hit_transient` predicate logic matches the close-aware gate description.
3. **`userspace-dp/src/session/expire.rs:166-168`**: Expiration check `now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns` aligns with the $D \le \text{now\_ns}$ overdue boundary analysis.
4. **`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959`**: `FlowCacheEntry::from_forward_decision` insertion point correctly reflects the marker-conditioned suppression rule.
5. **`userspace-dp/src/afxdp/shared_ops.rs:897-916`**: `publish_shared_session` behavior matches the republication marker-reset mechanics.
6. **`userspace-dp/src/nat/allocator.rs:1664-1674` & `userspace-dp/src/afxdp/worker/loop_body/mod.rs:1490-1505`**: Dual reachability of the conflicted reservation state via unrefcounted sibling release (#6522) and import-window race (#6600) is accurately documented.

---

### Conclusion

Plan v10.14.0 is fully converged, mechanically sound, and ready for execution via `/engineer 6461`.
