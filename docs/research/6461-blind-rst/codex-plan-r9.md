# Codex hostile plan review — round 9 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v7.5 @ bb2d3e5f3 (v7.6 landed mid-review and is excluded from its line refs).
Run ledger: task-mrzr3o36-444ag1 (19m36s, completed). Verbatim final output below (.scratch/r9-codex-final.txt).

---

PLAN NO

Scope: v7.5 at `bb2d3e5f3`, as pinned by the prompt. The branch advanced to v7.6 during review; those later edits are excluded. No files were edited.

### Findings

1. **BLOCKER — ID-conditional teardown has neither end-to-end identity nor one shared flow incarnation**

   V7.5 claims the Close ID is already carried and downstream deletes become conditional (`plan.md@bb2d3e5f3:659-663`). `SessionDelta` does contain the ID ([entry.rs:326](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:326)), and expiry fills it ([expire.rs:372](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:372)), but every relevant output currently drops it:

   - The Close encoder has no ID field, and its caller omits the ID ([session_sync.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/session_sync.rs:215), [event_stream/mod.rs:662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/mod.rs:662)).
   - Go’s Close decoder ends after zone IDs, and Go queues key-only deletes ([eventstream.go:1467](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/eventstream.go:1467), [daemon_ha_userspace_stream.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:393)).
   - Rust worker deletes and shared removals are key-only and unconditional ([runtime.rs:408](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/runtime.rs:408), [delete_synced.rs:9](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:9), [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960)).
   - The shim redirect map stores only a `u8`, so it cannot compare incarnations ([bpf_map/mod.rs:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:48), [bpf_map/mod.rs:600](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:600)).

   Locally born forward and reverse shared entries also publish ID zero, while their live halves independently allocate different IDs ([poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560), [poll_descriptor/mod.rs:2897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2897)). An imported synthesized reverse likewise carries zero ([shared_ops.rs:750](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:750)). A forward Close ID therefore cannot conditionally delete its reverse half or aliases. Strict matching leaks them; zero-as-wildcard restores ABA.

   The architecture needs one full-flow incarnation on both halves, every alias, and every worker replica—or both expected IDs—plus transactional conditional deletion across Rust, BPF/DNAT, Go storage, and cluster sync.

2. **BLOCKER — Publish-before-flip does not make promotion atomic**

   The accepted “microseconds” pre-republish interval (`plan.md@bb2d3e5f3:651-659`) is unsafe:

   1. A stale import sibling wins the CAS and removes alias `S`.
   2. The promoter unconditionally republishes `SharedPromote,S`.
   3. The stale sibling’s delayed ID-conditional cleanup still matches `S` and removes the promoted live session.

   Current promotion and shared publication are separate operations ([promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86), [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897)). Promotion must atomically transition `import+S → promoted+S` and abort if the alias is missing/mismatched, or allocate a new incarnation.

   The post-publication/pre-flip interval is deletion-safe—stale siblings see a promoted origin and lose—but a crash there strands a promoted alias over an import entry. A delayed HA import can also overwrite and re-arm the ticket because the generation guard acts only when both generations are nonzero, while promoted aliases currently publish generation zero ([session_import.rs:39](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:39), [promote.rs:123](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:123)).

3. **BLOCKER — Mint-on-zero is not universal**

   Coordinator HA import could mint once before publication and fan out one ID, but the only existing allocator is private to each worker and embeds worker bits ([session/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:682), [session/mod.rs:784](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:784)). Today the coordinator publishes the original entry before cloning it to all workers ([session_import.rs:115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:115), [session_import.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:215)); if zero reaches the workers, each mints a different ID.

   More decisively, local tunnel `UpsertLocal` bypasses that coordinator path: it creates `SyncImport` with ID zero, publishes the zero-ID alias, then fans it to every worker ([tunnel.rs:563](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:563), [tunnel.rs:691](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:691)). Each worker allocates independently on zero ([install.rs:340](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:340)). For an active-RG tunnel flow, every ticket compares a nonzero worker ID to a zero alias and loses.

4. **BLOCKER — The cross-node incarnation fence is unavailable and restart-unsafe**

   V7.5’s `(node_id,session_id)` fence (`plan.md@bb2d3e5f3:697-703`) has no origin-node field or Close transport. After failover, a Close emitted on node B must identify the original incarnation from node A; using B fails to match, while the Rust entry does not retain A’s node ID.

   The Go BPF-backed store also discards `RTFlowSessionID`, so it has nothing to compare ([bpf_session_value.go:204](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:204), [session_store.go:132](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:132)). The claimed stored generation is similarly lost when `SyncedSessionEntry` becomes `SessionInstall` ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)).

   IDs restart at one per worker. Thus an old entry surviving on the peer and a restarted same-node worker can reuse `(node,S)`. Phase 2’s wall-clock `boot_id` does not guarantee uniqueness under timestamp collision or clock rollback; the empty local table is irrelevant because the peer/sidecar is the survivor. Use a random process nonce, following the existing precedent at [heartbeat.go:624](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/heartbeat.go:624).

5. **BLOCKER — “Final admission” still cannot update the source worker’s canonical anchor**

   V7.5 requires all geometry checks before mutation while explicitly rejecting per-item callbacks (`plan.md@bb2d3e5f3:439-460`). But `TxRequest`/`PreparedTxRequest` carry no segment, incarnation, or source-session mutation token ([tx.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/tx.rs:12), [tx.rs:108](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/tx.rs:108)). A request can cross to a different CoS owner before final admission ([cos.rs:125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/cos.rs:125)); that owner cannot mutate the RX worker’s canonical `SessionTable`.

   The named checks are not all source-hoistable:

   - Length versus frame capacity is geometric and hoistable ([stage.rs:23](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/transmit/stage.rs:23)).
   - UMEM slice validity depends on the target UMEM, assigned offset, and current runtime state ([verify.rs:16](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/transmit/verify.rs:16)).
   - TUN `EINVAL` is observed only after an asynchronous write and explicitly denotes per-packet malformed/mis-sliced input ([tunnel.rs:119](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:119), [tunnel.rs:180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:180)).
   - Generic slow-path writes can fail or become ambiguous after enqueue acceptance ([slowpath.rs:534](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/slowpath.rs:534), [slowpath.rs:607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/slowpath.rs:607)).

   Analytic residual: a valid session-hit non-close sample advances the anchor at enqueue/admission, but chosen malformed inner geometry later receives TUN `EINVAL`; the endpoint never observed the coordinate now trusted by the firewall. Actual commitment requires a correlated return command or a weaker, honestly documented contract.

6. **BLOCKER — Phase-2 split-worker repair has neither a local transport leg nor writer-transfer semantics**

   The Phase-1 master-parity correction is valid: B’s close propagation probes only B’s table, and its `WorkerLocalImport`/reverse entries reap silently ([session/mod.rs:1241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241), [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342)). No shared-map or Go path marks A.

   Phase 2 nevertheless does not provide its claimed repair:

   - The specified route is Rust→local Go→peer Go→peer Rust (`plan.md@bb2d3e5f3:1460-1485`), not local Go→local Rust/shared alias.
   - A’s live entry has ID α, its local shared alias has zero, and B allocates β from that zero ([poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560), [install.rs:340](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:340)). `(node,boot,α)` cannot update either B or the alias.
   - Writer migration has no writer identity, epoch, or transfer rule. Section 7 says the old heartbeat stops without observation (`plan:1199-1202`), while the emission rule mandates a timer heartbeat when the anchor has not moved (`plan:1523-1528`). A migrated-away writer and a genuinely idle SSH flow are locally indistinguishable. Timer heartbeats preserve stale writers; observation-gated heartbeats let idle flows decay.

7. **BLOCKER — `bulk_epoch >= stored` is not an ordering protocol**

   Bulk releases `writeMu` between records, allowing incrementals to interleave ([sync_bulk.go:81](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:81), [sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268)). Two failures remain:

   - Within epoch E, newer incremental `U(k+1)` may arrive before older baseline `B(k)`. Equality passes v7.5’s `>=` rule, allowing baseline regression unless ordering is lexicographic per side.
   - An E−1 update queued before `BulkStart(E)` can be written afterward. Before that key’s E baseline arrives, its stored epoch remains E−1, so the old update is accepted. There is no receiver-global epoch floor established at `BulkStart`.

   Current full session receipt immediately installs, and synced install removes/replaces the Rust entry ([sync_conn_read.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:109), [install.rs:317](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:317)). Even if Go retains `U`, a subsequent raw full upsert can wipe it. The protocol needs a global epoch floor, per-side `(epoch,seqno)` ordering, and full installs rebuilt from the effective merged sidecar state.

8. **HIGH — Lease renewal can resurrect time-stale trust, and field ordering remains incomplete**

   A “current epoch” proves message ordering, not observation freshness. V7.5 grants every current bulk baseline a fresh receiver-local lease (`plan.md@bb2d3e5f3:1549-1564`), but transmits no owner-side observation age. A sidecar value stale for minutes after overflow, writer movement, or update loss can therefore regain another 240 seconds of trust. The sender must retain per-side freshness and omit expired sides or transmit bounded age.

   `side_present`, monotone `established`, immutable OPENING endpoints, and absent-side preservation are sound improvements. Window ordering remains ambiguous: each direction has two independently versioned coordinates but only one `wnd`; “wnd follows the corresponding side’s seqno” does not specify which seqno wins a partial merge.

   The listed payload is 77 bytes packed—not approximately 72—and likely 88 bytes under native alignment (`plan:1437-1447`). The 56-byte local cost covers only the 40-byte anchor plus four leases, excluding per-side emission seqnos, baselines, freshness/emit timestamps, incarnation state, and scheduling bookkeeping.

9. **HIGH — `owner_rg_id` coverage and the normative gate contradict each other**

   Live-state gating is the correct fix for properly stamped transit entries (`plan.md@bb2d3e5f3:629-638`). Owner-zero classes are:

   - LocalDelivery, explicitly zero ([poll_descriptor/mod.rs:1919](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1919)). Local fallback is acceptable cross-node because Go deliberately excludes LocalDelivery from HA sync ([daemon_ha_userspace_stream.go:29](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:29)).
   - Ordinary non-RG local flows: local fallback is correct.
   - Reverse entries and `MissingNeighborSeed`: already excluded.
   - Pre-upgrade HA entries and imports whose referenced tunnel endpoint is unavailable: these remain zero; activation refresh skips zero-owner non-fabric entries ([manager_ha.go:1606](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/manager_ha.go:1606), [refresh_owner_rgs.rs:126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs:126)). Imported origins stay silent and may strand aliases.

   More seriously, the later invariant says `locally-born || owner active` (`plan:1094-1105`), contradicting the operative rule. That formula authorizes a demoted stamped `ForwardFlow` solely because it was locally born. The normative predicate must be explicit: `(owner_rg_id > 0 && active_now) || (owner_rg_id == 0 && locally_born)`.

10. **MEDIUM — Capacity is recalculated honestly but the pipeline still cannot demonstrate that rate**

   The revised arithmetic is correct: `50k/60 + 10k/30 ≈ 1,167` records/s, or about 4.56 full 256-record messages/s (`plan.md@bb2d3e5f3:1537-1548`). That is under the 16-message/s cluster cap.

   However, Go→Rust is limited to 1–4 batches/s (`plan:1481-1487`), already below 4.56 unless those batches are larger or separately coalesced. Split workers can emit two partial records per flow, and the 4,096-key dirty ring has no specified mechanism for re-scheduling an idle key after its first emit. Safe decay-to-refusal is documented, but steady-state one-interval freshness still lacks coalescing, fairness, and records/s budgets end to end.

11. **MEDIUM — Exact arithmetic is fixed, but stale probability and loss assertions remain**

   The operative cardinalities are now correct: 393,219 at the floor and 655,355 at the cap (`plan.md@bb2d3e5f3:163-174,795-892`). The remaining text still says `1/7,282` in revision history (`plan:46-49`) and summarizes guesses as `~1/2^13–1/2^14` (`plan:841-842`), optimistic at the cap, whose denominator is 6,554.

   The loss explanation correctly says leg 3 fails during the unresolved hole and recovers afterward (`plan:735-740`), but the next sentence says stall is confined to leg 2 (`plan:746-747`), and the test still states legs 1/3 validate normally without a during-hole case (`plan:1326-1329`).

12. **LOW — Mandatory tests still describe older contracts**

   The suite retains v7.4/v7.2 authority and Phase-2 assertions (`plan.md@bb2d3e5f3:1284-1325`) and enqueue/cache-rewrite-as-commit (`plan:1350-1353`). It does not exercise:

   - zero-ID tunnel fanout or common forward/reverse identity;
   - CAS-win-before-promotion and delayed re-import;
   - delayed conditional teardown after republish;
   - originating-node and same-node-restart reuse;
   - owner-zero classes;
   - same-epoch/old-epoch bulk interleavings;
   - stale-current-bulk lease renewal;
   - writer migration and idle heartbeat distinction;
   - the one-shot pending-neighbor deadline/probe preservation and second-pend drop.

### Round-8 dispositions

- **R8-1 — not resolved.** Mint/CAS does not extend to a common full-flow incarnation or conditional Rust/BPF/Go teardown.
- **R8-2 — not resolved.** Reordering promotion leaves the prepublication resurrection race and delayed-import re-arming.
- **R8-3 — partially resolved.** Live RG lookup fixes stamped-entry demotion ordering conceptually; the invariant conflicts, generation is lost, and the replacement cross-node fence is unavailable and restart-unsafe.
- **R8-4 — not resolved.** No carrier or callback connects target-side final admission to the source canonical anchor; TUN `EINVAL` remains a geometry-dependent asynchronous drop.
- **R8-5 — partially resolved.** Phase-1 master parity is confirmed, but Phase-2 same-node convergence and writer transfer are absent.
- **R8-6 — partially resolved.** Presence, monotone phase, immutable endpoints, and receiver-local leases improve the encoding; incarnation uniqueness, window versioning, writer ownership, freshness, and layout remain incomplete.
- **R8-7 — partially resolved.** `bulk_epoch` is necessary but insufficient without a global floor, per-side lexicographic ordering, and merged full-install application.
- **R8-8 — partially resolved.** The quiet-workload calculation and safe overload posture are honest; helper capacity, coalescing, fairness, and heartbeat scheduling remain inconsistent.
- **R8-9 — resolved.** The design now mandates exactly one re-resolution, preserves the original deadline/probe budget, recomputes proof/promotion, and drops a second `MissingNeighbor` (`plan:471-482`). Tests remain missing.
- **R8-10 — partially resolved.** Core cardinality and loss prose are fixed; stale probability summaries and during-hole test wording remain.
- **R8-11 — not resolved.** The decisive v7.5 transition, ordering, freshness, capacity, and bounded-retry cases are absent or contradicted by older expectations.

Bottom line: v7.5’s local plausibility validator and bounded pending-neighbor redesign are implementable, and the Phase-1 split-steering behavior is correctly recognized as master-parity. The overall plan still fails because Close authority is not one incarnation-wide transaction, promotion can resurrect an already-ticketed incarnation, the cross-node fence is neither transported nor restart-safe, actual packet commitment cannot reach the canonical anchor, and Phase 2 lacks coherent writer-transfer, bulk-ordering, and freshness semantics. Implementation should not begin from v7.5.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
