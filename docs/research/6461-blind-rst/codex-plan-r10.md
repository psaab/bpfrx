# Codex hostile plan review — round 10 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v8 @ 3d89f0dab (v8.1 landed mid-review and is excluded from its line refs).
Run ledger: task-mrzsb8yw-3oxx15 (25m22s, completed). Verbatim final output below (.scratch/r10-codex-final.txt).

---

PLAN NO

Scope: v8 at `3d89f0dab4a162ca4b335524c94b31908ec6f43c`, as pinned by the prompt. The branch advanced to v8.1 during review; those later edits are excluded. No files were edited.

### Findings

1. **BLOCKER — The normative Close-emission predicate omits the validated-close mark**

   V8 says the expiry gate “becomes” the ownership-only formula at `plan.md@3d89f0dab:637-640,1077-1081`, but separately says `SyncImport`/`SharedMaterialize` emit only when marked by a validated close and unmarked imports remain silent at `:649-655,1083-1091`. Those are different predicates.

   Implementing the literal formula at the current single gate, [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), lets an unmarked import on the active RG emit during ordinary expiry—the failure the redesign intends to avoid. No explicit validated-close mark is defined in `SessionEntry` ([session/mod.rs:343](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:343)). Existing `closing` cannot substitute: imports currently derive it from synchronized TCP flags ([install.rs:399](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:399)), including tunnel imports ([tunnel.rs:563](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:563)).

   The plan needs one exact predicate and a separately represented, incarnation-bound mark whose creation, companion propagation, reimport merge, and clearing rules are normative.

2. **BLOCKER — The TTL replacement has no live-refresh clock; no finite K is safe as written**

   V8 proposes purging after `K × timeout` “without worker refresh” at `plan:660-670,1087-1089`, but neither the refresh nor its timestamp exists. `SyncedSessionEntry` has no age/effective-timeout field ([worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)); packet activity updates only worker-local state ([session/mod.rs:1082](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1082), [session/mod.rs:1177](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1177)); and `refresh_owner_rgs` is transition-driven, not a periodic liveness publication ([refresh_owner_rgs.rs:21](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs:21)).

   Therefore an indefinitely active flow eventually loses its shared aliases despite continuous traffic. If its original worker remains live while a later packet moves to a worker whose replica expired, midstream pickup is allowed ([poll_descriptor/mod.rs:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1607)); the re-seed can select a different SNAT pool port while the old worker still holds the original flow.

   This is not narrowly “refused close + TTL”: it occurs after `K×T` since publication without any close. Under the intended model, `K=2` would mean at least 600 seconds for the default 300-second established timeout and 48 hours for an 86,400-second timeout; under actual v8 mechanics it can purge during active traffic. The current standby hold can also extend roughly an initial `T` plus `3T` ([session/mod.rs:103](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:103), [expire.rs:585](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:585)), so the suggested `≥2T` floor is not derived. A throttled authoritative activity refresh, age schema, jitter allowance, and explicit exclusion of refused closes are prerequisites to choosing K.

3. **BLOCKER — TTL family deletion is collision-, replacement-, and materialization-unsafe**

   Shared publication permits one flow to displace another at a derived NAT alias ([shared_ops.rs:918](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:918)). Family removal then derives NAT/wire keys from the removed canonical entry and deletes their current values unconditionally ([shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960)).

   Thus sweeping stale canonical E1 can delete an alias now owned by live colliding E2. A promotion/republish between age scan and deletion creates the same ABA race. Readers also clone shared values before later materialization, so a clone taken before purge can materialize after it.

   “Under the coordinator mutex” at `plan:667-668` is insufficient unless every publish, promotion, scan, alias delete, and materialization commit participates. Deletion needs an age recheck plus expected canonical/incarnation comparisons on every alias. A TTL purge racing a `SharedPromote` reap is harmless only after those rules exist; otherwise the purge or delayed Close can remove a replacement.

4. **BLOCKER — Same-node Phase-2 key-only propagation crosses flow incarnations**

   Local forward publication stores `session_id=0` ([poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560)); each importing worker independently allocates a nonzero ID from that zero ([install.rs:317](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:317)). Consequently A’s authoritative entry, B’s replica, and the shared alias do not share an incarnation. Declaring IDs irrelevant because the alias is key-indexed allows a delayed trusted update for old E1 to attach to same-key E2.

   The B→alias→A trust path is safe only if an unproved B bundle remains untrusted end to end, can never overwrite or upgrade trusted state, and is not dirtied/re-emitted by remote application. A later B sample may become trusted only by the existing cross-proof rules at `plan:536-620`. The broad statement that wire-carried sides land trusted at `plan:1592-1594` must not override this provenance.

   For merged installs, the correct rules are: no sidecar means default/untrusted; matching, fresh, current-owner-validated sidecar state may be reapplied as trusted; any incarnation mismatch refuses the reapply; and reapply preserves remaining lease rather than renewing it. V8 does not state these guards.

5. **BLOCKER — Phase 2 has no exclusive writer generation or owner-authority epoch**

   V8 versions each direction only by `(bulk_epoch, side_seqno)` at `plan:1512-1544`. After RX-queue migration, an old worker can retain queued `k+1` while the new worker inherits `k` and independently emits another `k+1`; strict lexicographic merge accepts whichever equal-version update arrives first. Observation-gated heartbeats stop future old-writer emissions but do not cancel queued ones. Heartbeats also need to be direction-specific: observation of D must not renew O.

   “Exactly one writer” also fails across HA nodes. A non-owner can observe an external packet before converting it to `FabricRedirect` ([poll_descriptor/mod.rs:3438](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3438)); the owner subsequently observes the forwarded copy. V8 says only the “current owner” renews trust at `plan:1565-1580`, but neither emission nor application has an active-RG/ownership-epoch gate. A former owner’s delayed update can therefore renew stale trust.

   Phase 2 needs a coordinator-issued flow incarnation, per-bundle writer generation or centralized sequence allocation, current-owner RG epoch validation, and non-reemitting remote application.

6. **BLOCKER — Reconnect ordering and queued `fresh` bits still resurrect stale trust**

   The sender retains an already encoded frame and retries it indefinitely across disconnects ([sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268)). A new connection becomes visible at [sync_conn.go:244](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:244) before reconnect bulk begins. An old `U(E,fresh=1)` can therefore land before `BulkStart(E+1)`, pass the old floor, and renew trust. V8’s floor at `plan:1485-1492` only governs messages received after `BulkStart`; it does not invalidate effective E-state already accepted immediately before it.

   `bulkSendNext` is process-local ([sync_bulk.go:65](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:65)), while `BulkStart` carries only an epoch ([sync_conn_read.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:183)). After sender restart, retaining the floor rejects the new low epoch; resetting it admits delayed old-process messages. The per-flow origin nonce cannot scope this stream because B may bulk-send flows originated by A. `BulkStart` needs its own random sender-process nonce.

   Finally, `fresh` is computed before records traverse bounded Rust/Go queues and reconnect retries (`plan:1450-1455`). Receipt time can be more than `T_anchor` after observation. Freshness must be recomputed at serialization/write time or carry bounded observation age; incrementals must be barred until `BulkStart` establishes the new floor.

7. **HIGH — The claimed single marked producer is neither unique nor durable**

   The requested NAT companion check passes only within one worker: accepted reverse-entry close propagation marks both halves ([session/mod.rs:1254](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1254)); the reverse half has `is_reverse=true` ([shared_ops.rs:689](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:689)) and is suppressed at expiry, leaving the forward half as the one emitter.

   It is not exactly one per flow:

   - Imports are fanned to every worker ([session_import.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:215)). A retransmitted valid close after steering movement can mark two worker copies; each has its own wheel and can emit.
   - A full reimport before the two-second reap removes/replaces the marked record ([install.rs:317](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:317)), yielding zero emitters unless the mark is merged.
   - A close accepted on worker B’s `WorkerLocalImport` marks only B. V8 says that origin stays silent, so A’s authoritative entry is untouched; allowing marked `WorkerLocalImport` to emit fixes that gap but introduces the cross-worker duplicate problem.
   - An accepted reverse-synth close with no local forward companion initially has zero forward emitters until a later hit propagates it.

   The contract must be at-least-once with downstream deduplication, or introduce a real cross-worker authority/handoff. “Exactly one” is false.

8. **HIGH — The cross-node Close fence still lacks one exact end-to-end identity**

   Section 5.2 compares `(origin_node_id, session_id)` at `plan:673-683`, while Phase 2 defines incarnation as `(node_id, process_nonce, session_id)` at `plan:1434-1446`. If `origin_node_id` means the random nonce, the separately encoded `node_id` is unexplained; if it means stable node ID, the fence is restart-unsafe.

   Every seam currently lacks the full tuple: `SessionDelta` and `SyncedSessionEntry` retain only a session ID ([entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)); helper import carries only that ID ([control.rs:1107](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/protocol/control.rs:1107)); Close encoding carries neither node nor nonce ([session_sync.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/session_sync.rs:215)).

   After failover, node B must retain and emit A’s exact `(node, process_nonce, session)` incarnation—not substitute B’s sender identity—and peer deletion must atomically compare that tuple against the current entry. V8 has not specified that complete chain. Phase-1 id-less unconditional deletion remains a documented replacement race.

   A close accepted against a stale-but-unexpired, owner-validated anchor is otherwise legitimate within the design’s advertised blind-window probability, provided the delete is fenced to that exact incarnation.

9. **HIGH — RX-worker admission fixes ownership, but the documented asynchronous residual is broader and internally inconsistent**

   All `LocalDelivery`, `NoRoute`, `MissingNeighbor`, and `NextTableUnsupported` decisions are eligible for slow-path reinjection ([forwarding.rs:955](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/forwarding.rs:955)) and reach the trailing reinjector ([poll_descriptor/mod.rs:5117](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5117)). Ordinary `ForwardCandidate` build failures also bypass the normal allow-list ([slow_path.rs:60](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60)). This includes firewall-local SSH/BGP and exceptional routing/neighbor paths, not just “tunnel-egress TCP.”

   Native GRE/WireGuard endpoints stop before the generic TUN path ([slow_path.rs:255](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:255)); mapped GRE LocalDelivery queues before a later TUN write ([slow_path.rs:213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:213), [tunnel.rs:180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:180)); generic acceptance similarly precedes the asynchronous write ([slow_path.rs:297](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:297), [slowpath.rs:534](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/slowpath.rs:534)).

   An accepted-but-later-dropped precursor plus a close at its learned coordinate can demote, although it provides no probability advantage over sending the close directly: the precursor still needs the approximately 1/6,554–1/10,923 hit. Freezing every asynchronous anchor is worse—64–128 KiB advances in about 52–105 μs at 10 Gbit/s or 21–42 μs at 25 Gbit/s, after which legitimate closes could refuse for 300–86,400 seconds. The missing alternative is selective no-learning on exceptional `NoRoute`/`MissingNeighbor`/`NextTableUnsupported` and build-failure reinjection while preserving normal geometry-validated LocalDelivery learning.

   Capacity semantics also conflict: `enqueue_tx_owned` can discard the newcomer while returning `Ok` ([umem/mod.rs:1257](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/umem/mod.rs:1257), [umem/mod.rs:1314](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/umem/mod.rs:1314)), although a reporting API exists ([umem/mod.rs:1290](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/umem/mod.rs:1290)). V8 accepts this tail at `plan:451-466`, while its mandatory test at `:1365-1369` requires that capacity discard not move the anchor.

10. **MEDIUM — Phase-2 capacity and memory claims still do not close**

   V8 calculates about 1,167 records/s, roughly five 256-record messages/s, at `plan:1553-1564`, but specifies only 1–4 Go→Rust batches/s at `:1493-1499`. No larger helper batch or independent coalescing contract closes the gap. A synchronized 50k-flow heartbeat cycle also places about 8,333 writer keys per worker at six-way distribution, above the 4,096-key ring, without a fairness/rescheduling rule.

   The stated 56-byte cost covers only anchor/proof state and leases (`plan:383-419`), excluding bundle seqnos, baselines, observation/heartbeat timestamps, incarnation/writer metadata, sidecar storage, and dirty scheduling state. Safe decay-to-refusal under overload is sound; the claimed steady-state freshness is not demonstrated.

11. **MEDIUM — Pending-neighbor re-resolution lacks a complete fresh-disposition contract**

   Current pending insertion resets the deadline/probe counters ([poll_descriptor/mod.rs:5057](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057)); retry reuses the old decision and forcibly converts it to `ForwardCandidate` ([neighbor_dispatch.rs:156](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:156), [neighbor_dispatch.rs:270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:270)). V8 correctly requires one deadline-preserving re-resolution, but specifies only the second-`MissingNeighbor` case at `plan:467-491`.

   It must say what happens when fresh resolution returns `LocalDelivery`, `FabricRedirect`, `NoRoute`, `NextTableUnsupported`, or no session. The safe rule is standard-dispatch the fresh result or drop; never transmit using the stale NAT/egress decision.

12. **MEDIUM — §9/§11 still contain stale and mutually incompatible contracts**

   The operative arithmetic at `plan:163-180` is correct, but revision history still says 1/7,282 at `:48`, and `:196` still summarizes the cap as approximately `1/2^13–1/2^14` although it is 1/6,554. The loss test at `:1323-1326` says leg 3 validates normally without exercising its documented refusal during the unresolved hole.

   Tests at `plan:1301-1315` still require deleted ticket-era behavior, including an unmarked import’s natural reap emitting/deleting. `:1316-1322` retains the older Phase-2 side-level/capacity contract, while `:1347-1350,1365-1369` conflicts with v8’s accepted commit tail. Missing decisive cases include mark loss on reimport, two marked workers, `WorkerLocalImport` split-close authority, live TTL refresh, stale-E1/colliding-E2 purge, promotion during scan/delete, pre-`BulkStart` stale delivery, sender restart, equal-version writer handoff, owner-epoch rejection, and freshness expiry in queues. Section 11 (`:1608-1648`) remains a list of unanswered questions rather than resolved design decisions.

### Round-9 dispositions

- **R9-1 — moot-by-deletion.** ID-conditional full-flow ticket teardown was deleted; the replacement TTL protocol fails independently.
- **R9-2 — moot-by-deletion.** The publish-before-flip ticket transition no longer exists; TTL/promotion still needs expected-incarnation serialization.
- **R9-3 — moot-by-deletion.** Mint-on-zero is no longer required for tickets; zero-ID aliases now expose Phase-2 key-only ABA.
- **R9-4 — partially resolved.** Random process nonce and a Go sidecar are correct directions; the comparison tuple, transport, post-failover origin retention, and atomic deletion remain incomplete.
- **R9-5 — partially resolved.** RX-worker admission resolves source-table ownership, but asynchronous scope, selective learning, capacity reporting, and tests remain wrong.
- **R9-6 — partially resolved.** V8 adds same-node propagation, per-direction bundles, and observation-gated heartbeats; incarnation, writer handoff, trust provenance, and current-owner gating remain unresolved.
- **R9-7 — partially resolved.** Per-bundle lexicographic ordering, a global floor, and merged installs fix ordinary same-connection cases; reconnect-before-floor and sender-restart scoping remain blockers.
- **R9-8 — partially resolved.** Per-direction window grouping, presence, random nonce, and freshness bits improve the model; queued freshness, per-bundle heartbeat ownership, trust-preserving merge, and full cost remain incomplete.
- **R9-9 — resolved.** V8 gives the correct owner-RG predicate shape, universal forward stamping requirement, and explicit LocalDelivery/#2120 owner-zero exceptions. The separate validated-mark contradiction is a new authority defect.
- **R9-10 — partially resolved.** Workload arithmetic and safe refusal under overload are honest; helper throughput, ring fairness, sidecar bounds, and state accounting remain unspecified.
- **R9-11 — not resolved.** Stale probability and during-hole loss assertions remain.
- **R9-12 — partially resolved.** New v8 cases were added, but deleted ticket behavior and contradictory Phase-2/commit contracts remain in the mandatory suite.

Bottom line: deleting the ticket tower is reasonable, but v8 does not replace it with a coherent cleanup and trust protocol. The exact Close predicate is contradictory, live shared aliases have no refreshable age, TTL deletion can remove a different incarnation, key-only Phase-2 updates cross tuple reuse, writer/reconnect ordering can renew stale trust, and the alleged single marked producer is neither unique nor durable. These are state-authority failures capable of recreating the cluster delete or SNAT mid-flow-swap consequences the issue is meant to eliminate; implementation should not begin from v8.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
