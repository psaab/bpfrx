# Codex hostile plan review — round 8 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v7.4 @ fdf54f7af.
Run ledger: task-mrzpy4kp-52b8bu (18m59s, completed). Verbatim final output below (.scratch/r8-codex-final.txt).

---

PLAN NO

Scope: plan v7.4 at `fdf54f7af`; current cited code inspected in the specified worktree. No files were edited.

### 1. BLOCKER — The canonical `session_id` CAS is neither universal nor ABA-safe

The normal nonzero materialization path does inherit the shared ID ([session_glue/mod.rs:1109](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1109)), but imported entries do not always have one:

- Legacy imports explicitly allow ID zero and allocate a different ID in each worker ([session_sync.rs:274](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/helpers/session_sync.rs:274), [install.rs:335](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:335)).
- HA bulk export emits `session_id: 0` ([export.rs:143](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/export.rs:143)).
- `session_id` restarts at one and has only a worker namespace, not a node/boot incarnation ([session/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:682), [session/mod.rs:753](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:753)).

A strict zero-ID CAS can never win; treating zero as a wildcard restores key-only deletion. Even with nonzero IDs, v7.4 protects only the canonical alias and defers the rest to ordinary Close processing ([plan.md:620](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:620), [plan.md:636](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:636)). Publication and deletion span separately locked canonical/NAT/wire maps ([shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897), [shared_ops.rs:918](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:918), [shared_ops.rs:943](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:943)). Thus E1 may win canonical CAS, E2 republish, and E1’s delayed key-only Close then delete E2’s aliases and worker entries ([session_delta.rs:436](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:436), [session_delta.rs:453](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:453)). The full alias/BPF/worker teardown must remain conditional on one globally unique incarnation.

### 2. BLOCKER — Promotion straddles ticketed and direct Close authority

`maybe_promote_synced_session` first changes the local entry from `SyncImport`/`SharedMaterialize` to direct-authority `SharedPromote` ([promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86), [promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:99)). Only afterward does it republish the alias and sibling replicas—and the replacement alias deliberately has ID zero ([promote.rs:116](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:116), [promote.rs:125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:125), [promote.rs:131](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:131)).

During that interval, another worker’s stale `SyncImport` still matches the old alias ID and can win the proposed ticket. Its delayed key-only Close then deletes the newly promoted live owner. `WorkerLocalImport` narrowing is correct ([entry.rs:252](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:252)), but it does not make the `SyncImport → SharedPromote` transition atomic. Promotion needs an atomic authority revocation/epoch transition coupled to alias publication.

### 3. BLOCKER — Demotion and generation are not fenced

The runtime is published before worker demotion commands are queued ([state.rs:72](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:72)). A worker can load the inactive state, see no command yet, and expire while still locally born ([loop_body/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:682), [loop_body/mod.rs:811](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:811)). Because v7.4 authorizes “locally born OR active,” this window exists after local HA state is inactive—not only during VRRP overlap. Interpreting “no origin flip” literally makes old-owner authority indefinite; retaining current retagging leaves the transition window ([install.rs:568](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:568)).

The claimed imported-generation Close also has no plumbing: `SessionDelta` and the Close codec carry no generation ([entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [session_sync.rs:210](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/session_sync.rs:210)). Go consequently creates an ordinary delete, with zero-generation fallback applying unconditionally ([daemon_ha_userspace_stream.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:393), [sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)). Generations are comparable only per sender/key ([sync.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:537)), so independent cross-node wins are not idempotent.

### 4. BLOCKER — “Final admission” still does not define the promised observation boundary

V7.4 says anchors learn only from packets committed to the wire/local stack ([plan.md:431](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:431)), but ordinary `TxRequest` and `PreparedTxRequest` carry no mutation token ([types/tx.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/tx.rs:12), [types/tx.rs:108](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/tx.rs:108)). Cross-worker handoff can precede owner-side CoS admission ([drain/mod.rs:390](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:390)), while later stage/slice failures discard admitted requests ([stage.rs:23](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/transmit/stage.rs:23), [verify.rs:16](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/transmit/verify.rs:16)). TUN delivery can likewise end in a per-packet malformed/mis-sliced rejection ([tunnel.rs:119](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:119)) or terminal write error after queue acceptance ([slowpath.rs:607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/slowpath.rs:607)).

No tail branch directly tests the TCP sequence value, so the initial blind in-window probability is not reduced; however, packet geometry/content can be paired with any chosen sequence, so the tail is not purely capacity/allocation. A weaker “accepted into the egress pipeline” contract may be defensible, but v7.4 cannot simultaneously promise actual delivery. Actual XSK/TUN commitment requires per-item correlation back to the source worker.

### 5. BLOCKER — Split steering leaves a deterministic untrusted direction, and Phase 2 does not repair it

Queue selection follows physical RX queue, not canonical flow identity ([userspace-xdp/lib.rs:1460](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs:1460)). A forward flow born on worker A is replicated to B as non-promotable `WorkerLocalImport` ([shared_ops.rs:212](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:212), [entry.rs:252](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:252)). Reverse packets on B synthesize/use a reverse entry but fold validation and tracking onto B’s untrusted canonical forward replica ([session_glue/mod.rs:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1264)).

Consequently, for every split flow, reverse-direction first FIN/RST packets consistently land on B and soft-refuse; they do not randomly alternate between workers. Assuming independent uniform direction hashes over N queues, approximately `1−1/N` flows split—about 83% at six queues—and 100% of reverse closes in that class take this residual. Forward closes on A can validate.

Phase 2 specifies owner Rust→Go→peer Rust, not trusted same-node A→B aggregation/fanout ([plan.md:1394](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1394)). Exporting B’s raw observation as trusted would recreate the two-packet planting class; refusing to export it leaves the residual. Queue/path migration further permits old and new writers for one side, while the old replica can continue idle heartbeats indefinitely. A local canonical aggregator plus writer epoch/transfer semantics is required.

### 6. BLOCKER — Phase 2 cannot represent its claimed incarnation, merge, or lease semantics

The listed payload is 64 packed bytes, not approximately 52, before generation or lease state ([plan.md:1372](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1372)). More importantly:

- Sync generation is not stable identity: every sweep or bulk resend deliberately assigns a fresh generation to the same live session ([sync_conn_gen.go:113](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:113), [sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:142)).
- The payload lists no generation and no per-side presence/tombstone. `valid`/`trusted` are state masks, not message-presence masks; a partial writer cannot safely distinguish “leave absent side unchanged” from “invalidate it.”
- Window, OPENING endpoint, and `established` fields lack explicit ordering ownership. A stale full snapshot can regress phase or overwrite fresher non-owned fields.
- The 40-byte anchor and validator signature contain no lease or `now` input ([plan.md:383](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:383), [plan.md:744](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:744)), despite later requiring a lazy per-side lease ([plan.md:1468](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1468)).

After a receiver-side lease expires, a reconnect bulk either stamps a new 240-second lease and resurrects stale trust, or preserves freshness—but no age/deadline is transmitted. Absolute monotonic deadlines cannot be copied between nodes. The protocol needs a stable boot/session incarnation, explicit per-side bundles and presence, writer epochs, monotone phase semantics, and receiver-local freshness derived from transmitted owner age.

### 7. HIGH — “Bulk supersedes incremental” is not an ordering protocol

Bulk holds `writeMu` only per frame and yields between records ([sync_bulk.go:81](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:81), [sync_bulk.go:105](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:105)); the ordinary send loop can therefore interleave incrementals inside `BulkStart..BulkEnd` ([sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268)). The receiver immediately installs each full session rather than staging the snapshot to `BulkEnd` ([sync_conn_read.go:96](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:96)), and `BulkStart` resets generation guards ([sync_conn_read.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:183)).

Sidecar locking alone cannot order the BPF snapshot, sidecar snapshot, and queued updates. V7.4 needs a bulk epoch on every baseline/update or a staged snapshot followed by post-`BulkEnd` replay; unconditional “bulk supersedes” can overwrite a newer incremental.

### 8. HIGH — The quiet-heavy capacity calculation omits the active population

At 60-second heartbeats, 50,000 idle entries require about 833 records/s. Adding 10,000 active entries at the specified maximum of one update/s gives approximately 10,833 records/s, or 42.3 fully packed 256-record messages/s. That is 2.65 times the 16-message/s node cap ([plan.md:1457](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1457), [plan.md:1466](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1466)). The separate Go→Rust budget of 1–4 batches/s is lower still ([plan.md:1409](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1409)).

Overload fails safely into refusal, but it defeats the claimed one-interval freshness and quiet-flow protection. Heartbeat scheduling, fairness, ring-overflow behavior, and reserved service relative to Open/Close installs remain unspecified.

### 9. HIGH — Pending-neighbor re-resolution is unbounded

V7.4 now correctly says an incarnation mismatch must re-resolve or drop ([plan.md:452](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:452)), but defines neither a one-shot limit nor preservation of the original timeout. Current retry removes the old packet and has no `SessionTable` or full resolution context ([neighbor_dispatch.rs:156](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:156), [neighbor_dispatch.rs:270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:270)). Normal re-admission to `MissingNeighbor` resets both `queued_ns` and `probe_attempts` ([poll_descriptor/mod.rs:5057](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057)).

Route/incarnation churn can therefore repeatedly re-pend one packet and pin its frame. Either always drop on mismatch, or allow one complete re-resolution while preserving the original deadline and drop on a second `MissingNeighbor`. Close proof and promotion must also be recomputed against the new incarnation.

### 10. MEDIUM — Loss and probability text remain internally inconsistent

The new loss paragraph correctly says leg 3 may fail during an unresolved scaled-window hole and recover after repair ([plan.md:788](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:788)). Earlier analysis and the test expectation still say the loss consequence is confined to leg 2 and leg 3 remains unaffected ([plan.md:689](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:689), [plan.md:1261](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1261)).

The separate per-leg serial assertions are now correct ([plan.md:838](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:838)), but §5.4 retains the stale `1/7,282` cap while §2 correctly gives `1/6,554` ([plan.md:163](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:163), [plan.md:763](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:763)).

### 11. LOW — Mandatory tests still assert the broken contracts

The authority and Phase-2 tests state conclusions without exercising zero-ID imports, promotion straddling, delayed downstream ABA, demotion ordering, cross-node generation, partial-side presence, writer migration, stale-bulk lease replay, or 50k+10k saturation ([plan.md:1219](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1219), [plan.md:1228](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1228)). The suite also retains dispatch-enqueue-as-commit and the stale leg-3 expectation ([plan.md:1285](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1285)).

### Round-7 finding dispositions

- **R7-1 — partially resolved.** `WorkerLocalImport` is correctly excluded, but the stale-sibling kill survives across `SyncImport → SharedPromote`.
- **R7-2 — partially resolved.** Nonzero materialization inheritance and canonical CAS are improvements; zero/reused IDs and delayed key-only alias cleanup remain unsafe.
- **R7-3 — not resolved.** Demotion authority exists outside VRRP overlap, and generation still does not reach or order Close processing.
- **R7-4 — not resolved.** No general token/callback reaches actual XSK/TUN commitment; the documented residual is incomplete.
- **R7-5 — partially resolved.** Node scope, per-side sequence numbers, and phase were added, but stable incarnation, local split-worker trust, writer transfer, presence, and phase ordering remain undefined.
- **R7-6 — partially resolved.** Dedicated message types and a sidecar are named, but bulk interleaving, staging, worker-apply ordering, and capacity are unresolved.
- **R7-7 — partially resolved.** The 240-second lazy lease, 60-second heartbeat, and retained rebaseline are directionally sound; lease representation, stale-bulk behavior, dead-writer suppression, and volume are not.
- **R7-8 — partially resolved.** Re-resolve-or-drop prevents deliberate stale-decision transmission in principle, but lacks a bounded retry/deadline/proof state machine.
- **R7-9 — partially resolved.** The new paragraph states the during-hole leg-3 residual correctly; earlier analysis and tests still contradict it.
- **R7-10 — partially resolved.** Both serial assertions are fixed; the cap arithmetic remains inconsistent elsewhere.
- **R7-11 — partially resolved.** Some intended invariants were added, but the decisive transition, ordering, freshness, and saturation cases remain absent.

Bottom line: v7.4’s local close-plausibility rule remains broadly defensible, but the plan is not implementable as a safe HA design. The authority ticket is not an incarnation-wide transaction, promotion and demotion cross unfenced authority states, split steering lacks trusted same-node convergence, and Phase 2 cannot encode or order the freshness state it promises. Implementation should not begin until authority, packet-commit semantics, stable wire identity, per-side ownership/freshness, and bulk ordering are specified as complete state machines.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
