PLAN-NEEDS-MAJOR

## Initial checkout verification

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r13-review`
- HEAD: `34619216673f66b1180274b50877f40628556999`
- State: detached HEAD
- `git status --short --branch`: `## HEAD (no branch)`
- Staged diff: empty
- Unstaged diff: empty

The immutable-checkout gate passed. I read the complete 4,653-line revision-13 plan, all three round-12 reviews, and the relevant production paths.

## Findings

1. **BLOCKER — an in-flight authority mutator can prevent the supposedly urgent negative fence from even starting.**

   The plan requires every authority-mutating RPC—including `apply_snapshot`—to retain `haInventoryTxnMu` across helper mutation, response, and publication. It also prohibits map writes before acquiring that mutex. See [plan.md:1238-1246](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1238), [plan.md:1253-1257](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1253), and [plan.md:1278-1295](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1278).

   The one-second urgent rule only preempts registered authority-neutral side effects. It provides no cancellation or process-kill handoff for the authority-mutating RPC currently owning `haInventoryTxnMu`; see [plan.md:1302-1313](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1302). A maximum-sized snapshot currently receives approximately 67 seconds, with a general 120-second cap, in [process_control.go:31-56](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/dataplane/userspace/process_control.go:31) and [process_control.go:85-103](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/dataplane/userspace/process_control.go:85).

   Executable interleaving:

   1. Config apply acquires `haInventoryTxnMu` and sends `apply_snapshot`.
   2. Rust mutates the helper, but stalls or loses its response.
   3. Election, stop, or rebind requests an urgent demotion.
   4. Demotion blocks acquiring `haInventoryTxnMu`. Because no map write may precede that acquisition, it cannot apply its fail-closed fence.
   5. It cannot reach the one-second drain-and-kill logic because `apply_snapshot` is not in the side-effect registry.
   6. The old forwarding authority can remain active for the snapshot deadline while a peer independently becomes authoritative, or shutdown/rebind remains unfenced.

   This contradicts the stated safety-critical demotion latency contract. The plan needs a precise urgent-preemption path for the current authority-mutating RPC: who may close the socket/process without holding the transaction mutex, how ambiguous apply debt is recorded, and how the old apply is prevented from publishing afterward. A paused-after-mutation/before-response `apply_snapshot` raced against demotion must be a required test.

2. **BLOCKER — receipt-bound remote failover has a pre-publish join cycle unless implementors invent an undocumented worker split.**

   A remote failover waiter completes only after final `PublishRGAuthority`; see [plan.md:2348-2361](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2348). But `CompleteOwnershipTransition` runs before publication and joins every callback capable of changing the ownership map; see [plan.md:2383-2393](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2383) and [plan.md:2407-2425](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2407).

   Production currently treats remote request processing as one handler: it invokes `OnRemoteFailover`, waits for actuation, and then emits the ACK in [sync_failover.go:423-450](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/cluster/sync_failover.go:423). That handler is launched from the receive path in [sync_conn_read.go:397-405](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/cluster/sync_conn_read.go:397), while the daemon callback performs the ownership mutation and wires the waiter in [daemon_ha_sync.go:999-1020](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/daemon/daemon_ha_sync.go:999) and [daemon_ha_sync.go:1063-1068](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/daemon/daemon_ha_sync.go:1063).

   Executable interleaving under the natural/current worker scope:

   1. The receive loop starts remote-failover callback worker `W`.
   2. `W` performs `ManualFailoverWithAuthorityReceipt`, changing the desired ownership map.
   3. `W` waits for that receipt before sending `applied`.
   4. The coordinator reaches `CompleteOwnershipTransition` and joins `W` because it is the callback that changed ownership.
   5. The receipt cannot complete until `PublishRGAuthority`.
   6. Publication cannot run until `CompleteOwnershipTransition` returns.

   That is a cycle: `W → Publish → Complete → W`. The proposed test explicitly requires the waiter to remain blocked until publication at [plan.md:4164-4169](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:4164), so timeout is not a legitimate escape.

   If the intended design is a two-stage worker, the plan must say so: the mutation subhandle must finish and surrender the receipt before `Complete`; a separate source-fenced waiter/ACK handle must be excluded from this transition’s pre-publish join while remaining joinable on disconnect/process replacement/Stop.

3. **BLOCKER — authoritative userspace bulk has no selected, operation-bound snapshot source. One available source is known unsafe; the other is not integrated.**

   The plan says only that a “snapshot/export step” occurs between direct `BulkStart` and `BulkEnd writes`; see [plan.md:2917-2954](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2917). It mentions both `export_all_sessions` and `export_owner_rg_sessions` only in helper classification/deadline tables, never selecting either or defining its causal relationship to the producer gate.

   That omission is decisive because the choices have incompatible behavior:

   - Current `BulkSync` directly iterates `SessionStore` and writes authoritative members in [sync_bulk.go:50-107](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/cluster/sync_bulk.go:50), but userspace `SessionStore` still wraps the legacy dataplane iteration path in [manager.go:387-391](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/dataplane/userspace/manager.go:387) and [session_store.go:118-129](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/dataplane/session_store.go:118). Production explicitly records its mirror-map drift and identifies owner-RG table-truth export as future work in [daemon_ha_sync.go:974-985](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/daemon/daemon_ha_sync.go:974).
   - `export_all_sessions` returns only after pushing Open events into the separate event-stream machinery; see [export.rs:49-79](/home/ps/git/xpf-worktrees/6744-plan-r13-review/userspace-dp/src/server/handlers/export.rs:49) and [export.rs:192-206](/home/ps/git/xpf-worktrees/6744-plan-r13-review/userspace-dp/src/afxdp/ha/export.rs:192). Go then treats them as ordinary session deltas and queues them without a bulk operation identity in [daemon_ha_userspace_stream.go:185-214](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/daemon/daemon_ha_userspace_stream.go:185) and [daemon_ha_userspace_stream.go:344-390](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/daemon/daemon_ha_userspace_stream.go:344).
   - Existing production comments already warn that event-stream delivery cannot delimit a complete authoritative set and can cause deletion of live sessions in [sync_bulk.go:14-39](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/cluster/sync_bulk.go:14).

   Executable interleaving if `export_all_sessions` is chosen:

   1. Sender closes producers and directly writes `BulkStart`.
   2. Rust snapshots sessions and enqueues Open events into its event stream.
   3. The control response succeeds before the independent Go event-stream consumer has processed all those events.
   4. Sender directly writes `BulkEnd`.
   5. Receiver reconciles against an empty or partial membership set and deletes absent live sessions.
   6. Delayed exported Opens arrive as ordinary deferred-tail traffic or violate the bound receive-window rule.

   A failed export is equally underspecified: [plan.md:1315-1325](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1315) says to “discard partial output,” but exported events carry no operation identity by which they can be distinguished from genuine concurrent tail events.

   `ExportOwnerRGSessions` does return concrete deltas in [manager_status.go:228-252](/home/ps/git/xpf-worktrees/6744-plan-r13-review/pkg/dataplane/userspace/manager_status.go:228), so it may be a viable basis. The plan must explicitly select it or another table-truth API and define the snapshot cut, RG filter, unlimited/continuation behavior, operation identity, relationship to deferred tail, partial-failure handling, and direct member-write order.

4. **BLOCKER — terminal eviction is incompatible with the sparse request window.**

   The plan allows eviction of the oldest terminal transaction whenever any terminal victim exists; busy is used only when no terminal victim exists. See [plan.md:2124-2151](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2124). Separately, the reject floor may advance only through a contiguous prefix, and gaps cannot be skipped; see [plan.md:2177-2202](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:2177).

   Executable capacity trace:

   1. IDs 1–100 are request-applied/commit-pending. Their request phases are complete, so the request floor reaches 100, but their transactions remain nonterminal and unevictable.
   2. Leave ID 101 unseen.
   3. Admit IDs 102–1025 as terminal mutation-free rejects: 924 terminal entries plus 100 nonterminal entries fill the 1,024-entry ring.
   4. ID 1026 is still within the advertised right edge, `floor + 1024`.
   5. The stated policy evicts oldest terminal ID 102.
   6. Because gap 101 prevents advancing the floor, a retry of exact ID 102 is now absent from the cache and above floor 100, so it is admitted and re-executed.
   7. Alternatively advancing the floor to 102 would falsely reject unseen ID 101, directly violating the no-gap-skipping rule.

   The proposed test makes the contradiction explicit by requiring both that gaps are not skipped and that “oldest-terminal eviction advances the reject-below floor” in [plan.md:4033-4044](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:4033).

   The plan must define an actually evictable terminal subset—normally only entries covered by a contiguous reject floor—or a bounded tombstone/range representation. In the trace above, new work must return busy unless such durable duplicate suppression exists. This is a new composition failure, not the round-12 complaint about unbounded replay storage.

5. **NIT — the deadline test table contradicts the normative setup timeout.**

   The normative constants specify a three-second capability setup and five-second protocol/repair budgets at [plan.md:1867-1875](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:1867). The proposed fake-clock test says “five-second setup/protocol/repair start” at [plan.md:4069-4077](/home/ps/git/xpf-worktrees/6744-plan-r13-review/docs/research/6744-kimi-review-003/plan.md:4069). This is straightforward wording/test correction, not an architectural blocker.

## Round-12 disposition

I did not carry forward closed findings. Revision 13 now specifies complete heartbeat rows including priority and weight, canonical metadata-free config identity, startup process identity and generation-one recovery, counter-exhaustion shutdown, bounded replay capacity, explicit operation deadlines, and last-fabric/process retirement ownership. The four blockers above arise from new cross-feature interleavings in those revised mechanisms.

## A–M disposition

| Workstream | Disposition | Review result |
|---|---|---|
| A | No blocker | Dedicated VIP-warning synchronization and reset/write ownership are implementable. |
| B | No blocker | Empty security identity handling is gated in both relevant views. |
| C | No blocker | Prepared normalized SNMP intent supplies one consistent compiler/runtime representation. |
| D | No blocker | ICMP argument generation is constrained by family and layer-4 type. |
| E | No blocker | DDNS family/source authority matrix is explicit. |
| F | No blocker | `LoadOverride` classification occurs on detached state before store publication. |
| G | No blocker | Persisted-AST traversal and missing-key handling are explicit. |
| H | No blocker | Route-map expansion shares the renderer’s family-count semantics. |
| I | **Blocked** | Findings 1–4: urgent fencing, receipt worker ownership, authoritative bulk source, and sparse replay eviction. |
| J | No blocker | Global address-book fragments use the established entry-level merge behavior. |
| K | No blocker | Link lookup distinguishes absence from operational lookup failure. |
| L | No blocker | Session-log action applicability and wire encoding are exhaustively classified. |
| M | No blocker | Combined selector forms are either explicitly lowered or rejected without the unsafe fallback. |

## Checkout verification after review

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r13-review`
- HEAD: `34619216673f66b1180274b50877f40628556999`
- State: detached HEAD
- `git status --short --branch`: `## HEAD (no branch)`
- Staged diff: empty
- Unstaged diff: empty