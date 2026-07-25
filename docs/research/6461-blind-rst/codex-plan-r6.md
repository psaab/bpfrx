# Codex hostile plan review — round 6 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v7 @ 238038949 (the v7.1 interim commit 02871f673 landed mid-run; findings 1-2 adjudicate both).
Run ledger: task-mrzmtihg-eo9gek (19m22s, completed). Verbatim final output below (.scratch/r6-codex-final.txt).

---

PLAN NO

1. **BLOCKER — Activation self-heal is not a single-authority transaction.**

   V7 proposes changing each imported entry to `SharedPromote` in the worker-local expiry self-heal ([plan.md:600](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:600), [plan.md:978](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:978)). But every HA import is fanned unchanged to every worker ([session_import.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:215)). Each copy independently reaches `SelfHeal` ([expire.rs:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:168), [expire.rs:213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:213)); after the proposed origin flip, every forward copy is eligible to emit `Close` ([entry.rs:245](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:245), [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342)). Concurrent worker expiries can therefore generate duplicate authoritative deletes before the first worker’s deletion reaches the others.

   Worse, `fabric_ingress` returns `Age` before the self-heal predicate ([expire.rs:544](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:544)). Those imports never flip, reap silently as peer-synced state, and leave shared/NAT aliases because shared deletion is `Close`-driven ([session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406)). Thus the exact r5 stale-alias failure remains for this class.

   Existing packet promotion demonstrates the required shape: select one worker, publish the authoritative shared entry, and retag other workers as silent replicas ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:99), [shared_ops.rs:212](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:212)). A direct per-worker wheel mutation bypasses that transaction.

2. **BLOCKER — Authority transfer is lazy, unfenced, and absent from shared/generation truth.**

   Activation refreshes forwarding entries by resetting `last_seen_ns` and `seen_rg_epoch` ([refresh_owner_rgs.rs:43](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs:43), [session/mod.rs:1642](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1642)). Self-heal is then considered only after a full idle timeout and itself re-stamps the entry for another timeout ([expire.rs:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:168), [expire.rs:213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:213)). A quiet import is therefore non-authoritative for approximately `T`, and its authoritative natural reap occurs around `2T`, not “from activation” or at its true natural timeout. Repeated sub-timeout RG flaps can postpone the flip indefinitely. Refused blind closes remain inert and do not accelerate this; the failure is the ownership mechanism itself.

   HA runtime is published before worker demote/refresh commands are queued ([state.rs:72](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:72)). Workers load runtime before processing commands and expiry ([loop_body/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:682), [loop_body/mod.rs:765](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:765)). During whole-node demotion, an old `ForwardFlow` can consequently observe inactive state before being retagged and emit an old-owner `Close`. Conversely, the new owner can self-heal before its refresh command. The prompt’s premise that owner-born entries keep their origin is false: completed demotion changes every non-peer origin to `SyncImport` ([install.rs:568](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:568)).

   The proposed worker mutation also leaves coordinator/shared copies as `SyncImport`, unlike real promotion’s publication at [promote.rs:116](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:116). It emits no `Open`/authority delta. Consequently Go may have no sender generation for the eventual `Close`; `takeDeleteGen` then returns zero ([sync_conn_gen.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:176)), and a generation-zero delete applies unconditionally ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)). Duplicate or delayed closes across a flap can delete a newer same-key incarnation. Authority needs a coordinator-serialized activation transaction plus an authority generation/epoch, not a lazy worker-local origin edit.

3. **BLOCKER — Phase 2 still has no complete wire/apply contract, and authoritative reconnect bulk erases anchors.**

   The specified 18-byte tail contains only four coordinates plus `valid`/`trusted` ([plan.md:1250](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1250)). It omits:

   - The `anchor_seqno` required by its own import rule ([plan.md:1278](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1278)).
   - `fwd_wnd`/`rev_wnd`, although every slack calculation depends on them ([plan.md:396](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:396)).
   - The four immutable OPENING endpoints ([plan.md:401](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:401)).
   - A session-incarnation identity, allowing an old high-seqno update to bless a same-tuple replacement.

   Current `MSG_SESSION_UPDATE` handling decodes it as a full session and maps it to `"open"` ([eventstream.go:559](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/eventstream.go:559), [daemon_ha_userspace_stream.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:205)). That stamps a new install generation and queues a full upsert ([sync_conn_write.go:53](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:53)). Rust’s helper protocol supports only `upsert` and `delete` ([sync_session.rs:19](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/sync_session.rs:19)); worker commands likewise lack an anchor-update operation ([runtime.rs:408](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/runtime.rs:408)). A full import removes the old entry first ([install.rs:310](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:310)). V7 does not specify the dedicated cross-chassis opcode, Go queue/apply path, or in-place updates for all shared aliases and worker replicas.

   Reconnect is independently fatal: `doBulkSync()` always runs authoritative `BulkSync()` ([sync_bulk.go:40](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:40)), which enumerates the anchorless BPF-compatible store ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:95)). Production deliberately does not use Rust table export as its authoritative bulk source ([daemon_ha_sync.go:974](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_sync.go:974)). A reconnect therefore full-upserts a tail-less snapshot and wipes a previously current quiet-flow anchor; with no later traffic, no update repairs it. The claimed “no Go behavioral change beyond decode/re-encode” scope guard is impossible.

4. **BLOCKER — Dirty-ring loss and the quiet-flow filter leave trusted wrong-state windows, not refuse-biased state.**

   V7 emits only when advancement since the last emission is at most one slack and drops the oldest key on ring overflow ([plan.md:1270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1270)). Both rules have terminal states:

   - Once a flow advances more than one slack, every future comparison with the unchanged last-emitted anchor remains over threshold—even after the flow becomes quiet.
   - If a dirty key is evicted and that flow then becomes idle, nothing re-enqueues it.

   More importantly, an older standby anchor remains `trusted`. It still accepts a random RST in its stale interval at the normal blind-window probability, even though that RST is nowhere near current endpoint state. This is a wrong accept and firewall-only demotion, not “refuse-biased” behavior. Phase 1’s zero-trust state is safer for such a flow.

   A watermark counter provides observability but no recovery or trust invalidation. Existing Open/Close deltas instead latch loss and force a table-truth rescan ([session/mod.rs:1693](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1693), [loop_body/mod.rs:1062](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1062)). Phase 2 needs reliable invalidation/freshness epochs and retained-dirty or rescan semantics. The ring is also cheaply fillable without victim-sequence guessing: permitted clients can establish and advance thousands of their own known flows.

5. **BLOCKER — The proposed commit boundary still precedes traffic-driven drops, while pending-neighbor delivery has no commit carrier.**

   V7 claims observation occurs after CoS/drop evaluation ([plan.md:179](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:179), [plan.md:424](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:424)). In reality, cache “rewrite success” merely appends a `PreparedTxRequest` ([flow_cache_hit.rs:444](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:444)); slow-path enqueue similarly appends to software queues ([cos.rs:100](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/cos.rs:100)). Later CoS admission drops on flow-share/buffer pressure but still returns `Ok(())` ([cos_classify.rs:1449](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/cos_classify.rs:1449), [cos_classify.rs:1527](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/cos_classify.rs:1527)); bounded pending queues also evict frames ([drain/mod.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:33)). These are controllable pre-transmit drops, not the documented post-enqueue completion residual. A never-forwarded sample can still slide an anchor or apply a staged establishment promotion.

   Pending-neighbor traffic has the opposite omission. `PendingNeighPacket` carries no segment/proof/promotion token ([types/mod.rs:77](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/mod.rs:77)); `retry_pending_neigh` has no `SessionTable` ([neighbor_dispatch.rs:156](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:156)) and directly rewrites/enqueues resolved packets ([neighbor_dispatch.rs:344](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:344)). A valid SYN-ACK buffered for ARP can be delivered without applying OPENING→ESTABLISHED; the live flow can then reap on the 20-second opening trajectory. Applying at initial buffer admission would instead mutate packets that later time out. The commit token must survive through final admission and be bound to a stable session incarnation.

6. **HIGH — `anchor_seqno` has neither a safe writer namespace nor a viable volume budget.**

   Serial comparison works only with one incarnation-bound writer. V7 instead gives each worker-local entry its own `u32` counter and dirty ring ([plan.md:1270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1270)), while an import is replicated to every worker. Different workers can emit equal sequence numbers for different directional changes; accepting the first causes the second to be discarded.

   Incrementing on every trusted packet change also crosses the RFC-1982 half-space quickly: at 25 Gbit/s, approximately 58 seconds for minimum-sized packets or about 17 minutes for MTU-sized traffic. A fast flow that later becomes quiet can therefore produce a numerically “older” update relative to its last wire value. Use an incarnation-bound emission sequence with a single writer or explicit changed-field merge; late updates must also be rejected once the receiver becomes authoritative.

   `≤1 update/entry/s` is not a global bound. A 4,096-key ring on each worker can generate multi-worker bursts exceeding the cluster’s 4,096-message nonblocking queue ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:36)). Peer helper apply currently serializes a fresh Unix-socket JSON round trip per session request ([process_control.go:181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/process_control.go:181)), while repository guidance warns that new control requests above 1/s starve session synchronization ([CLAUDE.md:44](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/CLAUDE.md:44)). Phase 2 needs a globally budgeted batched/persistent update path.

7. **HIGH — Receiver direction is corrected, but raw-u16 slack permanently stalls legal scaled-window ACK streams.**

   V7 correctly derives `ack_hi(D)` slack from `wnd(D)`, but caps it implicitly at `2 × raw_u16` ([plan.md:492](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:492), [plan.md:691](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:691)). Consider raw window 512 with scale 14: the effective receive window is 8 MiB. One early lost segment can hold cumulative ACK while later data buffers; repair then produces a single legal multi-megabyte ACK jump. Duplicate ACKs do not advance the anchor, and the eventual jump exceeds the 64 KiB gate. Every subsequent ACK remains too far ahead, so the field stalls until sequence wrap.

   The 64–128 KiB range is consumed in roughly 52–105 μs at 10 Gbit/s and 21–42 μs at 25 Gbit/s. Consequences are legitimate close soft-refusal and ordinary-timeout table retention, not packet loss, but the promised scaled-window test cannot pass. Either track window scale/effective windows or define a safe trusted ACK re-anchor.

8. **HIGH — OPENING intervals lack an explicit validity predicate.**

   The 40-byte structure has validity/trust bits only for live seq/ack fields, not for the immutable opening pairs ([plan.md:390](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:390)). Rule 2 then performs unconditional interval membership tests ([plan.md:733](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:733)), conflicting with the earlier prose that a consulted leg must be trusted.

   On an ordinary forward-SYN install, the unused reverse interval remains default `[0,0]`. A literal implementation accepts a reverse-direction bare RST with `seq=0` through the self-abort leg. Phase 2 makes this worse by importing live `trusted` bits without carrying the immutable intervals. The rule must explicitly require `open_valid/trusted(direction)` before either interval can validate. The immutable-endpoint concept itself is sound; its predicate is underspecified.

9. **MEDIUM — Cap arithmetic and “three independent guesses” remain wrong.**

   At maximum raw window, each `seg.seq` leg is `65,536 + 131,070 + 1 = 196,607` values. Leg 3 is symmetric `±131,070`, hence `262,141` values—not 196,607 ([plan.md:719](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:719)). With disjoint sequence windows, the additive total is `2×196,607 + 262,141 = 655,355`, giving approximately **1/6,554** and **6.55 seconds at 1,000 pps**, not 1/7,282 and ~7 seconds ([plan.md:163](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:163)). The floor figure remains correct.

   One RST|ACK carries two independently chosen 32-bit values: `seg.seq` tests the union of two windows, while `seg.ack` tests leg 3. It does not carry three independent guesses, although the additive disjoint-window approximation remains valid. At roughly 1/6,554 versus an RFC 5961 endpoint’s exact `RCV.NXT` coordinate, the firewall remains the weaker validator; the improvement over today’s one-packet kill is still substantial, but the stronger story is not supportable.

10. **LOW — Mandatory tests still contain a contradiction and do not exercise the new authority architecture.**

   The provenance test still says a non-close materialization promotes the entry and that the promoted entry emits no `Close` ([plan.md:1090](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1090)). Promotion creates `SharedPromote` ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:99)), which is not peer-synced and therefore does emit on forward expiry. The activation tests merely assume self-heal “HAS flipped” ([plan.md:1133](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1133)); they omit multi-worker simultaneous expiry, `fabric_ingress`, state-publication/command ordering, sub-timeout flapping, generation-zero closes, reconnect bulk, dirty-record eviction, and fast→quiet convergence. The 40-byte sum, `wrapping_add`, and simultaneous-open master-parity documentation are otherwise correct.

### Round-5 finding dispositions

- R5-1 — **not resolved.** Activation self-heal does not create one durable cleanup authority and is unreachable for `fabric_ingress`.

- R5-2 — **resolved.** Immutable opening endpoints fix the mutable-ceiling attack locally; finding 8 is a new validity/schema defect.

- R5-3 — **partially resolved.** V7 correctly rejects the Go sweep and identifies a Rust producer, but lacks a complete schema, operation, bulk source, apply path, ordering model, and volume budget.

- R5-4 — **partially resolved.** Receiver direction is corrected; raw-window scaling still permits permanent ACK-anchor stalls.

- R5-5 — **partially resolved.** All three legs are now counted, but leg 3’s width and the independence wording remain wrong.

- R5-6 — **partially resolved.** Redirect-inbox discard reporting and fallback reinjection are folded; CoS/FIFO false commits and pending-neighbor missing commits remain.

- R5-7 — **partially resolved.** Staging promotion until commit is the right invariant, but the defined commit path cannot reliably carry or apply it.

- R5-8 — **resolved.** Lost-SYN-ACK simultaneous-open behavior is explicitly documented and tested as master parity.

- R5-9 — **partially resolved.** The 40-byte assertion, wrapping arithmetic, and newer activation expectations are folded; the older impossible provenance expectation remains.

V7 makes real progress on immutable OPENING proof, per-stream direction, staged establishment, and layout precision, but its new activation design is not an authority-transfer protocol, its required Phase 2 cannot preserve or safely apply anchors, and its commit boundary still mutates state for undelivered packets while missing delayed deliveries. These are architecture failures, not test-polish issues; implementation should not begin until authority is coordinator-serialized and generation-fenced, packet mutations are tied to final admission, and Phase 2 has an incarnation-safe, loss-recovering, globally budgeted end-to-end transport.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
