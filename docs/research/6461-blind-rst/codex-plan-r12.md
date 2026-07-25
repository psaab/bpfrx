# Codex hostile plan review — round 12 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v8.4 @ 9f30a1fce (v8.4.1 landed mid-review and is excluded from its line refs).
Run ledger: task-mrzvbi3h-3kaqng (6m03s, turn failed — content-filter infra error mid-analysis); resumed task-mrzvmwvx-xz909e (6m45s, completed). Verbatim final output below (.scratch/r12-codex-final.txt).

---

PLAN NO

Scope: pinned v8.4 at `9f30a1fce`, as required by the prompt. The branch advanced to `8a57a9284` during review; that later text-only revision was excluded. No files were edited.

## Findings

1. **BLOCKER — A per-worker reap is not a valid family-wide NAT release signal**

   V8.4 purges the alias family whenever reservation release succeeds (`plan.md@9f30a1fce:784-797`). But locally born forwards are published and replicated to every sibling worker at [poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560) and [session_glue/mod.rs:838](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:838). Each `WorkerLocalImport` forward reserves the same node-global allocation idempotently at [upsert_synced.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:80); [allocator.rs:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1664) has no replica refcount.

   An unobserving sibling eventually AGE-reaps while the traffic-owning worker remains live. Every expired forward unconditionally calls release at [loop_body/mod.rs:1481](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1481), and the first release removes the one shared allocation at [allocator.rs:1318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318). The proposed hook then purges the live worker’s same-incarnation family and permits mid-flow port reuse. The 30-second push refreshes the shared clock, not sibling worker entries.

   Release/purge must be driven by a last-node-local-holder or refcounted family-lifetime decision, not any worker reap.

2. **BLOCKER — A detached pre-purge clone preserves the stale-NAT collision**

   Shared lookups clone entries and release their locks at [shared_ops.rs:482](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:482), while materialization later installs the detached decision without a canonical-incarnation or live-reservation recheck at [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092).

   Analytic race: E1 is cloned; release purges E1 and frees its translation; the allocator assigns that translation to E2; the detached E1 clone then materializes and forwards. V8.4 explicitly permits this at `plan:775-781`, relying on the “lookup touch” that `plan:744-749` removed.

   Materialization needs an atomic commit-time incarnation check plus successful retain/re-reserve of the NAT allocation; failure must discard the stale decision and re-resolve.

3. **BLOCKER — Phase-2 freshness compares unrelated monotonic clocks**

   The sender carries absolute `observed_ns`, while the receiver computes `now − observed_ns` directly (`plan:1605-1644,1684-1692`). Monotonic-clock origins differ across hosts and boots; the code explicitly notes this at [screen/mod.rs:786](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/screen/mod.rs:786).

   Existing HA sync already exchanges an offset and rebases peer timestamps at [sync_protocol.go:18](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:18) and [sync_conn_read.go:475](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:475). Without equivalent nonce-bound normalization, unequal uptimes can reject every fresh bundle or make stale anchor/closing state appear fresh.

   Carry sender-computed age at actual write, or establish a process-nonce-bound clock offset and reject anchor traffic until it is ready.

4. **BLOCKER — The promised wire close mark is neither in the payload nor guaranteed to emit**

   The plan says the mark rides the Phase-2 tail as `closing:u8` (`plan:683-688`), but the normative payload at `plan:1605-1611` contains no such field. Import semantics at `plan:1808-1815` provide no mark-specific incarnation, ordering, freshness, or owner rule.

   Moreover, closing packets never advance anchors (`plan:535-538`), while emission is driven by anchor movement or an approximately 60-second heartbeat (`plan:1739-1754`). A reset-marked entry normally reaps in two seconds. Without an explicit immediate, sticky accepted-close emission trigger, the mark ordinarily never enters the dirty pipeline; a drop-oldest ring also cannot guarantee its survival through the reimport race it is intended to fix.

   The mark needs an incarnation-bound monotone record, current-owner admission, defined trust semantics, and immediate/retried emission independent of anchor movement.

5. **BLOCKER — Phase-2 bundle versions have no owner/process namespace**

   Merge ordering is only `(bulk_epoch, coord_seqno)` (`plan:1617-1629,1669-1674`), although both counters are sender-process-local. Current `bulkSendNext` is local state initialized in [sync.go:805](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:805) and incremented at [sync_bulk.go:53](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:53). `AnchorStreamStart` resets a connection floor, not the stored per-key high-water.

   A former owner or pre-restart process with a high version can block every lower-version update from the current owner indefinitely. Its lease eventually decays, leaving the exact refuse-biased failover state Phase 2 is required to repair. Version state must be namespaced by accepted owner and sender-process nonce, or atomically reset on authority/process transition.

6. **HIGH — The canonical family clock still has orphaned and undefined states**

   V8.4 puts the only clock on the canonical forward (`plan:755-768`), but a lone reverse import is explicitly accepted at [session_import.rs:78](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:78), published at line 115 and fanned out at lines 215-223. With no forward record, that family has nowhere to store or read its clock.

   The sweep also compares against `expires_after_ns` (`plan:750-754`), but current `SyncedSessionEntry` contains no timeout at [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375), and the proposed additive schema lists only `last_touch_ns` and `flow_incarnation_id` (`plan:1180-1182`). Its exact timeout provenance is unspecified.

   A fourth direct mutator is also missing from the stamp inventory: `demote_shared_owner_rgs` changes all three maps at [shared_ops.rs:161](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:161). I found no existing reverse two-map lock order—removal is canonical→NAT→wire—but current publication/removal interleave index locks, so implementing the promised maps-before-indexes transaction requires a real refactor.

7. **HIGH — Non-NAT aliases can resurrect obsolete authorization indefinitely**

   After the last worker entry expires at `T`, a non-NAT shared alias remains until at least `K×T`. A tuple hit can clone it through [shared_ops.rs:594](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:594), materialize its old decision without current policy at [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092), and promote it at [session_glue/mod.rs:1238](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1238). Materialization plus subsequent worker pushes then refresh the family clock.

   This is not equivalent to creating a new flow: a new flow must pass current policy, while this path revives the old permit/route decision. Removing read-touch merely moves the attacker-controlled refresh to packet-driven materialization. A refused materializing close also ceases to be shared-clock-inert.

8. **HIGH — Incarnation inheritance is not end-to-end**

   The fabric-return constructor has no forward match from which to inherit an ID: it accepts packet/routing state at [fabric.rs:389](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/fabric.rs:389) and installs directly at [poll_descriptor/mod.rs:981](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:981). That contradicts `plan:801-815`’s forward-only mint/inheritance claim.

   Reverse synth also requires `ForwardSessionMatch` to carry the ID—today it has only key/decision/metadata at [entry.rs:208](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:208)—and an install API that adopts rather than always mints at [install.rs:140](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:140).

   Cross-node semantics conflict as well: Phase 1 says IDs are node-local/not wire-carried (`plan:1180-1184`), while imports mint locally (`plan:811-815`), yet Phase-2 AnchorUpdates apply only on the owner ID match (`plan:1605-1614`). Full Open/import must explicitly adopt the owner ID before sidecar updates can match. Conditional `DeleteSynced` and Close codec fields are good folds, but the construction invariant remains incomplete.

9. **HIGH — `current_owner(rg)` is not a defined unique authority during overlap**

   Current state exposes independent local-primary and heartbeat-derived peer-primary predicates at [group_state.go:218](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/group_state.go:218); both can be true until election resolves dual-active at [election.go:213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/election.go:213). V8.4 simultaneously requires equality to one `current_owner` and states that both nodes may pass (`plan:1813-1823`).

   A unique fail-closed selection rule is required. Once the receiver’s view corrects, a former owner’s last accepted state survives at most `T_anchor`; if the view remains split/stale, former-owner heartbeats can renew indefinitely, so master-down timing alone is not a bound.

   The non-owner’s local fabric observation is otherwise not a direct bypass: its wire update is rejected and its inactive reap emits nothing. One missing test is activation between validation and reap—a locally accepted mark becomes authoritative if the node activates inside the two/30-second close window.

10. **MEDIUM — Reverse synth retains a Phase-2 zero-producer case**

   V8.4 acknowledges that synth acceptance initially marks only the reverse entry (`plan:1088-1095`) but claims the forward eventually emits because it is locally born (`plan:695-698`). A Phase-2 trusted match can instead come from a shared import at [shared_ops.rs:649](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:649).

   With no later packet, the marked reverse is `is_reverse`-silent and the imported forward is neither locally born nor marked. Both natural reaps are silent. Cleanup can eventually occur through reservation/TTL machinery, but the claimed Close/RT_FLOW producer does not exist. Accepted synth validation should mark the matching forward family atomically.

11. **MEDIUM — Poisoned-walk retention is bounded by spray duration, not one timeout**

   A refused close does not refresh `last_seen`, but every walking precursor/follow-on is an ordinary non-close packet. Slow lookup refreshes at [lookup.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:150), while cache hits refresh at [flow_cache_hit.rs:295](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:295).

   Therefore the correct bound is attacker spray duration plus one inactivity timeout, not one timeout (`plan:469-480,1488-1491`). Endpoint ACKs/challenge ACKs do not reliably rewind a serial-max anchor. This does not create a new basic pin primitive—today ordinary tuple-matching traffic already refreshes the flow—but poisoning can additionally soft-refuse the endpoint’s legitimate close for one full timeout after spraying stops.

12. **MEDIUM — Secondary-stream setup still has a readiness race**

   Every-connection `AnchorStreamStart`, typed retry, and atomic `BulkStart` are directionally sound. A dequeued record can be retried on the newly active fabric by the existing loop at [sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268); a genuinely lost update safely decays to refusal.

   However, current setup publishes a connection through `installConn` before sending even `ClockSync` at [sync_conn.go:125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:125). Unless v8.4 requires marker/clock readiness before publication—or gates active selection on readiness—an incremental can reach the secondary before its marker and be discarded, with no later repair for a quiet flow.

13. **MEDIUM — Capacity and memory accounting remain internally inconsistent**

   Go→Rust delivery is specified as only 1–4 batched messages/s (`plan:1703-1709`), while the stated steady-state floor is at least 3,000 records/s—twelve 256-record messages/s (`plan:1777-1782`).

   The literal payload is already about 91 packed bytes, or 92 with the omitted `closing`, not ~80. The claimed ~48-byte scheduling increment also has to contain 16-byte incarnation, baselines, two observation timestamps, sequence/version state, writer identities, heartbeat and dirty bookkeeping. Sidecar bounds must use the aggregate synced-flow capacity, not an assumed single 131,072-entry worker cap; the code’s import ceiling is based on `2 × worker_count × max_sessions` at [protocol_status.go:259](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/protocol_status.go:259).

14. **MEDIUM — Mandatory tests and normative text still describe incompatible protocols**

   Examples at the pinned commit:

   - `plan:1425-1448` retains single-producer/no-duplicate Close behavior, obsolete `(origin_node_id, session_id)` fencing, `(bulk_epoch, writer_gen, seqno)`, sender `fresh`, and owner-epoch language.
   - `plan:1808-1815` again uses obsolete `writer_gen`.
   - `plan:1488-1491` asserts one-timeout retention without testing ongoing non-close walking.
   - The suite lacks last-replica release, detached-clone commit, unequal-uptime/reboot freshness, owner/process high-water reset, reverse-only family clock, non-NAT stale-policy revival, closing-mark emission/loss, and activation-before-reap cases.

## Round-11 dispositions

- **R11-1 — not resolved.** Direct read-touch was removed, but per-worker release, detached clones, and packet-driven materialization preserve the stale-NAT hazard.
- **R11-2 — partially resolved.** One clock and a nominal lock order are stated; reverse-only families, timeout provenance, mutation coverage, and transaction mechanics remain incomplete.
- **R11-3 — not resolved.** Phase-1 mark loss is documented, but the Phase-2 payload omits the mark and defines neither safe merge nor emission.
- **R11-4 — partially resolved.** Unrelated numeric RG epochs were removed; unique overlap authority and owner-transition convergence are not defined.
- **R11-5 — partially resolved.** Per-bundle writers and coordinator sequencing fix same-node migration, but owner/process namespaces and clock semantics remain broken.
- **R11-6 — partially resolved.** Typed records, secondary markers, and atomic epoch activation are folded; cross-node freshness, stored high-water reset, and pre-publication readiness are unresolved.
- **R11-7 — partially resolved.** Conditional deletion and Close fields are specified, but constructor inheritance, import adoption, and the reverse-synth producer chain remain incomplete.
- **R11-8 — partially resolved.** The resource-retention objective is now acknowledged, but its ordinary-timeout bound ignores refreshing walk packets.
- **R11-9 — resolved.** Fabric SYN-bearing close seeds and LocalDelivery bare-close seeds are now inventoried, correctly bounded by class, and included in tests.
- **R11-10 — partially resolved.** The ≥3k floor and whole-cost headline improve the text, but throughput, payload size, scheduling memory, and sidecar bounds remain inconsistent.
- **R11-11 — partially resolved.** Several invariants and tests were corrected, but old cleanup, fencing, freshness, ownership, and sequencing contracts remain normative elsewhere.

Bottom line: the packet-level plausibility gate and constructor inventory have substantially converged, and stable non-owner learning is not a direct blind-close bypass. The surrounding cleanup and Phase-2 protocols have not: an idle sibling can release and purge a live NAT family, detached clones can resurrect released translations, freshness uses incomparable clocks, close marks are absent/non-emitting, and authority-local version counters cannot survive owner or process changes. Implementation should not proceed from v8.4.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
