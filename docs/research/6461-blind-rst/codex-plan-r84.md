PLAN NO

Reviewed v10.1.1 at `d5e992cdc44f69483614d4271df595d7e6123452`, read-only. No files were edited.

## Round-83 fold dispositions

1. **r83-B1 — PARTIALLY RESOLVED.** The proposed provenance gate prevents the original HIT-side raw replacement, and there is no second such installer: the other installers are inside the cold branch beginning at [poll_descriptor/mod.rs:884](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:884); common ForwardCandidate/FabricRedirect/LocalDelivery/NoRoute/NextTableUnsupported dispatch does not install, and FIN/RST is flow-cache-ineligible at [flow_cache.rs:354](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/flow_cache.rs:354). However, the fold gates only the install, after seed-only NAT work has already run—new finding 1.

   On an ordinary HIT, the pending packet initially carries the resolver’s stored decision with freshly recomputed forwarding resolution, copied at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662). It is then currently mutated by seed-only NPT/SNAT at `:4739/:4757` and stored by value at `:5063`. It carries no canonical backing-entry key, family identity, provenance, or validation verdict.

2. **r83-B2 — RESOLVED.** `materialize_shared_session_hit` performs only a worker-local upsert at [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092); it neither allocates NAT nor publishes shared/BPF state nor fans out replicas. Carrying `probation` in `ExpiredSession` can gate all global expiry actions at [worker/loop_body/mod.rs:1491](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1491), while retaining local flow-cache invalidation at `:1516`. Explicit policy/operator/HA teardown can still remove a probation copy, but no blind-close-triggered residual global path was found.

   The cleared-probation scope cut is accepted. A promoted entry has published state that warrants normal cleanup; an unpromoted cleared entry has acquired no new global holding, leaving only pre-existing #6522 behavior.

3. **r83-B3 — PARTIALLY RESOLVED.** The intended invariant fixes the simple exact-key local-entry trace, but the plan does not identify or retain the actual local session family, does not handle resolver outcomes with no surviving entry, and does not provide a per-session cumulative bound. See findings 2, 5, and 6.

   The early-removal inventory is incomplete: besides operator delete and RG vacate, there are `DeleteSynced`, input-filter configuration purges, terminal host/lo0/junos-host policy teardown, same-key replacement, and translated-synced transient purge. Admission has no eviction—it refuses. RG vacate affects shared CoS slots only, and screens do not delete live sessions. The deliberate policy/configuration removals are acceptable; the automatic transient purge is not.

4. **r83-M4 — RESOLVED.** Section 5.2 now documents the drop-oldest residual at [plan.md:533](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:533), matching [tx/drain/mod.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:33) and the push-then-bound enqueue order.

5. **r83-L5 — RESOLVED.** OPENING explicitly requires `open_valid && open_trusted` at [plan.md:797](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:797), with the mixed-trust regression test.

6. **r83-L6 — RESOLVED.** [phase2-brief.md:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:20) no longer relies on the removed family clock or purge hook. Its “exactly once” wording should be tightened as noted below.

7. **r83-nit — RESOLVED.** The header correctly says v10.1.1 and identifies the one additive Go worker-status decode field at [plan.md:3](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:3).

## New findings

1. **BLOCKER — the MissingNeighbor provenance gate occurs after seed-only NAT allocation.**

   A live no-SNAT session can survive a configuration update that adds a matching pool-SNAT rule, then HIT with a cold next hop. The common arm unconditionally enters SNAT derivation at [poll_descriptor/mod.rs:4680](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4680) and allocates through `source_nat_decision_for_flow` at `:4745`, before the cited install at `:4787`. Under the literal fold, provenance skips the install but leaves an unowned allocation.

   Pool allocation creates a non-expiring `live_by_flow` record at [nat/source.rs:1548](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1548); allocator GC explicitly never touches it at [allocator.rs:2134](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:2134). Repeating across flows exhausts the pool/tracked-flow cap. Treating the skipped install as an install failure is unsafe too: allocation is idempotent at [allocator.rs:1035](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1035), while rollback removes the existing mapping at `:1399`.

   Provenance must branch before all seed-only NAT/NPT preparation, metadata, counters, install, rollback, and publication. Define distinct `ExistingResolved`, `SeedInstalled`, and `SeedRefused` outcomes; `ExistingResolved` must preserve the resolver decision and allocator state exactly.

2. **BLOCKER — the interim hold has no typed backing-family identity, and `Some(resolved)` does not imply a live entry.**

   `PendingNeighPacket` carries only the query tuple and decision at [types/mod.rs:77](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/mod.rs:77). Forward-wire lookup can return a different canonical key at [shared_ops.rs:614](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:614), but the outer path discards `ResolvedFlowSessionDecision.key` at [poll_descriptor/mod.rs:883](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:883). Site-2b REFUSE likewise installs no reverse entry while returning the reverse query key at [session_glue/mod.rs:1330](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1330); the actual entry to retain is the forward match.

   Worse, `keep_transient` calls [purge_translated_synced_hit](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:167), deleting local/shared state and releasing NAT, after which resolve still returns `Some` at [session_glue/mod.rs:1254](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1254). A subsequent MissingNeighbor therefore has nothing to hold; fresh retry misses and drops.

   Finally, holding only a reverse entry does not preserve the forward NAT owner. If both halves are idle, `companion_keeps_alive` rejects the stale reverse at [expire.rs:468](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:468), the forward expires, and global NAT/BPF teardown runs while the reverse packet remains pending.

   The resolve outcome must explicitly distinguish `LocalFamily{forward,matched}`, `ResolvedWithoutLocalBacking`, and genuine miss, and the pending hold must cover the canonical forward/NAT owner plus its companion.

3. **BLOCKER — a successfully delivered `MissingNeighborSeed` never becomes an authoritative session and has incomplete cleanup.**

   A genuine cold-neighbor miss installs and process-publishes a transient seed at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787), including shared state at `:4823` and a DNAT alias at `:4879`. Fresh retry sees an ordinary HIT, but only `SyncImport`/`SharedMaterialize` are promotable at [entry.rs:252](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:252); no successful-delivery path retags the seed.

   A later accepted close marks it, yet expiry suppresses its Close delta at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342). Worker GC releases NAT and BPF state, while shared and DNAT cleanup exists only in the absent Close-delta drain at [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406). The stale shared seed can later be materialized with a released or reassigned translation. This is both an accepted-close zero-producer trace and an ordinary-expiry stale-NAT trace.

   A committed retry needs an idempotent in-place `MissingNeighborSeed → ForwardFlow` transition with correct session-limit, Open, shared, and replication accounting. Timeout/uncommitted expiry must instead remove all shared/DNAT aliases.

4. **BLOCKER — site 2b erases the Local-versus-Shared provenance required by its trust rule.**

   `lookup_forward_nat_across_scopes` returns the same `ForwardSessionMatch` for both scopes at [shared_ops.rs:638](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:638), and the type carries only key/decision/metadata at [entry.rs:208](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:208). The plan nevertheless requires Local to validate and Shared to refuse.

   Concrete trace: an old shared reverse alias for `K/NAT1` survives while local replacement `K/NAT2` exists. The old reply tuple misses the local NAT index and returns the Shared `K/NAT1` match; a key-only anchor re-probe then finds local `K/NAT2`, validates against the wrong flow, and can mark that replacement while synthesizing the old decision. Shared publication inserts new aliases without removing aliases from the prior NAT decision at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897).

   Carry explicit match scope and require key/NAT/entry-identity agreement before reading or marking a local anchor. Shared matches must refuse even if the same canonical key is locally occupied.

5. **HIGH — the claimed pending timeout is per packet/binding, not a cumulative per-session bound.**

   Pending and negative-neighbor maps are per binding at [worker/mod.rs:140](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:140), while one worker `SessionTable` serves all its bindings at [loop_body/mod.rs:894](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:894). Each binding supplies a fresh `queued_ns`; rotating the same tuple/hop across three 2-second bindings, or five 800-ms bindings, can maintain a continuous union of pending holds despite each individual timeout and 3-second negative-cache interval.

   The session/NAT slot can therefore remain held indefinitely. At the admission cap, `can_admit` continues refusing otherwise-admissible flows at [install.rs:45](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:45). This is not a stronger primitive than the pre-existing ordinary non-close refresh pin, but it contradicts §5.7’s refused-close inertness and §5.2’s bounded-hold claim. Use a per-session first-hold deadline that cannot be reset across bindings.

6. **MEDIUM — wheel reinsertion and the actual release bound are unspecified.**

   Expiry pops the canonical wheel hint before deciding at [expire.rs:145](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:145). Implementing “skip” as a bare `continue` permanently strands the entry. It must reinsert without refreshing `last_seen_ns`, following [rebucket_alive_entry](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:424).

   Expiry also runs before pending retry/removal, so the finite bound is pending timeout plus up to one GC cadence, not exactly the pending timeout. Section 9 needs post-resolution and post-timeout eventual-reap/admission-recovery tests.

7. **nits — two stale claims remain.** [plan.md:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:48) still says Part B is “exactly four local rules,” despite the three new folds. The “owner performs global cleanup exactly once” wording at `plan.md:1000/:1173` and `phase2-brief.md:24` should be qualified as the authoritative cleanup event, because §10.6.1 explicitly admits unrefcounted sibling cleanup calls.

## Core-gate recheck

The gate remains sound in isolation: the anchor is exactly 40 bytes and canonical-forward-only; RFC-1982 membership and `<2^31` assertions are correct; receiver-window selection is correct; `open_valid && open_trusted` closes the default-interval case; imported trust remains absorbing; and the apply hook has no missing-forward fallback.

The arithmetic is exact:

- Floor: 393,219 values; `2^32 / 393,219 = 10,922.58`, about 10.923 seconds at 1,000 pkt/s.
- Cap: 655,355 values; `2^32 / 655,355 = 6,553.65`, about 6.554 seconds at 1,000 pkt/s.

No additional raw-flag installer or duplicate-producer trace was found. Finding 3 is a new zero-producer trace.

## Section 11 answers

1. **Terminal cut:** No—the local provenance, pending-family, and seed-lifecycle traces still allow pool exhaustion, stale/reassigned NAT use, or legitimate-close loss.
2. **Round-83 folds:** No overall—there is no second raw HIT installer and probation cleanup is sound, but B1 is not transaction-safe and B3 is neither identity-complete nor cumulatively bounded.
3. **Emission posture:** One zero-producer trace remains for committed `MissingNeighborSeed`; no new duplicate-producer trace was found.
4. **Arithmetic:** Yes—393,219 and 655,355 are the correct disjoint-union bounds and yield approximately 1/10,923 and 1/6,554.
5. **Re-scope:** The removed distributed protocol, #6522 fix, and Phase 2 still need not ship here; only the local corrections above must ship with this plan.

The sequence-window gate itself remains substantially converged, and r83-B2 plus the three minor folds are sound. The plan is not yet a safe terminal cut because provenance is represented as booleans or erased match types where the code needs transactional scope and session-family identity, and because `MissingNeighborSeed` lacks a committed/aborted lifecycle. These are all local state-machine corrections; none justifies restoring the removed distributed protocol.
tokens used
457,734
PLAN NO

Reviewed v10.1.1 at `d5e992cdc44f69483614d4271df595d7e6123452`, read-only. No files were edited.

## Round-83 fold dispositions

1. **r83-B1 — PARTIALLY RESOLVED.** The proposed provenance gate prevents the original HIT-side raw replacement, and there is no second such installer: the other installers are inside the cold branch beginning at [poll_descriptor/mod.rs:884](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:884); common ForwardCandidate/FabricRedirect/LocalDelivery/NoRoute/NextTableUnsupported dispatch does not install, and FIN/RST is flow-cache-ineligible at [flow_cache.rs:354](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/flow_cache.rs:354). However, the fold gates only the install, after seed-only NAT work has already run—new finding 1.

   On an ordinary HIT, the pending packet initially carries the resolver’s stored decision with freshly recomputed forwarding resolution, copied at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662). It is then currently mutated by seed-only NPT/SNAT at `:4739/:4757` and stored by value at `:5063`. It carries no canonical backing-entry key, family identity, provenance, or validation verdict.

2. **r83-B2 — RESOLVED.** `materialize_shared_session_hit` performs only a worker-local upsert at [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092); it neither allocates NAT nor publishes shared/BPF state nor fans out replicas. Carrying `probation` in `ExpiredSession` can gate all global expiry actions at [worker/loop_body/mod.rs:1491](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1491), while retaining local flow-cache invalidation at `:1516`. Explicit policy/operator/HA teardown can still remove a probation copy, but no blind-close-triggered residual global path was found.

   The cleared-probation scope cut is accepted. A promoted entry has published state that warrants normal cleanup; an unpromoted cleared entry has acquired no new global holding, leaving only pre-existing #6522 behavior.

3. **r83-B3 — PARTIALLY RESOLVED.** The intended invariant fixes the simple exact-key local-entry trace, but the plan does not identify or retain the actual local session family, does not handle resolver outcomes with no surviving entry, and does not provide a per-session cumulative bound. See findings 2, 5, and 6.

   The early-removal inventory is incomplete: besides operator delete and RG vacate, there are `DeleteSynced`, input-filter configuration purges, terminal host/lo0/junos-host policy teardown, same-key replacement, and translated-synced transient purge. Admission has no eviction—it refuses. RG vacate affects shared CoS slots only, and screens do not delete live sessions. The deliberate policy/configuration removals are acceptable; the automatic transient purge is not.

4. **r83-M4 — RESOLVED.** Section 5.2 now documents the drop-oldest residual at [plan.md:533](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:533), matching [tx/drain/mod.rs:33](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/drain/mod.rs:33) and the push-then-bound enqueue order.

5. **r83-L5 — RESOLVED.** OPENING explicitly requires `open_valid && open_trusted` at [plan.md:797](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:797), with the mixed-trust regression test.

6. **r83-L6 — RESOLVED.** [phase2-brief.md:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:20) no longer relies on the removed family clock or purge hook. Its “exactly once” wording should be tightened as noted below.

7. **r83-nit — RESOLVED.** The header correctly says v10.1.1 and identifies the one additive Go worker-status decode field at [plan.md:3](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:3).

## New findings

1. **BLOCKER — the MissingNeighbor provenance gate occurs after seed-only NAT allocation.**

   A live no-SNAT session can survive a configuration update that adds a matching pool-SNAT rule, then HIT with a cold next hop. The common arm unconditionally enters SNAT derivation at [poll_descriptor/mod.rs:4680](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4680) and allocates through `source_nat_decision_for_flow` at `:4745`, before the cited install at `:4787`. Under the literal fold, provenance skips the install but leaves an unowned allocation.

   Pool allocation creates a non-expiring `live_by_flow` record at [nat/source.rs:1548](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1548); allocator GC explicitly never touches it at [allocator.rs:2134](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:2134). Repeating across flows exhausts the pool/tracked-flow cap. Treating the skipped install as an install failure is unsafe too: allocation is idempotent at [allocator.rs:1035](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1035), while rollback removes the existing mapping at `:1399`.

   Provenance must branch before all seed-only NAT/NPT preparation, metadata, counters, install, rollback, and publication. Define distinct `ExistingResolved`, `SeedInstalled`, and `SeedRefused` outcomes; `ExistingResolved` must preserve the resolver decision and allocator state exactly.

2. **BLOCKER — the interim hold has no typed backing-family identity, and `Some(resolved)` does not imply a live entry.**

   `PendingNeighPacket` carries only the query tuple and decision at [types/mod.rs:77](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/types/mod.rs:77). Forward-wire lookup can return a different canonical key at [shared_ops.rs:614](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:614), but the outer path discards `ResolvedFlowSessionDecision.key` at [poll_descriptor/mod.rs:883](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:883). Site-2b REFUSE likewise installs no reverse entry while returning the reverse query key at [session_glue/mod.rs:1330](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1330); the actual entry to retain is the forward match.

   Worse, `keep_transient` calls [purge_translated_synced_hit](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:167), deleting local/shared state and releasing NAT, after which resolve still returns `Some` at [session_glue/mod.rs:1254](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1254). A subsequent MissingNeighbor therefore has nothing to hold; fresh retry misses and drops.

   Finally, holding only a reverse entry does not preserve the forward NAT owner. If both halves are idle, `companion_keeps_alive` rejects the stale reverse at [expire.rs:468](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:468), the forward expires, and global NAT/BPF teardown runs while the reverse packet remains pending.

   The resolve outcome must explicitly distinguish `LocalFamily{forward,matched}`, `ResolvedWithoutLocalBacking`, and genuine miss, and the pending hold must cover the canonical forward/NAT owner plus its companion.

3. **BLOCKER — a successfully delivered `MissingNeighborSeed` never becomes an authoritative session and has incomplete cleanup.**

   A genuine cold-neighbor miss installs and process-publishes a transient seed at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787), including shared state at `:4823` and a DNAT alias at `:4879`. Fresh retry sees an ordinary HIT, but only `SyncImport`/`SharedMaterialize` are promotable at [entry.rs:252](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:252); no successful-delivery path retags the seed.

   A later accepted close marks it, yet expiry suppresses its Close delta at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342). Worker GC releases NAT and BPF state, while shared and DNAT cleanup exists only in the absent Close-delta drain at [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406). The stale shared seed can later be materialized with a released or reassigned translation. This is both an accepted-close zero-producer trace and an ordinary-expiry stale-NAT trace.

   A committed retry needs an idempotent in-place `MissingNeighborSeed → ForwardFlow` transition with correct session-limit, Open, shared, and replication accounting. Timeout/uncommitted expiry must instead remove all shared/DNAT aliases.

4. **BLOCKER — site 2b erases the Local-versus-Shared provenance required by its trust rule.**

   `lookup_forward_nat_across_scopes` returns the same `ForwardSessionMatch` for both scopes at [shared_ops.rs:638](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:638), and the type carries only key/decision/metadata at [entry.rs:208](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:208). The plan nevertheless requires Local to validate and Shared to refuse.

   Concrete trace: an old shared reverse alias for `K/NAT1` survives while local replacement `K/NAT2` exists. The old reply tuple misses the local NAT index and returns the Shared `K/NAT1` match; a key-only anchor re-probe then finds local `K/NAT2`, validates against the wrong flow, and can mark that replacement while synthesizing the old decision. Shared publication inserts new aliases without removing aliases from the prior NAT decision at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897).

   Carry explicit match scope and require key/NAT/entry-identity agreement before reading or marking a local anchor. Shared matches must refuse even if the same canonical key is locally occupied.

5. **HIGH — the claimed pending timeout is per packet/binding, not a cumulative per-session bound.**

   Pending and negative-neighbor maps are per binding at [worker/mod.rs:140](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:140), while one worker `SessionTable` serves all its bindings at [loop_body/mod.rs:894](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:894). Each binding supplies a fresh `queued_ns`; rotating the same tuple/hop across three 2-second bindings, or five 800-ms bindings, can maintain a continuous union of pending holds despite each individual timeout and 3-second negative-cache interval.

   The session/NAT slot can therefore remain held indefinitely. At the admission cap, `can_admit` continues refusing otherwise-admissible flows at [install.rs:45](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:45). This is not a stronger primitive than the pre-existing ordinary non-close refresh pin, but it contradicts §5.7’s refused-close inertness and §5.2’s bounded-hold claim. Use a per-session first-hold deadline that cannot be reset across bindings.

6. **MEDIUM — wheel reinsertion and the actual release bound are unspecified.**

   Expiry pops the canonical wheel hint before deciding at [expire.rs:145](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:145). Implementing “skip” as a bare `continue` permanently strands the entry. It must reinsert without refreshing `last_seen_ns`, following [rebucket_alive_entry](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:424).

   Expiry also runs before pending retry/removal, so the finite bound is pending timeout plus up to one GC cadence, not exactly the pending timeout. Section 9 needs post-resolution and post-timeout eventual-reap/admission-recovery tests.

7. **nits — two stale claims remain.** [plan.md:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:48) still says Part B is “exactly four local rules,” despite the three new folds. The “owner performs global cleanup exactly once” wording at `plan.md:1000/:1173` and `phase2-brief.md:24` should be qualified as the authoritative cleanup event, because §10.6.1 explicitly admits unrefcounted sibling cleanup calls.

## Core-gate recheck

The gate remains sound in isolation: the anchor is exactly 40 bytes and canonical-forward-only; RFC-1982 membership and `<2^31` assertions are correct; receiver-window selection is correct; `open_valid && open_trusted` closes the default-interval case; imported trust remains absorbing; and the apply hook has no missing-forward fallback.

The arithmetic is exact:

- Floor: 393,219 values; `2^32 / 393,219 = 10,922.58`, about 10.923 seconds at 1,000 pkt/s.
- Cap: 655,355 values; `2^32 / 655,355 = 6,553.65`, about 6.554 seconds at 1,000 pkt/s.

No additional raw-flag installer or duplicate-producer trace was found. Finding 3 is a new zero-producer trace.

## Section 11 answers

1. **Terminal cut:** No—the local provenance, pending-family, and seed-lifecycle traces still allow pool exhaustion, stale/reassigned NAT use, or legitimate-close loss.
2. **Round-83 folds:** No overall—there is no second raw HIT installer and probation cleanup is sound, but B1 is not transaction-safe and B3 is neither identity-complete nor cumulatively bounded.
3. **Emission posture:** One zero-producer trace remains for committed `MissingNeighborSeed`; no new duplicate-producer trace was found.
4. **Arithmetic:** Yes—393,219 and 655,355 are the correct disjoint-union bounds and yield approximately 1/10,923 and 1/6,554.
5. **Re-scope:** The removed distributed protocol, #6522 fix, and Phase 2 still need not ship here; only the local corrections above must ship with this plan.

The sequence-window gate itself remains substantially converged, and r83-B2 plus the three minor folds are sound. The plan is not yet a safe terminal cut because provenance is represented as booleans or erased match types where the code needs transactional scope and session-family identity, and because `MissingNeighborSeed` lacks a committed/aborted lifecycle. These are all local state-machine corrections; none justifies restoring the removed distributed protocol.
