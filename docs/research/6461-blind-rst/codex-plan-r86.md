PLAN NO

Reviewed `plan.md` v10.3.0 at `59e84ae2454a9b523df21be591d18481381d6593`, read-only. No files were edited.

## Fold dispositions

- **r85-1 — PARTIALLY RESOLVED.** The resolver-return partition is now exhaustive. Direct local/shared/forward-wire hits return through [session_glue/mod.rs:1157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1157); the only path deliberately destroying all backing is `keep_transient` at [session_glue/mod.rs:1178](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1178). The secondary forward-NAT branch returns `None` only at [session_glue/mod.rs:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1264); otherwise a local or shared forward record remains even when reverse construction refuses. Thus site-2b Shared REFUSE is correctly buffered using the shared forward decision. The plan’s “live local” wording should say “live local or shared resolve-time backing.” However, the purged-backing miss transaction itself remains unsafe—finding 1.

- **r85-2 — PARTIALLY RESOLVED.** The original arithmetic and stream-order defect is fixed on paper: flip-time increment balances the sole removal decrement at [session/mod.rs:1819](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1819); flip→demote is count-neutral, and re-import performs a decrement/re-increment replacement. Idempotent origin transition makes Open exactly once, and pushing Open before an accepted-close mark gives FIFO Open→Close. A cache hit is not normally the first flip: the seed install at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787) does not populate the cache; the later slow commit flips before cache insertion at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). The cache hook is defensive. Admission, metadata, and publication are still incomplete—findings 2, 3, and 6.

- **r85-3 — PARTIALLY RESOLVED.** Carrying the live entry’s ID through shared state and `ExpiredSession` protects ordinary same-process local generations: worker bits distinguish local cross-worker IDs. It does not protect cross-node collisions, zero-ID imports, or compare/delete races—finding 4.

- **r85-4 — PARTIALLY RESOLVED.** The new reverse-hit check closes the reported stale `R1/NAT1 → K/NAT2` trace. Full reciprocal key plus reversed `NatDecision` agreement is sufficient for NAT64, hairpin, and non-bijective transforms; `NatDecision::reverse` preserves NAT64/NPTv6 at [nat/mod.rs:105](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105), while [reverse_session_key](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) handles address-family/protocol conversion. Exact tuple+NAT reuse is packet-indistinguishable and needs no token. No separate site-2, fabric-return, tunnel, forward-wire, or cache close bypass was found. Forward-hit propagation still lacks target reciprocity—finding 5.

- **r84-7 residual nit — RESOLVED.** The inaccurate “global cleanup exactly once” claim is gone. [plan.md:1104](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1104), [plan.md:1312](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1312), and [phase2-brief.md:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:20) now correctly call the owner reap the family’s authoritative cleanup while acknowledging #6522 sibling calls.

## New findings

1. **BLOCKER — `ResolvedWithoutLocalBacking` retains the released SNAT decision during its “genuine miss” transaction.**

   Purge releases old translation `P1` at [promote.rs:181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181), but resolution still returns the stored decision containing `P1` at [session_glue/mod.rs:1194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1194). Site 9 starts with that stale object at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662). If the allocator returns `P2` at [poll_descriptor/mod.rs:4745](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4745), the merge at `:4757` keeps `P1` because [NatDecision::merge](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:123) is left-biased.

   Concrete trace: after purge frees `P1`, another worker claims it; this flow receives `P2`. The seed and aliases are nevertheless installed with `P1`, while `live_by_flow` owns `P2`. Reverse traffic can collide with the new owner of `P1`; later cleanup supplies `P1`, and [release_flow](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318) refuses to release recorded `P2`, leaking it. A current configuration that no longer matches SNAT is an even simpler variant: a default recomputation cannot clear old `P1`.

   The outcome needs a clean pre-SNAT miss baseline, not the purged session decision. Tests must cover `P2 != P1` and current-rule-no-longer-matches, not only deterministic persistent reacquisition.

2. **BLOCKER — flip-time increment balances accounting but bypasses the configured per-IP admission limit.**

   The cap is checked only on session miss at [session_admission.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:29), while seeds are uncounted at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225). `session_limit_inc` merely increments; it performs no limit check at [session/mod.rs:909](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:909).

   With source cap 1 and a cold neighbor, flows A and B both see count 0 and install seeds. After resolution, A commits and flips to count 1; B is now a session hit, never re-enters admission, and flips to count 2. Both ordinary sessions forward under a configured cap of 1. Count/reserve the slot at seed admission, with seed removal balancing it; delaying only Open emission until confirmation is safe.

3. **BLOCKER — flip publication can overwrite a newer generation or undo HA demotion.**

   Current shared publication unconditionally replaces the canonical and auxiliary records at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897). The plan requires the flip to “adopt” the install publication but gives no identity/origin-conditional transition.

   Concrete trace: worker A retains seed S; worker B publishes newer same-key generation N; A subsequently commits S and the flip republishes S, replacing N’s canonical record and restoring stale NAT/origin/identity. Cleanup-time checking cannot protect this write. The HA variant is equally concrete: the coordinator publishes the new state, queues worker demotion, then demotes shared records at [ha/state.rs:72](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:72). A worker already past its command check at [loop_body/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:682) can flip under its old snapshot and overwrite the demoted shared origin; its later demote handler updates only local/BPF state at [demote_owner_rgs.rs:49](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs:49).

   The flip must compare-and-transition matching `session_id`, NAT, and expected `MissingNeighborSeed` origin before arming publication/Open, or treat mismatch as a stale local seed.

4. **BLOCKER — `session_id` is neither collision-free nor atomically tied to alias deletion.**

   Three concrete traces survive:

   - Nonzero IDs collide across HA nodes. Allocation namespaces only by worker and counter at [session/mod.rs:766](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:766), while peer import adopts the remote ID and explicitly documents same-worker collisions at [install.rs:324](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:324). Old local seed S1 and newer imported S2 can therefore both have `id=X`; S1’s equality guard passes and deletes S2’s aliases.

   - Zero fallback is newly unsafe and occurs between same-version peers. Bulk export hardcodes `session_id: 0` at [ha/export.rs:143](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/export.rs:143). Import publishes that zero-ID state before worker replacement at [ha/session_import.rs:115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:115). An older seed expiry then takes the proposed fallback and key-deletes the newer import. This is not master parity: master excludes seeds from Close at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342) and currently performs no shared/DNAT removal during seed reap.

   - Check and delete have no linearization point. Shared publishing and removal use separate key-based operations at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897) and [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960). The BPF DNAT value contains no identity at [xpf_maps.h:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_maps.h:508), and deletion is key-only at [checksum.rs:246](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/checksum.rs:246). S1 can pass its check, S2 can publish, and S1 can then delete S2.

   A process-local alias-owner token plus serialized conditional publication/deletion is sufficient; no distributed protocol is required. Zero must mean “no new seed-cleanup authority,” not unconditional fallback.

5. **BLOCKER — forward-hit propagation still marks an unrelated entry.**

   The plan says forward hits need no target check and propagation remains unchanged at [plan.md:959](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:959), but current propagation derives a key at [lookup.rs:204](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:204) and blindly mutates whatever occupies it at [session/mod.rs:1241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241).

   Concrete trace: authoritative forward A occupies `K`; unrelated authoritative forward B occupies `R = reverse_session_key(K, NAT_A)` and has no companion—a supported state at [expire.rs:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:508). An accepted close on A validates A, then propagation marks B without checking `is_reverse` or reciprocity. B receives the 2-second/30-second timeout, emits its own authoritative Close at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), releases B’s NAT, and fans out deletion at [session_delta.rs:420](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:420).

   Forward propagation must require a reverse entry whose key and reversed NAT reciprocate A; mismatch skips only the companion mark.

6. **HIGH — the flipped seed retains transient stub policy metadata and the wrong idle timeout.**

   MissingNeighbor already evaluates policy, but [build_missing_neighbor_session_metadata](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:606) hardcodes logging false, policy 0, counter 0, and `inactivity_timeout_ns=None`. Ordinary ForwardFlow metadata records the matched application timeout and policy at [poll_descriptor/mod.rs:2407](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2407). Install and refresh derive expiry from the stored timeout at [install.rs:164](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:164) and [lookup.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:150).

   A policy-permitted mid-stream TCP flow with application timeout 3600 seconds can seed, flip, and still reap at the 300-second global timeout. Its SNAT allocation is released, and the next packet can recreate with another port. The new Open also replicates timeout 0/policy 0 and suppresses configured session-init logging. Preserve the admitted metadata at seed install—or replace it and recompute expiry atomically at flip.

7. **LOW — §5.8 contradicts the final-admission anchor rule.**

   Section 5.8 says `account_packet` gains the sequence apply at [plan.md:1148](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1148), while §5.2 correctly requires a separate final-admission hook. The existing slow-path accounting call at [poll_descriptor/mod.rs:3497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3497) precedes build/output-filter/CoS failures. A literal §5.8 implementation would let a dropped packet move the anchor. Clarify that counters stay in `account_packet`, while anchor mutation uses the distinct post-admission hook.

## Section 11 answers

1. **Terminal cut:** Yes—actual shipped-scope harm remains: stale/unowned SNAT reseeding, live-alias deletion, wrong-session propagation, cap bypass, and wrong idle-timeout replication.

2. **Pending-neighbor retreat:** The retreat remains accepted; no ISSUE-class retry trace was found, and finding 1 is a resolve-time NAT transaction defect.

3. **Round-85 fold:** (a) the provenance set is exhaustive, but the purged decision is not rebased into a true miss; (b) inc/dec and Open→Close ordering balance, but admission/metadata/publication are incomplete; (c) stale cleanup survives collisions, zero IDs, and TOCTOU; (d) reverse-hit key+NAT reciprocity is sufficient, but forward propagation bypasses it.

4. **Emission posture:** The idempotent seed flip itself has a coherent Open→Close producer, but forward propagation still creates a wrong extra Close producer for B.

5. **Attack arithmetic:** Confirmed—393,219 values are approximately `1/10,923`; 655,355 are approximately `1/6,554`.

6. **Re-scope:** Yes—local NAT rebasing, seed admission/metadata preservation, conditional flip publication, collision-free local alias ownership with linearized deletion, and propagation-target reciprocity must ship; none requires the removed protocol.

The pending-neighbor retreat and removal of the distributed protocol remain correct. The plan is still not safe to implement because its new local fold machinery can install an unowned translation, admit beyond the configured cap, overwrite or delete newer alias state, and mark an unrelated forward session for early reap. These are concrete local correctness and availability traces in the shipped scope, so v10.3.0 remains PLAN NO.
tokens used
469,380
PLAN NO

Reviewed `plan.md` v10.3.0 at `59e84ae2454a9b523df21be591d18481381d6593`, read-only. No files were edited.

## Fold dispositions

- **r85-1 — PARTIALLY RESOLVED.** The resolver-return partition is now exhaustive. Direct local/shared/forward-wire hits return through [session_glue/mod.rs:1157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1157); the only path deliberately destroying all backing is `keep_transient` at [session_glue/mod.rs:1178](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1178). The secondary forward-NAT branch returns `None` only at [session_glue/mod.rs:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1264); otherwise a local or shared forward record remains even when reverse construction refuses. Thus site-2b Shared REFUSE is correctly buffered using the shared forward decision. The plan’s “live local” wording should say “live local or shared resolve-time backing.” However, the purged-backing miss transaction itself remains unsafe—finding 1.

- **r85-2 — PARTIALLY RESOLVED.** The original arithmetic and stream-order defect is fixed on paper: flip-time increment balances the sole removal decrement at [session/mod.rs:1819](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1819); flip→demote is count-neutral, and re-import performs a decrement/re-increment replacement. Idempotent origin transition makes Open exactly once, and pushing Open before an accepted-close mark gives FIFO Open→Close. A cache hit is not normally the first flip: the seed install at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787) does not populate the cache; the later slow commit flips before cache insertion at [poll_descriptor/mod.rs:3900](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900). The cache hook is defensive. Admission, metadata, and publication are still incomplete—findings 2, 3, and 6.

- **r85-3 — PARTIALLY RESOLVED.** Carrying the live entry’s ID through shared state and `ExpiredSession` protects ordinary same-process local generations: worker bits distinguish local cross-worker IDs. It does not protect cross-node collisions, zero-ID imports, or compare/delete races—finding 4.

- **r85-4 — PARTIALLY RESOLVED.** The new reverse-hit check closes the reported stale `R1/NAT1 → K/NAT2` trace. Full reciprocal key plus reversed `NatDecision` agreement is sufficient for NAT64, hairpin, and non-bijective transforms; `NatDecision::reverse` preserves NAT64/NPTv6 at [nat/mod.rs:105](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:105), while [reverse_session_key](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:173) handles address-family/protocol conversion. Exact tuple+NAT reuse is packet-indistinguishable and needs no token. No separate site-2, fabric-return, tunnel, forward-wire, or cache close bypass was found. Forward-hit propagation still lacks target reciprocity—finding 5.

- **r84-7 residual nit — RESOLVED.** The inaccurate “global cleanup exactly once” claim is gone. [plan.md:1104](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1104), [plan.md:1312](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1312), and [phase2-brief.md:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:20) now correctly call the owner reap the family’s authoritative cleanup while acknowledging #6522 sibling calls.

## New findings

1. **BLOCKER — `ResolvedWithoutLocalBacking` retains the released SNAT decision during its “genuine miss” transaction.**

   Purge releases old translation `P1` at [promote.rs:181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181), but resolution still returns the stored decision containing `P1` at [session_glue/mod.rs:1194](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1194). Site 9 starts with that stale object at [poll_descriptor/mod.rs:4662](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662). If the allocator returns `P2` at [poll_descriptor/mod.rs:4745](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4745), the merge at `:4757` keeps `P1` because [NatDecision::merge](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:123) is left-biased.

   Concrete trace: after purge frees `P1`, another worker claims it; this flow receives `P2`. The seed and aliases are nevertheless installed with `P1`, while `live_by_flow` owns `P2`. Reverse traffic can collide with the new owner of `P1`; later cleanup supplies `P1`, and [release_flow](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318) refuses to release recorded `P2`, leaking it. A current configuration that no longer matches SNAT is an even simpler variant: a default recomputation cannot clear old `P1`.

   The outcome needs a clean pre-SNAT miss baseline, not the purged session decision. Tests must cover `P2 != P1` and current-rule-no-longer-matches, not only deterministic persistent reacquisition.

2. **BLOCKER — flip-time increment balances accounting but bypasses the configured per-IP admission limit.**

   The cap is checked only on session miss at [session_admission.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:29), while seeds are uncounted at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225). `session_limit_inc` merely increments; it performs no limit check at [session/mod.rs:909](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:909).

   With source cap 1 and a cold neighbor, flows A and B both see count 0 and install seeds. After resolution, A commits and flips to count 1; B is now a session hit, never re-enters admission, and flips to count 2. Both ordinary sessions forward under a configured cap of 1. Count/reserve the slot at seed admission, with seed removal balancing it; delaying only Open emission until confirmation is safe.

3. **BLOCKER — flip publication can overwrite a newer generation or undo HA demotion.**

   Current shared publication unconditionally replaces the canonical and auxiliary records at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897). The plan requires the flip to “adopt” the install publication but gives no identity/origin-conditional transition.

   Concrete trace: worker A retains seed S; worker B publishes newer same-key generation N; A subsequently commits S and the flip republishes S, replacing N’s canonical record and restoring stale NAT/origin/identity. Cleanup-time checking cannot protect this write. The HA variant is equally concrete: the coordinator publishes the new state, queues worker demotion, then demotes shared records at [ha/state.rs:72](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:72). A worker already past its command check at [loop_body/mod.rs:682](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:682) can flip under its old snapshot and overwrite the demoted shared origin; its later demote handler updates only local/BPF state at [demote_owner_rgs.rs:49](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/demote_owner_rgs.rs:49).

   The flip must compare-and-transition matching `session_id`, NAT, and expected `MissingNeighborSeed` origin before arming publication/Open, or treat mismatch as a stale local seed.

4. **BLOCKER — `session_id` is neither collision-free nor atomically tied to alias deletion.**

   Three concrete traces survive:

   - Nonzero IDs collide across HA nodes. Allocation namespaces only by worker and counter at [session/mod.rs:766](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:766), while peer import adopts the remote ID and explicitly documents same-worker collisions at [install.rs:324](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:324). Old local seed S1 and newer imported S2 can therefore both have `id=X`; S1’s equality guard passes and deletes S2’s aliases.

   - Zero fallback is newly unsafe and occurs between same-version peers. Bulk export hardcodes `session_id: 0` at [ha/export.rs:143](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/export.rs:143). Import publishes that zero-ID state before worker replacement at [ha/session_import.rs:115](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:115). An older seed expiry then takes the proposed fallback and key-deletes the newer import. This is not master parity: master excludes seeds from Close at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342) and currently performs no shared/DNAT removal during seed reap.

   - Check and delete have no linearization point. Shared publishing and removal use separate key-based operations at [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897) and [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960). The BPF DNAT value contains no identity at [xpf_maps.h:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_maps.h:508), and deletion is key-only at [checksum.rs:246](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/checksum.rs:246). S1 can pass its check, S2 can publish, and S1 can then delete S2.

   A process-local alias-owner token plus serialized conditional publication/deletion is sufficient; no distributed protocol is required. Zero must mean “no new seed-cleanup authority,” not unconditional fallback.

5. **BLOCKER — forward-hit propagation still marks an unrelated entry.**

   The plan says forward hits need no target check and propagation remains unchanged at [plan.md:959](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:959), but current propagation derives a key at [lookup.rs:204](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:204) and blindly mutates whatever occupies it at [session/mod.rs:1241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241).

   Concrete trace: authoritative forward A occupies `K`; unrelated authoritative forward B occupies `R = reverse_session_key(K, NAT_A)` and has no companion—a supported state at [expire.rs:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:508). An accepted close on A validates A, then propagation marks B without checking `is_reverse` or reciprocity. B receives the 2-second/30-second timeout, emits its own authoritative Close at [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), releases B’s NAT, and fans out deletion at [session_delta.rs:420](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:420).

   Forward propagation must require a reverse entry whose key and reversed NAT reciprocate A; mismatch skips only the companion mark.

6. **HIGH — the flipped seed retains transient stub policy metadata and the wrong idle timeout.**

   MissingNeighbor already evaluates policy, but [build_missing_neighbor_session_metadata](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:606) hardcodes logging false, policy 0, counter 0, and `inactivity_timeout_ns=None`. Ordinary ForwardFlow metadata records the matched application timeout and policy at [poll_descriptor/mod.rs:2407](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2407). Install and refresh derive expiry from the stored timeout at [install.rs:164](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:164) and [lookup.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:150).

   A policy-permitted mid-stream TCP flow with application timeout 3600 seconds can seed, flip, and still reap at the 300-second global timeout. Its SNAT allocation is released, and the next packet can recreate with another port. The new Open also replicates timeout 0/policy 0 and suppresses configured session-init logging. Preserve the admitted metadata at seed install—or replace it and recompute expiry atomically at flip.

7. **LOW — §5.8 contradicts the final-admission anchor rule.**

   Section 5.8 says `account_packet` gains the sequence apply at [plan.md:1148](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1148), while §5.2 correctly requires a separate final-admission hook. The existing slow-path accounting call at [poll_descriptor/mod.rs:3497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3497) precedes build/output-filter/CoS failures. A literal §5.8 implementation would let a dropped packet move the anchor. Clarify that counters stay in `account_packet`, while anchor mutation uses the distinct post-admission hook.

## Section 11 answers

1. **Terminal cut:** Yes—actual shipped-scope harm remains: stale/unowned SNAT reseeding, live-alias deletion, wrong-session propagation, cap bypass, and wrong idle-timeout replication.

2. **Pending-neighbor retreat:** The retreat remains accepted; no ISSUE-class retry trace was found, and finding 1 is a resolve-time NAT transaction defect.

3. **Round-85 fold:** (a) the provenance set is exhaustive, but the purged decision is not rebased into a true miss; (b) inc/dec and Open→Close ordering balance, but admission/metadata/publication are incomplete; (c) stale cleanup survives collisions, zero IDs, and TOCTOU; (d) reverse-hit key+NAT reciprocity is sufficient, but forward propagation bypasses it.

4. **Emission posture:** The idempotent seed flip itself has a coherent Open→Close producer, but forward propagation still creates a wrong extra Close producer for B.

5. **Attack arithmetic:** Confirmed—393,219 values are approximately `1/10,923`; 655,355 are approximately `1/6,554`.

6. **Re-scope:** Yes—local NAT rebasing, seed admission/metadata preservation, conditional flip publication, collision-free local alias ownership with linearized deletion, and propagation-target reciprocity must ship; none requires the removed protocol.

The pending-neighbor retreat and removal of the distributed protocol remain correct. The plan is still not safe to implement because its new local fold machinery can install an unowned translation, admit beyond the configured cap, overwrite or delete newer alias state, and mark an unrelated forward session for early reap. These are concrete local correctness and availability traces in the shipped scope, so v10.3.0 remains PLAN NO.
