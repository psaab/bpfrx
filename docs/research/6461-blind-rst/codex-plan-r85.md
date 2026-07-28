PLAN NO

Reviewed `plan.md` v10.2.0 read-only at `05d7af30f5a58dfc2468229334b4f0133a134b27`. No files were edited.

## Round-84 dispositions

1. **r84-1 — PARTIALLY RESOLVED.** For a genuinely live `ExistingResolved` entry, branching before the seed transaction kills the unowned-allocation trace. The MissingNeighbor telemetry, policy, negative-cache, resolver, and probe work at [poll_descriptor/mod.rs:4034](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4034) and [poll_descriptor/mod.rs:4396](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4396) is necessary master behavior; “no counters” should mean seed-transaction counters only. However, the three outcomes cannot represent a resolved result whose backing was purged—new finding 1.

2. **r84-2 — PARTIALLY RESOLVED.** I accept the retreat: no hold or re-resolution is required. The hold-family defect disappears, but its core fact—`Some(resolved)` does not prove live local backing—remains load-bearing at site 9.

3. **r84-3 — PARTIALLY RESOLVED.** The origin flip would restore the local Close producer: `ForwardFlow` passes [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), and the unchanged key/decision reaches normal cleanup. But the proposed flip is not accounting-complete, emits Close without a prior Open, and the alias owner guard is not implementable as specified—new findings 2 and 3.

4. **r84-4 — PARTIALLY RESOLVED.** The literal site-2b trace is closed: Shared always refuses, while Local requires canonical-key and NAT agreement. The broader wrong-generation invariant still fails on ordinary reverse hits in §5.5—new finding 4.

5. **r84-5 — RESOLVED BY RETRACTION.** No hold remains, so no cumulative per-session hold bound is needed.

6. **r84-6 — RESOLVED BY RETRACTION.** No expiry skip remains, so no wheel reinsertion or hold-release cadence must be specified.

7. **r84-7 — PARTIALLY RESOLVED, nit only.** “Exactly four” was corrected. The inaccurate “global cleanup exactly once” wording remains at [plan.md:1053](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1053), [plan.md:1474](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1474), and [phase2-brief.md:24](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:24).

## New findings

1. **BLOCKER — Site 9’s three outcomes are not exhaustive after transient purge.**

   A translated peer-synced hit can set `keep_transient`, delete its local/shared state, and release its NAT reservation at [session_glue/mod.rs:1178](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1178) and [promote.rs:181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181), yet resolution still returns `Some(created=false)` at [session_glue/mod.rs:1254](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1254).

   If current routing now gives `MissingNeighbor` through a different locally active RG, this result is neither live `ExistingResolved` nor a genuine miss. Classifying it as `ExistingResolved` skips the seed transaction; retry transmits, but a legitimate reply has no reverse-session backing. Master runs the transaction at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787). Persistent allocation can deterministically reacquire the released tuple at [allocator.rs:1265](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1265), in which case master restores reverse lookup and the proposed skip does not.

   Site 9 needs a current `ResolvedWithoutLocalBacking` outcome, handled by safe reseeding or refusal. This is resolve-time provenance, not a retry hold.

2. **BLOCKER — The seed flip crosses accounting and emission classes without a transition.**

   Installation explicitly defines a forward `MissingNeighborSeed` as uncounted; it therefore performs neither `session_limit_inc` nor an Open delta at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225) and [install.rs:234](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:234). Site 9’s [session_creates increment](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4889) is worker telemetry, not an Open.

   After the proposed bare flip, removal sees `ForwardFlow` and decrements at [session/mod.rs:1819](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1819). Concrete trace: counted flow A leaves count 1; uncounted seed B flips; B expires first and decrements the count to 0 while A remains, admitting traffic beyond the configured per-IP cap. Existing demotion code already performs this exact class-transition increment at [install.rs:558](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:558).

   The absent Open also means no correctness-critical HA delta is delivered through [session_delta.rs:282](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:282). On failover, the confirmed flow can lose reverse translation or be recreated with a different translated source. The flip must atomically balance the count class and establish a coherent exactly-once Open/replication lifecycle.

3. **BLOCKER — The promised seed-alias owner guard has no usable generation identity.**

   `ExpiredSession` carries no generation or session ID at [entry.rs:337](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:337). Local shared seed publication explicitly writes `generation=0` and `session_id=0` at [poll_descriptor/mod.rs:4811](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4811). Shared deletion is unconditional by key at [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960); DNAT deletion is likewise key-only at [checksum.rs:246](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/checksum.rs:246). A flipped seed’s normal Close drain is also unguarded at [session_delta.rs:420](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:420).

   An old seed can expire and release its tuple; another worker can then reuse and publish the same key/NAT for a newer generation before old cleanup completes. Key/NAT comparison cannot distinguish them, so the old cleanup removes the newer flow’s shared/DNAT aliases and breaks reverse traffic. The plan needs a stable identity carried through the live entry, shared aliases, `ExpiredSession`, and cleanup, with ordering that makes the comparison effective.

4. **BLOCKER — §5.5 ordinary reverse hits can mark a replacement forward generation.**

   Forward and reverse halves can be separated: HA import creates both, while deliberate stale-sync expiry or [purge_translated_synced_hit](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181) can remove only the old forward `K/NAT1`. A new forward `K/NAT2` can then be installed while stale reverse `R1/NAT1` remains. A close direct-hits `R1` at [lookup.rs:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:48).

   Section 5.5 derives `K` and validates against whatever now occupies it, with no `R1↔K` family-generation agreement. On acceptance, existing propagation derives the companion by key and blindly sets its close/reset timeout at [session/mod.rs:1241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241). `K/NAT2` then emits an authoritative Close, and [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406) deletes shared/BPF state and fans out deletes. That is an unjustified timeout transition and standby-copy deletion caused by a packet on the old reply tuple.

   §5.5 needs family identity before anchor validation and propagation. Reciprocal key/NAT agreement closes the `NAT1≠NAT2` case; exact tuple/NAT reuse additionally requires a linked local generation token or an invariant that removes the orphan companion before replacement.

## Section 11 answers

1. **Terminal cut:** No; the four local blockers above leave reverse-state loss, count under-accounting, alias deletion, and wrong-generation timeout transitions.

2. **Pending-neighbor retreat:** The retreat stands. The generic stale-decision transmit window need not close here; finding 1 is a separate resolve-time provenance correction.

3. **Fold verification:** (a) true-live `ExistingResolved` is clean, but no-backing is unrepresented; (b) seed lifecycle is not accounting- or identity-safe; (c) site 2b closes Shared/key/NAT mismatch; (d) no second raw closing/reset installer was found.

4. **Emission posture:** The flip repairs the committed-seed Close zero-producer in isolation, and no duplicate Close producer was found; however, the seed has no Open producer, and finding 4 creates a wrong-generation Close producer.

5. **Arithmetic:** Yes—393,219 values ≈ 1/10,923 and 655,355 values ≈ 1/6,554.

6. **Re-scope:** #6522, general never-transmit-stale hardening, Phase 2, and the removed distributed protocol may remain deferred; only the four local corrections above must ship.

The retreat is correct and the removed protocol should not return. PLAN NO is driven solely by concrete local state-machine defects in the folded shipped scope: a purged resolver hit is treated as backed, a seed crosses accounting/HA-emission classes without a transaction, alias cleanup lacks generation identity, and an ordinary reverse hit can validate against and close a newer forward generation.
tokens used
645,712
PLAN NO

Reviewed `plan.md` v10.2.0 read-only at `05d7af30f5a58dfc2468229334b4f0133a134b27`. No files were edited.

## Round-84 dispositions

1. **r84-1 — PARTIALLY RESOLVED.** For a genuinely live `ExistingResolved` entry, branching before the seed transaction kills the unowned-allocation trace. The MissingNeighbor telemetry, policy, negative-cache, resolver, and probe work at [poll_descriptor/mod.rs:4034](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4034) and [poll_descriptor/mod.rs:4396](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4396) is necessary master behavior; “no counters” should mean seed-transaction counters only. However, the three outcomes cannot represent a resolved result whose backing was purged—new finding 1.

2. **r84-2 — PARTIALLY RESOLVED.** I accept the retreat: no hold or re-resolution is required. The hold-family defect disappears, but its core fact—`Some(resolved)` does not prove live local backing—remains load-bearing at site 9.

3. **r84-3 — PARTIALLY RESOLVED.** The origin flip would restore the local Close producer: `ForwardFlow` passes [expire.rs:342](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:342), and the unchanged key/decision reaches normal cleanup. But the proposed flip is not accounting-complete, emits Close without a prior Open, and the alias owner guard is not implementable as specified—new findings 2 and 3.

4. **r84-4 — PARTIALLY RESOLVED.** The literal site-2b trace is closed: Shared always refuses, while Local requires canonical-key and NAT agreement. The broader wrong-generation invariant still fails on ordinary reverse hits in §5.5—new finding 4.

5. **r84-5 — RESOLVED BY RETRACTION.** No hold remains, so no cumulative per-session hold bound is needed.

6. **r84-6 — RESOLVED BY RETRACTION.** No expiry skip remains, so no wheel reinsertion or hold-release cadence must be specified.

7. **r84-7 — PARTIALLY RESOLVED, nit only.** “Exactly four” was corrected. The inaccurate “global cleanup exactly once” wording remains at [plan.md:1053](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1053), [plan.md:1474](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1474), and [phase2-brief.md:24](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:24).

## New findings

1. **BLOCKER — Site 9’s three outcomes are not exhaustive after transient purge.**

   A translated peer-synced hit can set `keep_transient`, delete its local/shared state, and release its NAT reservation at [session_glue/mod.rs:1178](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1178) and [promote.rs:181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181), yet resolution still returns `Some(created=false)` at [session_glue/mod.rs:1254](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1254).

   If current routing now gives `MissingNeighbor` through a different locally active RG, this result is neither live `ExistingResolved` nor a genuine miss. Classifying it as `ExistingResolved` skips the seed transaction; retry transmits, but a legitimate reply has no reverse-session backing. Master runs the transaction at [poll_descriptor/mod.rs:4787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787). Persistent allocation can deterministically reacquire the released tuple at [allocator.rs:1265](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1265), in which case master restores reverse lookup and the proposed skip does not.

   Site 9 needs a current `ResolvedWithoutLocalBacking` outcome, handled by safe reseeding or refusal. This is resolve-time provenance, not a retry hold.

2. **BLOCKER — The seed flip crosses accounting and emission classes without a transition.**

   Installation explicitly defines a forward `MissingNeighborSeed` as uncounted; it therefore performs neither `session_limit_inc` nor an Open delta at [install.rs:225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:225) and [install.rs:234](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:234). Site 9’s [session_creates increment](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4889) is worker telemetry, not an Open.

   After the proposed bare flip, removal sees `ForwardFlow` and decrements at [session/mod.rs:1819](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1819). Concrete trace: counted flow A leaves count 1; uncounted seed B flips; B expires first and decrements the count to 0 while A remains, admitting traffic beyond the configured per-IP cap. Existing demotion code already performs this exact class-transition increment at [install.rs:558](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:558).

   The absent Open also means no correctness-critical HA delta is delivered through [session_delta.rs:282](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:282). On failover, the confirmed flow can lose reverse translation or be recreated with a different translated source. The flip must atomically balance the count class and establish a coherent exactly-once Open/replication lifecycle.

3. **BLOCKER — The promised seed-alias owner guard has no usable generation identity.**

   `ExpiredSession` carries no generation or session ID at [entry.rs:337](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:337). Local shared seed publication explicitly writes `generation=0` and `session_id=0` at [poll_descriptor/mod.rs:4811](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4811). Shared deletion is unconditional by key at [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960); DNAT deletion is likewise key-only at [checksum.rs:246](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/checksum.rs:246). A flipped seed’s normal Close drain is also unguarded at [session_delta.rs:420](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:420).

   An old seed can expire and release its tuple; another worker can then reuse and publish the same key/NAT for a newer generation before old cleanup completes. Key/NAT comparison cannot distinguish them, so the old cleanup removes the newer flow’s shared/DNAT aliases and breaks reverse traffic. The plan needs a stable identity carried through the live entry, shared aliases, `ExpiredSession`, and cleanup, with ordering that makes the comparison effective.

4. **BLOCKER — §5.5 ordinary reverse hits can mark a replacement forward generation.**

   Forward and reverse halves can be separated: HA import creates both, while deliberate stale-sync expiry or [purge_translated_synced_hit](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:181) can remove only the old forward `K/NAT1`. A new forward `K/NAT2` can then be installed while stale reverse `R1/NAT1` remains. A close direct-hits `R1` at [lookup.rs:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:48).

   Section 5.5 derives `K` and validates against whatever now occupies it, with no `R1↔K` family-generation agreement. On acceptance, existing propagation derives the companion by key and blindly sets its close/reset timeout at [session/mod.rs:1241](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1241). `K/NAT2` then emits an authoritative Close, and [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406) deletes shared/BPF state and fans out deletes. That is an unjustified timeout transition and standby-copy deletion caused by a packet on the old reply tuple.

   §5.5 needs family identity before anchor validation and propagation. Reciprocal key/NAT agreement closes the `NAT1≠NAT2` case; exact tuple/NAT reuse additionally requires a linked local generation token or an invariant that removes the orphan companion before replacement.

## Section 11 answers

1. **Terminal cut:** No; the four local blockers above leave reverse-state loss, count under-accounting, alias deletion, and wrong-generation timeout transitions.

2. **Pending-neighbor retreat:** The retreat stands. The generic stale-decision transmit window need not close here; finding 1 is a separate resolve-time provenance correction.

3. **Fold verification:** (a) true-live `ExistingResolved` is clean, but no-backing is unrepresented; (b) seed lifecycle is not accounting- or identity-safe; (c) site 2b closes Shared/key/NAT mismatch; (d) no second raw closing/reset installer was found.

4. **Emission posture:** The flip repairs the committed-seed Close zero-producer in isolation, and no duplicate Close producer was found; however, the seed has no Open producer, and finding 4 creates a wrong-generation Close producer.

5. **Arithmetic:** Yes—393,219 values ≈ 1/10,923 and 655,355 values ≈ 1/6,554.

6. **Re-scope:** #6522, general never-transmit-stale hardening, Phase 2, and the removed distributed protocol may remain deferred; only the four local corrections above must ship.

The retreat is correct and the removed protocol should not return. PLAN NO is driven solely by concrete local state-machine defects in the folded shipped scope: a purged resolver hit is treated as backed, a seed crosses accounting/HA-emission classes without a transaction, alias cleanup lacks generation identity, and an ordinary reverse hit can validate against and close a newer forward generation.
