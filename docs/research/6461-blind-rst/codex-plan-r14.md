PLAN NO

All plan references below are to v9.2 at `245eac3a1`.

1. **BLOCKER — The required NAT reserve is not an incarnation fence and can destroy E2’s allocation.**

   V9.2 requires a canonical-incarnation match plus successful reserve before committing a detached E1 decision ([plan.md:828](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:828)). But E2 allocates NAT before publishing its shared family ([poll_descriptor/mod.rs:2255](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2255), [source.rs:1548](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1548), [poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560)). Therefore the allocator can already contain E2 while the canonical record still says E1.

   The reserve reconstructs only the original flow tuple, with no incarnation ([source.rs:880](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:880)). For the same flow key, `reserve_flow` either treats E2’s identical translation as an E1 success or removes E2 and frees its port before trying E1’s old translation ([allocator.rs:1671](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1671), [allocator.rs:1675](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1675)). Even a later reserve failure has already displaced E2. Address-only reserve likewise returns the same-flow allocation without verifying the requested translation ([allocator.rs:1748](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1748)).

   This leaves E2’s live NAT decision backed by a freed allocation, permitting mid-flow port reuse/collision. The fence needs an atomic, non-destructive `verify-or-acquire(expected_incarnation, exact_translation)` and allocator holder identity—the #6522 machinery cannot remain pending while this fence depends on it.

2. **BLOCKER — Stale-E1 cleanup remains unfenced before the Close delta.**

   The new rule covers mutations “driven by a Close delta” ([plan.md:854](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:854)), but expiration immediately calls `reap_expired_sessions` before packet processing and delta draining ([loop_body/mod.rs:811](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:811), [loop_body/mod.rs:825](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:825)). That function unconditionally releases NAT/NAT64 and tuple-deletes BPF/conntrack state ([loop_body/mod.rs:1490](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1490), [loop_body/mod.rs:1507](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1507)); `ExpiredSession` carries no incarnation ([entry.rs:337](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:337)).

   Thus worker B may publish E2 while worker A still holds E1; A’s later ordinary E1 reap deletes E2’s global BPF state and, for an identical translation, its allocator ownership. All workers share those map FDs ([bringup.rs:264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:264)).

   The delayed Close cleanup has a related atomicity gap: E2 currently publishes its unversioned BPF entry before the canonical E2 record ([poll_descriptor/mod.rs:2578](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2578), [poll_descriptor/mod.rs:2591](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2591)), while Close key-deletes external maps at [session_delta.rs:420](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:420). “Compare first” is insufficient unless publication and cleanup share one transaction spanning canonical state and every unversioned external map. Tuple-scoped queued-frame cancellation is safe because it only causes bounded packet loss.

3. **HIGH — Detached-clone coverage is still incomplete.**

   The normative rule rechecks only the canonical record ([plan.md:839](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:839)), while its rationale assumes the consumed alias was checked ([plan.md:849](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:849)). Different-forward E2 can displace E1’s NAT/wire alias while E1’s canonical remains unchanged. The canonical comparison then passes; static/interface NAT has no allocator conflict to catch it. Commit must compare both the exact source alias slot and its canonical family.

   Additional omitted consumers include:

   - The pre-materialization transient purge, where a detached `hit.shared_entry` drives unconditional shared/local/BPF deletion and NAT release ([session_glue/mod.rs:1165](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1165), [session_glue/mod.rs:1181](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1181), [promote.rs:167](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:167)). E1 lookup followed by E2 publication lets the E1 purge erase E2.

   - Activation prewarm publishes detached forwards and synthesized reverses into BPF/shared state before the proposed queued-command check ([shared_ops.rs:304](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:304), [shared_ops.rs:357](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:357), [shared_ops.rs:390](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:390)).

   - The activation republisher clones under lock and publishes after unlocking ([shared_ops.rs:448](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:448), [shared_ops.rs:462](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:462)).

   - Embedded-ICMP fallback/return resolution directly consumes detached shared decisions outside the two named NAT branches ([nat_match_v4.rs:78](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs:78), [nat_match_v6.rs:100](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs:100), [return_resolution.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/return_resolution.rs:20)).

4. **HIGH — Refused-close probation can indirectly stamp and shorten the family clock.**

   V9.2’s generic 30-second push stamps entries whose local `last_seen_ns` lies within the interval and carries their current timeout ([plan.md:770](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:770), [plan.md:787](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:787)). A refused-close materialization is supposed to install a fresh 20-second probation entry without stamping ([plan.md:1215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1215)), but construction necessarily sets `last_seen_ns=now` ([install.rs:345](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:345)).

   A materialization immediately before the batch therefore qualifies and indirectly stamps the family with a 20-second timeout. For a quiet live established sibling, that can reduce its shared-family horizon from roughly `K × 300s` to `K × 20s`, allowing aliases/DNAT state to disappear while the established worker entry remains valid. Repeated refused materializations also retain an obsolete permit through the generic push, contrary to “does not stamp.”

   Probation needs explicit state that excludes it from liveness pushes until a committed non-close packet converts it, and probation must never shorten the family’s authoritative timeout.

5. **MEDIUM — Absolute security wording remains.**

   The qualified statement at [plan.md:1705](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1705) is correct, but v9.2 still says “blind close remains inert,” “blind close never marks,” or “can never mark” at [plan.md:922](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:922), [plan.md:1362](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1362), [plan.md:1735](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1735), and [phase2-brief.md:14](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:14). These must say “refused/out-of-window/no-baseline close”; an in-window blind guess remains accepted by design.

6. **MEDIUM — The normative Part-B text and tests still conflict.**

   Full atomic reverse-synth forward marking is correctly specified at [plan.md:1142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1142) and [plan.md:1182](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1182), but old prose says only the reverse is marked ([plan.md:727](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:727)), and the old test still waits for a later hit to propagate ([plan.md:1515](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1515)).

   The additive schema list omits required `expires_after_ns` ([plan.md:1284](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1284)); the Close test still uses obsolete `(origin_node_id, session_id)` instead of `(origin_process_nonce, flow_incarnation_id)` ([plan.md:1535](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1535)); and Phase 2 remains simultaneously “required” and “not required” ([plan.md:242](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:242), [plan.md:1726](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1726)). The DNAT-family, SYN|RST, and poison-duration corrections themselves are resolved.

### Round-13 dispositions

R13-1 / B1, stale E1 Close erases E2 — **partially resolved**. The delayed delta is addressed; immediate reap and external-map atomicity are not.

R13-2 / B2, detached shared-decision coverage — **partially resolved**. Several consumers were added, but source-alias validation and multiple consumers remain missing.

R13-3, absolute “blind close never marks” wording — **partially resolved**.

R13-4, retain/reservation ownership fence — **not resolved**. The replacement reserve is destructive and incarnation-blind.

R13-5, unchecked asynchronous upsert/prewarm — **partially resolved**. Command consumption is covered, but pre-consumption publications are not.

R13-6, OPENING→ESTABLISHED timeout propagation — **resolved**, narrowly, for ordinary non-probation entries.

R13-7, refused-close stale-permit renewal — **not resolved**. Probation bounds the local entry but can still feed the generic family push.

R13-8, reverse-synth producer/full-mark semantics — **partially resolved**. Normative mechanics are fixed; old prose and tests contradict them.

R13-9, Part-B residual/schema/test consistency — **partially resolved**. DNAT, SYN|RST, and poison bounds landed; the remaining contract conflicts above did not.

Part A remains converged: I found no surviving one-packet-anytime blind mark or direct HA Close-propagation path through the sequence gate, and the acceptance-window probability is the honest claim. Part B does not yet converge: its reserve can evict E2, stale immediate cleanup and detached purges can key-delete E2, and probation can drive a live family onto the 20-second horizon. Those are concrete session-state loss and SNAT-reuse paths, so v9.2 cannot be signed off until the allocator, publication/cleanup transaction, complete clone-consumer fence, and probation push exclusion are specified together.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
