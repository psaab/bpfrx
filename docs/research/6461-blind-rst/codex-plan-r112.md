# Codex hostile plan-review — round 112 (v10.27.2)

Reviewer: Codex (fresh thread, job task-ms9g587p-wc370l, 2026-07-31). Verdict: PLAN NO (1B/1H/2M). The round's real catch (r112-1): OverdueSkipped cannot protect an overdue probation entry reached through an ordinary LOCAL hit (no shared_entry -> no materialization -> MaterializeReport::NONE -> the clear/restamp fires) — folded as the commit hook's direct matched-entry overdue test. Also: the buffered SYN-ACK promote had no realizable mechanism (the next packet is never is_syn_ack) — folded as the admission-point promote (the pending-queue enqueue is the commit-to-deliver point). The field declaration/initialization/consumer replacement/compositions/invalidation lifecycle 'otherwise check out'.

## Verbatim review

PLAN NO 1. **BLOCKER — `OverdueSkipped` cannot protect an overdue probation entry reached thr...

[2026-07-31T21:33:28.985Z] Assistant message
PLAN NO

1. **BLOCKER — `OverdueSkipped` cannot protect an overdue probation entry reached through an ordinary local hit.** After probation K is installed, a later canonical packet finds K locally before consulting shared state ([shared_ops.rs:594](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:594)). With no `shared_entry`, `materialize_shared_session_hit` performs no materialization ([session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092)), so the dispatch carries `MaterializeReport::NONE` (`plan.md:1780-1787`). If K crossed D before delayed GC, a committed non-close therefore passes `effective_transition != Some(OverdueSkipped)` and clears/restamps K to the ordinary timeout (`plan.md:1398-1408`, `plan.md:1838-1841), contradicting the explicit never-refresh guarantee at `plan.md:1356-1384`.

   This is reachable because expiry is strict and periodic ([expire.rs:130](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:130)). The commit hook needs a direct matched-entry test such as `probation && last_seen_ns.saturating_add(expires_after_ns) <= now_ns`, or a local-hit overdue outcome. Add a phase-shifted direct-local-hit regression.

2. **HIGH — The pending-neighbor establishment-promotion claim has no realizable mechanism.** The plan moves establishment promotion out of lookup and restricts it to a strong, non-closing reverse SYN-ACK (`plan.md:931-942`). MissingNeighbor is explicitly no-learn, and retry carries no `SessionTable` (`plan.md:607-610`, `plan.md:634-650`; [neighbor_dispatch.rs:272](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs:272)). After that buffered SYN-ACK is delivered, the next normal ACK/data packet is not `is_syn_ack`, so it cannot perform the only specified establishment promotion ([lookup.rs:129](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:129)). The forward half can remain OPENING on the short timeout ([session/mod.rs:2135](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:2135)).

   That contradicts `plan.md:647-660` and `plan.md:2611-2618`. Promoting an arbitrary subsequent ACK would reintroduce the #4109 half-open pin; preserving correctness requires a deferred validated-promotion token or promotion at a safe SYN-ACK admission point.

3. **MEDIUM — The stored raw/effective transition pair lacks one total invariant.** The legal product constrains raw `(validation, transition)`, while authority consumers trust the independently stored optional effective value (`plan.md:1741-1751`, `plan.md:1788-1819`). The document should normatively define and test:

   `site=None → effective=None`; legal Site2c `T → Some(T)`; invalid Site2c → `Some(OverdueSkipped)`.

   It should also exclude `Some(TransitionResult::None)` and site-qualify the refusal promotion gate. Otherwise malformed `site=None, validation=Refused` can violate the promised master fallback before the current promotion path mutates/publishes state ([promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86)).

4. **MEDIUM — Broad anchor statements still contradict the authority gates.** Sections 5.2 and 9 say every committed non-close/committed packet updates the anchor (`plan.md:812-815`, `plan.md:2425-2430`), while the SSOT suppresses the anchor commit for both `OverdueSkipped` and `UpsertRefused` (`plan.md:1727-1734`, `plan.md:1829-1847`). `UpsertRefused` is reachable when the synced upsert encounters a non-peer predecessor ([install.rs:310](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:310)).

The field declaration, initialization, raw-consumer replacement, both MissingNeighbor clauses, and S2/invalidation lifecycle otherwise check out.

Round-111 dispositions: r111-1 RESOLVED; r111-2 UNRESOLVED.