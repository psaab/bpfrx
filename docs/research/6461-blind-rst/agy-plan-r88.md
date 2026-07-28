VERDICT: PLAN YES

---

### Q1 (Re-entry & Sole-Decision Rule): SOUND

**File:Line Evidence:**
- [plan.md:332](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L332) (Section 3, Site 9): States that `ResolvedWithoutLocalBacking` re-enters the cold/miss pipeline from the packet as if the resolve returned `None`.
- [plan.md:573-610](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L573-L610) (Section 5.2(iv)): Specifies that re-entry occurs at the post-resolve miss-decision stage (pre-routing DNAT, routing, zone, policy, SNAT). Upstream screens and session lookup do not re-run (avoiding double-fire). The miss-derived decision object is established as the **sole** decision object across install, publication, buffering, replay, reinjection, telemetry, and flow-cache insert ([poll_descriptor/mod.rs:3900](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900)). This closes both the P1/P2 split (`poll_descriptor/mod.rs:4662` vs `:5126` -> `slow_path.rs:199`) and the DNAT port-remap erasure (`promote.rs:32` vs `destination.rs:699`).
- [plan.md:1222-1230](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1222-L1230) (Section 5.8): Reaffirms typed outcomes and sole-decision binding across dispatch paths.
- [plan.md:1616-1628](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1616-L1628) (Section 9): Includes test coverage verifying that full derivation handles `P2 != P1`, updated/deleted config rules, DNAT port remappings, and single-decision binding across all consumers.

**Analysis:**
1. **Airtightness:** Using the miss-derived decision object as the sole decision across install, publication, buffering, replay, reinjection, and flow-cache insertion ensures no residual outer/stored decision can leak down trailing slow-path paths.
2. **Re-entry Scope:** Scope is cleanly bounded to post-resolve miss decision derivation; screens and lookup side effects run exactly once per packet.
3. **Purged-Class Derivation:** Full derivation re-executes pre-routing DNAT, routing, policy, and SNAT against current configuration and packet headers. In the case of deleted/modified rules, NPTv6, or NAT64, the decision matches the packet's current evaluation path (or drops under the #4400 guard if a bare close).

---

### Q2 (Whole-Plan Sweep & Section 11): SOUND

**File:Line Evidence:**
- [plan.md:1191-1200](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1191-L1200) & [plan.md:624-633](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L624-L633): Resolves `account_packet` wording ambiguity—packet counters remain at `#2501` locations while anchor update logic attaches strictly to per-disposition final-admission commit hooks.
- [plan.md:1602-1615](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1602-L1615) (Section 9): Adds positive translated-family propagation coverage for plain SNAT, composed SNAT+DNAT hairpin, NPTv6, and NAT64 in both directions.
- [plan.md:1345-1362](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1345-L1362) (Section 7): Aligns seed emission carve-out naming and reverse-synth mark site documentation.
- [plan.md:1837-1893](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1837-L1893) (Section 11): Answers all six convergence round questions comprehensively (terminal cut justification, confirmation of the two retreats, verification of round-86/87 folds, emission posture, attack arithmetic, and re-scoping boundaries).

---

### NEW Traces

None. The v10.4.1 folds close all prior blocker/low findings without opening new architectural or state-machine traces.
