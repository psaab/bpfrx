VERDICT: PLAN YES

### Q1 (Typed Outcomes + Seed Lifecycle): SOUND

- **`ExistingResolved` side-effect freedom**: Stated explicitly at [plan.md:L327](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L327), [plan.md:L1113-L1120](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1113-L1120), and [plan.md:L1445-L1453](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1445-L1453). When a live entry is resolved (`ExistingResolved`), the arm branches at the head before any seed-only execution; NAT/NPT derivation/allocation (`nat/source.rs:1548`), metadata, counters, install, and publication are completely skipped. The packet is buffered with the resolver's stored decision without side effects.
- **Seed flip + alias cleanup completeness**:
  - **No suppressed confirmed Close**: At [plan.md:L532-L550](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L532-L550) and [plan.md:L921-L925](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L921-L925), any committed packet (slow-path, cache-hit, or accepted-close mark application) idempotently flips `MissingNeighborSeed -> ForwardFlow`. The entry is no longer transient, allowing `expire.rs:342-350` to emit the Close delta normally upon 2 s reap.
  - **Owner-identity alias protection**: At [plan.md:L551-L557](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L551-L557) and [plan.md:L1121-L1127](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1121-L1127), every seed-class expiry removes the install-published shared/DNAT aliases (`poll_descriptor/mod.rs:4823, :4879`) **only** when the recorded owner identity matches the expiring entry, preserving any alias owned by a newer live entry.
  - **Close drain matching**: Unconfirmed/uncommitted seeds expire silently under master's transient-seed rule, while confirmed/flipped seeds emit Close deltas matching their published HA shared state ([plan.md:L544-L550](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L544-L550)).

---

### Q2 (The Retreat): SOUND

- **Acceptance of retreat rationale**: Documented at [plan.md:L495-L531](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L495-L531), [plan.md:L1332-L1335](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1332-L1335), and [plan.md:L1602-L1612](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1602-L1612). Master's retry (`neighbor_dispatch.rs:156, :272, :310, :344, :369`) is preserved byte-identically. The stale-decision transmit window is pre-existing on master, not widened by Part A, and orthogonal to demote-gate security.
- **No ISSUE-class harm introduced**:
  - Buffered packets never update anchors, promote establishment, or clear probation ([plan.md:L508-L511](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L508-L511)).
  - The lag during ARP stalls fails toward refuse (closing segments soft-refuse and the session idles out on its normal established timeout), preventing any anchor poisoning or unauthorized state demotion.
  - No translated-source change or standby deletion occurs.

---

### Q3 (2b Scope/Identity + Whole-Plan Sweep): SOUND

- **Cross-generation anchor protection**: At [plan.md:L954-L986](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L954-L986), [plan.md:L1128-L1132](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1128-L1132), and [plan.md:L1465-L1469](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1465-L1469), `ForwardSessionMatch` carries explicit `scope: Local | Shared` and identity `(canonical key + NAT decision)`.
  - Validation runs **only** on a `Local` match.
  - Both the initial check and post-borrow re-probe enforce strict identity agreement (key AND NAT decision).
  - A `Shared` match or identity mismatch refuses close validation by construction, eliminating the `K/NAT1` shared alias vs. `K/NAT2` local replacement wrong-flow trace ([plan.md:L961-L966](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L961-L966)).
- **Whole-plan accounting sweep**: Origin flips re-attribute origin strictly for emission gating; Open telemetry is emitted once at install, and shared-map/HA states are adopted without duplicate publishing ([plan.md:L540-L546](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L540-L546)). All 9 packet-driven teardown sites remain fully gated or verified inert ([plan.md:L315-L327](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L315-L327)).

---

### NEW TRACES: None
