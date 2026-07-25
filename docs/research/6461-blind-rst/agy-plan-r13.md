### Verdict: PLAN YES

Part A (dataplane demote gate) and Part B (minimal HA machinery) fully neutralize issue #6461's actual harm (blind demote DoS, SNAT pool-port reassignment, and HA propagation teeth). Deferring Phase 2 leaves only a bounded table-retention trade-off (post-failover lingering to natural timeout on legitimate closes), which affects no connection delivery or state integrity.

---

### Findings

1. **[LOW] Post-failover imported entries linger to natural timeout on legitimate close**
   - **Evidence:** [phase2-brief.md:12-19](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md#L12-L19), [plan.md:228-240](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L228-L240)
   - **Analysis:** Without Phase 2 HA wire anchor carriage, imported entries sit in a zero-trust absorbing state. Legitimate closes soft-refuse demotion and age out at their standard inactivity timeout (300 s). Endpoints tear down normally; this is a table-retention trade-off, not a DoS or teardown failure.

2. **[LOW] Split-steering reverse-direction closes soft-refuse in Phase 1**
   - **Evidence:** [plan.md:1359-1383](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1359-L1383)
   - **Analysis:** Cross-worker queue steering causes reverse closes landing on non-owner workers to soft-refuse due to untrusted local replica anchors. The entry idles out at natural timeout, preserving master parity without premature teardown or HA teeth.

3. **[MEDIUM] Pre-existing SNAT allocator refcount defect (#6522) isolated by v9 TTL sweep**
   - **Evidence:** `userspace-dp/src/loop_body/mod.rs:1481`, `userspace-dp/src/nat/allocator.rs:1318-1330`, [plan.md:816-830](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L816-L830)
   - **Analysis:** Unobserving sibling worker expiration calls `release` without refcounting (`allocator.rs:1318`). Plan v9 decouples alias purging from worker reaps via incarnation compare-delete TTL sweeps and commit-time reservation rechecks, preventing premature alias deletion.

4. **[LOW] Re-imported / upserted entries reset anchor trust until fresh packet transit**
   - **Evidence:** [plan.md:1349-1355](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1349-L1355)
   - **Analysis:** Re-imports or bulk upserts replace local entry records (`upsert_synced_with_origin`), resetting anchor trust. Closes soft-refuse until fresh transit packets re-establish trusted sequence bounds.

---

### Verification of Core Checks

- **Check 1 (Packet-driven Close deltas):** Gated by `close_seq_plausible` ([plan.md:961](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L961)) and Close authority rules ([plan.md:679-738](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L679-L738)). Unvalidated closes never set `marked` (`closing`/`reset`), and closing packets never promote ([plan.md:664-678](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L664-L678)). `expire.rs:342-345` blocks Close delta emission for un-marked imported entries.
- **Check 2 (#6522 trace):** Isolated by driving alias family purges via last-holder reaps/TTL sweeps with incarnation compare-delete rather than unrefcounted sibling reaps ([plan.md:816-830](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L816-L830)).
- **Check 3 (Materialize commit recheck):** `materialize_shared_session_hit` re-reads canonical records under lock at commit time to verify `flow_incarnation_id` matching and NAT reservation liveness before commit ([plan.md:807-815](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L807-L815)).
- **Check 4 (Residual inventory):** All residual behaviors (post-failover lingering, path-switch stalls, split-steering) are accounted for in §2, §7, and §11 and cause bounded table retention rather than vulnerability to blind DoS.
