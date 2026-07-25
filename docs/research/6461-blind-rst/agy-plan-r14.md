# Defensive Firewall DoS-Hardening Design Review (#6461 Plan v9.2)

### 1. Uniform Incarnation Fencing
- **Status:** **HOLDS / CLOSED**.
- Fencing every local Close-driven mutation (`session_delta.rs:84` queued flow cancel, `session_delta.rs:406` BPF/conntrack/`dnat_table` deletes, `shared_ops.rs:960` shared map remove) on `delta.flow_incarnation_id` successfully closes the trace:
  `loop_body:811` (queue E1 Close) $\rightarrow$ `:887` (install E2) $\rightarrow$ `:970` (drain stale Close).
- When E1's stale Close drains at `:970`, its incarnation ID mismatches E2's state (`E1_id != E2_id`), preventing the stale Close from key-deleting E2.

### 2. Commit Coverage & Uncovered Shared Clones
- **Status:** **HOLDS WITH FINDINGS**.
- Consumers of detached shared decisions/clones in `afxdp` **not** on the covered list:
  1. [return_resolution.rs:20](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/return_resolution.rs#L20): `lookup_session_across_scopes` consumes a detached reverse decision for embedded ICMP return routing.
  2. [nat_match_v4.rs:78, :87](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs#L78) & [nat_match_v6.rs:100, :117](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs#L100): `lookup_session_across_scopes` session-fallback paths consume detached shared lookups.
  3. [session_glue/mod.rs:1194-1195](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1194): `keep_transient` branch clones `hit.lookup` directly without materialization recheck.

### 3. Refused Closing Materialize
- **Status:** **HOLDS / NO RENEWAL CHANNEL**.
- Refused closing materialize installs ALIVE at the 20s probationary opening-window timeout and explicitly suppresses `last_touch_ns` family clock updates (§5.6, §5.7).
- Because `last_touch_ns` is not stamped by refused closing packets, the coordinator TTL sweep clock continues aging uninterrupted, purging the shared entry after $K \times \text{expires\_after\_ns}$. No obsolete-permit renewal channel remains.

---

### **Verdict: PLAN YES**
