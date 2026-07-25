# AGY hostile plan review — round 10 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only, scoped sections). Scope: plan v8. Transcript: .scratch/r10-agy-out1.txt (verbatim below).

---

### Question 1: SOUND
- **Evidence**: [session/mod.rs:1232-1278](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1232-L1278), [expire.rs:342-345](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L342-L345)
- **Rationale**:
  - Worker session tables are thread-local. When a packet arrives, the marking worker updates the entry and re-buckets it into its own thread-local timer wheel ([session/mod.rs:1276](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1276)), making the marking worker necessarily the reaping worker for that marked entry.
  - Companion propagation ([session/mod.rs:1232-1278](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1232-L1278)) marks both matched and companion entries in the same worker table.
  - Upon expiration, [expire.rs:342-345](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs#L342-L345) enforces `!metadata.is_reverse`. The forward entry emits a single `Close` delta while the reverse companion is gated out by `is_reverse`, yielding exactly one `Close`.

---

### Question 2: UNSOUND
- **Evidence**: [promote.rs:131](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L131), [session_delta.rs:156](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs#L156), [loop_body/mod.rs:394](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L394), [plan.md:665-668](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L665-L668)
- **Rationale**:
  - In current code, `shared_sessions` entry age is refreshed strictly on event-driven operations (`materialize`, `promote`, `replicate`, `refresh_owner_rgs`). Fast-path packet forwarding (`account_packet` in [loop_body/mod.rs:394](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L394)) updates worker-local state, never `shared_sessions`.
  - A live-but-quiet TCP flow carrying data packets triggers no control events, so its shared map age is never refreshed.
  - After $K \times \text{timeout}$, the coordinator TTL sweep ([plan.md:665-668](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L665-L668)) purges the shared alias of the active flow. Subsequent non-owner worker lookups (e.g. following RSS re-steering or asymmetric traffic) miss the purged alias, resulting in dropped packets or broken flow delivery.

---

### Question 3: UNSOUND
- **Evidence**: [plan.md:651-659](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L651-L659), [plan.md:1083-1089](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1083-L1089), [plan.md:1301-1308](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1301-L1308)
- **Rationale**:
  - The plan text contains internal contradictions where legacy v7.2 text was preserved.
  - While v8 sections ([plan.md:651-659](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L651-L659), [plan.md:1083-1089](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1083-L1089)) specify that alias-CAS is deleted, import entries emit `Close` ONLY when marked by a validated close, and stranded aliases die silently to a coordinator TTL sweep without a `Close` producer, stale v7.2 text survives at [plan.md:1301-1308](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1301-L1308).
  - [plan.md:1301-1308](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1301-L1308) states that unvalidated reaps execute a "shared-alias delete race" where "exactly ONE worker wins the shared-alias delete and emits the authoritative Close", directly contradicting the v8 marked-only silent reap rule and TTL sweep.
