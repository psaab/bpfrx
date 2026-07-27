VERDICT: PLAN NO (third attempt — first two dispatches hit AGY infra timeouts, documented retries per feedback_codex_infra_must_retry)


### Q1 (repair-v2 version negotiation): UNSOUND
* **Evidence:** [plan.md:L4184-4191](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4184-L4191) (referencing `sync_auth.go:326, :336`, `sync_conn.go:100`)
* **Analysis:** On a freshly authenticated connection, the symmetric handshake writes its own capability advertisement before waiting to read the peer's record (`sync_auth.go:326`). Making A's advertised max conditional on learning B's record introduces a circular ordering dependency where neither peer can send its record first. Advertisements must be transmitted unconditionally, with `min(own_max, peer_max)` calculated deterministically post-exchange.

### Q2 (durable Authorized → Claimed → Applied activation): UNSOUND
* **Evidence:** [plan.md:L4451-4465](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4451-L4465) (referencing `failover.go:313, :335`, `daemon_ha.go:287, :314`)
* **Analysis:** Ownership activation is a multi-stage process where stage 5 (`ForceRGMaster`) emits wire advertisements (Gratuitous ARPs / VRRP Master adverts). If a failure occurs at or after wire advertisements are sent, an emitted packet cannot be unsent. Claiming that failure simply "rolls back or retains the old-owner lease" breaks when the old owner has already demoted (`failover.go:159`), leaving both nodes in an inconsistent state.

### Q3 (fence-first supersession + named promotion permit + ISSU): UNSOUND
* **Evidence:** [plan.md:L4347-4358](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4347-L4358), [plan.md:L4415-4423](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4415-L4423), [plan.md:L4608-4613](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4608-L4613) (referencing `vrrp/manager.go:354`, `instance.go:1305`, `failover.go:140`, `daemon_ha_userspace_readiness.go:155`)
* **Analysis:** During ISSU, if the peer is mid-upgrade or unreachable, forcing `ForceSecondary` to wait for a forced-repair `JOURNAL_END` before demoting causes `ForceSecondary` to block indefinitely. Additionally, holding the promotion permit across `vrrp.Manager.mu`, `vipMu`, and per-instance mutexes creates a cross-domain lock inversion risk.

### Q4 (operator-visible not-ready + BIT-5 literal): UNSOUND
* **Evidence:** [plan.md:L4477-4484](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4477-L4484), [plan.md:L4524-4530](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4524-L4530), [plan.md:L4778-4784](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4778-L4784) (referencing `failover.go:233, :321`, `daemon_ha_userspace_readiness.go:155`)
* **Analysis:** The plan lacks defined post-condition invariants for readiness publication following a disruptive mode transfer. If the receiver publishes readiness (`syncReady = true`) without fulfilling the five-class completeness predicate, it incorrectly signals table completeness to the cluster; if it remains in an alarming not-ready state while active, subsequent automated election logic is disrupted.

---

### NEW TRACES OPENED BY v9.9.54.16 FOLDS

1. **Unconditional Capability Advertisement Order:**
   * In symmetric connection bringup (`sync_auth.go:326, :336`, `sync_conn.go:100`), each peer writes its capability record before waiting for the peer's response. Maximum version capability must be advertised unconditionally and negotiated as `min(own_max, peer_max)` post-exchange.
2. **Point-of-No-Return (PONR) in Multi-Stage Ownership Activation:**
   * Wire-visible side effects in `ForceRGMaster` (`daemon_ha.go:314`) cannot be undone by simple local CAS rollback. The pipeline requires a Point-of-No-Return boundary post-which failures must either drive forward or execute a formal reverse transfer transaction.
3. **Fixed-Width Capability Word Decoding:**
   * Decoding fixed-width capability records (`sync_auth.go:345`) must ignore unassigned set bits rather than relying on trailing payload tolerance, preventing version negotiation deadlocks across heterogeneous releases.
