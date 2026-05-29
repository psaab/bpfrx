## Plan Review

### Correctness

[CRITICAL-1] The plan over-asserts a shared root cause for restart and failover, but failover does not re-enter `initial_neighbor_dump`.  
`initial_neighbor_dump` is only called inside `neigh_monitor_thread` ([neighbor.rs:514](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:514)), and that thread is spawned at bring-up ([bringup.rs:339](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:339)). RG promote only calls `on_rg_promote_active()` ([ha.rs:164](/home/ps/git/bpfrx/userspace-dp/src/afxdp/ha.rs:164)), which clears rate-limit state and runs `queue_warm_pass(true)` ([coordinator/mod.rs:745](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:745), [coordinator/mod.rs:749](/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs:749)).  
This means 5.A.2 cannot be assumed to fix failover behavior unless failover coincides with daemon startup.

[CRITICAL-2] The proposed 5.A.2 safety argument is incorrect; processing seq-mismatch NEW/DEL inline during dump can create stale final state.  
The dump loop currently skips non-matching seq ([neighbor.rs:434](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:434)). Proposed 5.A.2 would process seq=0 NEW/DEL during dump. But `RTM_DELNEIGH` is unconditional remove ([neighbor.rs:359](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:359)), while `RTM_NEWNEIGH` inserts resolved entries ([neighbor.rs:357](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:357)). Interleaving live events with older dump rows can resurrect deleted neighbors or remove newer ones depending on arrival order.  
This needs an ordering/replay design, not just “process seq=0 immediately.”

### Completeness

[HIGH-1] R1 still does not decisively answer “buffered vs dropped first SYN” under all drop paths.  
`MissingNeighbor` buffers only if queue has room ([poll_descriptor/mod.rs:2644](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2644)); otherwise packet is effectively dropped because `recycle_now` remains true from default ([poll_descriptor/mod.rs:463](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:463)).  
Plan asks for queued/recycled counters, but without explicit queue-full and pre-buffer drop attribution, the RTO conclusion can still be ambiguous.

[HIGH-2] R2 world classification is vulnerable to warm-state contamination and lacks strict trial reset criteria.  
Standby passive learning happens before HA disposition checks: stage call at [poll_descriptor/mod.rs:501](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:501), learn path at [poll_stages.rs:183](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:183).  
The plan names a second target, but does not define deterministic cold-state enforcement before each measured trial (dynamic map, kernel neigh, and session state), so World 2 can be falsely concluded.

[HIGH-3] Internal contradiction: 5.C.2 is rejected, but §8 still requires tests for 5.C.2 behavior.  
The plan says “Drop 5.C.2” but later asks to add tests that `on_rg_promote_active` warms prior-session on-link peers (explicitly tied to 5.C.2). That creates scope confusion and raises wrong-fix risk.

### Risks

[MEDIUM-1] Netlink overflow remains a plausible competing cause, but the plan does not require durable observability as part of acceptance.  
Current monitor loop discards `recv<=0` with no structured error handling ([neighbor.rs:527](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:527)). Even if Gate-R passes, overflow-induced misses can recur under load without detection.

[MEDIUM-2] PLAN-KILL gating is not crisp.  
The matrix says World 2 => PLAN-KILL, but recommendation text still allows “ship 5.A.2 OR PLAN-KILL.” That weakens decision discipline and can bias toward unnecessary changes after a kill outcome.

### Security

No blocking security-specific gaps were identified in this research plan. Main issues are correctness and experimental validity, not auth/input handling.

### Summary

- Critical: 2
- High: 3
- Medium: 2
- Low: 0

Overall: The plan has strong code-path coverage, but two blocking logic errors remain: it conflates restart and failover mechanisms, and its primary fix (5.A.2) is not correctness-safe as specified. These must be resolved before declaring PLAN-READY for Gate-R or implementation.