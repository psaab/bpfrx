## Plan Review

### Correctness

[CRITICAL-1] Gate-R R1 cannot prove the core seq-drop hypothesis with the proposed observability.  
The plan relies on `ip -ts monitor neigh`, but that is a separate netlink socket and does not tell you what the daemon socket consumed/skipped. The daemon explicitly drops non-matching seq messages during dump (`"if nlmsg_seq != next_seq { ... continue; }"`), so external monitor visibility is not sufficient to confirm or falsify mid-dump drops.  
Evidence: [neighbor.rs:434](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:434), [neighbor.rs:435](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:435), [neighbor.rs:436](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:436).  
Fix: add daemon-side counters/logging for “seq-mismatch skipped NEW/DEL” and “applied NEW/DEL during dump”.

[CRITICAL-2] Candidate 5.B is logically unsound as written (`neighbor_generation >= 1` is not “seed complete”).  
`neighbor_generation` is set to `1` on both dump success and dump failure. Gating on this would admit cold flows even when initial seed failed.  
Evidence: [neighbor.rs:516](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:516), [neighbor.rs:520](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:520), [neighbor.rs:521](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:521).  
Fix: gate on explicit dump-success state (or equivalent durable criterion), not generation value.

[HIGH-1] The plan over-assumes “first SYN is buffered”; it can be dropped on the first attempt.  
Buffering only happens if `pending_neigh.len() < MAX_PENDING_NEIGH`; otherwise packet is recycled (dropped). There are also earlier branch exits that recycle on errors before queueing.  
Evidence: [poll_descriptor/mod.rs:2644](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2644), [poll_descriptor/mod.rs:2652](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2652), [poll_descriptor/mod.rs:2734](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2734), [poll_descriptor/mod.rs:2735](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2735).  
Fix: R1 must explicitly count “queued vs recycled first SYN”.

[HIGH-2] “World 2” inference is confounded by standby passive learning, not just warm queue behavior.  
Standby can learn dynamic neighbors from RX without forwarding-active guards in multiple stages, including ARP/NA handling that also writes kernel neighbor entries. This can mask failover cold-start effects.  
Evidence: [poll_stages.rs:79](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:79), [poll_stages.rs:92](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:92), [poll_stages.rs:100](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:100), [poll_stages.rs:113](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:113), [poll_stages.rs:183](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_stages.rs:183), [neighbor_dispatch.rs:320](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:320).  
Fix: control for standby passive-learn contamination in R2 before drawing PLAN-KILL conclusions.

[HIGH-3] 5.C.2 is overstated as a primary fix; it misses “new host with no prior session,” which is exactly the cold-connect class.  
Activation prewarm machinery already restores/promotes synced session entries; it does not proactively probe arbitrary new on-link peers. So 5.C.2 is partial by design.  
Evidence: [shared_ops.rs:59](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:59), [shared_ops.rs:60](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:60), [shared_ops.rs:61](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:61), [shared_ops.rs:148](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:148), [shared_ops.rs:185](/home/ps/git/bpfrx/userspace-dp/src/afxdp/shared_ops.rs:185).  
Fix: reframe 5.C.2 as optimization, not root fix, and pair with a first-touch mechanism that works without prior session history.

[HIGH-4] The plan assumes the 800ms timeout path without requiring proof that it is active in test runs.  
Code falls back to 2000ms when sysctl checks fail or exceed threshold; this materially changes whether ~1.7s is expected.  
Evidence: [neighbor_dispatch.rs:99](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:99), [neighbor_dispatch.rs:102](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:102), [forwarding_build/mod.rs:433](/home/ps/git/bpfrx/userspace-dp/src/afxdp/forwarding_build/mod.rs:433), [forwarding_build/mod.rs:474](/home/ps/git/bpfrx/userspace-dp/src/afxdp/forwarding_build/mod.rs:474), [mod.rs:329](/home/ps/git/bpfrx/userspace-dp/src/afxdp/mod.rs:329).  
Fix: Gate-R must record effective `pending_neigh_timeout_ns` each run.

### Completeness

[MEDIUM-1] Netlink overflow is not instrumented, yet it is a direct competing explanation for missed neighbor events.  
The monitor socket config sets timeout, but no receive-buffer sizing or drop accounting is included in the plan.  
Evidence: [neighbor.rs:470](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:470), [neighbor.rs:498](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:498), [neighbor.rs:506](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:506).  
Fix: add drop/overflow telemetry to Gate-R.

[MEDIUM-2] R2 only tests one on-link destination; that can under-detect failover impact if that host is incidentally warm.  
Evidence for single-target coupling: [ha-cluster-userspace.conf:119](/home/ps/git/bpfrx/docs/ha-cluster-userspace.conf:119), [loss-userspace-cluster.env:41](/home/ps/git/bpfrx/test/incus/loss-userspace-cluster.env:41).  
Fix: include at least one additional on-link host not recently active.

### Alternatives

[MEDIUM-3] The plan under-considers a cleaner design: separate sockets for dump and multicast subscription.  
Current single-socket dump+subscription design creates seq-mixing complexity and makes correctness harder to prove.  
Evidence: [neighbor.rs:485](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:485), [neighbor.rs:514](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:514), [neighbor.rs:434](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor.rs:434).  
Fix: compare 5.A.2 against a dual-socket design before /engineer.

### Feasibility

[LOW-1] File map in the plan has at least one stale path, which risks bad trace execution.  
`update_ha_state` entrypoint is in `userspace-dp/src/server/handlers/ha.rs`, not under `userspace-dp/src/afxdp/server/...`.  
Evidence: [server/handlers/ha.rs:26](/home/ps/git/bpfrx/userspace-dp/src/server/handlers/ha.rs:26).  
Fix: correct path map before Gate-R runbook is finalized.

### Security

No major security-specific blockers in this research plan. Operational safety still requires explicit “lab-only” guardrails for `ip neigh flush all` and failover injection.

### Summary

- Critical: 2
- High: 4
- Medium: 3
- Low: 1

Overall: **Not PLAN-READY for Gate-R yet**. The plan is close, but it currently risks a wrong root-cause decision (and wrong fix) because the core measurements do not directly observe daemon-side netlink behavior.