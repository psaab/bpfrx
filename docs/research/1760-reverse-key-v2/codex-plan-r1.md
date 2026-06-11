PLAN-NEEDS-MINOR

1. Medium — §2.4 is right that AF_XDP does not kernel-bypass established transit, but it overstates session-table TCP-state visibility.

[userspace-xdp/src/lib.rs:535](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-xdp/src/lib.rs:535): `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` is documented as “LOCAL DELIVERY... NOT transit.”  
[userspace-xdp/src/lib.rs:587](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-xdp/src/lib.rs:587): “Let all session misses through to the userspace dataplane.”  
But pure TCP ACKs can be consumed by the userspace flow cache before slow-path session logic:
[afxdp/flow_cache.rs:215](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/flow_cache.rs:215): `packet_eligible` admits TCP packets where `(tcp_flags & 0x17) == 0x10`.  
[afxdp/poll_descriptor/mod.rs:235](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs:235): `FlowCacheOutcome::Consumed => continue`.  
[afxdp/poll_descriptor/flow_cache_hit.rs:153](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:153): cache hits only amortize `sessions.touch`, not `tcp_flags` handling.  
So “userspace sees ACK” is true; “SessionTable consumes every ACK flag / established bit is one-field slow-path” is not.

2. Medium — Path A1’s shared-map guard is not race-free as sketched.

The plan says a race-free guard uses `shared_nat_sessions`:
[plan.md:185](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:185): “A race-free guard still needs the in-process `shared_nat_sessions` map.”  
But current commit order installs locally first:
[poll_descriptor/mod.rs:1274](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1274): `forward_installed = ... sessions.install_with_protocol_with_origin(...)`.  
Then publishes shared state later:
[poll_descriptor/mod.rs:1311](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1311): `publish_shared_session(...)`.  
The shared NAT map then does a plain insert:
[shared_ops.rs:666](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/shared_ops.rs:666): `if !entry.metadata.is_reverse && let Ok(mut sessions) = shared_nat_sessions.lock()`.  
[shared_ops.rs:671](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/shared_ops.rs:671): `.insert(reverse_wire.clone(), entry.clone())`.  
Two workers can both observe K absent unless A1 reserves K under the shared lock before local/BPF commit. This strengthens W over A1.

3. Low — Path K contains stale “misses 5/6” text that contradicts §2.3 and code.

[plan.md:70](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:70): “That hypothesis is WRONG.”  
[plan.md:82](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:82): “The counter's event coverage is sound.”  
[plan.md:287](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:287): “misses 5/6 of events.”  
Code backs §2.3, not Path K: [session_glue/mod.rs:596](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/session_glue/mod.rs:596) queues replicas, and [session/mod.rs:811](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs:811) indexes the synced entry.

4. Low — §2.7 birthday math needs the cross-host correction.

[plan.md:57](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:57): collision needs “two distinct internal hosts.”  
[plan.md:59](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:59): one client does not reuse the same ephemeral port to the same destination.  
[plan.md:160](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:160): uses `C(F,2)/28232`.  
Correct expectation is cross-host pairs divided by the port range; for H equal hosts, roughly `C(F,2) * (1 - 1/H) / 28232`. The conclusion remains material for many hosts, but the formula as written overcounts.

5. Low — W2 needs an explicit SNAT-mode preflight.

[plan.md:221](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md:221): W2 claims it “forces a real collision through interface-SNAT.”  
Interface mode preserves source port:
[nat/source.rs:442](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/nat/source.rs:442): `if rule.interface_mode`.  
[nat/source.rs:447](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/nat/source.rs:447): returns `NatDecision { rewrite_src, rewrite_dst: None, .. }`.  
Pool mode rewrites the port:
[nat/source.rs:498](/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/nat/source.rs:498): `rewrite_src_port: Some(port)`.  
The harness should first assert live config is portless interface-SNAT and prove flow 1’s reverse path works before starting flow 2.

Net: Path W is still the right ship. I found no blocker against §2.3 watch coverage or §2.6 blast-radius; A1 is still not the right move at current incidence.

Codex session ID: 019eb50c-a092-75c0-bb07-dea5c9bb1ef1
Resume in Codex: codex resume 019eb50c-a092-75c0-bb07-dea5c9bb1ef1
