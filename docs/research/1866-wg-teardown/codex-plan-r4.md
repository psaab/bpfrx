===== RESULT =====
**Finding**

PLAN-NEEDS-CHANGES: v4 fixes my r3 crypto-identity counterexample, but the respawn comparison is still incomplete for the control thread it starts. It compares WG engine identity only, while the spawned thread also captures the TUN name derived from `endpoint.logical_ifindex`.

Verified counterexample:

S0: one WG tunnel `wg0`, endpoint id 1, identity A; thread dies into tombstone.  
S1: defer snapshot has one WG tunnel `wg1`, still endpoint id 1 and same WG identity A. `buildTunnelEndpointSnapshots` assigns sequential ids from sorted names, so a one-tunnel rename stays id 1 ([tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1866-research/pkg/dataplane/userspace/tunnels.go:36), [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1866-research/pkg/dataplane/userspace/tunnels.go:89)). The snapshot row carries `Interface`, `LinuxName`, and `Ifindex` ([protocol.go](/home/ps/git/bpfrx/.claude/worktrees/1866-research/pkg/dataplane/userspace/protocol.go:273)), but v4’s coherent-respawn tuple omits them: “listen_port, decoded local privkey, decoded peer pubkey, allowed-ips, endpoint, keepalive” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:257)).

The sweep would pass that comparison and respawn against stale forwarding. Current spawn resolves the actual TUN from stale `endpoint.logical_ifindex` ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs:537)) and passes that name into `wg_control_loop` ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs:555)); the thread then opens that TUN ([wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:113)). Later real reconcile does not necessarily repair it because `wg_identity_unchanged` also ignores ifindex/name ([wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs:87)), so the engine Arc can remain unchanged and the live stale thread is kept.

**r3 Resolution**

The exact r3 same-id crypto-identity change is resolved. v4 now says respawn is “TOMBSTONE-ONLY, SNAPSHOT-COHERENT” and requires the latest stored snapshot row to be “IDENTICAL to the forwarding endpoint it would spawn against”; `None`/missing/mismatch skips silently ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:249)). Test 6c pins identity A tombstone plus defer snapshot identity B ⇒ “NO respawn (identity mismatch)” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:442)).

**Round-4 Answers**

1. The WG crypto identity comparison is field-complete for engine identity, and `state.snapshot` is fresh enough when the sweep runs. Accepted apply branches store before `refresh_status` sweep visibility; rejects return before storing. But the comparison is not complete for control-thread spawn coherence because it omits the TUN attachment fields.

2. Yes: same-id, same-WG-identity, changed interface/TUN under a defer window with an existing tombstone can respawn the old TUN thread and survive the later reconcile.

3. No other blocker found. Fix scope is bounded: extend the coherent-respawn/stale-prune key to include control attachment, at least `logical_ifindex` plus resolved tunnel name or `linux_name`, and add a 6d regression for same-id same-identity interface rename under defer.

Verdict: PLAN-NEEDS-CHANGES.

Codex session ID: 019eb65f-9c7e-7cf2-a3dd-682ddb73357b
Resume in Codex: codex resume 019eb65f-9c7e-7cf2-a3dd-682ddb73357b
