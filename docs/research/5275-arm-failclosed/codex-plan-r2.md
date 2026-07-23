# Codex hostile plan-review r2 (#5275) — VERDICT: PLAN-NEEDS-MAJOR

Reviewed plan.md @ r3. Final synthesis (file-read dumps stripped):


[35m[3mexec[0m[0m
[1m/bin/bash -lc "nl -ba pkg/daemon/cluster_topology_preflight.go | sed -n '55,90p'"[0m in /home/ps/git/bpfrx/.claude/worktrees/5275-research
[32m succeeded in 0ms:[0m

[35m[3mcodex[0m[0m
No. r3 is substantially better, but it does not close the round-1 findings. The remaining problems are architectural and security-relevant, not editorial.

## 1. Quarantine is the right idea, but the arm state is still wrong

For ordinary routed IPv4/IPv6 leakage, an `inet` base chain hooked at `forward` with an unconditional terminal drop is the correct barrier. It does not need to precede conntrack: `ct state established accept` in another base chain cannot override a later forward-hook drop. Raw/prerouting would unnecessarily affect host-bound traffic.

However, r3 does not specify the family, base-chain declaration, priority, atomic ownership, or readback. Existing nft code already treats priorities and atomic `nft -f` operations as invariants ([daemon_nft.go:23](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_nft.go:23), [daemon_nft.go:57](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_nft.go:57)). It must also rule out bridge/flowtable bypasses.

The proposed management exemption is actively dangerous. SSH/gRPC to the firewall traverse INPUT, not FORWARD. Exempting a management interface from the FORWARD drop creates a routed bypass. Likewise, the claim that the barrier is “robust to relay” is false: DHCP relay sends through local sockets and raw L2, outside FORWARD ([plan.md:352](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:352)).

More importantly, `dataplaneEverArmed` remains the wrong security predicate ([plan.md:194](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:194)):

- An empty required set returns success ([loader.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:211)), so an empty config can establish “ever armed” vacuously.
- Removing all data interfaces detaches their XDP links but does not invalidate the historical boolean ([manager_compile.go:567](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:567)).
- With A already armed, a commit adding B can bring up/address B before attachment ([compiler_iface.go:338](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:338)). If B’s attach fails, `everArmed=true` takes the #5679 path. Old policy still covers A, but B is kernel-visible and uncovered, and the quarantine was removed after the earlier success. That recreates #5275 on a binding expansion.
- On a hitless restart, the opposite happens: the process-local boolean starts false despite an authoritative surviving-helper probe already existing ([boot_probe.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/boot_probe.go:24)).

The boundary must be candidate-generation/current-surface coverage, not historical success. The structured outcome also cannot represent a missing configured interface using only `requiredIfindexes`; lookup currently logs and skips it before an ifindex exists ([compiler_iface.go:343](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:343)). It needs unresolved logical identities, expected program identity, and kernel/helper readback.

There is also a success-path ordering hole. r3 sets `dataplaneEverArmed` on the ApplyConfig proof before the barrier is removed ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:197)). If nft deletion/readback fails, the node is classified as armed while still quarantined and may unfreeze ownership. Required transition:

`armPending → coverage verified → barrier removal verified → ownership unfrozen/armed`

That transition must run under the same lifecycle serialization that prevents concurrent detach. A deletion-failure test is absent.

Finally, `ownershipFrozen == dataplaneArmFailed` is reactive. Cluster election starts before attachment ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:161)); the node may advertise VIP/VRRP/RA ownership while arm is pending. An `armPending` hold must be installed before the first `UpdateConfig`, exactly like the existing kernel-candidate hold.

## 2. The HA design is not sufficient or mixed-version-safe

B1 remains internally contradictory.

If “yield posture” writes ordinary `StateSecondary`, RG0 still auto-confirms the failed commit—the source does this for both `StateSecondary` and `StateSecondaryHold` ([daemon_ha.go:466](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:466)). If B1 leaves stored state Primary and only overrides heartbeat/`IsLocalPrimary*`, then:

- RG0 receives no transition and the failed node remains config-writable.
- Direct VIP ownership still reads raw `GroupState()` ([daemon_ha_vip.go:112](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_vip.go:112)).
- VRRP priority still reads raw `LocalPriorities()` ([group_state.go:262](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:262)).
- RA/DDNS/Kea paths use separately snapshotted ownership.

The design needs one effective-ownership view for every consumer and a cause-aware RG0 transition that makes the store read-only without confirming the failed commit.

“`ArmFailed bool` or reserved group state” is not a wire specification ([plan.md:237](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:237)). If “protocol bump” means the heartbeat byte, legacy readers reject it. If it means `CurrentHAProtocolVersion`, compatibility is strict equality ([peer_state.go:100](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/peer_state.go:100)) and `SessionSyncWireVersion` is coupled to it ([sync.go:21](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync.go:21)). That breaks the existing coordinated-transfer readiness used by C1. An additive authenticated TLV may avoid a bump, but r3 does not define its framing, placement relative to the optional version/auth trailers, or downgrade behavior.

The old-peer weight-zero fallback also cannot guarantee promotion. Election still honors kernel-upgrade hold, manual-failover state, and readiness before promoting ([election.go:313](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:313)). The honest invariant is “failed node never owns; an eligible peer takes over,” not “peer owns every RG” regardless of peer state.

There is a fatal config-sync contradiction. r3 recommends suppressing config sync after the failed commit ([plan.md:199](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:199)). If that commit introduced an RG, VIP, or service, the healthy peer does not have it. Election iterates only locally configured groups, so it cannot own the new RG merely because it received a node-wide flag. “Let the operator reconcile” does not satisfy failover completion. The plan needs safe config-text replication plus peer apply/arm acknowledgment, or rollback to a mutually installed configuration.

The handoff is also not acknowledged as described. “Mark yield, then wait for local actuation” publishes the promotion trigger before asynchronous VIP/VRRP removal finishes. Existing `ResignRG` merely queues a nonblocking signal, while the current fence is released before the VRRP run loop actually processes it ([daemon_ha.go:383](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:383), [instance.go:1009](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:1009)). Direct VIP deletion errors are logged rather than verified.

The correct ordering is local drop/freeze, pre-arm per-RG completion, cancel/join and verify local ownership absent, then advertise yield, then obtain peer promotion acknowledgment. A timeout is safe from unpoliced kernel forwarding, but it does not prove “no dual VIP.”

## 3. Publisher completeness and TOCTOU remain unsolved

r3 added most named omissions, but the set is still incomplete:

- Normal DHCP-lease DDNS—Surface B—is separate from Surface A and remains omitted ([daemon_ddns.go:109](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns.go:109)).
- The DHCP relay master gate is checked before upstream `WriteTo`, leaving a check/freeze/send race, and the server-response delivery path has no ownership gate at all ([relay.go:1305](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1305), [relay.go:1455](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1455)). The existing `Manager.Stop()` already cancels and joins these goroutines; the plan should use it ([relay.go:891](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:891)).
- Kea, proxy ARP, standalone RA, and both DDNS paths lack an explicit verified stop/withdraw sequence.
- “Fabric redirect does not forward transit” is plainly false; it is the cross-chassis packet-forwarding path and at minimum belongs in the lifetime audit.

An epoch load at a façade does not linearize the external effect. Freeze can occur after the epoch check but before a DDNS network update completes, before a relay send, or after Kea queues work but before its worker executes. Correct choices are a lock held through the actual leaf effect, or cancel/join all in-flight work followed by an authoritative final withdrawal.

The proposed “prefer a façade” plus grep for known sink method names is still the circular canary from round 1 ([plan.md:308](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:308)). A new raw socket, netlink operation, manager method, or package evades it. G7 requires capability/package encapsulation or an enforceable AST/import rule around actual leaf effects.

## 4. Teardown is still incomplete

“Teardown before nil” is correct, but “under the same lock readers use” describes a lock that does not exist. `d.dp` is a bare interface ([daemon.go:69](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon.go:69)), and several long-lived consumers capture it or access it independently. Conntrack GC captures the backend directly ([daemon_gc.go:9](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_gc.go:9)); event streams, cluster callbacks, session sync, APIs, and HA watchdogs are not covered by the proposed NAT/sampler join.

The design needs one dataplane lifetime context/ref-guard plus a complete WaitGroup inventory. A synchronized nil write does not protect a goroutine holding an older pointer.

`Teardown()` is not presently verifiable either. The lower implementation ignores errors from close, unpin, pinned-link loading, and pin removal; only final `RemoveAll` propagates ([loader.go:1223](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:1223)). Error aggregation and kernel/pin readback are required. On failure, the cleanup owner must be retained for retry; setting `d.dp=nil` would again discard the only owner capable of cleanup.

## 5. The tests do not bind the dangerous seams

The proposed test suite still encodes the flawed historical boolean as desired behavior ([plan.md:417](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:417)). Required missing cases include:

- A armed, add B, B attach fails.
- Empty config, remove-all→add, and hitless survivor with real coverage readback.
- Raw attach sentinel through both local `applyAndSyncCommitted` and inbound `syncAndApply`; the classifier only receives an `error`, so first-arm needs a distinct contextual terminal error ([daemon_apply_commit.go:303](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:303)).
- Barrier deletion/readback failure and blocked attach proving no pre-arm VIP/VRRP/RA output.
- Authenticated legacy/new heartbeat goldens, manual-failover/readiness/hold precedence, config-skew/new-RG, and a real two-node handoff with blocked VIP/VRRP removal.
- Relay request and response races, blocked DDNS A/B wire operations, queued Kea work, and real pinned-link cleanup rather than only a recorder.
- Continuous v4/v6 traffic beginning before attach failure, including an established conntrack flow; final-state peer iperf does not prove absence of a transient leak.

The three-PR sequence introduces a new deployment problem: PR1 activates teardown and the drop barrier without publisher fencing or HA yield, and PR2 still lacks handoff. Those PRs are not independently safe on clustered systems unless activation remains feature-gated until the full invariant lands.

So: r3 fixed the conceptual detection location, chose the right routed-transit hook, recognized barrier-first ordering, expanded the publisher inventory, and acknowledged real teardown and test seams. It did not make current coverage, HA state, mixed-version handoff, publication linearization, or dataplane lifetime coherent. Most round-1 majors remain open in revised form.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
333,099
No. r3 is substantially better, but it does not close the round-1 findings. The remaining problems are architectural and security-relevant, not editorial.

## 1. Quarantine is the right idea, but the arm state is still wrong

For ordinary routed IPv4/IPv6 leakage, an `inet` base chain hooked at `forward` with an unconditional terminal drop is the correct barrier. It does not need to precede conntrack: `ct state established accept` in another base chain cannot override a later forward-hook drop. Raw/prerouting would unnecessarily affect host-bound traffic.

However, r3 does not specify the family, base-chain declaration, priority, atomic ownership, or readback. Existing nft code already treats priorities and atomic `nft -f` operations as invariants ([daemon_nft.go:23](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_nft.go:23), [daemon_nft.go:57](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_nft.go:57)). It must also rule out bridge/flowtable bypasses.

The proposed management exemption is actively dangerous. SSH/gRPC to the firewall traverse INPUT, not FORWARD. Exempting a management interface from the FORWARD drop creates a routed bypass. Likewise, the claim that the barrier is “robust to relay” is false: DHCP relay sends through local sockets and raw L2, outside FORWARD ([plan.md:352](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:352)).

More importantly, `dataplaneEverArmed` remains the wrong security predicate ([plan.md:194](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:194)):

- An empty required set returns success ([loader.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:211)), so an empty config can establish “ever armed” vacuously.
- Removing all data interfaces detaches their XDP links but does not invalidate the historical boolean ([manager_compile.go:567](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:567)).
- With A already armed, a commit adding B can bring up/address B before attachment ([compiler_iface.go:338](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:338)). If B’s attach fails, `everArmed=true` takes the #5679 path. Old policy still covers A, but B is kernel-visible and uncovered, and the quarantine was removed after the earlier success. That recreates #5275 on a binding expansion.
- On a hitless restart, the opposite happens: the process-local boolean starts false despite an authoritative surviving-helper probe already existing ([boot_probe.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/boot_probe.go:24)).

The boundary must be candidate-generation/current-surface coverage, not historical success. The structured outcome also cannot represent a missing configured interface using only `requiredIfindexes`; lookup currently logs and skips it before an ifindex exists ([compiler_iface.go:343](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:343)). It needs unresolved logical identities, expected program identity, and kernel/helper readback.

There is also a success-path ordering hole. r3 sets `dataplaneEverArmed` on the ApplyConfig proof before the barrier is removed ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:197)). If nft deletion/readback fails, the node is classified as armed while still quarantined and may unfreeze ownership. Required transition:

`armPending → coverage verified → barrier removal verified → ownership unfrozen/armed`

That transition must run under the same lifecycle serialization that prevents concurrent detach. A deletion-failure test is absent.

Finally, `ownershipFrozen == dataplaneArmFailed` is reactive. Cluster election starts before attachment ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:161)); the node may advertise VIP/VRRP/RA ownership while arm is pending. An `armPending` hold must be installed before the first `UpdateConfig`, exactly like the existing kernel-candidate hold.

## 2. The HA design is not sufficient or mixed-version-safe

B1 remains internally contradictory.

If “yield posture” writes ordinary `StateSecondary`, RG0 still auto-confirms the failed commit—the source does this for both `StateSecondary` and `StateSecondaryHold` ([daemon_ha.go:466](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:466)). If B1 leaves stored state Primary and only overrides heartbeat/`IsLocalPrimary*`, then:

- RG0 receives no transition and the failed node remains config-writable.
- Direct VIP ownership still reads raw `GroupState()` ([daemon_ha_vip.go:112](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_vip.go:112)).
- VRRP priority still reads raw `LocalPriorities()` ([group_state.go:262](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:262)).
- RA/DDNS/Kea paths use separately snapshotted ownership.

The design needs one effective-ownership view for every consumer and a cause-aware RG0 transition that makes the store read-only without confirming the failed commit.

“`ArmFailed bool` or reserved group state” is not a wire specification ([plan.md:237](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:237)). If “protocol bump” means the heartbeat byte, legacy readers reject it. If it means `CurrentHAProtocolVersion`, compatibility is strict equality ([peer_state.go:100](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/peer_state.go:100)) and `SessionSyncWireVersion` is coupled to it ([sync.go:21](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync.go:21)). That breaks the existing coordinated-transfer readiness used by C1. An additive authenticated TLV may avoid a bump, but r3 does not define its framing, placement relative to the optional version/auth trailers, or downgrade behavior.

The old-peer weight-zero fallback also cannot guarantee promotion. Election still honors kernel-upgrade hold, manual-failover state, and readiness before promoting ([election.go:313](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:313)). The honest invariant is “failed node never owns; an eligible peer takes over,” not “peer owns every RG” regardless of peer state.

There is a fatal config-sync contradiction. r3 recommends suppressing config sync after the failed commit ([plan.md:199](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:199)). If that commit introduced an RG, VIP, or service, the healthy peer does not have it. Election iterates only locally configured groups, so it cannot own the new RG merely because it received a node-wide flag. “Let the operator reconcile” does not satisfy failover completion. The plan needs safe config-text replication plus peer apply/arm acknowledgment, or rollback to a mutually installed configuration.

The handoff is also not acknowledged as described. “Mark yield, then wait for local actuation” publishes the promotion trigger before asynchronous VIP/VRRP removal finishes. Existing `ResignRG` merely queues a nonblocking signal, while the current fence is released before the VRRP run loop actually processes it ([daemon_ha.go:383](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:383), [instance.go:1009](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:1009)). Direct VIP deletion errors are logged rather than verified.

The correct ordering is local drop/freeze, pre-arm per-RG completion, cancel/join and verify local ownership absent, then advertise yield, then obtain peer promotion acknowledgment. A timeout is safe from unpoliced kernel forwarding, but it does not prove “no dual VIP.”

## 3. Publisher completeness and TOCTOU remain unsolved

r3 added most named omissions, but the set is still incomplete:

- Normal DHCP-lease DDNS—Surface B—is separate from Surface A and remains omitted ([daemon_ddns.go:109](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns.go:109)).
- The DHCP relay master gate is checked before upstream `WriteTo`, leaving a check/freeze/send race, and the server-response delivery path has no ownership gate at all ([relay.go:1305](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1305), [relay.go:1455](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1455)). The existing `Manager.Stop()` already cancels and joins these goroutines; the plan should use it ([relay.go:891](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:891)).
- Kea, proxy ARP, standalone RA, and both DDNS paths lack an explicit verified stop/withdraw sequence.
- “Fabric redirect does not forward transit” is plainly false; it is the cross-chassis packet-forwarding path and at minimum belongs in the lifetime audit.

An epoch load at a façade does not linearize the external effect. Freeze can occur after the epoch check but before a DDNS network update completes, before a relay send, or after Kea queues work but before its worker executes. Correct choices are a lock held through the actual leaf effect, or cancel/join all in-flight work followed by an authoritative final withdrawal.

The proposed “prefer a façade” plus grep for known sink method names is still the circular canary from round 1 ([plan.md:308](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:308)). A new raw socket, netlink operation, manager method, or package evades it. G7 requires capability/package encapsulation or an enforceable AST/import rule around actual leaf effects.

## 4. Teardown is still incomplete

“Teardown before nil” is correct, but “under the same lock readers use” describes a lock that does not exist. `d.dp` is a bare interface ([daemon.go:69](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon.go:69)), and several long-lived consumers capture it or access it independently. Conntrack GC captures the backend directly ([daemon_gc.go:9](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_gc.go:9)); event streams, cluster callbacks, session sync, APIs, and HA watchdogs are not covered by the proposed NAT/sampler join.

The design needs one dataplane lifetime context/ref-guard plus a complete WaitGroup inventory. A synchronized nil write does not protect a goroutine holding an older pointer.

`Teardown()` is not presently verifiable either. The lower implementation ignores errors from close, unpin, pinned-link loading, and pin removal; only final `RemoveAll` propagates ([loader.go:1223](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:1223)). Error aggregation and kernel/pin readback are required. On failure, the cleanup owner must be retained for retry; setting `d.dp=nil` would again discard the only owner capable of cleanup.

## 5. The tests do not bind the dangerous seams

The proposed test suite still encodes the flawed historical boolean as desired behavior ([plan.md:417](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:417)). Required missing cases include:

- A armed, add B, B attach fails.
- Empty config, remove-all→add, and hitless survivor with real coverage readback.
- Raw attach sentinel through both local `applyAndSyncCommitted` and inbound `syncAndApply`; the classifier only receives an `error`, so first-arm needs a distinct contextual terminal error ([daemon_apply_commit.go:303](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:303)).
- Barrier deletion/readback failure and blocked attach proving no pre-arm VIP/VRRP/RA output.
- Authenticated legacy/new heartbeat goldens, manual-failover/readiness/hold precedence, config-skew/new-RG, and a real two-node handoff with blocked VIP/VRRP removal.
- Relay request and response races, blocked DDNS A/B wire operations, queued Kea work, and real pinned-link cleanup rather than only a recorder.
- Continuous v4/v6 traffic beginning before attach failure, including an established conntrack flow; final-state peer iperf does not prove absence of a transient leak.

The three-PR sequence introduces a new deployment problem: PR1 activates teardown and the drop barrier without publisher fencing or HA yield, and PR2 still lacks handoff. Those PRs are not independently safe on clustered systems unless activation remains feature-gated until the full invariant lands.

So: r3 fixed the conceptual detection location, chose the right routed-transit hook, recognized barrier-first ordering, expanded the publisher inventory, and acknowledged real teardown and test seams. It did not make current coverage, HA state, mixed-version handoff, publication linearization, or dataplane lifetime coherent. Most round-1 majors remain open in revised form.

VERDICT: PLAN-NEEDS-MAJOR
