# Codex hostile plan-review r8 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (D1-D4 correct; D5 crash-restart dual-VIP + live interlock)

Reviewed plan.md @ r9 §13-D5. Final synthesis (file-read dumps stripped):


   The fatal sequence is:

   1. Primary `xpfd` crashes; kernel VIPs, stable link-locals, Kea, FRR, XDP state, and the userspace helper can survive.
   2. The peer may time out after the valid `1 ms × 1` configuration and calls `electSingleNode()` before attempting any fence ([schema_chassis.go:74](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74), [heartbeat_manager.go:358](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:358), [heartbeat_manager.go:425](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:425)).
   3. The replacement daemon has not necessarily started. Its later synchronous scrub cannot retroactively close the peer-promotion-to-restart interval. If restart never happens, the stale VIP is indefinite.

   During that interval, the old node has not advertised weight zero and the startup barrier does not yet exist. Existing watchdogs are too slow and do not remove ownership: BPF expires after more than two seconds, while the userspace lease is ten seconds ([xpf_helpers.h:2382](/home/ps/git/bpfrx/.claude/worktrees/5275-research/bpf/headers/xpf_helpers.h:2382), [runtime.rs:357](/home/ps/git/bpfrx/.claude/worktrees/5275-research/userspace-dp/src/afxdp/types/runtime.rs:357)). Source explicitly recognizes preserved addresses as duplicate-address and ECMP hazards ([instance_vip.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance_vip.go:24), [daemon_ha.go:910](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:910)).

   Therefore [D5’s claim](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:473) that there is “no dual ownership” is false. The peer takeover is desirable, but it must be delayed behind an independent, bounded ownership fence or lease—not behind cleanup performed by a process that may not be running.

2. **Asynchronous Kea is not harmless teardown debt.**

   The §6 barrier covers transit forwarding, not locally terminated/originated DHCP traffic. Source explicitly requires Kea to run only on Primary to prevent dual DHCP and recognizes that a previous `xpfd` may leave it running ([daemon_ha.go:1181](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:1181), [dhcpserver.go:126](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcpserver/dhcpserver.go:126)). Letting the peer activate Kea before the old service is stopped or packet-fenced creates two DHCP authorities.

   FRR is similarly not merely bookkeeping: it can restart with persisted advertisements and continue attracting traffic to the fenced node, producing a potentially indefinite blackhole ([bootstrap.go:481](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/bootstrap.go:481), [manager.go:824](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:824)).

   This also directly contradicts §3 and §12, which still require verified VIP/RA/Kea/FRR withdrawal or verified fallback before takeover/yield ([plan.md:95](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:95), [plan.md:383](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:383)).

3. **The shipped live guard is not a promotion interlock.**

   `shouldSuppressPeerHeartbeatTimeout` guards only the timeout path. A received weight-zero heartbeat immediately runs election without consulting it ([heartbeat_manager.go:293](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:293)). Therefore zero publication must itself be gated on completed VIP/service fencing.

   Further:

   - `SendLivenessKeepalive` is best-effort, has no acknowledgement, and silently no-ops without a connection ([sync_conn_write.go:230](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync_conn_write.go:230)).
   - Suppression ends on disconnect or after five seconds regardless of fencing completion ([daemon_ha_sync.go:139](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:139)).
   - The claimed self-clearing episode semantics are false: `hbSuppressStart` is not reset when ordinary UDP heartbeats recover.
   - “Authenticated keepalive” is conditional; legacy/unkeyed session sync remains unauthenticated ([sync_auth.go:21](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync_auth.go:21)).

   §2 also defines no `armed → fencing/re-arm → armed|failed` state transition, failure detector, or crash-mid-fence behavior for D5’s newly introduced live re-arm path.

### D1 and D4

Both wording fixes are correct:

- D1 now correctly separates preliminary attachment/instance proof from final digest, helper-generation, and ready-binding proof ([plan.md:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:164)).
- D4’s durably staged recovery receipt correctly avoids advancing the live-applied generation or using current `SyncApply` semantics ([plan.md:450](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:450)).

Minor residue: §13 claims facade OPEN was inserted into §5’s ordered release inventory, but §5 still omits it.

A safe D5 needs a peer activation gate backed by either verified external fencing or a conservative node-independent lease covering VIP, DHCP/service traffic, routing attraction, and forwarding. The live path needs an acknowledged suppression lease established before fencing, with zero advertisement permitted only after verified fast withdrawal. A dead node must still promote after that bounded lease expires. Then §3, §12, RA/stable-link-local handling, and the live re-arm state machine must be reconciled.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
281,067
No. r9 fixes D1/D4, but D5 still lacks the crash-side interlock required by r7. It preserves failover liveness by sacrificing ownership safety.

### Blocking findings

1. **Crash-restart still permits dual VIP and forwarding.**

   The fatal sequence is:

   1. Primary `xpfd` crashes; kernel VIPs, stable link-locals, Kea, FRR, XDP state, and the userspace helper can survive.
   2. The peer may time out after the valid `1 ms × 1` configuration and calls `electSingleNode()` before attempting any fence ([schema_chassis.go:74](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74), [heartbeat_manager.go:358](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:358), [heartbeat_manager.go:425](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:425)).
   3. The replacement daemon has not necessarily started. Its later synchronous scrub cannot retroactively close the peer-promotion-to-restart interval. If restart never happens, the stale VIP is indefinite.

   During that interval, the old node has not advertised weight zero and the startup barrier does not yet exist. Existing watchdogs are too slow and do not remove ownership: BPF expires after more than two seconds, while the userspace lease is ten seconds ([xpf_helpers.h:2382](/home/ps/git/bpfrx/.claude/worktrees/5275-research/bpf/headers/xpf_helpers.h:2382), [runtime.rs:357](/home/ps/git/bpfrx/.claude/worktrees/5275-research/userspace-dp/src/afxdp/types/runtime.rs:357)). Source explicitly recognizes preserved addresses as duplicate-address and ECMP hazards ([instance_vip.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance_vip.go:24), [daemon_ha.go:910](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:910)).

   Therefore [D5’s claim](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:473) that there is “no dual ownership” is false. The peer takeover is desirable, but it must be delayed behind an independent, bounded ownership fence or lease—not behind cleanup performed by a process that may not be running.

2. **Asynchronous Kea is not harmless teardown debt.**

   The §6 barrier covers transit forwarding, not locally terminated/originated DHCP traffic. Source explicitly requires Kea to run only on Primary to prevent dual DHCP and recognizes that a previous `xpfd` may leave it running ([daemon_ha.go:1181](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:1181), [dhcpserver.go:126](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcpserver/dhcpserver.go:126)). Letting the peer activate Kea before the old service is stopped or packet-fenced creates two DHCP authorities.

   FRR is similarly not merely bookkeeping: it can restart with persisted advertisements and continue attracting traffic to the fenced node, producing a potentially indefinite blackhole ([bootstrap.go:481](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/bootstrap.go:481), [manager.go:824](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:824)).

   This also directly contradicts §3 and §12, which still require verified VIP/RA/Kea/FRR withdrawal or verified fallback before takeover/yield ([plan.md:95](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:95), [plan.md:383](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:383)).

3. **The shipped live guard is not a promotion interlock.**

   `shouldSuppressPeerHeartbeatTimeout` guards only the timeout path. A received weight-zero heartbeat immediately runs election without consulting it ([heartbeat_manager.go:293](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:293)). Therefore zero publication must itself be gated on completed VIP/service fencing.

   Further:

   - `SendLivenessKeepalive` is best-effort, has no acknowledgement, and silently no-ops without a connection ([sync_conn_write.go:230](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync_conn_write.go:230)).
   - Suppression ends on disconnect or after five seconds regardless of fencing completion ([daemon_ha_sync.go:139](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:139)).
   - The claimed self-clearing episode semantics are false: `hbSuppressStart` is not reset when ordinary UDP heartbeats recover.
   - “Authenticated keepalive” is conditional; legacy/unkeyed session sync remains unauthenticated ([sync_auth.go:21](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/sync_auth.go:21)).

   §2 also defines no `armed → fencing/re-arm → armed|failed` state transition, failure detector, or crash-mid-fence behavior for D5’s newly introduced live re-arm path.

### D1 and D4

Both wording fixes are correct:

- D1 now correctly separates preliminary attachment/instance proof from final digest, helper-generation, and ready-binding proof ([plan.md:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:164)).
- D4’s durably staged recovery receipt correctly avoids advancing the live-applied generation or using current `SyncApply` semantics ([plan.md:450](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:450)).

Minor residue: §13 claims facade OPEN was inserted into §5’s ordered release inventory, but §5 still omits it.

A safe D5 needs a peer activation gate backed by either verified external fencing or a conservative node-independent lease covering VIP, DHCP/service traffic, routing attraction, and forwarding. The live path needs an acknowledged suppression lease established before fencing, with zero advertisement permitted only after verified fast withdrawal. A dead node must still promote after that bounded lease expires. Then §3, §12, RA/stable-link-local handling, and the live re-arm state machine must be reconciled.

VERDICT: PLAN-NEEDS-MAJOR
