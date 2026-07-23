# Codex hostile plan-review r1 (#5275) — VERDICT: PLAN-NEEDS-MAJOR

Reviewed plan.md @ r2. Final synthesis (file-read dumps stripped):

- DHCP relay is a per-packet user-space forwarder, not merely a control-plane reader. The package says it forwards DHCPv4 between clients and servers at [relay.go:1](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1). Standalone and RG0 gates are always open at [daemon_dhcp.go:334](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_dhcp.go:334), and it starts independently from `ActiveConfig` after the boot apply at [daemon_run.go:449](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:449). It bypasses `ip_forward=0`.
- Direct/no-RETH VIP ownership and scheduled GARP/NA bursts are absent from the table. They are separate from proxy ARP and are managed at [daemon_ha_vip.go:162](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_vip.go:162).
- Table row 9 is wrong. Cluster RA has a direct authoritative reconciler at [daemon_ra_reconcile.go:13](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ra_reconcile.go:13) and is periodically re-driven at [daemon_ha.go:962](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:962). Removing VRRP instances does not emit a BACKUP ownership event, so stale owner state can re-arm RA.
- DDNS Surface A explicitly publishes the firewall’s own addresses at [daemon_ddns_surface_a.go:142](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns_surface_a.go:142), while its node gate is always open standalone at [daemon_ddns.go:332](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns.go:332). Either gate it or narrow G7 and justify why advertising a failed data address is safe.
- Kea DHCP service can be started by ownership events and can advertise this node as clients’ router. It at least needs explicit threat-model treatment and tests; it cannot be silently covered by the table’s “daemon_dhcp (relay)” parenthetical.
- The two direct `enableForwarding()` sites are also missing from a table that lists only `applyKernelTuning`.

Session sync, SNMP, neighbor prewarming, and fabric state may legitimately remain outside the ownership set, but that requires lifecycle proof. Saying they become no-ops after an unsynchronized `d.dp=nil` is not such proof.

The canary architecture is circular: a table or registry containing known publishers cannot detect an unregistered new publisher. It becomes future-proof only if publication sinks are inaccessible except through a mandatory frozen-aware façade or enforceable static rule.

An atomic predicate is also not a publication barrier. A 500 ms callback can read “not frozen,” the handler can freeze and withdraw, and the callback can then republish. The existing timer callback at [daemon_ha.go:398](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:398) has exactly that shape. Freeze and final withdrawal need a shared lock, epoch/generation check at the sink, or cancellation-and-join discipline.

## 5. Teardown ordering is not safe

Relinquishing ownership before waiting on the slow FRR reload is directionally correct. The rest of §7 is not.

- The claimed “~1 ms” is only the peer’s VRRP takeover timer after receiving a priority-0 packet. It excludes local stop latency, packet loss, heartbeat delay, readiness, and direct-VIP actuation. It is not an end-to-end handoff bound or ACK.
- `UpdateInstances(nil)` synchronously waits for each instance goroutine at [instance.go:1382](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:1382). Because `disableForwarding` runs afterward, a stuck stop leaves unpoliced forwarding enabled indefinitely.
- VRRP VIP-removal failure is only logged at [instance.go:991](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:991); `UpdateInstances(nil)` does not prove the VIP is absent.
- FRR’s nominal worst case is approximately 40 seconds, but a degraded reload leaves stale removals pending on retries at [manager.go:540](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:540). Routes may therefore continue attracting traffic long after forwarding is disabled. “Drops nothing” is false.
- For a fail-closed security invariant, knowingly preferring an unpoliced interval over a blackhole is the wrong default. If availability requires lossless transfer, establish pre-arm quarantine or use an acknowledged handoff; do not postpone the local security barrier after failure detection.

The handler also lacks an actual dataplane teardown. The attach loop can attach/pin interface A and then fail on B at [loader.go:217](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:217). Setting `d.dp=nil` loses the only cleanup owner and leaves partial XDP links/pins. The first-arm path must install a local drop barrier, stop/join background consumers, call and verify `Teardown`, then safely publish the nil backend.

Bootstrap exit makes this immediately racy: it starts the NAT alarm monitor after `Start()` but before real attachment at [daemon_run_naming.go:240](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:240); its sampler reads `d.dp` concurrently at [daemon_natpoolalarm.go:16](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_natpoolalarm.go:16). The plan neither stops/joins that monitor nor defines synchronized backend replacement.

Readback and management-interface exclusion improve `disableForwarding`, but link-down escalation remains underspecified:

- Read/parse failure must itself mean unsafe.
- `resolveProtectedInterfaces` is only an exclusion set, not an exhaustive inventory of data VLANs, tunnels, xfrmi, bridges, RETH members, and fabric surfaces.
- Link-down failure and readback are not handled.
- Nothing prevents networkd or another reconciler from bringing the link back up.

A verified kernel FORWARD-drop barrier would be much more credible than attempting to infer a complete transit topology during an emergency.

## Tests do not bind the fix

The proposed tests would pass while the vulnerabilities above remain:

- Toggling a fake `dataplaneEverArmed` proves no real interface coverage.
- Directly testing `electRG` bypasses readiness, heartbeat transport, and daemon ownership actuation.
- A recorder verifies call order, not that VIPs/routes were actually withdrawn or the peer became primary.
- The publisher canary cannot discover an omitted sink.
- Allowing the real attach-failure injection seam to land as a later harness follow-up means the required smoke test is not runnable with the fix.

At minimum, the plan needs binding tests for:

- Old interface A armed; add B; B attach fails; A retains old policy while B is down/unaddressed/unadvertised.
- Empty-to-first-nonempty, remove-all-then-add, config-less HA first config, and hitless-restart cases.
- Partial multi-interface attach cleanup.
- Both commit wrappers’ local-live/session-clear/peer-sync behavior.
- Already-secondary and newly added RGs, all direct state writers, peer manual-failover, readiness, and full heartbeat-driven election.
- Direct VIP/GARP, cluster RA, DHCP relay, and in-flight timer-after-freeze races.
- Bootstrap-exit teardown under the race detector.
- Sysctl read failure, link-down failure, re-up attempts, VRRP withdrawal failure, and degraded FRR withdrawal.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
453,160
I reviewed the current revision at `71ee8d40946d`. It fails review. The proposed A3/B1 architecture does not establish G3, G4, G5, or G7.

Three narrow claims are correct:

- Returning an attach sentinel as the terminal `err` from `applyDataplaneAndHACore` really would skip the remaining core, routing, services, and tail publishers.
- Native attach failure followed by generic attach success returns nil and must count as armed.
- A bare weight-zero yield is unsafe because `recalcWeight` can overwrite it.

Those points do not rescue the plan.

## 1. Detection and day-2 semantics are architecturally wrong

### `dataplaneEverArmed` is the wrong state variable

A historical boolean cannot answer the required question: “Does the currently live old policy cover every currently forwarding surface?”

Concrete failures:

- Empty configurations return attach success with zero pending interfaces at [loader.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:211). Unless explicitly non-vacuous, that marks a node “ever armed” without attaching anything. Its first real attach failure is then incorrectly treated as day-2.
- After a successful configuration removes all data interfaces, `syncInterfaceAttachments` detaches the old XDP links at [manager_compile.go:567](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:567), but the sticky boolean remains true. A later first-real-interface failure is again misclassified as protected day-2.
- On a daemon restart, the inverse occurs: the process-local boolean starts false even if a surviving helper and old policy are genuinely forwarding. The repository already has an authoritative `Enabled && ForwardingArmed` restart probe for exactly that distinction at [boot_probe.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/boot_probe.go:24).

Most importantly, an in-process day-2 attach failure normally concerns a newly required interface because existing links return “already attached” at [loader.go:221](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:221). Before that failure, compilation may already create VLAN devices, assign addresses, and change MTUs at [compiler_iface.go:350](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:350) and [compiler_iface.go:572](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:572). The plan then deliberately treats the error as ordinary deferred and continues publication under the new config ([plan.md:183](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:183)).

That preserves the old Rust snapshot on old interfaces, but leaves the new interface without XDP while publishing new FRR/VRRP/service state. It recreates #5275 on the added surface.

Preserving #5679 means:

- Keep the old dataplane generation alive.
- Abort the candidate’s downstream publication.
- Roll back or quarantine every newly introduced/uncovered surface.

It does not mean “run the new tail because some policy was armed once.” This requires a generation- and interface-scoped arm result, not a global boolean.

### `ForwardingArmed()` is underspecified

The proposed no-argument boolean does not define:

- Which configuration generation it proves.
- The authoritative required-interface set.
- How intentionally skipped VLAN children versus generic tunnel attachments are represented.
- Whether missing configured interfaces count as unarmed.
- Whether it verifies actual kernel program identity or merely an entry in `m.xdpLinks`.
- What query/read failure means.
- Whether an empty required set is armed.

The test only fakes the boolean. It would not bind any of these requirements. A structured arm report returned with `ApplyResult` or the attach error—generation, required set, attached set, mode, and newly attached set—is the minimum credible contract.

### A2 has contradictory placement

The revised plan correctly says detection belongs inside the apply pipeline because `applyConfig` is void ([plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:166)), but A2/A3 still places the positive check “at the two arm sites” ([plan.md:198](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:198), [plan.md:209](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:209)).

At bootstrap exit, `runBootstrapExitStartup` calls only `Start()` at [daemon_run_naming.go:230](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:230); the actual `ApplyConfig` happens later in the surrounding `applyConfigLocked`. There is no completed apply to inspect at that “arm site.” A config-less HA node receiving its first config is a third first-arm path, also missed by site-scoped A2.

The positive check must occur immediately after the exact `d.dp.ApplyConfig` returns nil, inside `applyDataplaneAndHACore`, before any later publication.

### “Terminal” stops the inner pipeline, not the transaction

The plan omits `daemon_apply_commit.go`. `applyErrSkipsPeerSync` recognizes only required-protocol errors and context cancellation at [daemon_apply_commit.go:290](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:290). The new sentinel would therefore fall through code whose stated invariant is “the dataplane is armed,” clear sessions, and potentially push the candidate to the peer at [daemon_apply_commit.go:245](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:245). `syncAndApply` similarly sets `armedActive=true` at [daemon_apply_commit.go:451](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:451).

Blindly adding the sentinel to `applyErrSkipsPeerSync` is not necessarily correct either: a healthy peer may need the valid config when attachment failed only on this node. The plan needs separate outcomes for:

- Candidate live locally.
- Session invalidation safe locally.
- Candidate safe/desirable to propagate to the peer.
- Old dataplane retained versus global first-arm teardown.

### A1 is reactive, not “prevent-the-publish”

Normal boot enables forwarding before dataplane `Start`/Apply at [daemon_run_bringup.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:211). Bootstrap exit explicitly enables it before `Start` and the later attach at [daemon_run_naming.go:225](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:225). Cluster configuration, election, and event watching also begin before dataplane setup at [daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:161).

Therefore the claim that A1 means “no ownership is ever published” is false. Cold first-arm operation needs a pre-arm forwarding/ownership quarantine installed before cluster election and `enableForwarding`, released only after positive arm proof.

## 2. `StateSecondaryHold` B1 is not a sufficient HA signal

The peer-side branch at [election.go:165](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:165) is real, but B1 does not reliably put or keep the failed node in that state.

- The reused `SetArmFailedHold` changes only already-primary groups. New and already-secondary groups remain ordinary secondary. New RGs are initialized as `StateSecondary` at [group_state.go:23](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:23), while the proposed arm-failed election gate returns no-change. Their heartbeat therefore advertises ordinary secondary, recreating the higher-priority-failed-node both-secondary problem.
- It is not “naturally sticky.” `ForceSecondary` writes ordinary secondary at [failover.go:140](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/failover.go:140); single and batch transfer finalization do likewise at [failover.go:464](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/failover.go:464) and [failover.go:840](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/failover.go:840). The arm election gate then preserves the overwritten ordinary-secondary state.
- The claim that this avoids the manual-failover machine is false from the peer’s perspective. A healthy peer with pre-existing `ManualFailover` executes the dual-resign guard at [election.go:67](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:67) before it reaches the peer-hold branch. Both nodes can remain secondary for the two-second guard and longer if readiness blocks promotion at [election.go:322](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:322).
- `StateSecondaryHold` has non-VIP side effects the plan ignores. RG0 transition handling treats it as a demotion and automatically confirms any pending `commit confirmed` at [daemon_ha.go:466](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:466). Reusing this state during a failed first-arm commit can therefore confirm the configuration whose arm just failed.

The weight-zero rejection is directionally correct: `recalcWeight` overwrites weight at [election.go:496](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:496). The plan’s “every monitor tick” wording is inaccurate—it occurs on relevant recalculations—but B2 remains unsafe.

B1 needs either a distinct arm-failed wire signal or a central advertised-state override that applies to every current/future RG and every direct state writer. Mixed-version behavior must be designed, not assumed.

## 3. Peer-yield is not an ownership-handoff barrier

`SetArmFailedHold()` mutates local state; it does not prove that ownership transferred.

- State reaches the peer only on the periodic heartbeat ticker, normally 100 ms, at [heartbeat.go:52](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:52) and [heartbeat.go:708](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:708).
- Promotion can be rejected by readiness.
- Local demotion actuation is asynchronous through `watchClusterEvents` at [daemon_ha.go:263](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:263).
- In no-RETH/direct-VIP mode, `vrrpMgr.UpdateInstances(nil)` removes nothing; direct VIP removal occurs only when the asynchronous cluster event reaches [daemon_ha.go:375](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:375).
- Consequently, the peer can promote before local direct VIP removal—dual ownership—or forwarding can be disabled before peer promotion—blackhole.

The existing coordinated transfer machinery explicitly waits for demotion actuation. This plan provides no equivalent completion/ACK barrier.

## 4. Publisher completeness is false

The new explicit exclusions make the problem worse because at least one is factually wrong.

- DHCP relay is a per-packet user-space forwarder, not merely a control-plane reader. The package says it forwards DHCPv4 between clients and servers at [relay.go:1](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcprelay/relay.go:1). Standalone and RG0 gates are always open at [daemon_dhcp.go:334](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_dhcp.go:334), and it starts independently from `ActiveConfig` after the boot apply at [daemon_run.go:449](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:449). It bypasses `ip_forward=0`.
- Direct/no-RETH VIP ownership and scheduled GARP/NA bursts are absent from the table. They are separate from proxy ARP and are managed at [daemon_ha_vip.go:162](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_vip.go:162).
- Table row 9 is wrong. Cluster RA has a direct authoritative reconciler at [daemon_ra_reconcile.go:13](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ra_reconcile.go:13) and is periodically re-driven at [daemon_ha.go:962](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:962). Removing VRRP instances does not emit a BACKUP ownership event, so stale owner state can re-arm RA.
- DDNS Surface A explicitly publishes the firewall’s own addresses at [daemon_ddns_surface_a.go:142](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns_surface_a.go:142), while its node gate is always open standalone at [daemon_ddns.go:332](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ddns.go:332). Either gate it or narrow G7 and justify why advertising a failed data address is safe.
- Kea DHCP service can be started by ownership events and can advertise this node as clients’ router. It at least needs explicit threat-model treatment and tests; it cannot be silently covered by the table’s “daemon_dhcp (relay)” parenthetical.
- The two direct `enableForwarding()` sites are also missing from a table that lists only `applyKernelTuning`.

Session sync, SNMP, neighbor prewarming, and fabric state may legitimately remain outside the ownership set, but that requires lifecycle proof. Saying they become no-ops after an unsynchronized `d.dp=nil` is not such proof.

The canary architecture is circular: a table or registry containing known publishers cannot detect an unregistered new publisher. It becomes future-proof only if publication sinks are inaccessible except through a mandatory frozen-aware façade or enforceable static rule.

An atomic predicate is also not a publication barrier. A 500 ms callback can read “not frozen,” the handler can freeze and withdraw, and the callback can then republish. The existing timer callback at [daemon_ha.go:398](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:398) has exactly that shape. Freeze and final withdrawal need a shared lock, epoch/generation check at the sink, or cancellation-and-join discipline.

## 5. Teardown ordering is not safe

Relinquishing ownership before waiting on the slow FRR reload is directionally correct. The rest of §7 is not.

- The claimed “~1 ms” is only the peer’s VRRP takeover timer after receiving a priority-0 packet. It excludes local stop latency, packet loss, heartbeat delay, readiness, and direct-VIP actuation. It is not an end-to-end handoff bound or ACK.
- `UpdateInstances(nil)` synchronously waits for each instance goroutine at [instance.go:1382](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:1382). Because `disableForwarding` runs afterward, a stuck stop leaves unpoliced forwarding enabled indefinitely.
- VRRP VIP-removal failure is only logged at [instance.go:991](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/vrrp/instance.go:991); `UpdateInstances(nil)` does not prove the VIP is absent.
- FRR’s nominal worst case is approximately 40 seconds, but a degraded reload leaves stale removals pending on retries at [manager.go:540](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/frr/manager.go:540). Routes may therefore continue attracting traffic long after forwarding is disabled. “Drops nothing” is false.
- For a fail-closed security invariant, knowingly preferring an unpoliced interval over a blackhole is the wrong default. If availability requires lossless transfer, establish pre-arm quarantine or use an acknowledged handoff; do not postpone the local security barrier after failure detection.

The handler also lacks an actual dataplane teardown. The attach loop can attach/pin interface A and then fail on B at [loader.go:217](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:217). Setting `d.dp=nil` loses the only cleanup owner and leaves partial XDP links/pins. The first-arm path must install a local drop barrier, stop/join background consumers, call and verify `Teardown`, then safely publish the nil backend.

Bootstrap exit makes this immediately racy: it starts the NAT alarm monitor after `Start()` but before real attachment at [daemon_run_naming.go:240](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:240); its sampler reads `d.dp` concurrently at [daemon_natpoolalarm.go:16](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_natpoolalarm.go:16). The plan neither stops/joins that monitor nor defines synchronized backend replacement.

Readback and management-interface exclusion improve `disableForwarding`, but link-down escalation remains underspecified:

- Read/parse failure must itself mean unsafe.
- `resolveProtectedInterfaces` is only an exclusion set, not an exhaustive inventory of data VLANs, tunnels, xfrmi, bridges, RETH members, and fabric surfaces.
- Link-down failure and readback are not handled.
- Nothing prevents networkd or another reconciler from bringing the link back up.

A verified kernel FORWARD-drop barrier would be much more credible than attempting to infer a complete transit topology during an emergency.

## Tests do not bind the fix

The proposed tests would pass while the vulnerabilities above remain:

- Toggling a fake `dataplaneEverArmed` proves no real interface coverage.
- Directly testing `electRG` bypasses readiness, heartbeat transport, and daemon ownership actuation.
- A recorder verifies call order, not that VIPs/routes were actually withdrawn or the peer became primary.
- The publisher canary cannot discover an omitted sink.
- Allowing the real attach-failure injection seam to land as a later harness follow-up means the required smoke test is not runnable with the fix.

At minimum, the plan needs binding tests for:

- Old interface A armed; add B; B attach fails; A retains old policy while B is down/unaddressed/unadvertised.
- Empty-to-first-nonempty, remove-all-then-add, config-less HA first config, and hitless-restart cases.
- Partial multi-interface attach cleanup.
- Both commit wrappers’ local-live/session-clear/peer-sync behavior.
- Already-secondary and newly added RGs, all direct state writers, peer manual-failover, readiness, and full heartbeat-driven election.
- Direct VIP/GARP, cluster RA, DHCP relay, and in-flight timer-after-freeze races.
- Bootstrap-exit teardown under the race detector.
- Sysctl read failure, link-down failure, re-up attempts, VRRP withdrawal failure, and degraded FRR withdrawal.

VERDICT: PLAN-NEEDS-MAJOR
