# Codex hostile plan-review r3 (#5275) — VERDICT: PLAN-NEEDS-MAJOR

Reviewed plan.md @ r4. Final synthesis (file-read dumps stripped):


Bootstrap exposes both sides of the contradiction:

- The backend remains constructed but unarmed, so `!dataplaneArmFailed` would start phase-5 consumers before first arm.
- A real positive-proof gate would correctly suppress them, but `runBootstrapExitStartup` only performs naming, forwarding, `dp.Start`, seeding, and NAT-monitor startup; it does not start the gated cluster/GC/event/relay/DDNS/reconcile machinery ([daemon_run_naming.go:200](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:200)). Successful bootstrap exit would leave the node permanently half-started.

A reusable, idempotent `startTakeoverMachinery` lifecycle callable after actual coverage is required. A flag around the existing boot section is insufficient.

The claimed “config-less HA first commit” is also not a current path: constructing an HA runtime after boot is explicitly rejected as restart-required ([cluster_topology_preflight.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/cluster_topology_preflight.go:24)).

Committed-empty and remove-all transitions remain holes. An empty attachment set succeeds ([loader.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:211)), and committed-empty boots are classified as normal/full takeover ([bootstrap.go:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/bootstrap.go:164)). Machinery then starts without non-vacuous coverage; a later first data-interface attach failure happens after machinery is running. Removing all interfaces and later adding one creates the same state. r4 dropped the required empty→nonempty and remove-all→add tests.

### 4. Critical — hitless coverage and forwarding quarantine are unsafe

The hitless-survivor argument is incorrect. `ProbeForwardingArmed` proves only the helper’s global `Enabled && ForwardingArmed` flags ([boot_probe.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/boot_probe.go:24)). It proves neither expected interface coverage nor program identity.

Worse, the next compile deliberately deletes every `xdp_*` link pin before attempting fresh attachment ([manager_compile.go:162](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:162)). On process restart those pins may be the last references preserving the old links. The pre-compile probe can therefore say “covered,” the compile can destroy that coverage, and a subsequent attach failure can leave the node with neither old nor new protection. Treating the historical probe as surviving coverage recreates #5275.

The report must verify, after any failed mutation:

- the expected shim program ID/tag, not merely “some live XDP program”;
- mode and interface identity for every required surface;
- candidate/config digest and helper snapshot generation;
- exact armed/registered bindings;
- current kernel state, with readback failure meaning unarmed.

Forwarding quarantine is similarly reactive. Moving `enableForwarding` does not establish `ip_forward=0`; a service restart can inherit forwarding already enabled. Interface compilation also creates/addresses VLANs and brings links up before XDP attachment ([compiler_iface.go:350](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:350), [compiler_iface.go:521](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:521)). Disabling forwarding after attachment failure leaves a real unpoliced interval.

A verified IPv4/IPv6 forwarding disable or unconditional FORWARD barrier must be mandatory before destructive unpin/interface mutation and released only after coverage proof. The nft barrier cannot remain “optional” if sysctl disable/readback fails.

### 5. Major — teardown retention resurrects the dataplane-lifetime problem

Aggregated teardown errors and readback are good requirements, but retaining `d.dp` while management starts is unsafe. gRPC, REST, CLI, and the forwarding sampler all receive or dereference that backend ([daemon_run_servers.go:78](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_servers.go:78), [daemon_run.go:578](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:578)). The gRPC/CLI runtime interfaces expose mutators including `SetForwardingArmed`, queue state, and binding state ([server_diag_system_action.go:396](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/grpcapi/server_diag_system_action.go:396)).

That means the retained half-torn cleanup owner remains operationally reachable and can be re-armed. Cleanup ownership must live in a separate quarantined field while the published operational dataplane is unavailable.

The lower contract must also preserve each failed resource handle for retry. Current teardown ignores link-close, unpin, pinned-link-load, and pin-removal failures ([loader.go:1203](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:1203)). Retaining only the outer object is useless if the lower layer has already discarded the sole handle.

Finally, “sticky until restart” has no apply-admission design. A later management commit can re-enter `applyConfigLocked`: with `d.dp=nil`, it can continue publishing FRR/VRRP/services without enforcement; with teardown debt, it can invoke the half-torn backend. This is a new problem introduced by preserving management while gating only startup.

### 6. Major — day-2 scoping is not yet a decision and option (a) is insufficient

Deferring pure A-covered/add-B expansion can be legitimate only if the plan explicitly narrows #5275, creates a concrete security follow-up, and proves A remains continuously protected. “Decide at `/engineer`” is not an approved design decision.

It cannot be deferred for bootstrap-exit, committed-empty→first-interface, or remove-all→add: those are first-arm/no-prior-coverage cases inside r4’s own scope.

Option (a) is also reactive. B has already been created, addressed, and brought up before attach fails. Bringing it down afterward leaves a forwarding window and no persistence against a retry bringing it up again. Current #5679 behavior records an ordinary apply error but continues the candidate tail ([daemon_apply_dataplane.go:138](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:138)), including VRRP and other services ([daemon_apply_tail.go:18](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_tail.go:18)). A folded fix requires pre-mutation quarantine of B and aborting candidate-specific downstream publication while retaining A’s old policy.

The proposed tests would currently pass while the vulnerability remains: they check phase-5 starts and absence of heartbeat, but not pre-arm election/direct VIP publication, RG0 authority, stale former-primary state, inherited forwarding, post-unpin hitless failure, second commits, or API access to a retained teardown owner.

r4 does improve three pieces: it identifies `ApplyConfig` as the real arm boundary, proposes a structured per-generation outcome, and requires a terminal pre-tail abort plus hardened teardown. Those pieces should survive. The asserted no-start boundary and the resulting claim that prior HA, publisher-completeness, and lifetime findings disappear do not.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
369,049
No. r4 is not ready. Its decisive structural premise is false, and that produces a concrete dual-owner failure in the default HA mode.

### 1. Critical — election and ownership publishing already start before ARM

`Run` executes `manager-init` before `dataplane-setup` ([daemon_run.go:143](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:143)). During manager initialization, the daemon already:

- starts `ipmon`;
- calls `cluster.UpdateConfig`, which immediately runs election;
- starts the cluster monitor and `watchClusterEvents`;
- starts kernel self-recovery;
- enables IP forwarding;
- starts the VRRP manager.

These are all visible at [daemon_run_bringup.go:155](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_bringup.go:155). `UpdateConfig` explicitly calls `electSingleNode` when no peer is alive ([group_state.go:125](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/group_state.go:125)).

A configured `preempt` RG therefore becomes Primary before AF_XDP setup. Its transition is buffered and then consumed by the already-launched watcher. Private RG election is the default ([compiler_system.go:1897](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/compiler_system.go:1897)), making direct-VIP mode active; the watcher adds VIPs/link-locals, starts per-RG RA/Kea services, and schedules GARP/NA ([daemon_ha.go:329](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:329), [daemon_ha_vip.go:162](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_vip.go:162)). In legacy VRRP mode it raises priority/forces master and schedules `UpdateInstances` on a 500 ms timer ([daemon_ha.go:314](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:314), [daemon_ha.go:398](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:398)).

So the proposed phase-5 gate is after the election and after ownership side effects. The failed node is neither passive nor wire-silent.

One narrow claim is correct: `startClusterComms` is the sole initial UDP heartbeat starter. `RestartHeartbeat` cannot bootstrap an absent heartbeat ([heartbeat_manager.go:191](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:191)). But heartbeat startup is not the election boundary. r4 conflates `UpdateConfig=election`, `watchClusterEvents=ownership publication`, and `startClusterComms=heartbeat/sync`.

### 2. Critical — a silent heartbeat can create dual ownership

A valid split-brain sequence is:

1. Failed-arm node boots a preempt RG.
2. Pre-arm `UpdateConfig` promotes it and the watcher publishes direct VIP/GARP/RA/Kea.
3. AF_XDP attach fails.
4. The phase-5 gate suppresses heartbeat, so the failed node never receives peer state and never demotes.
5. The healthy peer independently remains/becomes Primary.
6. Both nodes own the RG indefinitely.

No-RETH/direct-VIP mode makes this an actual external ownership conflict, not merely stale internal state.

Other cluster states also contradict “peer owns ALL RGs”:

- Fresh simultaneous non-preempt boot waits the hard 30-second never-seen grace, not the normal ~500 ms timeout ([heartbeat.go:58](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:58)).
- `electSingleNode` does not promote groups blocked by kernel-upgrade hold, disabled state, or zero weight ([election.go:405](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:405)).
- The peer can only take over RGs present in its own locally installed configuration. A failed candidate that added an RG but was deliberately not synced cannot be owned by the peer.
- RG0 remains dangerous. `clusterReadOnly` defaults false, and only a cluster transition changes it ([store.go:204](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store.go:204), [daemon_ha.go:438](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:438)). A fresh non-preempt Secondary produces no demotion transition, while a preempt Primary explicitly enables writes. The failed node and healthy peer can therefore both accept configuration changes.

Former-primary restart is also uncovered. Orderly shutdown explicitly removes direct VIPs and stops VRRP ([daemon_run_shutdown.go:175](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_shutdown.go:175)); a crash does not. The source already acknowledges persistent link-local state and relies on the reconcile loop to remove it ([daemon_ha.go:891](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:891)), but r4 suppresses that loop. FRR is an independent service that can advertise persisted configuration ([bootstrap.go:481](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/bootstrap.go:481)), and an old Kea unit is stopped only by an explicit reconcile, including `Apply(nil)` ([dhcpserver.go:239](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcpserver/dhcpserver.go:239)). “Do not start” cannot withdraw already-persistent publishers.

Thus the prior peer-yield, effective-ownership, and handoff findings are not dissolved.

### 3. Major — the arm-state and deferred-start lifecycle are incoherent

The plan first requires a positive transition:

`armPending → coverage verified → forwarding opened → armedOK`

But it later defines `armedOK` as `!dataplaneArmFailed` ([plan.md:127](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:127), [plan.md:143](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:143)). Those are not equivalent: before any arm attempt, failure is false, so the negative gate is open.

Bootstrap exposes both sides of the contradiction:

- The backend remains constructed but unarmed, so `!dataplaneArmFailed` would start phase-5 consumers before first arm.
- A real positive-proof gate would correctly suppress them, but `runBootstrapExitStartup` only performs naming, forwarding, `dp.Start`, seeding, and NAT-monitor startup; it does not start the gated cluster/GC/event/relay/DDNS/reconcile machinery ([daemon_run_naming.go:200](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_naming.go:200)). Successful bootstrap exit would leave the node permanently half-started.

A reusable, idempotent `startTakeoverMachinery` lifecycle callable after actual coverage is required. A flag around the existing boot section is insufficient.

The claimed “config-less HA first commit” is also not a current path: constructing an HA runtime after boot is explicitly rejected as restart-required ([cluster_topology_preflight.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/cluster_topology_preflight.go:24)).

Committed-empty and remove-all transitions remain holes. An empty attachment set succeeds ([loader.go:211](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:211)), and committed-empty boots are classified as normal/full takeover ([bootstrap.go:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/bootstrap.go:164)). Machinery then starts without non-vacuous coverage; a later first data-interface attach failure happens after machinery is running. Removing all interfaces and later adding one creates the same state. r4 dropped the required empty→nonempty and remove-all→add tests.

### 4. Critical — hitless coverage and forwarding quarantine are unsafe

The hitless-survivor argument is incorrect. `ProbeForwardingArmed` proves only the helper’s global `Enabled && ForwardingArmed` flags ([boot_probe.go:24](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/boot_probe.go:24)). It proves neither expected interface coverage nor program identity.

Worse, the next compile deliberately deletes every `xdp_*` link pin before attempting fresh attachment ([manager_compile.go:162](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:162)). On process restart those pins may be the last references preserving the old links. The pre-compile probe can therefore say “covered,” the compile can destroy that coverage, and a subsequent attach failure can leave the node with neither old nor new protection. Treating the historical probe as surviving coverage recreates #5275.

The report must verify, after any failed mutation:

- the expected shim program ID/tag, not merely “some live XDP program”;
- mode and interface identity for every required surface;
- candidate/config digest and helper snapshot generation;
- exact armed/registered bindings;
- current kernel state, with readback failure meaning unarmed.

Forwarding quarantine is similarly reactive. Moving `enableForwarding` does not establish `ip_forward=0`; a service restart can inherit forwarding already enabled. Interface compilation also creates/addresses VLANs and brings links up before XDP attachment ([compiler_iface.go:350](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:350), [compiler_iface.go:521](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:521)). Disabling forwarding after attachment failure leaves a real unpoliced interval.

A verified IPv4/IPv6 forwarding disable or unconditional FORWARD barrier must be mandatory before destructive unpin/interface mutation and released only after coverage proof. The nft barrier cannot remain “optional” if sysctl disable/readback fails.

### 5. Major — teardown retention resurrects the dataplane-lifetime problem

Aggregated teardown errors and readback are good requirements, but retaining `d.dp` while management starts is unsafe. gRPC, REST, CLI, and the forwarding sampler all receive or dereference that backend ([daemon_run_servers.go:78](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_servers.go:78), [daemon_run.go:578](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:578)). The gRPC/CLI runtime interfaces expose mutators including `SetForwardingArmed`, queue state, and binding state ([server_diag_system_action.go:396](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/grpcapi/server_diag_system_action.go:396)).

That means the retained half-torn cleanup owner remains operationally reachable and can be re-armed. Cleanup ownership must live in a separate quarantined field while the published operational dataplane is unavailable.

The lower contract must also preserve each failed resource handle for retry. Current teardown ignores link-close, unpin, pinned-link-load, and pin-removal failures ([loader.go:1203](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/loader.go:1203)). Retaining only the outer object is useless if the lower layer has already discarded the sole handle.

Finally, “sticky until restart” has no apply-admission design. A later management commit can re-enter `applyConfigLocked`: with `d.dp=nil`, it can continue publishing FRR/VRRP/services without enforcement; with teardown debt, it can invoke the half-torn backend. This is a new problem introduced by preserving management while gating only startup.

### 6. Major — day-2 scoping is not yet a decision and option (a) is insufficient

Deferring pure A-covered/add-B expansion can be legitimate only if the plan explicitly narrows #5275, creates a concrete security follow-up, and proves A remains continuously protected. “Decide at `/engineer`” is not an approved design decision.

It cannot be deferred for bootstrap-exit, committed-empty→first-interface, or remove-all→add: those are first-arm/no-prior-coverage cases inside r4’s own scope.

Option (a) is also reactive. B has already been created, addressed, and brought up before attach fails. Bringing it down afterward leaves a forwarding window and no persistence against a retry bringing it up again. Current #5679 behavior records an ordinary apply error but continues the candidate tail ([daemon_apply_dataplane.go:138](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:138)), including VRRP and other services ([daemon_apply_tail.go:18](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_tail.go:18)). A folded fix requires pre-mutation quarantine of B and aborting candidate-specific downstream publication while retaining A’s old policy.

The proposed tests would currently pass while the vulnerability remains: they check phase-5 starts and absence of heartbeat, but not pre-arm election/direct VIP publication, RG0 authority, stale former-primary state, inherited forwarding, post-unpin hitless failure, second commits, or API access to a retained teardown owner.

r4 does improve three pieces: it identifies `ApplyConfig` as the real arm boundary, proposes a structured per-generation outcome, and requires a terminal pre-tail abort plus hardened teardown. Those pieces should survive. The asserted no-start boundary and the resulting claim that prior HA, publisher-completeness, and lifetime findings disappear do not.

VERDICT: PLAN-NEEDS-MAJOR
