# Failover Hardening Progress

Date: March 30, 2026

This document is the current checkpoint for the userspace HA investigation.
It replaces older optimistic notes that no longer match the live lab.

## Current baseline

Branch under test:

- `fix/per-interface-xdp-fallback`

Current head:

- `cb86dfa4` `docs: consolidate March 30 failover findings`

Cluster baseline after restore:

- `node0` primary for `RG0/1/2`
- `node1` secondary for `RG0/1/2`
- both nodes `Takeover ready: yes`

## What was actually fixed

### 1. XDP attach-mode / AF_XDP bind-mode mismatch

This was a real steady-state forwarding bug.

Problem:

- one interface could fail native XDP attach and force the whole box into
  `xdpgeneric`
- the helper still chose AF_XDP zero-copy vs copy mode from NIC driver name
  rather than the actual XDP attach mode
- on generic `mlx5`, the helper could take the wrong bind path and steady-state
  forwarding to `172.16.80.200` broke

Fixes:

- `#294` / PR `#295`
  - helper bind mode now follows actual XDP attach mode via `bpf_xdp_query()`
- `#293` / PR `#296`
  - native-to-generic fallback is now per-interface instead of global

Validated result:

- steady-state forwarding to `172.16.80.200` works again on the HA lab
- native interfaces remain native where possible
- generic interfaces bind in copy mode instead of trying the native/zero-copy
  path

Related doc:

- [userspace-xdp-mode-and-cold-start-findings.md](userspace-xdp-mode-and-cold-start-findings.md)

### 2. Reverse-session activation prewarm

This is a real narrowing fix for the HA failover path.

Problem before the fix:

- first manual `RG1` failover under `iperf3 -P 8` produced a large new-owner
  `session_miss` burst
- redirected traffic reached the new owner, but inherited state was not ready
  enough to carry it

Fix:

- `c84c35c7` `userspace: prewarm reverse sessions for activated RGs`
- reverse-session activation prewarm now considers the activated owner RG on
  both the forward entry and the synthesized reverse companion

Validated result:

- the large new-owner `session_miss` storm is gone on the first failover
- cluster ownership remains stable after the manual move
- the inherited flow still collapses, but the failure signature is now much
  narrower and better understood

### 3. Demotion-prep timeout and stuck-demoting recovery

This pass fixed two helper-side HA bugs.

Problem A:

- `PrepareRGDemotion` could time out at the daemon/manager layer even after the
  helper worker had already processed the demotion-prep request
- root cause: worker `demotion_prepare_ack` was only published after draining
  pending session deltas, so unrelated delta churn could delay the ack

Problem B:

- if the prepare timed out after the helper had already marked an owner RG as
  demoting, the still-primary helper could keep acting demoted

Fixes now in the local helper checkpoint:

- `demotion_prepare_ack` is published immediately after local worker demotion
  prep completes
- helper HA runtime carries a bounded demotion-prep lease instead of preserving
  `demoting=true` indefinitely on active groups
- HA resolution now treats demotion as active only while that lease is still
  valid

Validated result:

- the earlier failed-prepare repro no longer leaves the still-primary helper
  poisoned
- the same manual CLI move now admits cleanly on the clean build

## What is still open

### 1. Cold-start first-probe loss

This is separate from the XDP-mode fix.

Repro:

1. `RG1` primary on the owner node
2. delete the owner neighbor for `172.16.80.200`
3. send one host ping from `cluster-userspace-host`

Observed:

- first ping fails
- immediate second ping succeeds

Current best explanation:

- pending-neighbor retry still does not perfectly line up with the full
  forwarding neighbor view during cold start

Fix candidate already written:

- local commit `3e80b425` `userspace: retry pending neighbor packets from full view`

Status:

- unit-tested
- not live-proven yet

### 2. Manual RG failover under inherited `iperf3 -P 8` load

This is still the biggest HA bug.

Baseline artifact before reverse prewarm:

- `/tmp/userspace-ha-failover-rg1-20260330-092213`

Result:

- `1539` zero-throughput intervals
- `1368` per-stream zero-throughput intervals
- sender throughput `4.280 Gbps`

Important counters from the first failover window:

- old-owner LAN RX delta `5865927`
- old-owner fabric TX delta `38353`
- new-owner fabric RX delta `28494`
- new-owner WAN TX delta `7`
- new-owner `session_miss` delta `28493`

After reverse prewarm:

- `/tmp/userspace-ha-failover-rg1-20260330-174231`
- `/tmp/manual-oneway-rg1-20260330-174744`

Result:

- the new-owner `session_miss` storm is removed
- cluster ownership remains correct after failover
- the inherited `iperf3` flow set still collapses to sustained zero

Important counters after reverse prewarm:

- `fw0 Session misses` flat at `29`
- `fw1 Session misses` flat at `27-28`
- `fw1 Sessions installed` `151 -> 216`
- `fw1 Slow path local-delivery` only small growth `22 -> 32`

Interpretation:

- the remaining failure is no longer “new owner cannot install inherited state”
- the surviving bug is more likely in stale-owner demotion / redirected
  transport continuity after the ownership move

### 3. Split-RG crash and readiness

All-RGs-on-primary crash/rejoin is much better than it used to be.

Artifact:

- `/tmp/sysrqb-rgall-20260330-092844`

Result:

- traffic resumes and stays flat by the tail of the run

But split-RG crash is still broken.

Artifact:

- `/tmp/sysrqb-split-node0-actual-20260330-093636`

Observed precondition:

- `RG1=node1`
- `RG2=node0`
- `node1` stuck at `Takeover ready: no (session sync not ready)`

Result:

- `77` zero-throughput intervals out of `88`
- tail median `0.000 Gbps`

Interpretation:

- split ownership can still leave session-sync readiness stuck not-ready
- crash behavior from that split state is not safe yet

## Rejected experiment

One follow-up was tried and reverted.

Attempt:

- `b319046b` `userspace: delete demoted session aliases immediately`

Goal:

- remove demoted shared alias state earlier to stop stale-owner poisoning

What happened:

- the failover signature regressed back to a large new-owner `session_miss`
  storm
- traffic got worse, not better

Artifact:

- `/tmp/manual-oneway-rg1-20260330-175924`

Measured result:

- `fw1 Session misses: 28077 -> 28086`
- `fw1 Sessions installed: 140 -> 203`
- `fw1 TX packets: 0 -> 57`

Conclusion:

- the demotion alias set cannot be deleted naïvely at the ownership edge
- some alias continuity is still required during the handoff

This experiment was reverted by:

- `1a2da473` `Revert "userspace: delete demoted session aliases immediately"`

### 4. Aborted userspace demotion prep can poison the still-primary helper

This is the newest concrete forwarding bug.

Repro artifact:

- `/tmp/manual-oneway-rg1-20260330-180943`

What happened:

- the CLI failover did not complete
- `failover.out` reported:
  - `pre-failover prepare for redundancy group 1: read unix @->/run/bpfrx/userspace-dp.sock: i/o timeout`
- cluster ownership never moved:
  - `node0` stayed `RG1 primary`
  - `node1` stayed `RG1 secondary`

But the dataplane behavior on the still-primary node changed anyway.

Trace evidence from `fw0` after the failed prepare:

- forward flow from LAN to `172.16.80.200` resolved as:
  - `disposition=FabricRedirect`
  - `owner_rg=1`
  - `synced=false`
- reverse traffic from `172.16.80.200` still resolved locally as:
  - `disposition=ForwardCandidate`
  - `owner_rg=2`

Interpretation:

- the helper processed the demotion-prep request far enough to mark `RG1` as
  demoting
- the manager side timed out waiting for the userspace socket reply
- cluster ownership did not change, but the primary helper started treating the
  watched `RG1` flow as stale-owner fabric traffic

Why this is plausible in current code:

- `prepare_ha_demotion()` sets `demoting=true` before waiting for worker ack
- `update_ha_state()` preserves `demoting` for active groups across later HA
  state syncs
- if the socket request times out after the helper has already entered demoting,
  there is no positive clear path from the daemon side

Current fix direction:

- add a short demotion-prep lease in helper HA runtime state
- treat `demoting` as active only while that lease is still live
- let later `update_ha_state()` refresh or clear it instead of preserving it
  forever on an active group

Validated follow-up:

- with the demotion-prep lease plus earlier worker ack, the same manual `RG1`
  CLI move no longer times out in `PrepareRGDemotion`
- the CLI now returns:
  - `Manual failover triggered for redundancy group 1`

What it did not fix:

- immediate post-move traffic is still blackholed
- host ping to `172.16.80.200` still fails at `t+0s` and `t+6s`
- but it recovers by roughly `t+30s`
- once the path is warm again, fresh TCP works across the split state:
  - `iperf3 -P 4 -t 5` was about `2.74 Gbps`

Interpretation:

- the demotion-prep timeout was one real bug, and it is now narrowed/fixed
- the remaining post-move outage is not a permanent ownership failure
- it now looks more like stale moved-RG session state that takes about one
  non-TCP session lifetime to clear
- that matches current helper defaults:
  - `OTHER_SESSION_TIMEOUT_NS = 30s`
  - established TCP timeout is much longer (`300s`)

Why this matters:

- the `~30s` ICMP recovery window explains why fresh ping eventually comes back
- it also explains why established `iperf3` still does not recover: the stale
  TCP session state will outlive the ICMP-style recovery path by a wide margin

## Current interpretation

The current state of the HA work is:

1. steady-state forwarding is fixed on the correct XDP-mode baseline
2. cold-start first-probe loss is still a separate open issue
3. reverse-session activation prewarm fixed the old new-owner miss storm
4. aborted demotion prep can still poison the still-primary helper into acting
   demoted even when cluster ownership never changed
5. the surviving manual failover collapse is now centered on stale-owner
   demotion / redirected transport continuity
6. split-RG session-sync readiness is still not converging reliably enough for
   crash safety

## March 30-31, 2026 inherited-flow handoff findings

Two more concrete findings narrowed the remaining `RG1` failover collapse.

### 1. Node0->node1 neighbor convergence is still weak

Artifacts:

- `/tmp/rg1-neighbor-watch-20260330-200731`
- `/tmp/rg1-neighbor-node1-20260330-200816`

What happened:

- `fw1` logged repeated direct-mode re-announce sends after `RG1` moved to
  `node1`
- `cluster-userspace-host` kept the gateway neighbor for `10.0.61.1` pinned to
  the old owner MAC (`02:bf:72:16:02:00`)
- traffic could still recover later through stale-owner fabric redirect even
  though the host ARP entry never moved cleanly

What that means:

- post-transition GARP/NA sends are happening
- in the hard `node0 -> node1` direction they are not sufficient to update the
  host neighbor cache reliably
- this is a real convergence weakness, but it is not the whole failover
  collapse because redirected traffic can still reach the new owner

### 2. Immediate demotion alias deletion was the wrong fix

Artifact:

- `/tmp/userspace-ha-failover-rg1-20260330-201527`

Rejected experiment:

- remove the demoted owner's full `USERSPACE_SESSIONS` alias set immediately at
  the ownership edge

What live validation showed:

- target `Session misses` still exploded (`23323`)
- target `Neighbor misses` regressed (`185`)
- target last resolution became:
  - `missing_neighbor ingress-ifindex=4 egress-ifindex=13 next-hop=172.16.80.200 flow=172.16.80.8:58574->172.16.80.200:5201 zones=lan->wan`

Interpretation:

- a blind full alias purge on the demoting side regresses the new owner's
  install path
- some translated aliases are still needed during the handoff window

### 3. Active-owner fabric-ingress translated hits were too transient

Local fix candidate:

- translated synced forward hits on fabric ingress are now kept transient only
  when the owner RG is still locally inactive
- when the owner RG is locally active on the new owner, the translated hit is
  promoted and retained locally instead of being purged immediately

Validation artifact:

- `/tmp/userspace-ha-failover-rg1-20260330-202612`

Measured change versus the rejected demotion-cleanup experiment:

- target `Session misses`: `23323 -> 15424`
- target `Neighbor misses`: `185 -> 0`
- target helper progressed from effectively no real forward progress to:
  - `Session hits: 21`
  - `Session creates: 2`
  - `SNAT packets: 3`
  - `DNAT packets: 3`
  - `TX packets: 54`

What it did not fix:

- the hardened `iperf3 -P 8` failover gate still failed:
  - sender throughput `3.746 Gbps`
  - sender retransmits `149568`
  - `189` zero-throughput intervals

### 4. The remaining mismatch is now explicit on the new owner

From `/tmp/userspace-ha-failover-rg1-20260330-202612`:

- cluster status on `fw1` shows:
  - `RG1 primary`
  - `Takeover ready: yes`
- helper HA runtime on `fw1` shows:
  - `rg1 active=true`
- but helper dataplane state still shows:
  - `Last resolution: ha_inactive ingress-ifindex=4 egress-ifindex=13 next-hop=172.16.80.200 flow=172.16.80.8:51720->172.16.80.200:5201 zones=lan->wan`
- and `cycle1-failover-fw1-sessions.txt` still shows the inherited translated
  `.200` flows as `HA State: Backup`

Interpretation:

- the translated-hit promotion change removed one real miss class
- the remaining failure is now narrower:
  - the new owner is primary for `RG1`
  - but inherited translated forward-wire tuples still resolve as inactive or
    backup too often
- that is the next code-level target, not more coarse alias deletion

## Next steps

Priority order from the current narrowed baseline:

1. investigate stale-owner demotion / redirected transport continuity after the
   ownership move
2. validate or reject the pending-neighbor cold-start fix live
3. fix the split-RG `session sync not ready` stuck state
4. rerun the broader HA matrix only after those two remaining correctness gaps
   narrow further

More specifically, the next failover step should be:

1. explain why an `RG1`-primary new owner still resolves inherited translated
   `.200` tuples as `ha_inactive`
2. verify whether that comes from:
   - wrong synced owner-RG metadata
   - wrong shared forward-wire publication
   - or a promotion path that still leaves the session in backup state
3. rerun the hardened `RG1` `iperf3 -P 8` move only after that active-owner
   mismatch is corrected

## Related docs

- [userspace-xdp-mode-and-cold-start-findings.md](userspace-xdp-mode-and-cold-start-findings.md)
- [userspace-failover-next-steps.md](userspace-failover-next-steps.md)
- [userspace-failover-hardening-plan.md](userspace-failover-hardening-plan.md)
