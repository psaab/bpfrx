# Next Feature: Control-Link-Only RETH Ownership (Disable Data-Plane VRRP Adverts)

Date: 2026-03-04  
Status: Investigation / proposal

## Question

Can we stop running VRRP advertisements on LAN/WAN RETH interfaces and do HA election over private cluster links instead?

Short answer: **mostly yes**. Election is already over the private control link.  
The part still running on data interfaces is the VRRP VIP ownership/advertisement layer.

## Per-RETH Election Over Private Control Link

Yes, there is a viable path.

Important distinction:
- **Per-RG election already exists** in cluster heartbeat logic (private link), not on LAN/WAN VRRP.
- What VRRP still provides on data interfaces is **VIP ownership signaling** and takeover announcements.

So the target architecture is:
1. Keep/extend private-link per-RG election.
2. Move RETH VIP ownership fully to daemon-controlled lease/owner state.
3. Keep announcements (GARP/NA) but trigger them from lease acquire, not VRRP MASTER.

### Practical Design Direction

Recommended control-plane path:
- Use `control-interface` (prefer `fxp1`) for election, owner lease renewals, and failover control RPCs.
- Keep `fab0/fab1` for session/config sync and cross-chassis forwarding data-path needs.

Rationale:
- `fxp1` is already the dedicated heartbeat/election interface in current design.
- Separating election control from fabric forwarding reduces coupling to fabric load/churn.
- `fxp0` is typically external/OOB management and less ideal for HA control traffic dependence.

1. **Elect per RG over private links**
- Reuse current per-RG scoring (`priority`, `weight`, `preempt`, tie-break) from cluster election.
- Carry lease/election control over `control-interface` (`fxp1`), not LAN/WAN VRRP multicast.

2. **Add explicit per-RG owner lease (epoch)**
- Winner gets `(rg_id, owner_node, epoch, lease_expiry)`.
- Only current lease holder may:
  - add VIPs,
  - set `rg_active=true`,
  - run RG-scoped services (RA/DHCP).
- Epoch prevents stale late messages from restoring old owner state.

3. **Use dual private transports for resiliency**
- Primary: election/control strictly over control link (`fxp1`).
- Optional safety: fabric can carry corroboration/health hints, but should not be authority for ownership decisions.
- Do not couple ownership to LAN/WAN multicast reception.

4. **Fail-safe behavior**
- Lease timeout without renewal => immediate local demote for that RG.
- On split reachability, deterministic tie-break plus hold timer before reclaim.
- Keep peer fencing path (`disable-rg`) as final safety.

5. **Announcement path without VRRP**
- On lease acquire: daemon sends GARP/NA burst + gateway ARP probe.
- On lease loss: daemon removes VIPs and stops RG-scoped services.
- This is already mostly present in `no-reth-vrrp` direct mode and needs hardening.

### Why this matches your goal

This gives **per-RETH (per-RG) ownership election and failover over private HA links only**, while eliminating data-plane VRRP chatter on shared LAN/WAN segments.

## What The Code Does Today

1. **Cluster election is already private-link based**
- Heartbeat is unicast UDP on port `4784` (`pkg/cluster/heartbeat.go`, `HeartbeatPort`) and started via `control-interface + peer-address` (`pkg/daemon/daemon.go:3675`, `pkg/cluster/cluster.go:696`).
- Session/config sync is over fabric (`pkg/daemon/daemon.go:3707+`).

2. **RETH ownership still uses VRRP on data interfaces by default**
- RETH VRRP instances are generated per RG (`VRID = 100 + rg`) in `pkg/vrrp/vrrp.go`.
- Default RETH VRRP advertise interval is `30ms` (`pkg/vrrp/vrrp.go:65`, `:80`).
- If a unit has both IPv4 and IPv6 VIPs, each interval sends both IPv4 and IPv6 adverts (`pkg/vrrp/instance.go:823+`).
- XDP explicitly passes VRRP multicast to the host stack (`bpf/xdp/xdp_zone.c:485+`).

3. **There is already a switch to disable RETH VRRP**
- `set chassis cluster no-reth-vrrp` compiles (`pkg/config/compiler.go:6071`).
- In this mode, RETH VRRP instances are skipped (`pkg/vrrp/vrrp.go:72-75`).
- Cluster events directly add/remove VIPs and send GARP/NA (`pkg/daemon/daemon.go:4379+`, `:4408+`).

## What "Turn VRRP Off On LAN/WAN" Looks Like

### Config shape (current code)

```junos
set chassis cluster control-interface fxp1
set chassis cluster peer-address 10.99.0.2
set chassis cluster fabric-interface fab0
set chassis cluster fabric-peer-address 10.99.1.2
set chassis cluster no-reth-vrrp
```

Result:
- No RETH VRRP multicast on `224.0.0.18` / `ff02::12` on data interfaces.
- Cluster heartbeat + election remains on private control link.
- VIP ownership is managed by cluster role transitions.

## Obvious Gaps Before Using This As Default

1. **Direct mode reconcile only re-adds VIPs, never removes stale VIPs**
- `reconcileRGState()` has a direct-mode safety net that only calls `directAddVIPs()` when active (`pkg/daemon/daemon.go:4747-4754`).
- It does not remove VIPs on inactive RGs in reconcile (comment says event-driven only).
- If a cluster transition event is dropped, stale VIPs can persist on the wrong node.

2. **Direct mode reconcile does not emit GARP/NA when it self-heals state**
- GARP/NA is sent in event path (`pkg/daemon/daemon.go:4382-4384`) but not in reconcile direct-mode correction path.
- If event path is missed, upstream ARP/NDP may not converge quickly.

3. **Coverage is thin**
- `no-reth-vrrp` has parser tests, but no dedicated HA runtime/failover regression suite for direct ownership mode.

4. **Failover timing semantics change**
- Today, VRRP detect path is very fast (30ms advert based).
- Control-link-only mode depends on heartbeat interval/threshold for peer-loss detection (for example, `200ms * 5 = ~1s` with your current test config), unless tuned down.

5. **`strict-vip-ownership` guardrail is not available in direct mode**
- Compiler warns that `strict-vip-ownership` is incompatible with `no-reth-vrrp` (`pkg/config/compiler.go:449-455`).
- If you rely on strict VRRP-based ownership gating today, direct mode currently removes that control.

## Proposed Plan

### Phase 1: Harden Existing `no-reth-vrrp` Path

1. Make VIP ownership reconcile authoritative:
- For each RG, desired owner state drives both add and remove in reconcile (not add-only).
- Remove stale VIPs when desired inactive, idempotently.

2. Add ownership announcement reconcile:
- If reconcile detects ownership correction (or sees missing neighbor freshness), emit GARP/NA + ARP probe.
- Keep this rate-limited to avoid storms.

3. Add direct-mode HA tests:
- Event drop simulation.
- Rapid failover/failback loops.
- Peer crash/restart and daemon restart.
- Assert exactly one owner of each VIP at all times after convergence.

4. Add per-RG lease epoch tracking:
- Persist owner epoch in memory and sync transport payloads.
- Reject stale owner updates and stale failover requests.
- Tie VIP/service actions to current epoch ownership.

### Phase 2: Operational Guardrails

1. Add explicit observability:
- Per-RG "direct VIP owner" status in CLI.
- Counters for VIP add/remove success/failure, GARP sends, reconcile corrections, lease renew/expire events.

2. Tighten promotion readiness in direct mode:
- Require control heartbeat healthy, monitored interfaces up, and sync connectivity healthy before allowing promotion.

3. Add transport policy for election path:
- Make `control-interface` (`fxp1`) the explicit authoritative election/control path.
- Keep fabric signals non-authoritative (diagnostic/corroboration only) unless explicitly configured otherwise.
- Expose active authority path in config/status.

### Phase 3: Rollout Strategy

1. Keep current default (`VRRP-backed RETH`) until phase 1 and 2 pass.
2. Lab canary with `no-reth-vrrp` on one HA pair.
3. Compare failover loss windows and ownership correctness against current mode.

## Tradeoff Summary

### Keep VRRP on data interfaces (today)

Pros:
- Mature current path.
- Faster ownership signaling in some failure modes.

Cons:
- VRRP multicast chatter on LAN/WAN segments.
- More moving parts (cluster election + VRRP ownership).

### Control-link-only ownership (`no-reth-vrrp`)

Pros:
- Removes VRRP multicast from customer/data segments.
- Single authority for role: cluster manager.

Cons:
- Needs hardening in reconcile/remove/GARP paths before production default.
- Failover timing leans on heartbeat tuning.

## Recommendation

Do **not** flip globally yet.  
Create one issue to harden and validate the existing `no-reth-vrrp` path, then run a lab canary.

For architecture direction: choose `fxp1` as the control/election authority and avoid
using `fab0/1` as the primary control-plane election channel.

If you need lower chatter immediately without architecture change, raise
`chassis cluster reth-advertise-interval` from `30` ms to a higher value and
accept the corresponding failover-detect tradeoff.

## Suggested Issue Draft

Title:
- `HA: implement per-RETH private-link ownership (lease/epoch) and harden no-reth-vrrp mode`

Acceptance criteria:
1. Reconcile path enforces add/remove VIP ownership (no stale backup VIPs).
2. Reconcile-driven corrections emit rate-limited GARP/NA/probe.
3. Per-RG owner lease/epoch exists and rejects stale owner transitions.
4. HA regression tests cover direct mode under event drop + crash/failover loops.
5. CLI exposes per-RG direct ownership, epoch, and correction counters.
6. No VRRP multicast seen on data interfaces when `no-reth-vrrp` is enabled.
