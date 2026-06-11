# WireGuard live interop runbook (#1736 / #1703 S2b)

Operator guide for the live kernel-WireGuard interop harness
`test/incus/wg-interop.sh`. The harness proves the S2a WireGuard datapath
(#1432, PR #1739) against an independent reference peer — the Linux kernel
WireGuard implementation in a Debian-13 incus instance on the shared loss
userspace cluster. `WG_PEER_TYPE=vm` (default) gives a fully independent
guest kernel; `WG_PEER_TYPE=container` is the plan §4 fallback (kernel
WireGuard is netns-aware, so the protocol/crypto stack is still the
reference kernel implementation — it runs in the loss HOST kernel, a
reduced but still independent-implementation claim). The 2026-06-11
validation used the container fallback because freshly created incus VMs
never bring up the agent on the loss host (images:debian/13 and /12;
pre-existing fw VMs unaffected).

Converged research plan: `docs/pr/1736-wg-interop/plan.md`
(PLAN-READY 3-of-3: Codex + AGY + Claude SMR, 2 rounds).

## Topology

```
loss:xpf-userspace-fw0 (node0, RG0 primary)
  ge-0-0-1 10.0.61.1/24 (LAN VIP, VLAN 3667)   <- WG outer endpoint
  wg0      10.78.0.1/24 + fd00:78::1/64        <- inner (persistent TUN)
loss:xpf-wg-peer (Debian-13 VM or container, kernel WireGuard)
  eth1 (mlx1 SR-IOV VF, VLAN 3667) 10.0.61.103/24 + 2001:559:8585:ef00::103
  eth0 (incusbr0) mgmt/apt
  wgref    10.78.0.2/24 + fd00:78::2/64        <- kernel wg device
```

WG outer transport: UDP 51820 over the VLAN-3667 LAN. Inner subnets:
`10.78.0.0/24`, `fd00:78::/64`. Constants: `test/incus/wg-interop.env`.

## Running

```bash
./test/incus/wg-interop.sh all            # full plan order, then teardown
./test/incus/wg-interop.sh all --keep     # keep the peer VM afterwards
# or stepwise:
./test/incus/wg-interop.sh preflight      # P0 + fast-path baseline
./test/incus/wg-interop.sh provision      # peer VM (idempotent)
./test/incus/wg-interop.sh configure      # keys + P1 initiator handshake
./test/incus/wg-interop.sh test p2        # p2 p4a p3 p4b p5 p6 p7 | all
./test/incus/wg-interop.sh teardown
```

Evidence lands in `/tmp/wg-interop-<timestamp>/` (override with
`WG_EVIDENCE_DIR`). Every cluster command runs under
`flock /tmp/xpf-cluster.lock sg incus-admin`; long traffic runs detached
inside the instances so the lock is never held across a phase.

Phase order is `P0 P1 P2 P4a P3 P4b P5 P6 P7` (P4a needs the
xpf-initiated session from P1; P4b needs the kernel-initiated session
from P3 — see plan §5.2).

## The restart runbook (TAI64N)

xpf's TAI64N handshake-timestamp high-water survives only in-process
until S6 adds disk persistence. **Whenever xpfd restarts during WG
testing, flush the kernel peer's WG state** so its per-peer TAI64N
high-water is cleared:

```bash
ip link del wgref
ip link add wgref type wireguard
wg set wgref private-key ... listen-port 51820 peer <xpf-pub> allowed-ips ...
ip addr add 10.78.0.2/24 dev wgref && ip link set wgref up mtu 1420
```

(The harness's `peer_wg_setup` is exactly this procedure; P6 exercises
it.) Note: xpf's TAI64N is wall-clock-derived, so with a sane NTP clock a
restart usually recovers WITHOUT the flush (post-restart timestamps are
naturally higher). The flush guards the backwards-clock-step /
same-whitened-tick edge — perform it unconditionally during tests.

## Mandatory: node0 scoping of the WG stanza

The cluster config is synced to both nodes and the SECONDARY also
carries `10.0.61.1/24` on its LAN interface. The wg0 stanza MUST live
under `groups node0` (the canonical config applies
`apply-groups "${node}"`), or fw1 would run a WG control thread with the
SAME static identity: its initiations would never complete (handshake
responses go to the VRRP master's MAC), retry every 1 s forever, and
ratchet the peer's TAI64N high-water against fw0 (intermittent
replay-rejection of fw0's own re-handshakes). The harness asserts at P1
that fw1 has neither a `wg0` netdev nor a `:51820` bind, and fails hard
("BLOCKING finding") if scoping ever stops compiling.

## Known S-step limitations the operator will observe

| Observation | Cause | Owner |
|---|---|---|
| xpf never sends keepalives; one-way traffic makes the kernel peer re-handshake every ~25 s | persistent-keepalive timer unimplemented (config field is plumbed, ignored) | S5 |
| xpf never initiates time-based rekey; on an xpf-initiated session the tunnel recovers via the peer's expiry-driven re-handshake at REJECT_AFTER_TIME (~180 s) with a small bounded gap | REKEY/REJECT timers unimplemented | S5 |
| brief egress drop right after a peer-initiated rekey | stricter-than-spec unconfirmed-responder TX gate (`engine.rs` try_encap; no `peer.previous` TX fallback) — ms-scale vs kernel wg | file if >1 s measured |
| keys are hex in xpf config, base64 in `wg` | minimal S2a grammar | S6 (#1434) |
| no `wg show`-equivalent / WG counters on the xpf side | telemetry not wired into status/Prometheus | S6 follow-up issue |
| cookie (type 3) messages dropped | cookie/MAC2 consume unimplemented | S7 |
| PSK must be absent/zero on the peer | PSK plumbing unimplemented | S4 |
| WG tunnel removed from config leaks the wgN TUN until `ip link del`/restart | S2a persistent-TUN tradeoff | S6; harness teardown deletes it |
| failover during WG = tunnel outage until fw0 preempts back | WG engine state is per-node, not HA-synced; wg0 is node0-scoped | S8 |

## >MTU / fragmentation semantics (P5)

- peer→xpf with peer `wgref` MTU raised to 1500: inner 1500 B encaps to a
  1560 B outer; kernel wg sends outer with DF=0 → on-wire IPv4
  fragmentation. At xpf, fragment 1 reaches the kernel via the shim WG
  port gate; fragment 2 (no UDP header) reaches the kernel via the
  session-miss local-destination fallback — kernel reassembly then feeds
  the control-thread socket, so **clean success is the expected
  outcome**; a clean drop is acceptable; a wedge is a failure.
- xpf→peer oversize: the wg0 TUN MTU (≈1425, computed as
  1500 − overhead − worst-case pad) makes the kernel fragment the INNER
  packet; each fragment encaps independently and the peer reassembles
  after decap — deterministic success.

## Shared-cluster hazards observed live (2026-06-11 validation)

- **Concurrent agents commit on this cluster.** Any foreign commit that
  does a config replace/rollback (CoS sweeps and similar loops commit
  every ~75 s when active) WIPES the wg0 stanza mid-run: the dataplane
  snapshot loses the endpoint, the coordinator stops the WG control
  thread, and the tunnel dies at a random point in a phase — observed
  as a P4a tail blackout that was NOT a WireGuard bug. Before a run,
  check `/etc/xpf/.config.journal` on fw0 is quiet; if a phase dies
  mid-run, re-check it before triaging the engine.
- **The WG outer VIP is the real mastership predicate.** After any
  xpfd restart/deploy, fw0 comes up SECONDARY on ALL redundancy groups
  (preempt off) and 10.0.61.1 is removed from ge-0-0-1; the kernel then
  fails every WG send with a SILENT EINVAL (no route/source — visible
  only via strace or the RecentExceptions ring, #1865), so the tunnel
  looks dead-air while `show chassis cluster status` can still read
  "node0 primary" for RG0. The engine itself is fine: it keeps
  initiating at 1/s and handshakes within seconds of the VIP returning
  (root-caused live 2026-06-11). The harness gates every phase on
  `ensure_wg_mastership` (VIP-present check + all-RG failback); when
  driving manually, fail back EVERY RG, not just RG0:
  `request chassis cluster failover redundancy-group <0|1|2> node 0`.
  This mechanism also retro-explains the earlier "first commit after a
  daemon start brings the engine up late" observation.
- **Config removal leaks the control thread + port** (#1866): the
  harness preflight self-cleans the leaked TUN and P1 restarts xpfd if
  the listen port is still pinned with no stanza present.

## Failure triage

1. P1 no handshake: tcpdump UDP 51820 on the peer — msg1 arriving?
   If NOTHING leaves fw0, strace the `xpf-wg-control-` thread for
   `sendto` errors (the dual-stack v4-mapped send bug fixed in this PR
   showed exactly one silent EINVAL per initiator tick).
   xpf side: `journalctl -u xpfd | grep -i wg`, check the wg0 TUN exists
   and `:51820` is bound on fw0; check the peer's `wg show wgref` for
   key mismatch (hex↔base64 conversion).
2. wg0 TUN missing after commit: the daemon-side collect gate — see the
   #1736 fix in `pkg/daemon/daemon_run.go` (`collectAppliedTunnels`
   wireguard exemption); confirm the deployed build includes it.
3. Handshake but no transport: AllowedIPs mismatch (xpf decap gates
   inner SOURCE against the peer's allowed-ips in the xpf config).
4. P4a permanent blackout after ~180 s: file the S5 timer blocker with
   the capture (plan §7.2).
5. Cluster unhealthy / VIP not on fw0: wait for preemption or
   `request chassis cluster failover`; the WG outer endpoint follows RG0.

## Teardown guarantees

Teardown removes the config stanza, deletes the leaked `wg0` TUN,
verifies BOTH nodes have no `wg0` and no `:51820` bind, deletes
`xpf-wg-peer` (unless `--keep`), and re-checks the fast path. If a run
dies mid-phase, `./test/incus/wg-interop.sh teardown` is safe to run
standalone (idempotent).
