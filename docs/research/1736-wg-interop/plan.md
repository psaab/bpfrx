# #1736 / #1703 S2b — Live kernel-WireGuard-on-VM interop test + smoke

Revision: v3-final (CONVERGED PLAN-READY 3-of-3 at round 2 — see §11)
Branch: `research/1736-wg-interop`
Issue: https://github.com/psaab/xpf/issues/1736 (part of #1703; follow-up of
#1432 S2a, PR #1739)

> PLAN-KILL invitation: a valid outcome of this review is "the S2a engine is
> not ready for live interop — file the engine blockers instead of building a
> harness that cannot pass". §7 lists the specific kill-shapes. Reviewers
> should kill the plan if they can show (with code evidence) that one of the
> acceptance criteria is structurally unreachable with the shipped engine.

## 1. Issue framing (in my words)

S2a (#1432, PR #1739) wired the S1 wire-compliant WireGuard engine into the
live AF_XDP daemon: minimal `tunnel mode wireguard` config → `Wg*` DTO →
persistent `wgN` TUN → per-tunnel control thread (kernel `UdpSocket` on
`listen-port` + TUN fd + `Arc<WgEngine>`), with a shim early-return steering
local-destination UDP on the WG port to the kernel. S2a was validated only by
unit tests + an xpf-against-xpf round-trip and a fast-path no-regress smoke.
**Nothing has ever proven xpf interops with an independent WireGuard
implementation.** S2b is that proof: a kernel-WireGuard peer on a real VM,
handshake both directions, transport both ways, the >MTU full-tunnel case
observed and bounded, and a fast-path no-regress smoke with WG configured.

The deliverable is **test + smoke infrastructure** (a harness script under
`test/incus/` + a runbook doc + captured evidence), NOT engine features.
Engine gaps the live test exposes are findings — small ones may be fixed
in-PR, structural ones are filed as blockers against the right S-step
(S4 PSK, S5 timers, S6 grammar/CLI, S7 cookie/IPv6-outer).

## 2. Honest scope / value framing

- Value: this is the single highest-leverage validation in the whole #1703
  chain. Every later S-step (PSK, timers, grammar, cookie, HA) builds on the
  assumption that the S1/S2a engine actually speaks WireGuard to a real peer.
  S1's KATs prove framing; only a live kernel peer proves the protocol *flow*
  (initiation retry, rekey acceptance, keepalive records, endpoint learning,
  fragmented-outer behavior).
- Honesty: the S2a engine has known, deliberate holes (no time-based rekey
  initiation, no keepalive TX, no REJECT_AFTER_TIME expiry, no cookie consume,
  zero PSK, no WG telemetry). The harness must be designed so those holes are
  *observed and bounded*, not silently routed around — and must distinguish
  "S5 hole behaving as expected" from "engine bug".
- This is operator-driven (CI-less) like every other smoke harness in
  `test/incus/`: a script + runbook the operator (or the parent agent) runs
  against the shared loss cluster, with evidence captured into the PR body.

## 3. What exists today (capability matrix, verified against origin/master @ aa6fa6fc8)

### 3.1 Engine + control thread (Rust)

| Capability | Status | Evidence |
|---|---|---|
| Handshake initiator (msg1 → consume msg2) | YES, wire-compliant | S1 KATs (`wg/handshake.rs`, spec known-answer vectors, both roles); `wg_control.rs:147-150` initial bring-up + 1 s re-init timer (`WG_INITIATOR_POLL_NS`) |
| Handshake responder (consume msg1 → msg2) | YES | `dispatch_inbound` type-1 → `consume_initiation_create_response` (`wg_control.rs:392-404`) |
| Transport encap/decap (type 4) | YES, both directions | control thread: socket→`try_decap`→TUN, TUN→`try_encap`→socket; transit AF_XDP egress encap at `frame/mod.rs:246` → `frame/wg.rs` |
| Keepalive RX (empty data record) | YES (decap len 0 → `write_all(&[])` is a no-op) | `wg_control.rs:425`; `std::io::Write::write_all` returns Ok for empty buf |
| Keepalive TX (persistent-keepalive timer) | **NO — S5** | `peer.rs:49-55` TODO; config field plumbed end-to-end but no timer consumes it |
| Time-based rekey initiation (REKEY_AFTER_TIME 120 s) | **NO — S5** | only `REJECT_AFTER_MESSAGES` (counter) exists (`session.rs:28`); re-init fires only when `!peer_has_confirmed_session` (`wg_control.rs:252`) |
| Peer-initiated rekey acceptance | YES | `install_session_fresh_index_rekey_preserves_previous_demux`, `..._second_rekey_evicts_dropped_session` (`engine.rs:1237-1300`) — fresh session replaces current, previous retained for in-flight RX |
| REJECT_AFTER_TIME (180 s) session expiry | **NO — S5** | no time field consulted on encap/decap |
| Cookie (type 3) consume / MAC2 retry | **NO — S7** (dropped + debug-log) | `wg_control.rs:412-417` |
| PSK | zero-only — **S4** | `WG_ZERO_PSK` (`wg/mod.rs:81`) |
| Endpoint roaming / learning | PARTIAL — endpoint learned from cryptographically authenticated inbound only | `wg_control.rs:160-179` (Codex r3 fix: gate on `dispatch_inbound == true`) |
| Outer IPv6 | socket is dual-stack (`bind_dual_stack_v6`), MTU math v6-aware; full v6-outer validation is **S7** | `wg_control.rs:288-344` |
| TAI64N monotonicity across restart | **in-process only** (disk persistence = S6) | issue body restart-runbook requirement |
| Multi-peer / multi-tunnel | NO — single tunnel, `first_peer_pubkey()` | `wg_control.rs:127` |
| WG telemetry (handshake/encap/decap counters in status or Prometheus) | **NONE operator-visible** | no `wg_` fields in `coordinator/status.rs` or `pkg/api/metrics*.go`; only `RecentExceptions` (bind/TUN/send errors) and `debug_log!` (debug builds) |

### 3.2 Config plumbing (Go) — end-to-end, hex keys

The full path **works today** (S2a):
`set interfaces wg0 tunnel mode wireguard` + `tunnel wireguard {listen-port,
private-key <hex>, peer {public-key <hex>, allowed-ips (multi), endpoint,
persistent-keepalive}}` → `parseTunnelWireguard`
(`compiler_interfaces.go:519+`, schema `schema.go:1356`) → `TunnelConfig.Wg*`
(`types_routing.go:306-315`, privkey-redacting `String()`) →
`TunnelEndpointSnapshot.Wg*` (`tunnels.go:106-111`, protocol.go json) →
persistent `wgN` TUN with MTU cap (`pkg/routing/tunnel.go`
`applyWireguardTunLocked`, `wgTunMTUForEndpoint` = 1500 − overhead − pad ≈
1425 for v4 outer) → Rust control thread attaches by name.

**Gap (cosmetic, S6-owned):** keys are HEX in xpf config; `wg`/`wg-quick` use
base64. The harness converts (`wg genkey | base64 -d | xxd -p -c 64`). Filed
as a note, not a blocker — S6 (#1434) owns the Junos grammar + base64.

Unit addresses on `wg0 unit 0 family inet/inet6` flow to the TUN via the
existing tunnel-address reconciliation, giving the kernel connected routes
for the inner subnet — this is how inner ping/iperf3 route into the tunnel.

### 3.3 The cluster environment (verified live, 2026-06-10)

- `loss:` remote reachable; `xpf-userspace-fw0` RUNNING and primary (holds
  LAN VIP `10.0.61.1` on ge-0-0-1); fw1 secondary.
- `mlx1` (0000:65:00.1) has 32 VFs configured; consumers today: fw0/fw1 LAN
  VFs (`0000:65:05.4/.5`) + `cluster-userspace-host` (container,
  `nictype=sriov parent=mlx1 vlan=3667`, auto-assigned vf.id 2) → **free VFs
  exist** (issue precondition satisfied).
- `cluster-userspace-host` (10.0.61.102/24, gw 10.0.61.1) is the NIC/VLAN
  template the peer mirrors; `10.0.61.103` is free.
- The cluster is SHARED: every command runs under
  `flock /tmp/xpf-cluster.lock sg incus-admin -c "..."`; smoke is serialized
  (one smoke at a time, per `feedback_smoke_serialized_single_agent`).

### 3.4 S2a runbook notes carried forward (from the converged S2a plan §8)

(a) inbound WG must not be `rp_filter`-dropped on the WAN/LAN ingress;
(b) `listen-port` must not collide with a host kernel `wgX` (EADDRINUSE);
(c) `wgN` is persistent + MTU-capped; (d) DNAT-to-WG-port limitation
(non-issue here — xpf is the terminator); (e) a WG tunnel REMOVED from config
leaks the TUN until `ip link del`/restart (S2a known limitation, AGY M1) —
the harness teardown must `ip link del wg0` explicitly after deleting the
stanza.

## 4. Multiple Path Options

### Path A — loss-resident dedicated peer (RECOMMENDED; issue-literal)

Provision `loss:xpf-wg-peer` as a Debian-13 **VM** (`incus launch
images:debian/13 xpf-wg-peer --vm`) with `eth0 nictype=sriov parent=mlx1
vlan=3667` (incus auto-picks a free VF), static `10.0.61.103/24` +
`2001:559:8585:ef00::103/64`, gw `10.0.61.1` — byte-for-byte the issue's
scope and the NIC path `cluster-userspace-host` already proves works — plus
`eth1` on `incusbr0` as a mgmt NIC (the fw VMs' fxp0 pattern: apt access for
`wireguard-tools`, agent reachability, de-risks VF teething; data-path
asserts pin to eth0 addresses so the mgmt NIC cannot contaminate results). Kernel
`wg` on the peer (`ip link add wgref type wireguard`); xpf side is the
cluster's existing fw0 (primary), WG terminating on the LAN VIP
`10.0.61.1:51820`.

- Pros: matches the issue scope exactly; the **fast-path no-regress smoke
  runs in the same canonical environment** (iperf3 → 172.16.80.200, the only
  blessed smoke target); independent kernel = honest "independent reference
  peer" claim; mlx5-VF→VM is the same mechanism the fw VMs use.
- Cons: touches the shared cluster (mitigated: flock everything, additive
  config stanza + verified teardown, smoke serialized); one more loss
  instance to manage (named `xpf-wg-*`, torn down on failure paths or
  documented if left for the parent's smoke).
- **MANDATORY secondary suppression (round-1 blocker, all three
  reviewers):** the cluster config is synced, and the SECONDARY fw1 also
  carries `10.0.61.1/24` on `ge-7-0-1` (verified live 2026-06-10) — without
  scoping, BOTH nodes spawn WG control threads with the SAME static
  identity, both can reach the peer, and fw1's never-completing initiations
  (its msg2 replies go to the VRRP virtual MAC = fw0, which drops them as
  unknown-index) would (a) re-fire every 1 s forever
  (`wg_control.rs:77,245`) and (b) ratchet the peer's per-peer TAI64N
  high-water with fw1's whitened clock — if fw1 runs ahead, fw0's OWN later
  re-handshakes are rejected as replays (intermittent, clock-skew-dependent
  interop failure). Mitigation is config-layer: the wg0 stanza is committed
  under `groups { node0 { interfaces wg0 {...} } }` (the canonical cluster
  config already carries `apply-groups "${node}"`,
  `docs/ha-cluster-userspace.conf:61`) so ONLY node0 compiles it. The
  harness preflight + post-commit asserts on fw1: no `wg0` netdev, no
  `:51820` UDP bind, no WG control thread. If groups-expansion turns out to
  drop the `tunnel wireguard` subtree (the #1796/#1797 flat-set/dual-AST
  gap class), that is a BLOCKING S2b finding to file — do NOT fall back to
  an unscoped both-nodes config.
- Fallback inside A: if VM-on-VF provisioning misbehaves, a **container**
  peer (the `cluster-userspace-host` recipe verbatim) is the documented
  fallback — kernel WireGuard is netns-aware, so the crypto/protocol stack is
  still the reference kernel implementation; the only loss is the
  "fully independent kernel" purity. Recorded in the runbook as fallback,
  used only if the VM path fails for infra reasons.

### Path B — standalone local incus pair (full isolation)

A local `xpf-wg-fw` standalone VM (make test-vm equivalent) + local
`xpf-wg-peer` on a private bridge; never touches the shared cluster.

- Pros: zero shared-cluster contention; cheap iteration.
- Cons: **cannot deliver the issue's acceptance** — the fast-path no-regress
  smoke is defined against the canonical loss userspace cluster (mlx5 native
  XDP, reth/VLAN topology, 22-23 Gb/s baseline); a virtio standalone VM
  proves neither the shim steering on the real NIC nor the no-regress number.
  Would still require a loss-cluster pass at the end → two environments, more
  total cluster time, not less. Rejected as primary; noted as an optional
  dev-iteration adjunct if interop debugging gets deep (not part of the
  deliverable).
  (Round-1 rebuttal: Codex F7/AGY F5 proposed B-for-protocol + a reduced A
  with a dummy/unreachable peer for the smoke. A dummy-peer no-regress
  smoke is exactly what S2a already shipped — it proves nothing new; the
  issue's scope is the live peer ON `loss:` mirroring the host NIC path,
  and the round-1 HA hazard is closed at the config layer by node0 scoping,
  removing the safety argument for relocating the protocol phases.)

### Path C — minimal handshake-only proof (kill-shape fallback)

Add `wgref` to the existing `cluster-userspace-host` container, prove
handshake + ping, skip >MTU/rekey/restart phases.

- Pros: zero new instances.
- Cons: mutates a shared fixture; silently skips three of the issue's
  acceptance criteria → does NOT close S2b. Only acceptable as the fallback
  *if* review concludes the full harness is premature — in which case the
  honest outcome is PLAN-KILL + blockers, not a C-shaped partial.

**Recommendation: Path A.**

## 5. Concrete design (Path A)

### 5.1 Deliverables

1. `test/incus/wg-interop.sh` — the harness. Subcommands:
   `preflight | provision | configure | test [phase] | evidence | teardown |
   all`. Every incus/cluster command wrapped in
   `flock /tmp/xpf-cluster.lock sg incus-admin -c "..."`. Idempotent
   provision (reuses an existing healthy peer); `--keep` flag to leave the
   peer + config for the parent's smoke (documented in output).
2. `test/incus/wg-interop.env` — constants (peer name `xpf-wg-peer`, addrs,
   ports, inner subnets `10.78.0.0/24` + `fd00:78::/64`, listen-port 51820,
   timing budgets).
3. `docs/wg-interop-runbook.md` — operator runbook: topology, key
   generation/conversion (hex↔base64), the **restart runbook** (flush peer WG
   state after any xpfd restart — TAI64N high-water is in-process only),
   known S4-S7 limitations the operator will observe (no keepalive TX, no
   xpf-initiated rekey, cookie drop, hex keys, no WG counters), failure
   triage, teardown.
4. PR-body evidence: captured `wg show` output proving handshakes (both
   roles), timestamped ping/iperf3 transcripts both directions v4+v6,
   P4a/P4b rekey timelines, >MTU outcome with tcpdump proof, fast-path
   smoke numbers vs baseline.
5. Filed follow-up issues per the §10.5 discipline (at minimum the S6
   telemetry-counters issue).

### 5.2 Test phases (what the harness asserts)

- **P0 preflight**: cluster healthy (both fw RUNNING, fw0 primary), `mlx1`
  free-VF check (`incus query /1.0/resources` sriov counts vs consumers),
  `xpf-wg-peer` absent-or-healthy, no kernel `wgX` on fw0 claiming 51820,
  no stale `wg0` netdev on EITHER node, baseline fast-path iperf3 sample
  recorded.
- **P1 initiator handshake**: commit the wg0 stanza on the cluster config
  (additive, scoped under `groups node0` — §4 Path A secondary
  suppression; `endpoint 10.0.61.103:51820` configured → xpf initiates at
  bring-up). Post-commit asserts: fw0 has the wg0 TUN + :51820 bind; fw1
  has NEITHER. Assert within 15 s: peer `wg show wgref latest-handshakes`
  nonzero. This proves xpf-as-initiator against kernel wg (msg1 accepted,
  msg2 consumed — kernel only reports a handshake after the full exchange).
- **P2 transport both directions, v4 + v6**:
  from fw0: `ping -c 10 10.78.0.2` + `ping -c 10 fd00:78::2`;
  from peer: `ping -c 10 10.78.0.1` + v6. Assert 0% loss after a 5 s settle.
  `wg show wgref transfer` rx AND tx both grow. iperf3 through the tunnel
  (peer server, fw0 client, then `-R`): assert ≥ a breakage floor (50 Mb/s)
  and **record** the number (control-thread single-thread path — baseline
  data, not a perf gate).
- **P4a rekey survival I — expiry-driven recovery (xpf-initiated session)**:
  runs directly after P2 on the P1 session (xpf was the handshake
  initiator, so the kernel peer is the RESPONDER of the current keypair).
  Corrected kernel semantics (Codex r1 / wireguard-linux `send.c` +
  `receive.c` `keep_key_fresh()`): BOTH kernel time-rekey triggers are
  gated on `keypair->i_am_the_initiator` — the kernel will NOT time-rekey
  as responder at 120 s or 165 s. The actual recovery path: at t≈180 s the
  kernel's per-packet `wg_birthdate_has_expired(..., REJECT_AFTER_TIME)`
  invalidates the keypair; the kernel's next SEND (ping/reply/keepalive)
  finds no valid keypair, stages the packet, and fires a NEW handshake
  initiation (kernel becomes initiator). xpf responds; traffic resumes.
  Procedure: continuous 1 s pings both directions for ≥210 s sampling
  `wg show wgref dump` every 5 s. Assert: 0 loss before t=170 s; a bounded
  outage around t≈180 s (gap ≤10 s); `latest-handshakes` advances; 0 loss
  after recovery. A permanent post-180 s blackout = FAIL → file the
  S5 REKEY/REJECT-timer blocker with the capture.
  Secondary observable (AGY r1 F1, severity-refuted but real): when the
  kernel re-initiates, xpf installs the fresh responder session UNCONFIRMED
  and `try_encap` gates egress until the first authenticated inbound
  record (`engine.rs:720-722`, `handshake_session.rs:524-527` — no TX
  fallback to `peer.previous`). Against kernel wg this window is ms-scale
  (the kernel initiator transmits its staged packet/keepalive immediately
  on handshake completion, which confirms the session), NOT a deadlock —
  but the harness measures it (timestamped ping loss around the rekey) and
  the runbook documents the stricter-than-spec responder-TX behavior; if
  the measured gap is material (>1 s), file the responder-TX-fallback
  engine issue with the capture.
- **P3 responder role + endpoint learning**: delete `endpoint` from the xpf
  stanza, commit. The endpoint is part of the WG engine identity tuple
  (`forwarding_build/wg.rs:85`), so this is a session-tearing rebuild —
  fresh engine (TAI64N high-water carried per the S2a reload contract) +
  control-thread restart (`coordinator/mod.rs:508`), NOT an in-place role
  flip (Codex r1 F4). Flush peer WG state (restart-runbook procedure) and
  configure the PEER with `endpoint 10.0.61.1:51820` + persistent-keepalive
  25. Peer initiates; assert a FRESH handshake completes + bidirectional
  ping (xpf reply path uses the LEARNED endpoint — `wg_control.rs`
  `effective_endpoint`, authenticated-inbound-gated).
- **P4b rekey survival II — seamless initiator rekey (kernel-initiated
  session)**: runs directly on the P3 session (kernel is now the handshake
  INITIATOR, `i_am_the_initiator` true). Continuous 1 s pings both
  directions for ≥180 s. Kernel time-rekeys at REKEY_AFTER_TIME (120 s) +
  jitter on send. Assert: `latest-handshakes` advances at t≈120-135 s with
  loss <1% and NO multi-second gap (this is the spec-clean rekey), plus the
  same unconfirmed-egress-window measurement as P4a. Together P4a+P4b
  capture both the S5-hole-bounded case and the clean case.
- **P5 >MTU full-tunnel + fragmented-outer (the issue's bounded-limitation
  case)**: peer reconfigured `AllowedIPs=0.0.0.0/0` (full tunnel), peer
  `wgref` MTU raised to 1500 so a `ping -s 1472 -M dont 10.78.0.1` emits an
  inner that encaps to a 1560 B outer → kernel wg sends the outer with DF=0
  (`socket.c send4` passes `df=0`, `skb->ignore_df=1`) → the outer UDP
  **fragments on the wire** toward xpf, deterministically.
  Expected mechanism at xpf (round-1-verified, corrects both Codex F2 and
  AGY F2): fragment 1 carries the UDP header → `wg_steer_to_kernel`
  (lib.rs:1236) → kernel; fragment 2 has NO UDP header and its
  garbage-parsed L4 ports miss the WG gate (`parse_ipv4` ignores
  `frag_off`, lib.rs:1095+), but its dst is locally-owned, so the
  session-table MISS path hits `is_local_destination` → `cpumap_or_pass`
  (lib.rs:567-579) → kernel. Kernel IP reassembly then delivers the
  complete datagram to the control-thread UdpSocket → decap succeeds.
  Outcome (i) clean success is therefore the EXPECTED result; outcome (ii)
  clean drop (oversize ping fails, normal ping immediately after passes,
  xpfd healthy, no exception flood, fast path unaffected) is the acceptable
  alternative if an unmodeled branch intervenes. The harness records which
  outcome occurred, with tcpdump on both ends proving the fragments'
  arrival. A wedge (tunnel dead for in-MTU traffic afterward,
  control-thread stall, daemon unhealthy) = FAIL + blocker.
  Also exercised xpf→peer: `ping -s 1472 -M dont 10.78.0.2` from fw0 — the
  wg0 TUN MTU (~1425) makes the kernel fragment the INNER (DF not set);
  both inner fragments encap individually and the peer reassembles after
  decap — assert success. Restore peer MTU/AllowedIPs afterward.
- **P6 restart recovery (restart runbook)**: restore the initiator config
  (endpoint back in the stanza — initiator-role is the case TAI64N
  monotonicity can bite); `systemctl restart xpfd` on fw0; apply the
  issue's restart runbook on the peer (`ip link del wgref; ip link add
  ...; wg set ...` — clears the peer's per-peer TAI64N high-water). Assert
  tunnel re-establishes + ping passes within 30 s. ALSO capture the
  negative control FIRST: restart xpfd WITHOUT flushing the peer and
  RECORD the outcome — note (SMR r2): xpf's TAI64N is wall-clock-derived
  (`tai64n.rs`: `SystemTime` + whitened nanos), so with a sane NTP clock
  the post-restart timestamps are naturally HIGHER and the peer will
  normally accept without a flush; the flush guards the backwards
  clock-step / same-whitened-tick edge (S1 §5.2). The negative control is
  therefore observe-and-record (either acceptance-without-flush or a
  TAI64N rejection is consistent with spec), NOT an assert — but the
  runbook still performs the flush unconditionally per the issue text.
- **P7 fast-path no-regress smoke**: with WG configured and the tunnel up
  (and idle-keepalive traffic only), run the standard smoke: iperf3 v4+v6
  push + reverse P=12 against 172.16.80.200, compare to the P0 baseline
  (expect 22-23 Gb/s reverse, 0-retransmit class, per the canonical numbers).
  Re-apply CoS config after any deploy (deploy wipes CoS).
- **Teardown**: delete the wg0 stanza (commit), `ip link del wg0` on fw0
  (S2a teardown leak, §3.4e), VERIFY both nodes have no `wg0` netdev and no
  :51820 bind (Codex r1 F6 — with node0 scoping fw1 should never have had
  one; the verify catches a scoping failure), delete `xpf-wg-peer` (unless
  `--keep`), restore peer-free state; verify fast path one last time.

### 5.3 Assertion surfaces (given zero xpf-side WG telemetry)

Primary: the **peer's kernel** (`wg show wgref latest-handshakes | transfer |
endpoints` + periodic `wg show all dump` snapshots) — the independent
reference's own accounting is the strongest interop evidence. Secondary:
traffic-level (timestamped ping/iperf3 transcripts) + **tcpdump on BOTH
ends** (`udp port 51820` on the peer's eth0 and fw0's LAN interface) per
phase — this is what disambiguates "xpf dropped it" from "network dropped
it" (Codex r1 F5 / AGY r1 F4). Tertiary: xpf `RecentExceptions` via the
status surface must stay free of `wg_*` exceptions (bind/TUN/send errors —
these ARE release-visible, `record_local_tunnel_exception`), journald
slices, and a post-phase health check (status query + fast-path ping). The
missing `wg_handshakes/wg_encap/decap_drops` counters are recorded as a
**filed follow-up issue** for S6's `show security wireguard` (#1434
adjacency) — the harness must not need debug builds, and per-drop-reason
triage beyond the above is accepted as out of reach until that lands.

## 6. Public API / config preservation

No production API changes planned. The harness uses only the existing
S2a config surface. If the live test exposes a SMALL fix (e.g. an endpoint
parse bug, a TUN write edge), it ships in-PR with its own test; anything
structural (timers, cookie, telemetry, base64) is filed against its owning
S-step. The cluster config is mutated only additively (the wg0 stanza) and
restored at teardown — CoS/policy/NAT stanzas untouched.

## 7. Risk assessment + kill-shapes

1. **Engine-not-ready kill-shape (the invited kill)**: if kernel wg rejects
   xpf's initiation/response in a way S1 KATs didn't catch (e.g. an
   endianness/padding deviation only a real peer exposes), the harness can't
   pass P1. Mitigation: S1's byte-exact dual-source KATs + both-role
   framed-handshake regression make this unlikely; if it happens anyway, the
   capture (peer-side `dmesg`/`wg` + tcpdump) IS the deliverable → file the
   engine blocker, PR ships the harness + the finding, issue stays open
   ("Part of #1736" not "Closes").
2. **P4 rekey dynamics (corrected, round 1)**: kernel wg time-rekeys ONLY on
   sessions where it was the initiator (`i_am_the_initiator` in both
   `keep_key_fresh()` sites). On the xpf-initiated session the recovery is
   expiry-driven at REJECT_AFTER_TIME (bounded gap, P4a); on the
   kernel-initiated session the rekey is seamless at REKEY_AFTER_TIME
   (P4b). xpf's own holes (no REKEY/REJECT timers — S5) and the
   stricter-than-spec unconfirmed-responder egress gate
   (`engine.rs:720-722`: fresh responder session blocks TX until the first
   authenticated inbound record; no `peer.previous` TX fallback) are both
   measured, not hidden. Against kernel wg the unconfirmed window is
   ms-scale — the kernel initiator transmits staged data/keepalive
   immediately on handshake completion, confirming the session; a measured
   gap >1 s files the responder-TX-fallback engine issue. A permanent
   blackout files the S5 timer blocker. Either way the capture is the
   deliverable.
3. **One-way-traffic churn (S5 keepalive TX missing)**: kernel peer expects a
   passive-keepalive ack within KEEPALIVE_TIMEOUT+REKEY_TIMEOUT when sending
   one-way data; xpf never sends keepalives → kernel re-handshakes every
   ~25 s under one-way load. All harness phases use bidirectional traffic;
   the limitation is documented in the runbook (S5).
4. **Fragmented-outer (P5)**: frag-1 reaches the kernel via the WG gate;
   frag-2 misses the WG gate (garbage L4 parse, `parse_ipv4` ignores
   `frag_off`) but is caught by the session-miss `is_local_destination` →
   `cpumap_or_pass` path (lib.rs:567-579) — kernel reassembly is expected
   to succeed. AGY r1's "100% reassembly failure / XSK black-hole" missed
   that fallback; Codex r1's "clean-drop default" likewise. Residual risks
   the harness watches: a <8 B-payload trailing fragment fails `parse_l4`
   and is dropped (not triggered by the chosen sizes), and any unmodeled
   strict-mode branch → outcome (ii). Both outcomes acceptable per the
   issue; a wedge = blocker.
5. **Shared-cluster blast radius**: additive config only; flock on every
   command; teardown verified on BOTH nodes (`incus list` + config diff +
   `ip link` + ss); smoke serialized; CoS re-applied after any deploy. The
   harness NEVER runs `cluster-deploy` implicitly — binary deploys stay an
   explicit operator step. Failure paths trap-teardown the peer instance;
   anything intentionally left running is documented in the PR body.
6. **HA/VIP subtleties**: WG terminates on the LAN VIP held by the primary;
   WG engine state is per-node and NOT HA-synced (S8). The secondary
   ALSO holds `10.0.61.1/24` (verified live), so fw1 must never compile the
   WG stanza — node0-group scoping per §4, asserted at P1. Failover during
   WG is explicitly out of S2b scope (S8). The peer's `AllowedIPs=0.0.0.0/0`
   phase changes only cryptokey routing via `wg set` (no 0/0 route is
   installed — `wg set` does not touch routes), so the peer's mgmt path
   stays usable.
7. **Known flake adjacency**: `reconcile_peers_snapshot_is_atomic_under_
   concurrent_load` (engine.rs:1582) is a known unit-test ledger flake
   (~5/20 at base). It exercises reconcile-under-concurrency, which the LIVE
   path doesn't hit (S2a reload reuses the engine Arc identity-stable;
   reconcile_peers is not called on the shared Arc). Live amplification risk:
   low. Harness discipline anyway: no tight internal-timing asserts; bounded
   retry windows (handshake ≤15 s, ping settle 5 s); each phase re-entrant.
8. **iperf3-through-tunnel expectations**: control-thread path is
   single-threaded with 1 ms idle sleep + 64-packet bursts — throughput will
   be modest (hundreds of Mb/s, not line rate). The harness records, floor-
   gates at 50 Mb/s (breakage detection), and does NOT perf-gate. Perf is the
   post-S2 measured follow-up per #1432.

## 8. Test plan (for the harness PR itself)

- `bash -n` + shellcheck-clean for `wg-interop.sh`; env file sourced by the
  script with `set -u` safety.
- Go/Rust: `go build ./...` + full `go test ./...`; cargo only if any Rust is
  touched (not planned) — UNMASKED gates per project rules.
- **The harness is run end-to-end by the implementer** (P0→teardown) against
  the live cluster before the PR is MERGE-READY; evidence in the PR body. An
  untested test harness is not MERGE-READY.
- Idempotency check: run `provision` twice; run `teardown` twice.
- Negative control captured (P6 no-flush case).

## 9. Out of scope (explicit)

S4 PSK; S5 timers (keepalive TX, REKEY/REJECT, roaming timers) — *observed*,
not implemented; S6 Junos grammar/base64/CLI/TAI64N persistence/multi-tunnel
(#1434); S7 cookie consume + IPv6-outer validation + DSCP/ECN; S8 HA/failover
during WG; WG perf optimization; any change to the shim or hot path.

## 10. Open questions for reviewers

1. Is the P5 fragmented-outer design (peer MTU 1500 + `-s 1472 -M dont`) the
   right deterministic trigger, or should the harness ALSO drive a raw
   oversized-UDP injector to guarantee outer fragmentation independent of
   kernel-wg DF behavior? (v2 note: kernel-wg DF=0 is verified in
   `socket.c send4`; the injector is held as a fallback only.)
2. RESOLVED (round 1): P3's endpoint removal is a session-tearing fresh
   engine + thread restart (identity tuple), asserted as a fresh handshake.
   Order stays initiator-first (issue wording); P4b rides P3's session.
3. Should the >MTU xpf→peer inner-fragmentation case assert success (current
   plan) or merely record? (Kernel fragments inner at the TUN; both fragments
   encap independently — believed deterministic.)
4. Is leaving `xpf-wg-peer` provisioned post-merge (--keep, for the parent's
   comprehensive smoke + future S4-S7 reuse) preferable to teardown-by-
   default? Current plan: teardown by default, `--keep` documented.
5. (v2) Follow-up issues the harness PR will file regardless of outcome:
   (a) WG telemetry counters (S6/#1434 adjacency) — per AGY r2, include
   exposing unconfirmed-window/decap drop REASONS (not just counts) so the
   transient drop window is operator-triageable without tcpdump;
   (b) responder-TX-fallback to `peer.previous` during the unconfirmed
   window IF the measured P4 gap is material; (c) shim `frag_off`
   awareness IF P5 lands on outcome (ii) for fragment-path reasons.
   RESOLVED round 2: filing discipline confirmed by all three reviewers.

## 11. Convergence log

- v1: pre-review draft (round 0).
- **Round 1 verdicts**: Codex `task-mq90vuiv-xy6e79` PLAN-NEEDS-MAJOR
  (7 findings); AGY `adversarial-review-mq916xob-8q2z2j` PLAN-KILL
  (3 "fatal" findings — F1 "permanent rekey deadlock" and F2 "100% fragment
  reassembly failure" severity-REFUTED with code evidence
  [`engine.rs:720` gate is a ms-scale window against a kernel-wg initiator
  that immediately confirms; lib.rs:567 local-destination miss-path
  delivers non-first fragments to the kernel], F3 HA interference CONFIRMED
  and folded as mandatory node0 scoping); Claude SMR PLAN-NEEDS-MAJOR
  (`claude-smr-plan-r1.md` — live-cluster evidence that fw1 carries
  10.0.61.1/24, upgrading the HA finding to TAI64N-poisoning class).
- v2 folds: P4 split into P4a (expiry-driven recovery, corrected
  kernel-timer semantics) + P4b (seamless kernel-initiator rekey);
  mandatory node0-group secondary suppression + fw1 asserts; P5 mechanism
  documented precisely with expected-success default; P3 re-specified as
  session-tearing rebuild; tcpdump/wg-dump/journald evidence surfaces;
  both-node teardown verify; peer mgmt NIC; follow-up-issue filing
  discipline (§10.5). AGY's PLAN-KILL is NOT adopted: its two fatal
  findings do not survive code-level verification (see
  `claude-smr-plan-r1.md` §S2 and §7.2/§7.4 here); its real observations
  (HA interference, telemetry blindness) are folded as mandatory
  mitigations. Round 2 to confirm.
- **Round 2 verdicts — CONVERGED PLAN-READY 3-of-3**:
  - Codex `task-mq91oljl-e4d97u`: **PLAN-READY** — all 7 r1 findings
    verified resolved; confirmed the kernel staged-data-or-keepalive
    confirmation claim, the lib.rs:567 fragment fallback, the
    `compiler.go:161` node-group expansion + `/etc/xpf/node-id` chain, and
    the P0..P7 phase-order protocol coherence.
  - AGY `adversarial-review-mq91if0w-zxjm2r`: **PLAN-READY, r1 PLAN-KILL
    revoked** — re-verified both refutations against the code; added the
    arithmetic proof that the non-first outer fragment is always a
    non-empty multiple of 8 bytes (so `parse_l4` never XDP_DROPs it);
    recommended the S6 telemetry follow-up include drop REASONS (folded,
    §10.5a) and the P6 expectation correction (folded).
  - Claude SMR `claude-smr-plan-r2.md`: **PLAN-READY** — caught + fixed
    the v2 P6 negative-control error (TAI64N is wall-clock-derived;
    restart-without-flush normally succeeds; observe-and-record, flush
    stays unconditional).
- v3-final: P6 corrected, §10.5 telemetry scope extended. This is the
  converged plan of record. Recommendation: **Path A** (loss-resident
  Debian-13 VM peer `xpf-wg-peer`, mlx1 VF VLAN 3667, node0-scoped wg0
  stanza), phases P0,P1,P2,P4a,P3,P4b,P5,P6,P7 + teardown.
