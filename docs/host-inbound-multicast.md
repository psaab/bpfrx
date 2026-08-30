# Host-bound routing multicast admission (#4455, HI-1)

This doc records the current behavior of host-bound **multicast** admission, the
protocol→multicast-group catalog that the eventual per-zone enforcement will use,
and the four coupled design decisions that keep the full enforcement deferred. It
is a **design artifact**: today the catalog backs only a commit-time advisory and
makes **no forwarding decision**.

## Current behavior: fail-open-but-bounded

The kernel `xpf_hostinbound` `chain input`
(`pkg/daemon/daemon_nft.go`, `buildHostInboundFilterPayload`) is:

```
type filter hook input priority <p>; policy accept;
ct state established,related accept
meta l4proto { 50, 51 } accept            # raw ESP/AH (host-terminated IPsec)
icmpv6 type { 1,2,3,4,133,134,135,136,137 } accept   # ND + PMTUD/error
icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
<per-zone>  <fam> daddr <zone-local-unicast-addrs> ... accept / counter drop
```

Every per-zone rule is scoped by `<fam> daddr <zone-local-addrs>` — a set of the
firewall's own **unicast** interface addresses. A host-bound packet addressed to
a well-known routing **multicast** group (OSPF `224.0.0.5`, VRRP `224.0.0.18`,
PIM `224.0.0.13`, …) matches **no** per-zone `daddr` set, so it falls through the
chain's `policy accept` to the host stack **without** any per-zone
`host-inbound-traffic protocols` scoping.

The Rust AF_XDP classifier
(`userspace-dp/src/afxdp/forwarding/host_inbound.rs`, `host_inbound_admits`) keys
only on `(ingress_zone_id, protocol, dst_port, is_v6, icmp_type)` — it has **no
destination-address dimension** — so it does not gate host-bound multicast
either.

**This is a Junos-parity/hardening gap, not an open door.** The exposure is
bounded:

- The host kernel delivers multicast only to groups a configured daemon actually
  **joined** (a routing daemon the operator enabled). Nothing is delivered to a
  group with no local subscriber.
- The always-on control set (IPv6 ND, PMTUD/error ICMP, ESP/AH) is already
  globally accepted, independent of the zone token set.

So OSPF / VRRP / PIM do **not** break today. The gap is that their host-bound
multicast is admitted **packet-wide** (on every ingress interface) rather than
scoped to the zone whose `host-inbound-traffic protocols` opted in — broader than
Junos, where host-bound routing multicast is admitted per-zone via
`host-inbound-traffic protocols <x>`.

## Commit-time advisory (shipped)

`ValidateConfig` (`pkg/config/compiler_validate_warn_host_inbound.go`,
`validateHostInboundMulticastWarnings`) emits a **WARN-only** commit-time
advisory for each zone-level `host-inbound-traffic` stanza AND each per-interface
override (#3362) whose `protocols` set admits a multicast routing protocol. The
advisory names the zone (and interface), lists the concrete well-known groups,
and states that the multicast is currently admitted packet-wide via the input
chain's accept fall-through — a known parity gap (#4455). It is **never a hard
reject**: the config is valid Junos, and rejecting or narrowing it would break a
zone that relies on today's accept (see the migration decision below). This
mirrors the #3226 `system-services all` SCOPING advisory pattern (that
advisory warns that `all` no longer admits packet-wide; it is not itself a
packet-wide admit).

A **companion advisory** (`validateHostInboundManagedRoutingMismatch`, #4455
Component B) closes the *inverse* blind spot: the advisory above fires only when
a multicast token is **present** (the already-compliant case), so a zone running
a managed FRR routing protocol with **no** matching token — the actual silent
fail-open — was invisible. Component B cross-checks the interfaces xpf renders
into FRR for OSPFv2/OSPFv3/RIP (`pkg/frr/policy_render.go`, global stanza and
each routing-instance) against each interface's zone's effective
`host-inbound-traffic protocols` set and WARNs when the matching token
(`ospf`/`ospf3`/`rip`) is absent, so the operator can make the admission
explicit. Zone attribution reuses the dataplane's `buildInterfaceZoneMap`
semantics (`zoneIfaceLogicalKeys`: a bare zone member `reth0` claims every
configured unit `reth0.10`), and the effective admission set reuses
`ZoneConfig.InterfaceHostInboundEffective` (the per-interface override where one
is declared — it REPLACES the zone-level set, #6515 — with #3720 physical-parent
inheritance for logical units, `all`-expanded) — so
the advisory matches runtime enforcement exactly (no missed or false warnings
on unit interfaces). Same WARN-only,
zero-dataplane-surface doctrine (the Component A per-zone `iifname` DROP
enforcement stays deferred/PLAN-KILLed). BGP/LDP (unicast) and PIM (unmanaged)
are out of scope.

## The DHCP-server sibling (#6460)

The same "the host-inbound stanza reads as enforced and is not" shape reaches the
**DHCP server**, and neither advisory above can see it — both cross-check
*routing protocols* against FRR, and the DHCP server is neither a routing
protocol nor rendered into FRR. A third advisory
(`validateDHCPServerHostInboundBypassWarnings`,
`pkg/config/compiler_validate_warn_dhcp_hostinbound.go`) covers it: it WARNs when
a `system services dhcp-local-server` / `dhcpv6-local-server` group binds an
interface whose zone's effective `host-inbound-traffic system-services` set omits
`dhcp` / `dhcpv6`.

The two families are unenforced for **different** reasons, and the message says
which — an operator told the wrong reason reaches for the wrong remedy:

| Family | Why the zone token does not bound it |
|---|---|
| DHCPv4 (`dhcp`) | **Two planes, both bypassed (#7489).** (1) A client addresses its DISCOVER/REQUEST to the **255.255.255.255 broadcast**, and `should_fallback_early` (`userspace-xdp/src/lib.rs`) hands `dst_v4 == 0xffff_ffff` straight to the kernel — the request never enters the AF_XDP userspace dataplane or its host-inbound gate. (2) xpf renders Kea's `Dhcp4` with **no** `dhcp-socket-type` key (`pkg/dhcpserver/dhcpserver.go` emits `interfaces-config` with an `interfaces` list and nothing else), so Kea's default `raw` applies and the server receives on an **AF_PACKET** socket, delivered **before** the netfilter input hook. |
| DHCPv6 (`dhcpv6`) | Kea's `Dhcp6` has no raw mode, but a client addresses the server at the **ff02::1:2** multicast group. Every per-zone host-inbound rule — the accepts AND the #3361 catch-all deny — is scoped `<fam> daddr <zone unicast addrs>` (`pkg/nftables/netlink_hostinbound.go`, `emitHostInboundZoneNetlink`), so a multicast destination matches neither and falls through the base chain's `policy accept` (`pkg/nftables/netlink_installer.go`). This is the same fall-through the routing-multicast gap above rides. |

The remedy in the message deliberately leads with **removing the interface from
the group**, not with adding the token: adding the token cannot enforce anything
on the DHCP server's request path (both planes above are bypassed), so presenting
it as *the fix* would restate the same false signal in a new place. The token is
offered only as a way to record that the segment is meant to be served.

### Scope of the bypass argument — do not generalise it (#7489)

"The AF_PACKET tap is upstream of netfilter" is an argument about **one** plane,
and it does **not** establish that a host-inbound token is inert for v4 traffic
at large. The AF_XDP userspace dataplane enforces host-inbound itself,
**fail-closed**, on the local-delivery path (`host_inbound_gated_lo0_action`,
`userspace-dp/src/afxdp/poll_descriptor/filter.rs`), and a packet dropped there
never reaches the kernel on any device — so an AF_PACKET tap cannot see it.

**Measured** on the loss userspace cluster: 20 unicast datagrams to an
interface-mode-SNAT address, on a port the arrival zone did not admit, produced
**+22 host-inbound denies and ZERO packets on `tcpdump -ni any`**, with a
same-host ping (which the zone *does* admit) answering normally.

What decides which plane applies is the **destination**, not the port. On a
session miss the shim steers on address alone — `should_fallback_early`, then
`is_local_destination`, which deliberately returns false for an address in
`USERSPACE_INTERFACE_NAT_V4` ("the common WAN case"). So:

| v4 destination | plane | host-inbound token |
|---|---|---|
| `255.255.255.255` (DHCP DISCOVER) | kernel, via the shim's early fallback | inert — this advisory's subject |
| ordinary local unicast | kernel, via `is_local_destination` | inert on the userspace plane |
| unicast to an **interface-mode-SNAT** address | **redirected to the AF_XDP dataplane** | **load-bearing, fail-closed** |

The third row is not this advisory's subject, but the sentence above was being
read as covering it. A DHCP **client** on such an interface receives its
RENEWING-state ACK as a unicast to that address; whether that specific frame
loses its lease when the token is absent was **not** measured and is not claimed
here.

### The userspace gate is DENY-ONLY for an AF_PACKET consumer (#7318)

A ceiling worth stating before someone designs into it. The AF_XDP gate looks
like a general enforcement point for host-bound traffic, and for a service that
reads from a kernel **socket** it is. For a service that taps the **physical
device** with `AF_PACKET` — Kea's Dhcp4 on the default `raw` is exactly this —
it can only ever DENY.

The asymmetry is in the delivery mechanism, not the gate. A DENIED packet is
dropped in the worker and reaches the kernel on no device, so an AF_PACKET tap
cannot see it (the measurement above: +22 denies, zero on `tcpdump -ni any`).
But an ADMITTED packet is not passed through on its ingress NIC — local delivery
is a `write()` into the TUN device `xpf-usp0`, opened `IFF_TUN | IFF_NO_PI`,
carrying a **bare L3 packet with the Ethernet header stripped**
(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`, `userspace-dp/src/slowpath.rs`).
A raw-socket consumer bound to `ge-0-0-1` therefore never sees it: wrong device
for `packet_rcv`'s filter, and no L2 header for a filter that reads the
ethertype at offset 12 — which Kea's LPF does, as its first test.

The practical consequence: routing DHCPv4 into the dataplane so the gate can
*admit* it would not gate DHCP, it would take the server off the air. Any
proposal to enforce host-inbound for a raw-socket service has to be a
deny-side-only change, leaving the admit path exactly as it is.

Zone attribution and effective-admission resolution reuse the same two SSOTs
Component B uses (`zoneIfaceLogicalKeys`, `ZoneConfig.InterfaceHostInboundEffective`),
so the three advisories cannot drift in which interfaces they can see.
WARN-only, zero dataplane surface, no error return and no `lenient` flag — the
#1960 no-brick property is structural, matching the #5619 doctrine.

**Enforcement is not planned by default.** The v6 leg needs the same per-zone
`iifname` class gate Component A was PLAN-KILLed for. The v4 leg cannot be
closed by netfilter *on the default `raw` socket* at all — not because the
input hook is bypassed unreached, but because it acts on a copy Kea never
reads (#7318 measured an INPUT drop at priority -100 counting the packet on
both the broadcast and the interface-unicast destination while Kea answered
regardless).

#7318 shipped the opt-in half: `system services dhcp-local-server
dhcp-socket-type udp` moves Dhcp4 onto a UDP socket that does traverse the
input hook, at which point the per-zone `dhcp` token governs the server path
with no Component A required — because on UDP Kea does not receive broadcast
at all, so the fall-through that Component A would have to close no longer has
anything listening behind it. The DEFAULT is unchanged (`raw`), because udp
serves relayed and renewing clients only and stops serving directly-attached
address-less clients; that is a deployment choice, not a bug fix. Whether the
default should ever flip is still open and deliberately unprejudiced.

## Protocol → multicast-group catalog

The single source of truth is `hostInboundMulticastCatalog` in
`pkg/config/host_inbound_multicast.go`. Only protocols whose host-bound **control
traffic** rides a well-known multicast group are listed; unicast routing control
(BGP TCP/179, LDP, MSDP, BFD to a peer address) and L2/non-IP protocols (IS-IS)
are deliberately absent. Family split mirrors `HostInboundProtocolFamily`.

| `protocols` token | IPv4 group(s) | IPv6 group(s) | Notes |
|---|---|---|---|
| `ospf`  | `224.0.0.5`, `224.0.0.6` | — | OSPFv2 AllSPFRouters / AllDRouters (IP proto 89) |
| `ospf3` | — | `ff02::5`, `ff02::6` | OSPFv3 (IP proto 89, IPv6) |
| `rip`   | `224.0.0.9` | — | RIPv2 (UDP 520) |
| `ripng` | — | `ff02::9` | RIPng (UDP 521) |
| `pim`   | `224.0.0.13` | `ff02::d` | ALL-PIM-ROUTERS (IP proto 103), dual-family |
| `igmp`  | `224.0.0.1`, `224.0.0.22` | — | all-hosts / IGMPv3 reports (IP proto 2), IPv4 only |
| `dvmrp` | `224.0.0.4` | — | ALL-DVMRP-ROUTERS, carried inside IGMP (IP proto 2), IPv4 only |
| `vrrp`  | `224.0.0.18` | `ff02::12` | VRRP (IP proto 112), dual-family |
| `router-discovery` | `224.0.0.1`, `224.0.0.2` | — | IRDP advertisements / solicitations (IPv4); the IPv6 equivalent is ND RS/RA, already in the always-accepted set |

`protocols all` expands (via `HostInboundAllExpansionProtocols`, #3199) to the
routing-protocol set including every catalog member above, so it also triggers
the advisory.

## Why the enforcement is deferred: four coupled decisions

Turning this catalog into an enforced per-zone multicast admission gate is a
**behavior change** that is fail-**closed** on revert of today's accept, so it
needs a converged plan. The four coupled decisions (tracked on #4455):

1. **New `iifname`-scoped rule structure.** Multicast admission is
   per-zone/per-interface (the destination is a group, not a firewall address).
   `buildHostInboundFilterPayload` has no `iifname` predicate today; the enforced
   form needs a new `iifname <zone-members> ip daddr <groups> accept` rule
   structure plus a multicast catch-all drop.

2. **The protocol→multicast-group catalog** (this doc / `hostInboundMulticastCatalog`)
   agreed against Junos semantics. Settled here as the design artifact.

3. **#1960 migration gating.** Enforcing per-zone multicast admission is
   fail-**closed** on revert of today's accept: a zone running an FRR routing
   protocol **without** the matching `host-inbound-traffic protocols` knob
   currently relies on the unconditional accept, and enforcement would break it
   (Junos requires both). This needs the strict-on-commit / warn-on-tolerant-load
   (#1960) treatment plus an operator migration story.

4. **Kernel/Rust lockstep.** The multicast dimension must be added to BOTH the
   nft set AND `host_inbound_admits` without split-brain — the Rust classifier
   has no destination-address dimension to extend yet. The existing lockstep
   contract (`docs/host-inbound-service-matrix.md`, the "keep in lockstep"
   comments, and the Go↔Rust parity tests) governs this.

Until those land, the catalog is inert design data and the commit-time advisory
is the only operator-visible surface.

## See also

- `docs/host-inbound-service-matrix.md` — the per-token service/protocol matrix
  and the sibling #3226 `system-services all` SCOPING advisory (which warns
  that `all` stopped admitting packet-wide).
- `pkg/config/host_inbound_tokens.go` — the recognized-token allowlist, family
  maps, and per-tuple L4 match SSOT.
- `pkg/config/compiler_validate_warn_dhcp_hostinbound.go` — the #6460
  DHCP-server sibling advisory described above.
- `pkg/dhcpserver/README.md` — the Kea render, including the AF_PACKET
  socket-type default that leg turns on.
