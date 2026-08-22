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

`ValidateConfig` (`pkg/config/compiler_validate_warn.go`,
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
