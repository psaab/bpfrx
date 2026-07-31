# Host-Inbound Service-Port Matrix

Authoritative, operator-facing map of every `security zones <zone>
host-inbound-traffic { system-services ...; protocols ...; }` token to the exact
ports / protocols it opens on the firewall, across all three enforcement
surfaces. This is the single reference so future audits stop re-deriving the
port sets from source (folds codex-review-002 M07/M08 and L02/L03/L07/L16/L19;
issue #3619).

## The three surfaces

Host-inbound admission is enforced (and validated) in three independent places
that MUST agree on the token set:

1. **Go SSOT — recognized-token allowlist + address family + structured
   token→tuple table.** The set of meaningful tokens, their address-family
   scoping, and (since #3627 B1a) their structured `(proto, ports, icmp-type)`
   tuples. Commit-time validation hard-rejects any token outside it (#3200).
   - `config.KnownHostInboundSystemServices` — `pkg/config/host_inbound_tokens.go`
   - `config.KnownHostInboundProtocols` — same file
   - `config.HostInboundServiceFamily` / `config.HostInboundProtocolFamily` —
     family scoping (`ip` = IPv4-only, `ip6` = IPv6-only, absent = dual)
   - `config.HostInboundL2Protocols` / `config.HostInboundAllExpansionProtocols()`
     — `protocols all` expansion minus L2/non-IP tokens
   - `config.HostInboundServiceMatch` / `config.HostInboundProtocolMatch`
     (`[]config.L4Match{Proto, Ports, ICMPType, Reject}`) — the STRUCTURED
     token→tuple SSOT added in #3627 B1a. The nft kernel mirror (surface 2) now
     RENDERS its match fragments from this table rather than carrying a parallel
     hard-coded copy, and the `request security match-policies` host-inbound
     classifier (surface 4) MATCHES queries against it. Before #3627 the Go SSOT
     declared only the token allowlist and family, and the port sets lived only
     on surfaces 2 and 3 as hand-mirrors; now surface 2 is a render of this
     table, and surface 3 (Rust) remains a hand-mirror pending the deferred
     per-tuple parity test.

2. **nft kernel mirror — PRIMARY enforcement.** Host-bound traffic to a
   firewall interface IP / VRRP VIP is shunted to the kernel by the XDP shim
   before it reaches userspace-dp, so the nftables `inet xpf_hostinbound` chain
   carries ~100% of real host-inbound traffic. Since #3627 B1a the per-token
   match fragments are RENDERED from the surface-1 structured SSOT
   (`renderHostInboundMatches`), byte-identical to the pre-#3627 strings
   (`TestHostInboundNftRenderGoldenByteIdentical`).
   - `hostInboundServiceMatches` — `pkg/daemon/daemon_nft.go` (services; renders
     `config.HostInboundServiceMatch`)
   - `hostInboundProtocolMatches` — same file (protocols; renders
     `config.HostInboundProtocolMatch`)
   - `hostInboundServiceAction` — same file (ident-reset reject verdict)
   - global always-accepts — `buildHostInboundFilterPayload`, same file

3. **Rust AF_XDP classifier — SECONDARY enforcement.** The XSK
   local-delivery path, reached only by the subset of host-bound traffic that
   arrives on the AF_XDP fast path (e.g. DNAT/static-NAT to a firewall-local
   address). The IPsec passthrough stage (`stage_ipsec_passthrough_check`) is
   likewise scoped to a firewall-local destination since #5620: it claims the
   kernel-XFRM passthrough short-circuit ONLY when `flow.dst_ip` is an address
   the firewall owns (`owns_configured_ip`), so a TRANSIT ESP/AH/IKE packet
   routed to a remote host falls through to transit zone policy instead of
   being reinjected to the local XFRM stack (codex-review-181 M03).
   - `classify_system_service` / `classify_protocol` —
     `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
   - `is_icmp_host_inbound_global_accept` — same file (global ICMP/ND accepts)

4. **match-policies host-inbound classifier — DIAGNOSTIC (not enforcement).**
   The `request security match-policies` simulator names WHICH host-inbound token
   admits a queried host-bound tuple (#3627 B1a). It does not enforce; it reads
   the surface-1 structured SSOT and mirrors the surface-2 global accepts so its
   report cannot drift from what the kernel opens.
   - `ClassifyHostInbound` / `hostInboundGlobalAccept` —
     `pkg/dataplane/userspace/host_inbound_classify.go`
   - wired into `pkg/policymatch` as `Result.HostInbound`

**Drift guards.** The token *sets* are pinned in lockstep by
`config.TestHostInboundRustClassifierMatchesGoSSOT` (`pkg/config/host_inbound_rust_parity_test.go`,
#3486 — parses the Rust source and asserts its match arms equal the Go SSOT) and
`TestHostInboundNftMatchesKnownTokens` (`pkg/daemon/host_inbound_parity_test.go`,
#3200 — asserts the nft matcher's domain equals the SSOT). The *port sets* for
deliberately-narrow tokens (sip, tftp, traceroute, bfd, the #3341 routing
protocols) are additionally pinned by fail-on-revert assertions in
`pkg/daemon/host_inbound_parity_test.go` so an accidental widen turns RED. Since
#3627 B1a the nft match fragments are RENDERED from surface 1 and pinned
byte-identical by `TestHostInboundNftRenderGoldenByteIdentical`
(`pkg/daemon/host_inbound_ssot_render_3627_test.go`); the structured tuples
themselves are pinned by `config.TestHostInboundServiceMatchTuples` /
`TestHostInboundProtocolMatchTuples`. A per-tuple parity test between the Rust
classifier (surface 3) and the structured SSOT (surface 1) is a deferred
follow-up; until it lands, surface 3 stays a hand-mirror held by the set-level
`TestHostInboundRustClassifierMatchesGoSSOT`.

## system-services matrix

| Token (aliases) | nft match (`daemon_nft.go`) | Rust admit (`host_inbound.rs`) | Family | Notes |
|---|---|---|---|---|
| `all` / `any-service` | full admit | `all_services = true` | dual | Blanket accept for the zone — a **packet-wide** admit of EVERY IP protocol/port (GRE/ESP/AH/OSPF/PIM/VRRP/future proto numbers), a superset of the Junos meaning (`all` = union of the *named* system-services). Deliberate & documented (#3199); `ValidateConfig` emits a commit-time advisory naming the zone/interface (#3226). See [`system-services all` / `any-service` is a packet-wide admit](#system-services-all--any-service-is-a-packet-wide-admit-3226). |
| `ssh` | tcp 22 | tcp 22 | dual | |
| `telnet` | tcp 23 | tcp 23 | dual | |
| `ftp` | tcp 21 | tcp 21 | dual | Control port only; FTP data is an ALG/transit concern. |
| `http` / `webapi-clear-text` | tcp 80 | tcp 80 | dual | Web-management HTTP. The admit port is the canonical Junos J-Web port (`webmgmt.HTTPPort` = 80) and EQUALS the actual listener bind (#5715): `resolveAPIBinds` binds an explicitly-configured `web-management http` on TCP/80, not the pre-#5715 8080. Listener↔admit are one contract (`webmgmt` SSOT), guarded by `TestWebMgmtListenerMatchesHostInboundAdmit_5715` + the Go/Rust port-parity `TestHostInboundRustWebPortsMatchSSOT_5715`. |
| `https` / `webapi-ssl` | tcp 443 | tcp 443 | dual | Web-management HTTPS. Admit port = `webmgmt.HTTPSPort` = 443 = the listener bind (#5715, was 8443). Same contract as `http` above. |
| `ping` | icmp/icmpv6 echo-request | ICMP type 8 (v4) / 128 (v6) | dual | Echo-request only; ICMP errors are global-accepted (see below). |
| `dns` | udp 53, tcp 53 | udp 53, tcp 53 | dual | |
| `dhcp` / `bootp` | udp {67, 68} | udp 67, 68 | **ip (v4)** | DHCPv4; must not open on v6 (#3225). |
| `dhcpv6` | udp {546, 547} | udp 546, 547 | **ip6** | DHCPv6; v6-only (#3225). |
| `ntp` | udp 123 | udp 123 | dual | |
| `snmp` | udp 161 | udp 161 | dual | |
| `snmp-trap` | udp 162 | udp 162 | dual | |
| `ike` / `ipsec` | udp {500, 4500} | udp 500, 4500 | dual | `ipsec` is an ALIAS of `ike` (L03). Raw ESP(50)/AH(51) are global-accepted (nft) / handled by `stage_ipsec_passthrough_check` (Rust), so `ipsec` is effectively a superset of `ike`. |
| `tftp` | udp 69 | udp 69 | dual | **UDP 69 only (M08). Data ports are ALG/transit, not host-inbound — matches vSRX.** See disposition. |
| `netconf` | tcp 830 | tcp 830 | dual | |
| `ssh-netconf` / `netconf-ssh` | tcp {22, 830} | tcp 22, 830 | dual | |
| `finger` | tcp 79 | tcp 79 | dual | |
| `ident-reset` | tcp 113 → **reject with tcp reset** | **drop** (no admit) | dual | **Cross-surface divergence (#3310):** nft actively RESETs TCP/113; the AF_XDP secondary path drops it. See divergences. |
| `lsping` | udp 3503 | udp 3503 | dual | |
| `sip` | udp 5060, tcp 5060 | udp 5060, tcp 5060 | dual | **UDP+TCP 5060 only (M07). SIP-over-TLS (TCP 5061) is NOT admitted — matches vSRX.** See disposition. |
| `r-login` / `rlogin` | tcp 513 | tcp 513 | dual | |
| `r-sh` / `rsh` | tcp 514 | tcp 514 | dual | |
| `r-exec` / `rexec` | tcp 512 | tcp 512 | dual | |
| `xnm-clear-text` | tcp 3221 | tcp 3221 | dual | JUNOScript clear-text. |
| `xnm-ssl` | tcp 3220 | tcp 3220 | dual | JUNOScript over SSL. |
| `traceroute` | udp 33434-33523 | udp 33434..=33523 | dual | **UDP probe range only (L07/L16).** UDP-only per #3368; ICMP time-exceeded replies ride the global ICMP-error accept. |
| `gre` | meta l4proto 47 | ip protocol 47 | dual | GRE listed as a system-service by some configs (repo HA cluster wan zone). |

## protocols (routing) matrix

| Token | nft match (`daemon_nft.go`) | Rust admit (`host_inbound.rs`) | Family | Notes |
|---|---|---|---|---|
| `all` | expansion (routing set minus L2) | `routing_protocol_all_expansion()` | dual | Expands to every routing protocol EXCEPT L2 (IS-IS). NOT a blanket accept — does NOT open system-services (#3199). |
| `ospf` | meta l4proto 89 | ip proto 89 | **ip** | OSPFv2, IPv4 (#3225). |
| `ospf3` | meta l4proto 89 | ip proto 89 | **ip6** | OSPFv3, IPv6 (#3225). Same proto 89, different family. |
| `bgp` | tcp 179 | tcp 179 | dual | |
| `rip` | udp 520 | udp 520 | **ip** | RIPv2, IPv4 (#3225). |
| `ripng` | udp 521 | udp 521 | **ip6** | RIPng, IPv6 (#3225). |
| `igmp` | meta l4proto 2 | ip proto 2 | **ip** | IPv4 group membership; v6 equivalent is MLD over the global ND accept (#3225). |
| `pim` | meta l4proto 103 | ip proto 103 | dual | |
| `vrrp` | meta l4proto 112 | ip proto 112 | dual | |
| `bfd` | udp {3784, 3785, 4784} | udp 3784, 3785, 4784 | dual | Single-hop control (3784) + echo (3785) + multi-hop control (4784, RFC 5883) (#3299). |
| `ldp` | tcp 646, udp 646 | tcp 646, udp 646 | dual | |
| `msdp` | tcp 639 | tcp 639 | dual | |
| `nhrp` | meta l4proto 54 | ip proto 54 | dual | |
| `rsvp` | meta l4proto 46 | ip proto 46 | dual | #3341. |
| `pgm` | meta l4proto 113 | ip proto 113 | dual | #3341. Distinct from ident-reset's `tcp dport 113` (this is IP protocol 113). |
| `sap` | udp 9875 | udp 9875 | dual | #3341. |
| `dvmrp` | meta l4proto 2 | ip proto 2 | **ip** | #3341. Carried inside IGMP; IPv4-only, like `igmp`. |
| `isis` | (none) | (none) | **L2/none** | Recognized but no IP match on either surface (L2/OSI-CLNP). Kernel hands IS-IS PDUs to FRR's isisd via an LLC socket, outside the IP host-inbound filter. Excluded from `protocols all` (#3311). |
| `router-discovery` | v4: `icmp type { 9, 10 }`; **v6: (none)** | v4 ICMP types 9, 10 | v4 per-zone; **v6 global** | **L02:** on IPv6, RS/RA (133/134) ride the always-accepted ND global set, so this token carries NOTHING on v6 — correct kernel parity, but a CLI/doc trap. |

## `system-services all` / `any-service` is a packet-wide admit (#3226)

`system-services all` and its `any-service` alias are the ONLY two
`system-services` tokens that are NOT a per-tuple match. Both set one boolean
(`all_services` in `host_inbound.rs`; `hostInboundAllowsAll` in `daemon_nft.go`)
that short-circuits admission to accept EVERY IP protocol and port destined to
the zone's local firewall addresses — GRE, ESP/AH, OSPF, PIM, VRRP, and any
future protocol number — with **no** catch-all drop. `config.HostInboundFullAdmitService`
(`pkg/config/host_inbound_tokens.go`) is the SSOT for which tokens are full-admit.

This is a **superset of the Junos meaning.** In Junos, `system-services all` is
naturally "all system-service *names*" (the union of the named tokens in the
matrix above), and `any-service` is "the entire TCP/UDP port range" — neither
opens arbitrary non-TCP/UDP IP protocols. xpf aliases both to the broader
packet-wide admit. The breadth is **deliberate and documented** (#3199 kept these
two tokens as a full-admit while scoping the sibling `protocols all` to the
routing-protocol set — see the protocols matrix note above) and is relied on by
the canonical HA control zone (`system-services { all }` on em0/fab* — though
there the lifeline exclusion, not the token, is the real protection; see
#3277 / `pkg/dataplane/userspace/zones.go`).

### Commit-time advisory (#3226 — shipped)

Because the breadth is easy to reach for and materially wider than Junos,
`ValidateConfig` (`pkg/config/compiler_validate_warn.go`) emits a WARN-only
commit-time advisory for each zone-level `host-inbound-traffic` stanza AND each
per-interface override (#3362) whose `system-services` set contains a full-admit
token. The advisory names the zone (and interface), states that the token
accepts every IP protocol/port to the zone's local addresses, and suggests
listing specific services if that is the intent. It is **never a hard reject** —
`system-services all` is legal Junos and a reject would brick previously
committed configs; the message only surfaces the breadth. This directly answers
the issue's Direction: "If `any-service` must remain a non-Junos full-admit
escape hatch, document it as such with an explicit commit warning."

### The admission-narrowing posture (A vs B) remains deferred

Whether to keep the documented broad alias (Option A, zero-surprise-on-upgrade)
or scope `all` to the union of named services + a catch-all drop and split
`any-service` off as an entire-port-range / escape-hatch (Option B, Junos-strict)
is a **security/product posture decision**, not an engineer-fixable bug. It stays
open on #3226 (`plan-deferred-operator`); the converged /research plan-of-action
lives on the `research/3226-system-services` branch
(`docs/research/3226-system-services/plan.md`). The commit-time advisory above is
independent of that decision — it makes the current behavior visible without
changing any forwarding.

## Host-bound routing multicast is admitted packet-wide (#4455)

The per-zone rules above match host-local **unicast** `daddr` only, so host-bound
**multicast** (OSPF `224.0.0.5/6`, VRRP `224.0.0.18`, PIM `224.0.0.13`, …) falls
through the input chain's `policy accept` **without** per-zone
`host-inbound-traffic protocols` scoping — admitted packet-wide on every ingress
interface, not scoped to the opting-in zone. This is fail-open-but-bounded (the
host delivers only to groups a joined daemon subscribed), a Junos-parity gap.
`ValidateConfig` emits a WARN-only commit-time advisory for a zone admitting a
multicast routing protocol; the per-zone `iifname` enforcement is deferred. Full
protocol→group catalog and the deferred four-decision plan:
[`docs/host-inbound-multicast.md`](host-inbound-multicast.md).

## Global always-accepts (independent of the zone token set)

These are accepted on EVERY host-inbound-configured zone regardless of its
`system-services` / `protocols` set, so enforcement never breaks core L3
operation or session return traffic. nft: `buildHostInboundFilterPayload`; Rust:
`is_icmp_host_inbound_global_accept` + `stage_ipsec_passthrough_check`.

| Class | nft | Rust | Rationale |
|---|---|---|---|
| Established/related | `ct state established,related accept` | conntrack fast path | Return / ongoing host traffic. **On a tightening the kernel entry is reconciled — see "Stale kernel authorization on a tightening (#5566)" below.** |
| Raw IPsec ESP/AH | `meta l4proto { 50, 51 } accept` | `stage_ipsec_passthrough_check` (before `host_inbound_admits`) | Kernel XFRM decrypts host-terminated IPsec; makes `ike`/`ipsec` a working superset. |
| ICMPv4 errors/PMTUD | `icmp type { destination-unreachable, time-exceeded, parameter-problem }` | proto 1 types 3, 11, 12 | PMTUD / unreachable / traceroute-to-self signalling. Echo-request is NOT here (gated on `ping`). |
| ICMPv6 errors + ND | `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }` | proto 58 types 1-4, 133-137 | v6 error/PMTUD (1-4) + Neighbor Discovery (133-137). Echo-request (128) is NOT here (gated on `ping`). |

## Stale kernel authorization on a tightening (#5566)

The `ct state established,related accept` above is the FIRST rule in the chain
(and, in the `to-zone junos-host` program branch, the residual established accept
follows the fine DROP but still precedes the per-zone coarse drops). Replacing the
`xpf_hostinbound` table does **not** flush Linux netfilter conntrack. So an
EXISTING direct-kernel host connection admitted under a looser prior config — an
SSH / HTTPS / SNMP session to a firewall-local address — kept riding that leading
established-accept after the operator REMOVED the service: the new per-zone
catch-all DROP never saw the flow's original-direction packets. That was a
host-inbound false-allow confined to the direct-kernel delivery path; the Rust
userspace local-delivery path already re-checks the effective host-inbound set on
every session hit and tears a now-denied session down
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs`), but the kernel path had no
equivalent teardown.

**Fix — conntrack reconcile after every successful apply**
(`pkg/daemon/host_inbound_conntrack_flush.go`, wired at the tail of
`applyHostInboundFilter`). After the real `xpf_hostinbound` table loads, the
daemon deletes every established/related **kernel** conntrack entry whose
original-direction destination is a **covered** firewall-local host-inbound
address (an address that carries a default-deny — the same `desiredDrop` set as
#5789) and whose `(proto, dport)` the CURRENT coarse rules no longer admit. The
next original-direction packet is then re-evaluated and dropped by the per-zone
catch-all instead of short-circuiting on the established-accept. Properties:

- **Reconcile, not a delta.** The flush condition is "not admitted by the CURRENT
  config", derived from the SAME structured SSOT the nft chain renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so the admit
  decision cannot drift from the chain's per-zone accepts. No prior-config
  snapshot is persisted; the sweep is a no-op on loosening / unchanged commits
  because still-permitted flows are kept. A service that stays configured is never
  flushed (no connection-reset regression).
- **Lifeline-safe.** Only addresses in the covered default-deny set are eligible;
  management / cluster-control lifelines (fxp0 / em0 / fab*) are excluded from the
  host-inbound views, so their conntrack is never flushed. Addressed-but-unzoned
  addresses (#4420 HI-2) are covered with an empty admit set (fully denied except
  the global exemptions below).
- **Global exemptions preserved.** ESP/AH (proto 50/51), ICMP ND/PMTUD/error, and
  the configured WireGuard listen port (#5582) are never flushed, mirroring the
  chain's global accepts. ICMP echo conntrack is short-lived and left to age out.
- **Best effort.** The nft table is already applied, so enforcement for NEW
  connections holds regardless; a conntrack-subsystem flush failure is logged, not
  surfaced as a commit failure (failing the commit would roll back correct
  enforcement over a transient error). It only leaves PRE-EXISTING flows on their
  old authorization — the pre-fix behavior.

Kernel netfilter conntrack on this appliance tracks only host-terminated /
kernel-forwarded flows (transit forwarding runs through userspace-dp's own session
table), so the swept table is small. Fail-on-revert proofs:
`pkg/daemon/host_inbound_conntrack_flush_5566_test.go`.

## Fail-closed invariant for a nil / configured=false known zone (#3705)

Every zone the control plane KNOWS about — a zone present in the snapshot with a
valid, addressable id — is host-inbound **enforcing** (default-deny at minimum),
and the two layers agree:

- **Go builder (`buildZoneSnapshots`, `pkg/dataplane/userspace/zones.go`).** A
  tolerant / HA-loaded config can carry a NIL zone value
  (`Security.Zones[name] == nil`, the #3493 shape). `HostInboundConfigured` is
  set UNCONDITIONALLY, so a nil zone ships `host_inbound_configured=true` with
  EMPTY token sets — default-deny, identical to a no-stanza zone (#3405). Before
  #3705 the flag was gated on `zone != nil`, so a nil zone shipped a valid
  name+id but `configured=false`.
- **Rust build path (`forwarding_build::zones::populate_zones`).** The
  `zone_host_inbound` insert is NOT gated on `host_inbound_configured`: every
  known zone gets an entry (an empty `ZoneHostInbound` when the flag is false /
  tokens are empty → default-deny). This is the dataplane fail-closed backstop
  for a mismatched-version control plane (e.g. an old pre-#3405 Go binary that
  omits the flag). `host_inbound_configured` now selects only WHICH tokens a
  zone admits, never WHETHER it is enforced.

Without both, a KNOWN configured zone with `configured=false` was left absent
from `zone_host_inbound` and hit the `None => true` admit-all arm in
`host_inbound_admits` — reopening the #3405 default-deny on the nil-object shape
(a management-plane fail-open on the exact tolerant-load / HA-sync path where nil
zones arise). `None` now means only a genuinely unknown / global ingress zone
(id 0, never in the table), which keeps the admit default; lifeline interfaces
(fxp0/em0/fab*) never reach the AF_XDP classifier (#3682).

## Deliberate narrowings & the one cross-surface divergence

These are intentional and match vSRX / Junos semantics. Documented here so future
audits do not re-file them.

- **`sip` — UDP+TCP 5060 only, no SIP-TLS (M07).** The Junos `junos-sip`
  predefined application is UDP and TCP destination-port 5060, and the SRX SIP
  ALG supports SIP signaling on port 5060 (UDP by default, TCP added in
  12.3X48-D25 / 17.3R1). Junos ships **no** predefined SIP-over-TLS (SIPS)
  application on port 5061; SIPS/5061 requires a **custom** application/service.
  xpf therefore opens UDP 5060 + TCP 5060 on both surfaces and does not admit
  5061 — working as intended. An operator terminating SIPS on the firewall must
  add a custom host-inbound service (there is no `sip` widen).
- **`tftp` — UDP 69 only (M08).** The Junos `junos-tftp` predefined application
  is UDP port 69. TFTP data transfers use ephemeral ports negotiated
  dynamically; for host-bound TFTP that is an ALG/transit concern, not a
  host-inbound listener. xpf opens UDP 69 only on both surfaces — matches vSRX.
- **`traceroute` — UDP 33434-33523 only (L07/L16).** UDP probe range only, per
  the #3368 disposition. The ICMP time-exceeded replies traceroute relies on ride
  the global ICMP-error accept.
- **`router-discovery` carries nothing on IPv6 (L02).** v6 RS/RA (types 133/134)
  are admitted unconditionally as part of the ND global-accept set
  (#3171/#3201/#3240), so the per-zone token adds nothing on v6 — correct kernel
  parity, but note it in operator docs.
- **`ipsec` is an alias of `ike` (L03).** Both open IKE (UDP 500 / NAT-T 4500).
  Raw ESP/AH is governed by the XFRM passthrough / global ESP-AH accept, so
  `ipsec` is effectively a superset of `ike`.
- **`isis` is a recognized no-op (#3311).** Valid at commit for vSRX parity but
  produces no IP match on either surface (rides L2/OSI-CLNP; delivered to FRR
  isisd over an LLC socket). Excluded from the `protocols all` IP expansion.
- **`ident-reset` — the one true cross-surface divergence (#3310).** On the nft
  (primary) path `system-services ident-reset` emits `reject with tcp reset` for
  TCP/113 (Junos actively resets ident probes). The AF_XDP (secondary) path does
  not synthesize an RST — it simply **drops** TCP/113 (the classifier arm
  contributes nothing to the admit set). This is a documented divergence on the
  near-nonexistent DNAT/static-NAT-to-113 path; both layers stop the prior
  plain-admit of 113.

## Addressless-zone fail-open window (#3698)

Host-inbound default-deny is scoped to a zone's firewall-local **addresses** —
the nft chain matches `<fam> daddr <zone-addrs> ... drop`. A configured,
host-inbound-enforcing zone whose non-lifeline interfaces have **no resolvable
address yet** (a DHCP WAN before its first lease, a backup node before VIP
install, or an interface the operator has not addressed) yields an EMPTY address
set, so `BuildZoneHostInboundViews` emits no deny for it and
`applyHostInboundFilter` scopes nothing. During that window, host-bound packets
to a freshly-usable address on that interface can reach the kernel input path
without the intended zone default-deny — a transient fail-open on a security
boundary. Address appearance makes the address available to a later snapshot;
it does not itself prove that host-inbound re-rendered or reached the kernel. A
later applicable full apply must reach host authorization and complete the nft
transaction (VRRP VIPs remain resolved from config, so a VIP-scoped zone is not
addressless even on the backup node). An address-scoped nft deny cannot be
rendered without an address, so #3698 makes the window **observable** rather
than silent.

The SSOT for "which configured enforcing zones are currently in the window" is
`dpuserspace.AddresslessEnforcingZones` (`pkg/dataplane/userspace/zones.go`). It
reads the scoped/unscoped decision back from `BuildZoneHostInboundViews` — the
same builder that drives the nft payload — so the signal describes the same
address snapshot, not whether the later nft transaction succeeded. It reports a
zone iff it has at least one **non-lifeline**
interface assigned yet resolves no address; zones that are scoped, whose only
interfaces are management/cluster-control lifelines (fxp0 / em0 / fab*), or that
have no interfaces are deliberately NOT reported (low-noise).

Two observability surfaces consume it:

- **State-transition log** (`daemon_nft.go`, `logHostInboundAddresslessTransitions`).
  A `WARN` is logged when a zone ENTERS the window and an `INFO` when it LEAVES
  (an address appears). These transitions describe the snapshot built before nft
  success and are not installation proof. A zone that stays addressless across
  repeated commits / DHCP renewals is logged once, not every apply.
- **Prometheus gauge** `xpf_host_inbound_addressless_zones{zone}` (`pkg/api`).
  Value `1` per zone currently in the window; the series is absent when the zone
  is enforced. Emitted BEFORE the dataplane gate (config-derived, so it stays
  visible in a config-only / degraded boot). Alert with e.g.
  `max_over_time(xpf_host_inbound_addressless_zones[1h]) > 0`.

## Cold-boot fail-closed install fence (#5644, M37)

`applyHostInboundFilter` loads the chain with `nft -f -`, which is **atomic**:
on a load failure the kernel keeps the exact PREVIOUS `inet xpf_hostinbound`
generation untouched, if one exists. That generation protects only rules and
destinations already represented in it; it does not cover a newly appeared
address (#5789). **On a COLD BOOT both nft tables are absent, so a failed install
has no prior generation to retain.** A boot apply that reaches
`applyHostInboundFilter` does so through `applyConfig`, which only **logs and
discards** the returned error
(a boot apply must not brick startup), so a cold-boot install failure would leave
the host input path with **no** `xpf_hostinbound` chain — every host-bound service
to a firewall-local address reachable with no host-inbound default-deny
(fail-open) — while the daemon proceeds to publish host service / VIP / HA-ready.

To close that window when the rendered snapshot has addresses, a cold-boot
install failure attempts a **fail-closed fallback** before returning the error.
That fallback is DENY-ALL for every address in the snapshot; an addressless
snapshot produces a zero-drop table shell:

- `d.hostInboundEnforced` (a `Daemon` atomic bool) is a process-local historical
  fallback gate. A successful real load stores true, including a program-only
  generation; a successful fallback stores true only when that exact fallback
  contains an address-scoped DROP. Repeated successful zero-drop fallbacks leave
  false. A successful **no-enforcement teardown** (nothing is enforceable, so the
  `xpf_hostinbound` table is deleted) stores **false** (#5790): with no table
  installed the "a protecting table exists" premise is gone, so a later
  enforceable generation whose first real load fails must take this cold-boot
  fence path rather than assume a retained table (the pre-fix sticky-true skipped
  the fence and left newly reachable addresses fail-open). A teardown **failure**
  (a table the delete could not remove may still be installed) does **not** clear
  it. True still proves neither current table presence nor coverage of current
  addresses — the DAY-2 COVERAGE gap is tracked separately (#5789, below). All
  Stores are serialized under `applySem`; nft completion and the following Go
  Store are ordered but not one atomic publication.
- `d.hostInboundCoveredAddrs` (a `Daemon` set, keyed `"<fam>|<addr>"`) is the
  #5789 COVERAGE discriminator that the sticky boolean alone cannot provide.
  `hostInboundEnforced=true` proves only that SOME protecting table loaded at SOME
  earlier generation, NOT that the RETAINED (atomic-untouched) generation covers
  the CURRENT desired destination set. Two fail-open paths otherwise remain: (1) a
  previously-addressed zone gains another static/DHCP/SLAAC address and the next
  real render fails — atomic nft retention keeps the OLD generation, which has no
  deny for the new address; (2) a successful addressless program-only install
  stores `enforced=true` with ZERO covered addresses, and an address later appears
  before a failed rerender. `hostInboundCoveredAddrs` records the destination set
  the currently-retained enforcement (last successful real load OR address-scoped
  cold-boot fence) drops. On a failed rerender while `enforced=true`, the desired
  drop set is diffed against it (`hostInboundUncoveredDropAddrs`); any UNCOVERED
  destination gets an ADDITIVE gap fence (below). It is set to the desired set on a
  successful real load / address-scoped fence, left UNCHANGED on any failure
  (atomic retention keeps the old generation, so its coverage claim stands), and
  CLEARED on a successful teardown (#5790 — no table covers nothing). `applySem`
  serialized, like the `hostInboundFailOpen` maps.
- `installHostInboundGapFence` / `buildHostInboundGapFencePayload` (#5789) build
  the ADDITIVE gap fence: a SEPARATE `inet xpf_hostinbound_gap` base chain at
  `nftHostInboundGapPriority` (11) — STRICTLY AFTER the main `xpf_hostinbound`
  table (10), which is strictly after `xpf_lo0` (0); the three distinct
  strictly-increasing hook-input priorities are pinned by
  `nft_chain_priority_test.go`. It denies ONLY the uncovered addresses (with the
  SAME mandatory L3 / return admits as the cold-boot fence, via the shared
  `hostInboundFenceMandatoryAdmits`) and, unlike the whole-table cold-boot fence,
  does NOT replace `xpf_hostinbound` — so the retained generation's per-service
  ACCEPTS for already-covered addresses stay intact (the issue's "do not weaken
  retained valid rules"). A newly-appeared uncovered address falls through the main
  chain's `policy accept` (a `drop` is terminal, an `accept` is not, so an already
  service-accepted or catch-all-dropped covered address keeps its main-table
  verdict) and is dropped by the gap. The uncovered lists derive from the same
  lifeline-subtracted views/unzoned sets, so the gap never fences management /
  cluster-control traffic. A gap install failure JOINS the commit error
  (fail-closed); the gap is torn down by the next successful real install (best
  effort — a lingering gap fences only, never opens) and on a successful teardown.
- `installHostInboundColdBootFence` / `buildHostInboundFencePayload`
  (`daemon_nft.go`) build the fence: the same atomic-replace `xpf_hostinbound`
  table reduced to the global mandatory admits (`ct established,related`, raw
  ESP/AH, IPv6 ND, v4/v6 PMTUD+error, the configured WireGuard listen port) and a
  catch-all `<fam> daddr <addrs> drop` for **every** firewall-local address the
  real ruleset would scope (the per-zone views + the addressed-but-unzoned set).
  It carries **no per-service accept and no named counters** — it is strictly the
  real table with every service ACCEPT removed, so during the fence window even a
  `system-services all` zone is denied (maximally fail-closed). The address sets
  are already lifeline-excluded (fxp0 / em0 / fab* and their addresses are
  subtracted by `BuildZoneHostInboundViews` / `BuildUnzonedHostInboundAddrs`), so
  the fence can **never** strand management or break HA.
- The requested apply still **fails** (`applyHostInboundFilter` returns the
  wrapped real nft error, joined with a fallback error when fallback also fails).
  A later full apply seeing an address gets another fallback opportunity only if
  it reaches host authorization, the real load fails, and state remains false.
  There is no host-inbound retry loop.
- A DHCP/DHCPv6 lease callback classified for full recompile runs serialized
  `applyConfig`, but classification does not prove host-inbound ran. A required
  protocol-gate error returns before `applyTailReconciles` and receives no
  cancellation closeout, leaving retry/re-render to a later applicable successful
  reconcile that reaches the tail. **#5791 (fixed):** the callback's
  management-only skip is now gated on the config-derived host-inbound LIFELINE
  set (`config.HostInboundLifelineSet` / `HostInboundLifelineInterface` — the SAME
  authority that lifeline-excludes these address sets), not the broad
  management-VRF name class (fxp*/fab*/em*). So a zoned NON-lifeline DHCP interface
  (a standalone `fxp1`) is classified for the full recompile that builds its
  address-scoped fence; only a true lifeline (fxp0/em0/fab*/configured
  control-interface) keeps the management-only fast path. The skip decision and
  this fence now share one classifier and cannot drift.
- If the fence **also** fails to load (nft itself broken), both errors are joined
  and an `ERROR`-level `COLD-BOOT FAIL-OPEN GUARD` log fires; `hostInboundEnforced`
  stays false. That is the irreducible catastrophic case — the daemon has done all
  it can short of holding forwarding.

Relationship to the addressless window above: at the first cold-boot apply an
interface may have no address yet, so both the real ruleset and fallback can
contain zero address-scoped DROPs. A successful zero-drop fallback leaves
`hostInboundEnforced` false. Address appearance alone does not re-run this path;
a later applicable full apply must reach host authorization, and a failed real
load while state is false then renders another fallback from that invocation's
snapshot. This is scoped to the **direct-host nft input authority** only; the
AF_XDP transit arm / attach readiness is owned separately by #5275.
Fail-on-revert proofs:
`pkg/daemon/host_inbound_coldboot_fence_5644_test.go`; for the
teardown-clears-the-gate ordering (#5790),
`pkg/daemon/host_inbound_teardown_enforced_5790_test.go`; and for the day-2
coverage gap + additive gap fence (#5789),
`pkg/daemon/host_inbound_coverage_gap_5789_test.go` (both the address-added and
the program-only-then-address paths) plus the three-chain priority invariant in
`pkg/daemon/nft_chain_priority_test.go`.

### lo0 RE-protection cold-boot fence (#6476)

The operator's `interfaces lo0 unit 0 family inet filter input <name>`
(the Junos protect-RE pattern) lowers to the `inet xpf_lo0` input chain — the
authoritative, operator-authored control-plane firewall, evaluated at hook-input
priority 0 (strictly BEFORE the `xpf_hostinbound` backstop at 10). Before #6476
it had the SAME cold-boot fail-open the host-inbound table closed in #5644: on a
COLD BOOT no prior `xpf_lo0` table exists to retain, and the boot apply reaches
`applyLo0Filter` through `applyConfig` (which only logs+discards the error), so a
failed `InstallLo0` left the RE input path with **no** lo0 filter and only a WARN,
while host service / VIP / HA-ready were published. Host-inbound (priority 10) may
still gate, so exposure is partial — but any service protected ONLY via the lo0
filter is unenforced.

The fix mirrors the host-inbound cold-boot fence for the lo0 table:

- `installLo0ColdBootFence` / `buildLo0FencePayload` (`daemon_nft.go`) build the
  fence from the SAME lifeline-excluded firewall-local address sets
  (`BuildZoneHostInboundViews` + `BuildUnzonedHostInboundAddrs`) and the SAME
  `buildFenceTablePayload` body as the host-inbound cold-boot fence — mandatory L3
  / return admits (`ct established,related`, raw ESP/AH, IPv6 ND, v4/v6
  PMTUD+error, the configured WireGuard listen port) then a catch-all
  `<fam> daddr <addrs> drop`, no per-service accept and no named counters — but
  rendered into the `xpf_lo0` table at priority 0, the same slot the real lo0
  filter occupies, so a later successful `InstallLo0` **atomically replaces** it.
  Netlink install is `Installer.InstallLo0ColdBootFence` (T1 parity gate:
  `lo0_cold_boot_fence`).
- **The gate keys on `d.lo0Enforced` — "is the live `xpf_lo0` table a REAL
  operator filter" — NOT "does any protecting table exist" (#6489).** A failed
  `InstallLo0` installs (or re-installs) a fence UNLESS a real filter is currently
  loaded. It is true ONLY after a successful real `InstallLo0`; a FENCE deliberately
  does **not** set it (a fence is not a real filter — its chain is `policy accept`
  and drops only the addresses in the snapshot it was rendered from — so it stays
  false across a fence). A successful no-filter TEARDOWN stores false (the table is
  deleted); a teardown FAILURE does not clear it. `applySem`-serialized.
- **Why it must not key on "any table exists".** The earlier design set a single
  `lo0Enforced` bool true on BOTH a real load AND a scoped fence, so this sequence
  FAILED OPEN: cold-boot real install fails → fence(snapshot A) installed → gate
  true → a new local address **B** appears + real install fails again → the gate
  skips re-fencing → the retained table is the OLD FENCE (`policy accept` + drops
  for A only), so **B** falls through `policy accept` → the RE input path is open
  for B. Keying on `lo0Enforced` instead RE-RENDERS the whole-table fence
  from the CURRENT snapshot on every day-2 failure while no real filter is loaded,
  so B is covered.
- **No day-2 gap fence (the deliberate divergence from #5789) — but only once a
  REAL filter is loaded.** When `lo0Enforced` is true, a day-2 failure
  installs no fence: the atomic `replaceTable` retains the operator's filter, which
  — unlike the auto-generated, per-destination-address-scoped `xpf_hostinbound`
  table — is hand-authored and NOT per-destination scoped (its terms, typically
  ending in a catch-all `discard`, govern every firewall-local address, including
  one that appears later). So lo0 needs neither a per-address coverage set nor an
  additive gap table; the whole-table re-render (fence path) and retain-the-real-
  filter (real-filter path) together close the gap.
- A zero-drop fence (an addressless boot snapshot) is likewise not a real filter,
  so it leaves `lo0Enforced` false and a later failed real invocation
  re-fences from a possibly-now-addressed snapshot; a catastrophic double-failure
  (real load AND fence both fail) joins both errors, fires the `COLD-BOOT
  FAIL-OPEN GUARD` ERROR log, and leaves `lo0Enforced` false.

**Pre-existing residuals (NOT introduced or addressed by #6476/#6489, tracked
separately):**

- A retained REAL lo0 filter with **no catch-all term** is a valid config
  (`compiler_filter_nocatchall_3295_test`); such a filter need not itself cover a
  new day-2 address. That is the lo0 filter's own coverage semantics, independent
  of this boot fence — the fence only guarantees the RE path is not left fully
  open when NO real filter is loaded.
- The shared fence body / `BuildZoneHostInboundViews` / `BuildUnzonedHostInbound
  Addrs` that this fence reuses carry two known behaviours that affect the
  **host-inbound #5644 fence identically** (a shared-mechanism concern, not
  lo0-specific — tracked in **#6492**): a management IP shared onto a non-lifeline
  interface can pick up a global `daddr` drop, and a zone-less router yields empty
  address sets → an accept-all fence shell. Both live in the shared mechanism and
  pre-date #6476.

Fail-on-revert proof: `pkg/daemon/lo0_coldboot_fence_6476_test.go` —
`TestColdBootLo0FenceThenNewAddressReFences` pins the #6489 fence→fail→re-fence
sequence (RED if a fence marks a real filter loaded). The lo0-first-then-host-
inbound priority ordering (0 < 10) is pinned by
`pkg/daemon/nft_chain_priority_test.go`; the fence's netlink/exec-nft parity by
the `lo0_cold_boot_fence` case in `daemon_nft_netlink_parity_test.go`.

### Per-interface / per-family refinement (#3710)

The zone-level signal above **collapses**: `AddresslessEnforcingZones` marks a
zone "scoped" (and stays silent) the moment ANY of its interfaces resolves an
address in EITHER family. But host-inbound ENFORCEMENT is per-destination-address
and per-family — the kernel chain emits `<fam> daddr <set> ... drop` separately
for `inet` and `inet6` — so a **MIXED** zone can still carry a real fail-open
window the zone-level view cannot express:

- **Mixed-interface zone**: `trust` has `ge-0-0-0.0` (static `192.0.2.1`) and
  `ge-0-0-1.0` (DHCP WAN, lease pending). The addressed sibling makes the zone
  scoped, so #3698 never surfaces `ge-0-0-1.0`'s window.
- **Mixed-family interface**: `ge-0-0-2.0` has a static/DHCP v4 address but its v6
  lease (DHCPv6) has not landed. `len(v.V4Addrs) > 0` marks the zone scoped, so
  the IPv6 side entering the same window is invisible — dual-stack edges commonly
  bring the two families up at different times.

`dpuserspace.AddresslessEnforcingInterfaces` (`pkg/dataplane/userspace/zones.go`)
surfaces the window at `{zone, interface-unit, family}` granularity. It reports a
non-lifeline logical unit assigned to a configured enforcing zone when, for a
family, the unit has a **DHCP / DHCPv6 client** configured (`family inet { dhcp; }`
/ `family inet6 { dhcpv6; }` / `dhcpv6-client`) but currently resolves **no
address** in that family — using the same static / live-kernel address resolution
plus configured VRRP VIPs that `BuildZoneHostInboundViews` scopes the deny with.

Only the `dhcp-pending` reason is reported: a static address or a VRRP VIP is
injected into the enforced deny from config regardless of link/lease state, so it
never opens a per-interface window. Gating on a configured DHCP client (rather
than "any family with no address") keeps the signal low-noise — an IPv4-only
interface is **not** flagged as addressless in `inet6`, because it never intends
to acquire a v6 address. A landed lease changes the next address snapshot; nft
enforcement still depends on a later applicable reconcile reaching host
authorization and completing its transaction.

Two observability surfaces consume it (mirroring #3698):

- **State-transition log** (`daemon_nft.go`,
  `logHostInboundAddresslessIfaceTransitions`). A `WARN` on ENTRY, an `INFO` on
  RECOVERY, transitions only.
- **Prometheus gauge**
  `xpf_host_inbound_addressless_interfaces{zone,interface,family,reason}`
  (`pkg/api`). Value `1` per open window; absent when the family is enforced.
  Emitted BEFORE the dataplane gate. The zone-level
  `xpf_host_inbound_addressless_zones` remains as a coarser compatibility
  aggregate — this per-interface series is strictly more sensitive and is exported
  alongside it, not in place of it.

## Per-interface override precedence (#3362, #3720)

Host-inbound-traffic can be authored at three granularities, and the EFFECTIVE
admission set for a logical unit is the **UNION** of all three (Junos
host-inbound is additive — an interface admits a service listed at ANY level):

1. **zone-level** — `security zones <z> host-inbound-traffic { ... }`, applies to
   every interface in the zone;
2. **physical-interface-level** — `security zones <z> interfaces <ifN>
   host-inbound-traffic { ... }` (a bare interface ref), applies to every
   configured unit of that physical interface;
3. **unit-level** — `security zones <z> interfaces <ifN.M>
   host-inbound-traffic { ... }`, applies only to that logical unit.

So for unit `ifN.M`: `effective = zone ∪ physical(ifN) ∪ unit(ifN.M)`. A
more-specific unit override never *replaces* a physical override — they are
merged. Before #3720 the resolver
(`buildInterfaceHostInboundMap`, `pkg/dataplane/userspace/zones.go`) walked refs
in sorted order and wrote each key first-writer-wins; a bare physical ref sorts
before (is a prefix of) its units, so it filled `out["ifN.M"]` first and the
later exact unit override was **dropped** — the less-specific physical ref
silently shadowed the more-specific unit ref (fail-open, admitting a service the
unit did not open, or fail-closed, denying one it did). The fix MERGES (unions)
the two levels instead.

**Cross-zone quarantine (#3720 M01, #5489).** A host-inbound override must
contribute to a unit's effective set ONLY from the unit's authoritative zone
owner. On the lenient / peer-synced load path an ownership conflict is downgraded
to a warning (`compiler_validate_strict.go`) and `buildInterfaceZoneMap` resolves
the owner as the **first sorted zone** that claims the unit, so two zones can
both name the same `ifN.M` while only one owns it. Both branches of
`buildInterfaceHostInboundMap` (`pkg/dataplane/userspace/zones_override.go`)
enforce the owner predicate `zoneByIface[ref] == zn`:

- **physical→unit expansion (#3720 M01)** does NOT apply a physical `ifN`
  override owned by zone trust onto `ifN.M` owned by zone guest — it skips any
  unit whose resolved zone differs from the override's zone.
- **exact unit-level ref (#5489)** does NOT merge a `ifN.M` override authored by
  a **non-owner** zone into `out["ifN.M"]`. Before #5489 the exact-unit branch
  unioned every zone's override unconditionally, so a losing zone's admission
  token (e.g. `ssh`) bled into the winning zone's `InterfaceSnapshot` /
  `ZoneHostInboundView` — a cross-zone host-inbound admission escalation. The
  quarantine mirrors the physical branch exactly (same `z != "" && z != zn`
  predicate, same skip), so a unit's effective tokens come only from its
  authoritative owner. Single-owner (non-conflict) configs are unchanged.

**Presentation parity (#3720 H05).** `ZoneConfig.InterfaceHostInboundEffective`
(`pkg/config/host_inbound_view.go`) — used by `show interfaces <unit>`, `show
security zones`, and the gRPC interface diagnostic — folds the physical-parent
override into a unit ref's effective set with the same additive rule, so the
operator diagnostic agrees with what the dataplane admits. Before #3720 it read
only the exact ref and reported "no override / default-deny" for a unit that in
fact inherited a physical override.

**Base-vs-unit-0 single-address reconciliation (#5699).** A non-VLAN unit 0
collapses onto the base netdev (`ge-0/0/0.0` → Linux `ge-0-0-0`), so the base
interface snapshot and the unit-0 snapshot (`buildInterfaceSnapshots`) enumerate
the IDENTICAL live kernel address through `buildLinkSnapshot`. `BuildZoneHostInboundViews`
groups addresses by `(zone, effective-token signature)`, and the base ref keys
its copy under `overrideByIface[ifN]` (physical-level override only) while unit 0
keys the same address under `overrideByIface[ifN.0]` (the base ∪ unit-0 merged
override above). A per-interface override on the **unit-0** ref therefore made
the two signatures diverge, emitting the SINGLE live address into TWO
host-inbound views with conflicting admit sets. Because the kernel
`xpf_hostinbound` chain matches destination address only (no ingress-interface
predicate), whichever view's rule block sorts first decides — a deterministic
false-deny (the base view's narrower set drops a service the unit-0 override
opened). The fix skips the base (physical) snapshot's host-inbound address
contribution when unit 0 is configured: unit 0's snapshot is the authoritative
carrier (its merged override matches enforcement and `InterfaceHostInboundEffective`),
so the address resolves to ONE view carrying the additive `zone ∪ physical ∪
unit-0` admit set. The skip is gated on the ACTUAL same-netdev collapse
(`snapshotLinuxName(base, unit0) == snapshotLinuxName(base, nil)`), NOT merely
"unit 0 exists": a VLAN unit 0 (`VlanID > 0` → Linux `<base>.<vlan>`) or a
tunnel-mapped unit 0 resolves to a DISTINCT netdev, so the base and unit-0
snapshots enumerate DISJOINT addresses — skipping the base there would drop the
base netdev's own live address from every view and the kernel input chain would
fall through to `policy accept` (FAIL-OPEN). The base snapshot is kept as the
sole carrier both for a VLAN/tunnel unit 0 (distinct netdev) and for an
interface with no unit 0 at all (rare bootstrap / DHCP-on-raw-netdev), so an
address is never dropped from the deny scope.

**Gate alignment.** The commit-time duplicate-address gate
(`buildHostInboundOverrideMapLocal` +
`validateDuplicateHostLocalAddressStrict`, `pkg/config/dup_host_local_address.go`)
mirrors the same additive resolution and quarantine, so the
`CanonicalHostInboundTokenSig` it compares equals the runtime's effective set.

## Repeated host-inbound-traffic blocks merge (#4544)

Junos MERGES two literal `host-inbound-traffic { ... }` blocks authored under
one `security-zone` (or one interface) into a single effective stanza — the
union of their `system-services` / `protocols`. xpf now matches that at both
the zone level and the #3362 per-interface level.

Where this bites is **`load override`** of a hand-authored file. The three
config-arrival paths differ in how they treat two same-key blocks:

- **flat-set** (`set ... host-inbound-traffic system-services ssh` then
  `... protocols ospf`) — `ConfigTree.SetPath` reuses the existing same-key
  container, so the two lines land under ONE node. Structurally immune.
- **`load merge`** — routes through `FormatSet` (a flat-set round-trip), so it
  merges for the same reason.
- **`load override`** (`store_command.go`, `s.candidate = tree`) — splices the
  RAW hierarchical parse straight into the candidate and commits it with no
  FormatSet round-trip. The hierarchical parser (`parseStatements`) keeps two
  literal `host-inbound-traffic { ... }` blocks as **separate same-key
  siblings** — it does not merge them — and there is no duplicate-block schema
  rejection.

Before #4544 the compiler dropped every block but one on the load-override path:
the zone-level `case "host-inbound-traffic"` OVERWROTE (`zone.HostInboundTraffic
= parseHostInboundNode(prop)`, last block wins) and the interface-level reader
used `FindChild` (first block wins). Either way the operator's authored
admission set silently narrowed — a service DoS — or fail-opened if the dropped
block was the restrictive one. A Junos-EXPORTED config always shows one already-
merged block, so the trigger is a hand-authored duplicate + `load override`.

The fix (`mergeHostInbound`, `pkg/config/compiler_security_zones.go`) accumulates
across **all** `FindChildren("host-inbound-traffic")` at both levels and unions
their token sets, deduplicated (first-seen order). A **single** block is
byte-identical to the pre-#4544 behaviour — the first parse is returned
unchanged, with no dedup, so a single block keeps its exact token multiset;
dedup applies only when a second block is actually merged. RED-on-revert guards:
`pkg/config/host_inbound_dup_block_4544_test.go`.

This is orthogonal to the "Per-interface override precedence (#3362, #3720)"
union above, which merges host-inbound authored at DIFFERENT granularities
(zone ∪ physical ∪ unit). #4544 merges repeated blocks at the SAME granularity.

**#4818 extends this merge one level UP.** #4544 merges repeated
`host-inbound-traffic {}` blocks *within one* `security-zone <name> {}`
instance. It did not help if the DUPLICATE was the outer instance itself — a
`load override` with two literal top-level `security-zone trust { ... }`
siblings (one carrying `interfaces`, the other carrying
`host-inbound-traffic`) still lost the first instance wholesale, because
`compileZones` allocated a brand new `ZoneConfig` per instance and the #4544
merge logic never got a chance to run against the discarded first instance's
properties. #4818 makes `compileZones` find-or-create the `ZoneConfig` by
name across instances too, so `mergeHostInbound` now unions
host-inbound-traffic both *within* one instance (#4544) and *across* sibling
instances of the same zone name (#4818) — and the per-interface
`InterfaceHostInbound` map merges the same way when two instances both
declare host-inbound-traffic on the same interface name. See
`docs/config-schema.md`'s "#4818/#4820/#4821" duplicate-block-registry entry
for the two sibling fixes (`services rpm probe`, `security ssh-known-hosts
host`) that share this exact root cause at the named-instance level.
RED-on-revert guards: `pkg/config/zone_dup_block_4818_test.go`.

## Duplicate host-local-address ambiguity (#3718, Option B)

The kernel host-inbound chain matches on **destination address only** — every
rule is `<fam> daddr <zone-addrs> ...` with **no** ingress-interface / VRF / zone
predicate, over a **single global** `inet xpf_hostinbound` input chain
(`emitHostInboundZone`, `pkg/daemon/daemon_nft.go`). So when two security zones
resolve the **same** firewall-local address — a duplicated interface address, a
duplicated VRRP VIP, or the same address reused across routing-instances (a zone
is not VRF-scoped in xpf, so overlapping-VRF reuse surfaces as the cross-zone
case) — they emit two rule blocks keyed on the same `daddr`, in zone-sort order,
and the **earlier-sorting zone decides the packet** regardless of which zone /
interface the traffic actually ingresses. A zero-service zone emits only a
terminal catch-all `drop` for the address, so if it sorts first it drops every
host-bound service the other zone opened (or the inverse admits what the owning
zone denied). Worse, the userspace-dp secondary path (`host_inbound_admits`,
`forwarding/host_inbound.rs`) is **already ingress-zone scoped**, so the kernel
`daddr` path and the userspace path can render **opposite** verdicts on the same
packet — a kernel/userspace split-brain.

This is caught fail-closed at commit and surfaced at runtime:

- **Commit-time gate** `config.validateDuplicateHostLocalAddressStrict`
  (`pkg/config/dup_host_local_address.go`) hard-rejects a config where the same
  `(family, host address)` — an interface address OR a VRRP VIP — is
  host-inbound-reachable from **more than one distinct effective host-inbound
  token set**. It keys on differing token sets, NOT merely ">1 zone", so it does
  **not** false-positive on a deliberate duplicate: the same address in two zones
  with **identical** host-inbound service sets renders the same block twice
  (order-independent, both paths agree) and is allowed; only a differing set (two
  zones with different `host-inbound-traffic`, or one zone with differing #3362
  per-interface overrides) is rejected. Covers IPv4 (H01), IPv6 (M02), VRRP VIPs
  (M03), and the cross-zone subset of same-address-across-routing-instances
  (M04). Management / cluster-control lifeline interfaces (fxp0 / em0 / fab*) are
  excluded, mirroring the deny scoping. On the tolerant load / peer-sync path the
  rejection is downgraded to a `cfg.Warnings` entry (`lenientDuplicateHostLocalAddress`)
  so an already-persisted or peer-synced config an older binary accepted still
  boots (#1960 no-brick).
- **Runtime SSOT** `dpuserspace.AmbiguousHostInboundAddresses`
  (`pkg/dataplane/userspace/zones.go`) reads the scopes back from
  `BuildZoneHostInboundViews` (the same builder that drives nft emission), using
  the shared `config.CanonicalHostInboundTokenSig` so it can never disagree with
  the commit gate on what counts as a differing set. Unlike the addressless
  window above, an ambiguity is **NOT self-healing** — it stands until the config
  is fixed.
- **State-transition log** (`daemon_nft.go`,
  `logHostInboundAmbiguousTransitions`): a `WARN` on ENTRY, an `INFO` on RECOVERY,
  logged once per transition (not every apply).
- **Prometheus gauge** `xpf_host_inbound_ambiguous_addresses{address,family}`
  (`pkg/api`), value `1` per ambiguous address, emitted BEFORE the dataplane gate
  so it stays visible in a config-only / degraded boot. Alert with
  `max_over_time(xpf_host_inbound_ambiguous_addresses[1h]) > 0`.

### Deferred follow-ons

Option B rejects the ambiguity fail-closed; it does **not** yet make the kernel
path ingress-scoped. Two follow-ons are tracked on #3718:

- **Option A — kernel `iifname` ingress-scope**: emit host-inbound rules with an
  `iifname` (ingress netdev / VRF) predicate so the ingress zone disambiguates
  the `daddr`, matching the Junos model and ending the split-brain with the
  already-ingress-scoped userspace path. Deferred: `iifname` must enumerate every
  ingress netdev for a zone (physical, `.0` units, VLAN subinterfaces, VRF
  members, `lo` for locally-generated traffic, HA/fabric paths) or a legitimate
  management packet fails closed and locks out the box — it needs the
  netdev-enumeration audit + loss-cluster lab validation (VLAN units + a VRRP
  failover).
- **Option C — per-VRF host-inbound chains**: separate per-routing-instance input
  chains so the same address can be **intentionally** reused across VRFs with
  distinct host-inbound policies (which Option B rejects). A larger architectural
  fork; deferred until there is demand.

## `to-zone junos-host` policy and the direct host-bound path (#4146)

vSRX layers management-plane admission in two places: the coarse
`host-inbound-traffic system-services <svc>` port gate above, PLUS a fine
`security policies from-zone <z> to-zone junos-host` (or a global
`match to-zone junos-host`) policy that can restrict the source or application
and can `then deny`. On xpf the **representable ordered `then deny` class is now
kernel-enforced on the direct host-bound path** (direction (b), #4146 below); an
un-representable remainder (feed-tainted source, multi-term/ALG application,
scheduler-gated policy, `tcp-rst` ingress zone, `reject`, and the "deny
non-permitted" half of a source-restricted `permit`) is a documented
partial-coverage limitation that keeps the commit warning.

### The gap

Ordinary traffic to a firewall interface IP is delivered by the **Linux kernel**,
not the userspace dataplane. On a session miss the XDP shim's `is_local_destination`
(`userspace-xdp/src/lib.rs`) returns true for any address in the local set and
shunts the packet to the kernel (`cpumap_or_pass`). The nft `xpf_hostinbound`
chain — the PRIMARY enforcement surface documented above — is **permit-by-service
only**: it admits configured `system-services`/`protocols` to a firewall-local
address from **any** source, with **no per-source and no per-application deny**.
The fine `to-zone junos-host` policy runs **only** on the userspace AF_XDP
`LocalDelivery` path (`junos_host_local_policy`), which is reached only by the
subset of host-bound traffic that arrives on the XSK fast path (e.g. DNAT /
static-NAT to a firewall-local address) — never by a direct-to-interface-IP
packet, which was already shunted to the kernel. Net: a
`from-zone X to-zone junos-host { match source-address ...; then deny; }` (or a
source-scoped permit) on a plain interface IP is silently unenforced for the
direct path; hit counters stay zero. This is distinct from #3019 (which wired the
deny into the XSK `LocalDelivery` arm) and #3292 (the flowless arm): those are the
XSK paths that DO enforce it.

### Enforcement (direction b — shipped, #4146)

The representable `to-zone junos-host` DENY class is enforced on the direct
host-bound path by a DROP-only subchain in the kernel `xpf_hostinbound` chain —
the availability-preserving locus (the kernel delivers the packet; the userspace
helper never sees it, so a helper crash cannot lock management out).

- **Projection SSOT (`config.BuildJunosHostDenyProjection`,
  `pkg/config/junos_host_deny.go`).** Per ingress zone, the effective ordered
  program is assembled in Junos's exact three tiers — exact `from-zone Z to-zone
  junos-host` → `from-zone any to-zone junos-host` (#3090) → applicable global
  `match to-zone junos-host` — mirroring `policymatch.matchJunosHost` /
  userspace-dp `evaluate_junos_host_policy`. The projection is decided on the
  **whole ordered program**: if any contributing term is un-representable the
  program emits nothing (no coarsened / partial rule) and its policies keep the
  warning.
- **DROP-only via set-subtraction.** A `deny` becomes a silent `drop`; a `permit`
  NEVER emits a fine `accept` (that would let a fine permit re-admit a
  coarse-rejected service — Rust `poll_descriptor/mod.rs:138`). Instead each later
  deny SUBTRACTS an earlier permit's source set (`saddr != <permit-set>`), so the
  coarse host-inbound gate stays the **sole admit authority**.
- **Ingress `iifname` scope, never `daddr` as the ZONE scope.** The DROP is scoped
  by the from-zone's kernel netdev names
  (`pkg/dataplane/userspace/BuildJunosHostPrograms`), excluding lifelines
  (fxp0/em0/fab*) — a daddr-derived zone scope would both under- and over-deny
  across zones. A global-any term renders per ingress zone with that zone's
  netdevs, never unscoped. An EXPLICIT `match destination-address` adds a
  narrowing `daddr` predicate ON TOP of that iifname scope (see the destination
  slice below); it never replaces it. Because the scope is the ingress netdev, a
  destination-scoped deny on a data zone can never suppress management ingress on
  a lifeline, whichever firewall address it names.
- **Coarse-then-fine order (`pkg/daemon/daemon_nft.go`).** The fine DROP runs after
  ESP/AH accept + the firewall-originated reply-direction established accept, but
  BEFORE the ND/PMTUD accepts and the residual full established accept, so a denied
  source's NEW *and* original-direction-established inbound (including its
  ND/PMTUD) are dropped — matching Rust's per-hit re-eval/teardown. ESP/AH (proto
  50/51) are always exempt; IKE 500/4500 is shielded when the ingress interface
  coarse-admits `ike`; ident-reset TCP/113 keeps its RST when the interface's
  effective coarse verdict is the RST (ident-reset set AND not `all`/`any-service`).
  - **Per-interface scope of the IKE / ident shield (#5565).** The shield is
    scoped to the SPECIFIC netdevs whose EFFECTIVE per-interface host-inbound set
    (`InterfaceHostInboundEffective`, zone-level ∪ interface override) admits the
    exemption — `JunosHostDenyProgram.IKEExemptNetdevs` / `IdentResetNetdevs`,
    each a subset of the program's `IngressNetdevs`. A per-INTERFACE `ike` /
    `ident-reset` override therefore shields only the interface(s) that configured
    it (`iifname "<that-netdev>" ...`), never the whole zone iifname set — a
    least-privilege override on one interface is not widened to a sibling that did
    not configure it. A genuinely ZONE-LEVEL exception (authored on the zone's own
    `host-inbound-traffic`) is folded into every interface's effective set, so its
    subset equals `IngressNetdevs` and the shield stays zone-wide (no regression).
    The zone-wide `application any` DROP itself is unaffected — the deny is a zone
    policy and still scopes by the full zone iifname set; only the ACCEPT/RST
    exemption ahead of it is narrowed. Before #5565 the shield used a single
    zone-wide `CoarseAdmitsIKE` / `CoarseIdentResets` bit derived by unioning
    every per-interface override, so one interface's `ike` falsely admitted IKE
    on every interface in the zone.
  - **Operator note — exempt tuples survive an `application any` deny.** On an
    **IKE-admitting** zone, `from-zone Z to-zone junos-host { match source-address
    BAD; match application any; then deny; }` does **NOT** stop BAD's IKE / IPsec
    NAT-T (UDP 500/4500): the userspace IPsec-passthrough stage returns BEFORE the
    fine junos-host policy, and the kernel decrypts host-terminated IPsec before
    any deny — so 500/4500 is admitted regardless of the deny. Likewise on an
    **ident-resetting** zone (`system-services ident-reset`, not `all`) the same
    deny still answers BAD's TCP/113 with a RST, not a silent drop. This is
    faithful to the Rust runtime (Stage-11 passthrough / the coarse ident-reset
    terminal both run pre-fine), not a bug. To actually deny IKE/ident from a
    source, remove the coarse admission (drop `ike` / `ident-reset` from the
    zone's `host-inbound-traffic`) rather than relying on a junos-host `deny`.
- **Observability.** `xpf_host_inbound_junos_host_denies_total{scope,family}`
  (nft named counters, distinct from the coarse
  `xpf_host_inbound_kernel_denies_total`). This does **not** populate per-Junos-
  policy hit counters / `then count` / RT_FLOW deny attribution — nft cannot
  attribute a drop to a policy object; that is the one "counters stay zero" symptom
  the direct path retains. The userspace XSK path keeps its own attribution.

**Representable subset:** action `deny`; `match source-address` /
`source-address-excluded` **and** `match destination-address` /
`destination-address-excluded` resolving entirely to *static* address-book CIDRs
(recursively feed-untainted); `match application` reducing to simple
proto + optional dst/src port + optional ICMP type/code (application-sets
OR-expanded to multiple rules); **no** `scheduler-name`; ingress zone **not**
`tcp-rst`.

**Address-match semantics (source AND destination).** Both dimensions route
through ONE projection formula (`junosHostProjectAddrMatch`,
`pkg/config/junos_host_deny.go`) so they cannot drift, and both mirror Junos
`matchAddr`:
- A **constrained** set (e.g. `source-address 10.0.0.0/8` + excluded) drops
  every source EXCEPT the set on the family that carries a prefix (IPv4:
  `saddr != 10.0.0.0/8`), and — because the set has no prefix of the *other*
  family — drops **ALL** of that other family (IPv6 here): "everything except
  10/8" is all IPv6. This match-all-of-opposite-family behavior is intentional.
- The **wildcard** case `any` (or the family-scoped `any-ipv4` / `any-ipv6`) +
  excluded is the degenerate "every address EXCEPT every address" = the **empty
  set**: it matches NOTHING and projects **no drop rule** for the affected
  family. `any` suppresses both families; `any-ipv4` / `any-ipv6` suppress only
  their own. Emitting an unconditional drop here (the #5828 bug — the old
  `len(src)==0 => SrcAny` classification) would invert the authored domain and
  could lock out **all** direct host-bound traffic on the ingress zone. A plain
  `source-address any` + `then deny` with **no** exclusion is unaffected — that
  is a legitimate drop-all deny and still emits the unconditional drop.
- A **constrained positive** set with no prefix of a family matches nothing on
  that family and emits no rule there (Junos empty-positive-set semantic).

**`match destination-address` on a DENY (#4146 destination slice).** The kernel
`xpf_hostinbound` chain hooks the INPUT path, so every packet it evaluates is
already host-destined; an explicit destination therefore renders as a narrowing
`<fam> daddr <set>` / `daddr != <set>` predicate **on top of** the `iifname`
zone scope — never as a replacement for it. A destination naming no firewall
address simply matches nothing in the chain, exactly as the Rust /
`policymatch` evaluation of that policy matches nothing, so the live
firewall-local address set is **not** needed to render it. Rust already matched
this dimension on the junos-host path (`rule_l3_matches(rule, state, src_ip,
dst_ip)` in `evaluate_junos_host_policy_l3_aware`); the kernel projection was
the only surface dropping it, which made a `from-zone X to-zone junos-host {
match destination-address <fw-ip>; then deny; }` silently unenforced — and,
because the representability gate is whole-program, silently disabled kernel
enforcement of **every other** junos-host deny on that ingress zone.

A destination-scoped **`permit`** stays un-representable: a permit is projected
only as a `saddr !=` SUBTRACTION of later denies (see DROP-only above), which
cannot express a carve that is also destination-scoped. The whole program then
emits nothing and every one of its policies keeps the warning — never a deny
widened past the permit's destination scope.

**Un-representable remainder (keeps the commit warning below):** feed-tainted
source **or destination**, multi-term / ALG application, an application scoped
to an IPsec/ident exempt tuple, a **destination-scoped `permit`**, a
scheduler-gated policy, a `tcp-rst` ingress zone (silent drop would diverge from
Junos's RST verdict class), `reject`, and the "deny non-permitted" half of a
source-restricted `permit` (the reject and source-restricted-permit slices are
tracked follow-ups using the identical machinery). No partial/coarsened kernel
rule is ever emitted for the remainder.

### Commit-time warning (direction c — shipped; now suppressed on render)

`config.validateJunosHostDirectDeliveryWarnings` (`pkg/config/compiler_validate_warn.go`,
run inside `ValidateConfig`) emits a WARN-only commit message for each `to-zone
junos-host` policy — zone-pair or global — that is **stricter than the coarse
gate** (a `then deny`/`then reject`, or a source-restricted `then permit`) AND is
**not** enforced by the direction-(b) projection above. A representable DENY that
renders an enforced kernel rule in every enforceable ingress zone it applies to
has its warning **suppressed** (`BuildJunosHostDenyProjection().RenderedPolicyKeys`);
an un-representable / lifeline-only / unenforceable policy still warns. The trigger
is deliberately conservative — a plain `permit`-from-any to junos-host only mirrors
the coarse permit-by-service gate and does **not** warn. It is **never a hard
reject**: the config is legal Junos and a reject would brick a previously committed
config. The warning names the policy and points here.

### Historical alternatives (rejected)

- **(a) Withhold junos-host-policy'd interface IPs from the local set** so the
  packet falls through to the XSK `LocalDelivery` junos-host gate. Rejected: the
  XSK redirect-error arm is fail-CLOSED (`drop_degraded_transit` → `XDP_DROP`,
  `lib.rs`), so a withheld IP is **dropped** while the helper is down — inverting
  "management always reachable". Also blocked by the #1864 shim verifier ceiling.
- Enforcing the fine restriction inside **userspace-dp** — wrong locus: a direct
  host-bound packet never reaches the helper (the kernel delivers it).

## Non-handshake TCP first packet on the LocalDelivery session-miss install (#2151 / #4487 / #4539)

The XSK `LocalDelivery` arm may CACHE a firewall-local session on a session
miss so subsequent established packets bypass userspace and return straight to
the kernel (`should_cache_local_delivery_session_on_miss` →
`install_helper_local_session_on_miss`, `userspace-dp/src/afxdp/forwarding/local_delivery.rs`).
That install is gated so a **TCP** session is seeded only off the handshake — a
first packet that carries **SYN** (an initial SYN, or the SYN|ACK inbound leg of
a firewall-originated flow). The gate is a **single positive predicate**:
`crate::tcp_flags::has_syn(tcp_flags)`. Non-TCP (ICMP / UDP) LocalDelivery is
unaffected — the `has_syn` gate is TCP-only and those protocols always cache.

That single `has_syn` predicate (#4539) subsumes two earlier NARROW
decline-gates and closes the residual they left open:

- **#2151** declined to cache off a bare/established **ACK** (`has_ack &&
  !has_syn`, ACK set / SYN clear). Still declined — it is a `!has_syn` case.
- **#4487** declined a **bare RST or bare FIN with no ACK bit** (`is_closing &&
  !has_syn`). Still declined — also `!has_syn`. Without it a RST/FIN flood to a
  firewall interface IP churns the per-worker session table (a cheap host-IP
  session-table DoS) and a later real SYN would HIT the immediately-`closing`
  seed instead of being re-evaluated by the host-inbound / junos-host gates (a
  policy-evaluation skip).
- **#4539** (gate-consistency hardening, LOW) closes the residual the two
  decline-gates missed: a non-handshake anomalous / crafted first packet that is
  **neither ACK-set nor closing** — **pure PSH (0x08), a null segment (0x00),
  pure URG (0x20), or an ECE/CWR-only** segment. Under the old two-gate form
  these fell through to the default `true` and seeded a 300s host-local session
  (`is_initial_syn` false at install → `established = true`). Aligning on
  `has_syn` matches the gate to its stated "only off the handshake" intent.

The `!has_syn` decline is the **same predicate** the transit strict-syn-check
applies (#4400, `strict_syn_check_drops_new_flow`), but the **action differs by
disposition**, exactly as #4400 chose. Transit dispositions (ForwardCandidate /
MissingNeighbor) **DROP** the packet. Host-inbound `LocalDelivery` must **NOT**
drop it: a peer RST/FIN tearing down a firewall-**originated** TCP flow
(BGP-active, syslog-TCP/TLS, feed/RPM fetches, DNS-over-TCP), or a
connection-refused RST for the firewall's own outbound SYN whose dataplane
session was already GC'd, arrives as a session MISS and must still reach the
local stack so the kernel socket tears down promptly (the #4400 LocalDelivery
drop-exemption). So the guard here only declines to **cache**; the
`LocalDelivery` disposition still delivers the declined packet to the host via
the reinject chokepoint. An established-session packet is a session HIT and
never consults this miss-only gate; and any later real SYN is re-evaluated by
the `to-zone junos-host` mandatory-teardown gate that runs on EVERY
LocalDelivery session hit (`poll_descriptor`), so declining to cache never skips
policy.

## Adding a new host-inbound service

Adding or changing a token is a coordinated edit across all three surfaces so the
drift guards stay green:

1. Add the token to `config.KnownHostInboundSystemServices` /
   `config.KnownHostInboundProtocols` (and a family map if it is v4/v6-only, and
   `config.HostInboundL2Protocols` if it rides L2).
2. Add the port/protocol match to `hostInboundServiceMatches` /
   `hostInboundProtocolMatches` in `pkg/daemon/daemon_nft.go`.
3. Add the matching arm to `classify_system_service` / `classify_protocol` in
   `userspace-dp/src/afxdp/forwarding/host_inbound.rs` (and
   `KNOWN_ROUTING_PROTOCOL_TOKENS` for a routing protocol).
4. Update this matrix, and add a fail-on-revert port assertion in
   `pkg/daemon/host_inbound_parity_test.go` for any deliberately-narrow set.

The port sets on surfaces 2 and 3 have **no** automated cross-check of the exact
port numbers (only the token set is guarded by #3486) — the fail-on-revert
assertions in `host_inbound_parity_test.go` plus this matrix are the contract
that keeps the nft and Rust port numbers aligned.

## WireGuard listen port: a dynamic exception, NOT a token (#5582)

WireGuard is deliberately **not** a `system-services` token. Its UDP listen port
is operator-configured (`interfaces <wg> tunnel wireguard listen-port <n>`), so
it does not fit the static token→port SSOT above (a token like `ssh` maps to a
fixed port on all three surfaces). Instead, the kernel host-inbound builder emits
an **automatic, dynamic** `udp dport <configured-wg-port(s)> accept` on the input
hook whenever a WG tunnel is configured (`emitHostInboundWireGuardAccept`,
`pkg/daemon/daemon_nft.go`; port set from `config.WireGuardListenPorts()`). This
mirrors the shim's steer-to-kernel of that exact port so a fresh passive handshake
to a restricted zoned address is admitted rather than dropped. See
`docs/wireguard-interop.md` → "Host-inbound admission of the WG listen port". Do
NOT add a `wireguard` token to `KnownHostInboundSystemServices` — the port is
dynamic and the automatic exception already covers it.

## Junos references

- SIP ALG — default SIP signaling on port 5060; TCP support added in
  12.3X48-D25 / 17.3R1:
  <https://www.juniper.net/documentation/us/en/software/junos/alg/topics/topic-map/security-sip-alg.html>
- Predefined policy applications (junos-sip = UDP+TCP 5060; junos-tftp = UDP 69):
  <https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html>
- system-services (security zones host-inbound-traffic):
  <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-system-service-zone-host-inbound-traffic.html>
- protocols (security zones host-inbound-traffic):
  <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-protocols-zone-host-inbound-traffic.html>
