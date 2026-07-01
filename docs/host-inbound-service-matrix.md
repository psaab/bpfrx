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

1. **Go SSOT — recognized-token allowlist + address family.** The set of
   meaningful tokens and their address-family scoping. Commit-time validation
   hard-rejects any token outside it (#3200).
   - `config.KnownHostInboundSystemServices` — `pkg/config/host_inbound_tokens.go`
   - `config.KnownHostInboundProtocols` — same file
   - `config.HostInboundServiceFamily` / `config.HostInboundProtocolFamily` —
     family scoping (`ip` = IPv4-only, `ip6` = IPv6-only, absent = dual)
   - `config.HostInboundL2Protocols` / `config.HostInboundAllExpansionProtocols()`
     — `protocols all` expansion minus L2/non-IP tokens
   - The Go SSOT declares the token allowlist and family, **not** the port
     numbers. The port sets live on the two enforcement surfaces below, which are
     hand-mirrors of each other.

2. **nft kernel mirror — PRIMARY enforcement.** Host-bound traffic to a
   firewall interface IP / VRRP VIP is shunted to the kernel by the XDP shim
   before it reaches userspace-dp, so the nftables `inet xpf_hostinbound` chain
   carries ~100% of real host-inbound traffic.
   - `hostInboundServiceMatches` — `pkg/daemon/daemon_nft.go` (services)
   - `hostInboundProtocolMatches` — same file (protocols)
   - `hostInboundServiceAction` — same file (ident-reset reject verdict)
   - global always-accepts — `buildHostInboundFilterPayload`, same file

3. **Rust AF_XDP classifier — SECONDARY enforcement.** The XSK
   local-delivery path, reached only by the subset of host-bound traffic that
   arrives on the AF_XDP fast path (e.g. DNAT/static-NAT to a firewall-local
   address).
   - `classify_system_service` / `classify_protocol` —
     `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
   - `is_icmp_host_inbound_global_accept` — same file (global ICMP/ND accepts)

**Drift guards.** The token *sets* are pinned in lockstep by
`config.TestHostInboundRustClassifierMatchesGoSSOT` (`pkg/config/host_inbound_rust_parity_test.go`,
#3486 — parses the Rust source and asserts its match arms equal the Go SSOT) and
`TestHostInboundNftMatchesKnownTokens` (`pkg/daemon/host_inbound_parity_test.go`,
#3200 — asserts the nft matcher's domain equals the SSOT). The *port sets* for
deliberately-narrow tokens (sip, tftp, traceroute, bfd, the #3341 routing
protocols) are additionally pinned by fail-on-revert assertions in
`pkg/daemon/host_inbound_parity_test.go` so an accidental widen turns RED.

## system-services matrix

| Token (aliases) | nft match (`daemon_nft.go`) | Rust admit (`host_inbound.rs`) | Family | Notes |
|---|---|---|---|---|
| `all` / `any-service` | full admit | `all_services = true` | dual | Blanket accept for the zone. |
| `ssh` | tcp 22 | tcp 22 | dual | |
| `telnet` | tcp 23 | tcp 23 | dual | |
| `ftp` | tcp 21 | tcp 21 | dual | Control port only; FTP data is an ALG/transit concern. |
| `http` / `webapi-clear-text` | tcp 80 | tcp 80 | dual | |
| `https` / `webapi-ssl` | tcp 443 | tcp 443 | dual | |
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

## Global always-accepts (independent of the zone token set)

These are accepted on EVERY host-inbound-configured zone regardless of its
`system-services` / `protocols` set, so enforcement never breaks core L3
operation or session return traffic. nft: `buildHostInboundFilterPayload`; Rust:
`is_icmp_host_inbound_global_accept` + `stage_ipsec_passthrough_check`.

| Class | nft | Rust | Rationale |
|---|---|---|---|
| Established/related | `ct state established,related accept` | conntrack fast path | Return / ongoing host traffic. |
| Raw IPsec ESP/AH | `meta l4proto { 50, 51 } accept` | `stage_ipsec_passthrough_check` (before `host_inbound_admits`) | Kernel XFRM decrypts host-terminated IPsec; makes `ike`/`ipsec` a working superset. |
| ICMPv4 errors/PMTUD | `icmp type { destination-unreachable, time-exceeded, parameter-problem }` | proto 1 types 3, 11, 12 | PMTUD / unreachable / traceroute-to-self signalling. Echo-request is NOT here (gated on `ping`). |
| ICMPv6 errors + ND | `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }` | proto 58 types 1-4, 133-137 | v6 error/PMTUD (1-4) + Neighbor Discovery (133-137). Echo-request (128) is NOT here (gated on `ping`). |

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
boundary. The window **self-heals**: the DHCP lease-change and commit paths
re-render the chain the moment an address appears (and VRRP VIPs are resolved
from config, so a VIP-scoped zone is never in the window even on the backup
node). An address-scoped nft deny cannot be installed without an address, so the
window itself is accepted as unavoidable; #3698 makes it **observable** rather
than silent.

The SSOT for "which configured enforcing zones are currently in the window" is
`dpuserspace.AddresslessEnforcingZones` (`pkg/dataplane/userspace/zones.go`). It
reads the scoped/unscoped decision back from `BuildZoneHostInboundViews` — the
same builder that drives the nft emission — so the signal can never disagree with
what the daemon enforces. It reports a zone iff it has at least one **non-lifeline**
interface assigned yet resolves no address; zones that are scoped, whose only
interfaces are management/cluster-control lifelines (fxp0 / em0 / fab*), or that
have no interfaces are deliberately NOT reported (low-noise).

Two observability surfaces consume it:

- **State-transition log** (`daemon_nft.go`, `logHostInboundAddresslessTransitions`).
  A `WARN` is logged when a zone ENTERS the window and an `INFO` when it LEAVES
  (an address appears). It logs only transitions — a zone that stays addressless
  across repeated commits / DHCP renewals is logged once, not every apply.
- **Prometheus gauge** `xpf_host_inbound_addressless_zones{zone}` (`pkg/api`).
  Value `1` per zone currently in the window; the series is absent when the zone
  is enforced. Emitted BEFORE the dataplane gate (config-derived, so it stays
  visible in a config-only / degraded boot). Alert with e.g.
  `max_over_time(xpf_host_inbound_addressless_zones[1h]) > 0`.

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
