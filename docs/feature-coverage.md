# xpf feature coverage

xpf replicates the Juniper vSRX feature set on a Rust AF_XDP userspace
dataplane driven by a Go control plane. vSRX parity tracking lives in
[`feature-gaps.md`](feature-gaps.md) and [`vsrx-gaps.md`](vsrx-gaps.md);
the userspace dataplane admission boundary is in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

## Firewall & security

- **Zone-based policies** with stateful inspection, address books,
  application matching (multi-term apps), global policies, filtered
  session clearing.
- **NAT**: source (interface + pool, userspace-v2 address-persistent),
  destination (with hit counters), static 1:1 (with optional
  `match destination-port` + `mapped-port` per-port forwarding, #2491),
  NAT64, NPTv6 (RFC 6296 stateless prefix translation).
- **Dual-stack**: IPv4 + IPv6, DHCPv4/v6 clients, embedded Router
  Advertisement sender (replaces radvd), SLAAC.
- **Screen/IDS**: 11 checks (land, SYN flood, ping of death, teardrop,
  SYN-FIN, no-flag, winnuke, FIN-no-ACK, rate-limiting), SYN cookie flood
  protection (userspace-minted/validated SYN-ACK cookies replied through
  the AF_XDP TX path).
- **Firewall filters**: policer (token bucket + three-color), lo0 filter,
  flexible match, port ranges, hit counters, logging, forwarding-class
  DSCP rewrite.

## Flow processing

- **TCP MSS clamping** in the userspace AF_XDP dataplane (all-tcp,
  ipsec-vpn, and GRE gre-in/gre-out).
- **Path MTU Discovery** on the forwarding path: a forwarded frame that
  exceeds the egress interface MTU and is not transparently TCP-segmented
  (UDP, ICMP, ESP, GRE, TCP seg-miss) triggers an ICMPv4 Fragmentation
  Needed (type 3 code 4, next-hop MTU) for IPv4 DF / ICMPv6 Packet Too
  Big (type 2, MTU) for IPv6 back to the sender, instead of a silent MTU
  drop (#2301). RFC 792/4443 suppression applies (no reply to inbound
  ICMP errors or non-first fragments). NAT64 already translates
  PTB↔Frag-Needed across the boundary (#2219). The generated PTB is
  classified by its OWN egress 5-tuple through the shared
  `classify_generated_reply` output classifier (#2328, #2238 contract
  parity with the Time Exceeded / policy-reject / SYN-cookie generators):
  an output firewall filter `then discard` / CoS forwarding-class / DSCP
  rewrite keyed on the generated ICMP fires, and a parse failure of the
  built bytes fails CLOSED (drop + `generated_reply_classify_parse_errors`).
  Output-filter drops of the PTB land on `ptb_output_filter_drops`.
- **ALG control**, allow-dns-reply, allow-embedded-icmp.
- **Configurable timeouts** (per-application inactivity).
- **Session management**: filtered clearing, idle time tracking, brief
  tabular view, aggregation reporting.

## Routing & networking

- **FRR integration**: static, OSPF, BGP, IS-IS, RIP, ECMP multipath,
  export/redistribute.
- **VRFs** with inter-VRF route leaking (next-table + rib-group).
- **GRE tunnels**, XFRM interfaces, PBR (policy-based routing).
- **Probe-driven WAN failover** (`services ip-monitoring` preferred-route
  injection, #1827).
- **VLANs**: 802.1Q tagging, trunk ports.
- **IPsec**: strongSwan config generation, IKE proposals, gateway
  compilation.
- **Full interface management**: xpfd owns ALL interfaces — renames via
  `.link` files, configures addresses/DHCP via `.network` files, brings
  down unconfigured interfaces (see
  [`network-topology.md`](network-topology.md) and the interface-management
  notes in [`critical-patterns.md`](critical-patterns.md)).

## High availability

- **Chassis cluster** with ~60ms failover (30ms VRRP intervals).
- **Native VRRPv3**: Go state machine, AF_PACKET, per-instance sockets,
  IPv6 NODAD, 30ms RETH advertisements, async GARP burst, single-interface
  tracking (nested `track-interface <if> priority-cost <n>`). Tracking
  follows the configured interface NAME (Junos semantics) and is robust to a
  runtime kernel rename: the link watcher keys rename detection on the stable
  ifindex, so when the tracked name is renamed away (a single `RTM_NEWLINK`
  with the same ifindex but a new name, no `RTM_DELLINK`) the instance demotes
  rather than holding stale "up" state (#2944).
- **Bondless RETH**: VRRP on physical member interfaces, per-node virtual
  MAC (`02:bf:72:CC:RR:NN`), no Linux bonding required.
- **Session sync**: incremental 1s sweep + ring buffer + GC delete
  callbacks, TCP on fabric link.
- **Config sync**: primary → secondary with `${node}` variable expansion,
  reverse-sync on reconnect.
- **IPsec SA sync**: shared IKE/ESP state across cluster nodes.
- **Dual fabric links**: independent fab0/fab1 for redundancy (no
  bonding).
- **Fabric cross-chassis forwarding**: redirects to peer when FIB fails
  for synced sessions — prevents TCP death on VRRP failback (see
  [`fabric-cross-chassis-fwd.md`](fabric-cross-chassis-fwd.md)).
- **Dataplane watchdogs**: userspace heartbeat fails closed on
  daemon/helper failure; config naming the retired `ebpf` backend runs in
  config-only mode until updated.
- **Readiness gate**: per-RG readiness (interfaces + VRRP) + hold timer
  gates election.
- **Planned shutdown**: near-instant takeover (priority-0 burst);
  failback ~130ms.
- **ISSU**: in-service software upgrade with rolling deploy.
- **RA lifecycle**: goodbye RAs (lifetime=0) on failover/startup to
  prevent stale IPv6 ECMP routes.

## Observability

- **Syslog**: facility/severity/category filtering, structured RT_FLOW
  format, TCP/TLS transport, event mode local file.
- **NetFlow v9 / IPFIX**: 1-in-N sampling, per-collector write-health
  (`show flow-monitoring statistics`, REST `/api/v1/services/flow-exporters`,
  `xpf_flow_export_collector_*` Prometheus metrics — a collector going
  unreachable surfaces write_failures + a state-change warn, #2464).
- **Prometheus metrics** (`/metrics` endpoint).
- **SNMP**: system + ifTable MIB.
- **RPM probes**, dynamic address feeds.
- **Dataplane buffer utilization** (`show system buffers`): AF_XDP
  UMEM/TX-ring capacity, CoS queued-byte capacity, helper-published
  session-table and flow-cache capacity.
- **LLDP**: link layer discovery protocol.

## Management

- **Interactive CLI**: Junos-style prefix matching, tab completion, `?`
  help, pipe filters (`| match`, `| count`, `| except`).
- **Remote CLI**: `cli` binary connects via gRPC with full tab/`?` parity.
- **gRPC API**: 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP,
  cluster).
- **REST API**: HTTP on port 8080 (health, Prometheus, config, full gRPC
  parity).
- **Config management**: candidate/active with commit model, 50 rollback
  slots, `load override`/`load merge`, `show | display set`.
- **Configure mode protection**: blocked on secondary cluster nodes (RG0
  primary is config authority).
- **DHCP server**: Kea integration with lease display; static / fixed /
  reserved host bindings (`static-binding <mac> { fixed-address; host-name; }`
  under `dhcp-local-server`/`dhcpv6-local-server` → Kea per-subnet
  `reservations`, HA-consistent via config-sync — #2243).
- **DHCP relay**: Option 82 support.
- **Event engine**: event-driven automation.

## Userspace dataplane capability matrix

The userspace dataplane covers the transit feature set in native Rust.
The exact admission boundary is documented in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

| Capability | Userspace AF_XDP (the runtime path) |
|------------|-----------|
| Stateful forwarding | Yes |
| Zone + global policies | Yes |
| Application matching | Yes |
| Source NAT (interface + pool) | Interface and pool mode yes; userspace `address-persistent` uses a documented userspace-v2 seeded FxHash selector (#2349 replaced the prior SHA-256; see `docs/userspace-dataplane-gaps.md` for the authoritative algorithm/contract). Non-HA per-pool `persistent-nat` lease reuse and pool exhaustion counters are implemented in helper-local runtime state; HA/restart persistence and cross-backend new-flow parity remain outside the current contract |
| Destination NAT | Yes |
| Static NAT (1:1) | Yes; optional per-port forwarding (#2491) — `match destination-port <port>` + `then static-nat prefix <ip> mapped-port <port>` translates the destination port on the inbound DNAT and un-translates the source port on the reverse SNAT, so several services can share one external IP. A port-less rule is the whole-address 1:1 fallback; both can coexist on one external IP. Per-port forwarding is HOST-scope only: a subnet block map (`static-nat prefix <subnet>`, #3031) is address-only 1:1 and a `match destination-port` / `mapped-port` combined with a block prefix is REJECTED at commit (`StaticNatBlock` has no port fields, so the port mapping would be silently dropped into an all-port whole-subnet NAT, #3202). The inbound DNAT lookup evaluates the `from zone` constraint PER CANDIDATE (#2864): a port-specific entry whose zone does not match the packet's ingress zone falls through to the whole-address `(dst_ip, None)` entry (which is then zone-checked on its own) instead of short-circuiting to no-DNAT — the port-specific entry still wins when its zone matches. The reverse SNAT lookup is symmetrically gated on the EGRESS zone (#2871): static NAT is bidirectional, so the reverse (source) translation applies only when the packet egresses TOWARD the rule's configured `from zone` (the same per-candidate zone check as DNAT, but on the destination/egress zone instead of the ingress zone). An empty `from zone` ("any zone") still matches every egress zone. Without this gate an outbound packet sourced from a static-NAT internal IP but destined for ANOTHER internal zone was source-translated to the public external IP — an east-west cross-zone leak |
| NAT64 (IPv6↔IPv4) | Yes; translates ICMP echo AND error messages (Destination-Unreachable, Time-Exceeded, Packet-Too-Big↔Fragmentation-Needed with MTU adjustment, Parameter-Problem) per RFC 7915 §4.2/§5.2, including the embedded quoted packet — so PMTUD and traceroute work across the boundary (#2219). Per-packet **fragment translation** is RFC 7915 §4/§5 compliant (#2488): v6→v4 derives the IPv4 MF/offset/Identification from the IPv6 Fragment Header (low 16 bits of its 32-bit id) instead of the `no-v6-frag-header` config; v4→v6 inserts an IPv6 Fragment Header (next-header 44) for a fragmented IPv4 input. The TCP/UDP checksum on a first fragment is adjusted incrementally for the pseudo-header address change (RFC 1624, the full payload is not present). **Limitation:** only first/atomic fragments translate — non-first fragments are dropped both directions because the round-robin SNAT pool + port-keyed sessions cannot consistently map a port-less fragment to its datagram, so end-to-end fragmented NAT64 needs a stateful fragment-id cache (separate follow-up) |
| NPTv6 (RFC 6296) | Yes |
| Screen/IDS (11 checks) | Yes; userspace SYN-cookie runtime is wired |
| Firewall filters + policers | Filters yes; three-color policers admitted for the reviewed color-blind `then discard` slice; broader color-aware and non-drop action work is tracked as production hardening |
| TCP MSS clamping | Yes |
| GRE tunnel transit | Yes (passthrough) |
| IPsec / XFRM | Yes (passthrough) |
| VLANs (802.1Q) | Yes |
| Flow export (NetFlow v9) | Yes |
| HA cluster + session sync | Integrated; HA hardening tracked in open issues |
| SYN cookie flood protection | Yes |
| Throughput (25G mlx5) | See validation/perf docs for current results |

SYN-cookie-dependent screen behavior runs in userspace with bounded
SYN-ACK/RST replies and userspace status counters (#1374 closed). Port
mirroring has bounded userspace runtime admission (#1376 closed).
Three-color policers are admitted for the bounded color-blind
`then discard` runtime slice (#1375 closed); remaining color-aware,
non-drop action, and HA/restart continuity work is production hardening
tracked in open issues such as
[#1614](https://github.com/psaab/xpf/issues/1614) (CoS regression) and
[#1608](https://github.com/psaab/xpf/issues/1608) (cold-path hardening),
not the closed #1373 feature-gap trackers. Pool-mode SNAT is admitted,
#1385 added userspace-v1 `address-persistent` selection, and the runtime
fails closed for unusable or exhausted source-NAT pool rules before
forwarding.
