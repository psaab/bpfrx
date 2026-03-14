# Userspace Dataplane: Feature Gap Analysis

Comprehensive comparison between the eBPF dataplane (full feature set) and the Rust AF_XDP userspace dataplane. When the userspace dataplane encounters unsupported configuration, it transparently falls back to the eBPF pipeline via the XDP shim.

Last updated: 2026-03-14

## Implemented Features

These features work natively in the userspace dataplane:

| Feature | Status | Notes |
|---------|--------|-------|
| Stateful forwarding | Full | Per-worker session tables, forward + reverse entries |
| Zone-based policies | Full | Zone-pair matching with permit/deny actions |
| Application matching | Full | Protocol + port range terms, multi-term apps (pre-expanded by daemon) |
| Source NAT (interface mode) | Full | IPv4 and IPv6, egress interface address |
| Static NAT (1:1 bidirectional) | Full | O(1) hash lookup, zone-aware, pre-routing DNAT + post-routing SNAT |
| NAT64 (IPv6↔IPv4) | Full | Header translation, ICMPv6↔ICMP mapping, checksum recomputation, pool allocation |
| VLANs (802.1Q) | Full | Ingress VLAN tracking, egress VLAN tagging, VLAN sub-interfaces |
| HA cluster | Full | Session sync, fabric redirect, VRRP integration, ~60ms failover |
| Session sync | Full | Incremental sync, GC delete callbacks, peer session replication |
| allow-dns-reply | Full | Unsolicited DNS reply bypass for session-miss path |
| Address books | Full | Pre-expanded to CIDRs by daemon before snapshot delivery |
| Neighbor resolution | Full | Dynamic ARP/NDP tracking, proactive resolution |
| FIB lookup | Full | Per-table IPv4/IPv6 route lookup with longest-prefix match |

## Not Implemented (Fallback to eBPF)

These features cause the userspace dataplane to defer packets to the kernel eBPF pipeline. The `deriveUserspaceCapabilities()` function in `manager.go` detects these and marks forwarding as unsupported for affected traffic.

### NAT

| Feature | Gap | Complexity |
|---------|-----|------------|
| Source NAT (pool mode) | No address pool allocation, no port translation | Medium |
| Destination NAT | Being implemented — plan at `docs/userspace-dnat-plan.md` | Medium |
| NPTv6 (RFC 6296) | No stateless IPv6 prefix translation | Low |

### Security

| Feature | Gap | Complexity |
|---------|-----|------------|
| Screen/IDS (all 11 checks) | No land, SYN flood, ping-of-death, teardrop, SYN-FIN, no-flag, winnuke, FIN-no-ACK, rate-limiting | High |
| SYN cookie flood protection | No XDP-generated SYN-ACK cookies | High |
| Global policies | `junos-global` zone pair not matched | Low |
| Firewall filters | No port-range filters, hit counters, logging, DSCP rewrite, policer, lo0 filter | High |

### Flow Processing

| Feature | Gap | Complexity |
|---------|-----|------------|
| TCP MSS clamping | No ingress/egress MSS adjustment (including GRE gre-in/gre-out) | Medium |
| ALG control | No application layer gateway support | High |
| allow-embedded-icmp | Field tracked but not actively enforced | Low |
| Per-application timeouts | Static timeouts only (TCP 300s, UDP 60s, ICMP 15s) | Low |
| Embedded ICMP error NAT reversal | Partial — reverse DNAT exists but incomplete inner-packet analysis | Medium |
| TTL check / ICMP Time Exceeded | TTL checked and decremented; no ICMP TE generated (packet dropped) | Medium |

### Routing

| Feature | Gap | Complexity |
|---------|-----|------------|
| Policy-based routing (PBR) | No `ip rule` integration, no routing-instance action | Medium |
| ECMP multipath | Routes loaded but no equal-cost tie-breaking / load balancing | Medium |
| VRF enforcement | Routes per-table but no full per-VRF policy isolation | Medium |
| GRE tunnel transit | No POINTOPOINT detection, no pseudo-Ethernet header | High |
| IPsec / XFRM interfaces | No strongSwan integration, no XFRM support | High |

### Observability

| Feature | Gap | Complexity |
|---------|-----|------------|
| Syslog (per-packet) | No RT_FLOW structured logging, no facility/severity filtering | Medium |
| NetFlow v9 export | No 1-in-N sampling or flow export | Medium |
| SNMP counters | No ifTable MIB integration | Low |

### Session Management

| Feature | Gap | Complexity |
|---------|-----|------------|
| Filtered session clearing | Sessions can be deleted but not filtered by criteria | Low |
| Session idle time display | No per-session idle time tracking for CLI display | Low |

### Control Plane Features (Not Applicable)

These features are handled by the Go daemon, not the dataplane. They work regardless of which dataplane is active:

- DHCP relay (Option 82)
- DHCP server (Kea integration)
- RPM probes
- Dynamic address feeds
- LLDP
- Router Advertisements (RA)
- FRR routing protocol integration
- Config management (candidate/active/rollback)
- CLI / gRPC / REST APIs
- Event engine

## Fallback Mechanism

When any unsupported feature is detected in the active configuration, the Go manager (`pkg/dataplane/userspace/manager.go`) calls `deriveUserspaceCapabilities()` which checks for:

1. Firewall filters or policers configured
2. TCP MSS clamping enabled
3. Screen profiles assigned to zones
4. IPsec gateways, VPNs, or policies
5. Tunnel interfaces (GRE, ip6gre)
6. Per-application session timeouts
7. Global policies
8. NetFlow/flow monitoring
9. Destination NAT rules (being implemented)

If any are found, `ForwardingSupported` is set to `false` with reasons logged. The XDP shim then passes all transit packets to the kernel eBPF pipeline instead of AF_XDP sockets.

## Priority Roadmap

Based on real-world usage patterns, suggested implementation priority:

1. **Destination NAT** — in progress, plan at `docs/userspace-dnat-plan.md`
2. **Source NAT (pool mode)** — common in enterprise configs
3. **Global policies** — trivial to add (treat `junos-global` as wildcard zone)
4. **Per-application timeouts** — low effort, high value
5. **TCP MSS clamping** — important for tunnel/VPN environments
6. **Screen/IDS** — SYN flood protection is the highest priority check
7. **PBR** — needed for multi-VRF deployments
8. **Firewall filters** — complex but needed for advanced deployments
