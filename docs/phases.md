# Implementation Phases

## Phase 1-3: Foundation, Stateful Firewall, NAT
- XDP pipeline with tail calls, zone lookup, 5-tuple conntrack
- SNAT with interface masquerade, DNAT with destination pools
- Session creation with dual entries (forward + reverse)

## Phase 3.5: IPv6 Dual-Stack
- Separate BPF maps per address family (v4/v6)
- IPv6 extension header walking in BPF
- `csum_update_16` for incremental IPv6 checksum updates

## Phase 4: TC Egress + Host-Inbound
- TCX attachment for egress pipeline
- 17 host-inbound service flags (ssh, ping, dhcp, dhcpv6, dns, http, https, etc.)
- 10 global counters (rx/tx packets, drops, sessions, screen drops, policy denies)

## Phase 5: Screen/IDS
- 7 stateless checks: land, syn-flood, ping-death, source-route, teardrop, winnuke, ip-sweep
- 3 rate-based checks with per-CPU token buckets
- Screen applied per-zone in xdp_screen

## Phase 6: NAT Port Allocation + ICMP NAT + Source Pools
- Ephemeral port range allocation for SNAT
- ICMP echo ID-based NAT (maps ID like a port)
- Multiple source pools with round-robin IP selection

## Phase 7: Interface Management & Traffic Counters
- Per-interface, per-zone, per-policy packet/byte counters
- Interface config compilation (IPs, zones, host-inbound flags)

## Phase 8: Configuration Management
- `delete` command support, `default-policy` setting
- `show | compare` config diff, `show configuration` display

## Phase 9: Reject + Static NAT + SNAT Fix
- TCP RST generation for REJECT action
- Static 1:1 bidirectional NAT
- Fixed SNAT return path via dnat_table

## Phase 10: Session Close Events, Clear Sessions, DNAT CLI
- BPF ring buffer events for session close (TCP FIN/RST, timeout)
- `clear security flow session` CLI command
- DNAT rule display in CLI

## Phase 11: Observability & CLI
- Syslog client forwarding from ring buffer events
- Event buffer (last N events in memory)
- `show security zones`, `show security address-book` display

## Phase 12: Config Persistence & Reload
- Rollback files saved on commit (up to 50 slots)
- Syslog hot-reload on config changes

## Phase 13: Multi-Address Policy & Multiple SNAT Rules
- Policies matching multiple source/destination addresses
- Up to 8 SNAT rules per zone-pair

## Phase 14: Rollback N + CLI Polish
- `rollback N` command restores Nth previous config
- Tab completion for all CLI commands
- `?` context help, value providers for IPs/interfaces/zones

## Phase 15: TC Egress NAT + Egress Screen
- Shared `bpfrx_nat.h` between XDP and TC programs
- Egress NAT translation (return traffic)
- Egress screen checks (12 total BPF programs)

## Phase 16: Logging Enhancements & CLI Completion
- Per-rule log flags (session-init, session-close)
- `| match PATTERN` pipe filtering for show commands

## Phase 17: Configurable Session Timeouts + Graceful Shutdown
- Per-protocol-state timeout configuration
- Session filtering (show sessions by source/dest/zone)
- Signal handler for clean daemon shutdown

## Phase 18: Application Sets, Commit Confirmed, Screen Fixes
- Application-sets with recursive expansion (max depth 3)
- `commit confirmed N` with auto-rollback timer
- NAT port range configuration

## Phase 19: Routing, GRE Tunnels, FRR Integration, IPsec
- Static route management (now via FRR)
- GRE tunnel creation via netlink, zone binding
- FRR config generation for OSPF/BGP
- strongSwan config generation for IPsec VPNs

## Phase 20: VLAN Support & Logical Interfaces
- 802.1Q VLAN tagging in BPF (push/pop)
- Trunk port support with multiple VLAN IDs
- Logical interface (unit N with vlan-id) compilation

## Phase 21: DNAT End-to-End Verification
- Protocol match in DNAT rules
- Wildcard port fallback for DNAT
- Critical byte-order fixes (ipToUint32BE -> NativeEndian)

## Phase 22: Built-in DHCP Client + SR-IOV Internet Zone
- DHCPv4 client with lease management and auto-recompile
- DHCPv6 client with DUID persistence (DUID-LL)
- Host-inbound DHCPv6 flag for ICMPv6/UDP 546-547
- SR-IOV PCI passthrough for WAN interface in Incus

## Phase 23: REST API + Prometheus Metrics
- HTTP server on configurable address (default 127.0.0.1:8080)
- Custom Prometheus collector for all counter types
- 17 REST endpoints (health, config, zones, policies, sessions, routes, etc.)

## Phase 24: gRPC API + bpfrxctl Remote CLI
- Protobuf service definition with 36 RPCs
- Full config management (set, delete, commit, rollback, show compare)
- Session/stats/routes/IPsec/DHCP query RPCs
- Remote tab completion via gRPC streaming
- `cli` binary connects to gRPC for remote management

## Phase 25: Nested Address-Sets
- Nested address-sets with recursive expansion (max depth 5, cycle detection)

## Phase 26: Routing Instances (VRFs)
- Routing instances using Linux VRF devices (`ip link add type vrf table N`)
- Per-VRF static routes, OSPF, BGP via FRR
- Policy-based routing via firewall filter -> VRF table ID

## Phase 27: IPv6 Router Advertisements
- IPv6 Router Advertisements via radvd daemon management

## Phase 28: NAT64 in BPF/XDP (Native Implementation)
- Native BPF/XDP implementation (no Tayga/Jool), designed for performance
- New BPF program: `bpf/xdp/xdp_nat64.c` (tail call index 6)
- Forward (v6->v4): `bpf_xdp_adjust_head(ctx, 20)` shrinks packet, builds IPv4 header
- Reverse (v4->v6): `bpf_xdp_adjust_head(ctx, -20)` grows packet, restores IPv6
- Incremental checksums: pseudo-header swap (no full-payload iteration)
- ICMP translation: echo request/reply type mapping (128<->8, 129<->0)
- Maps: nat64_configs (ARRAY), nat64_count (ARRAY), nat64_state (HASH)
- Config: `set security nat nat64 rule-set NAME prefix 64:ff9b::/96` + `source-pool POOL`
- **Known:** fails verifier on kernel 6.12 (too complex for xdp_zone), passes on 6.18

## Phase 29: Firewall Filters & DSCP Marking
- Filter evaluation in xdp_main (before zone pipeline)
- DSCP matching in filter terms
- Policy-based routing via VRF table ID assignment
- IPv6 filter support (ICMPv6 type/code matching)

## Phase 30: NetFlow v9 Export
- Event-driven export (session close callback from ring buffer)
- UDP collectors with configurable addresses/ports
- Template refresh at configurable interval
- Wire format: v9 header + template flowset + data flowset

## Phase 31: Dynamic Address Feeds
- HTTP fetcher for external IP/CIDR lists
- Periodic refresh with configurable interval
- CIDR validation and deduplication
- Auto-recompile dataplane on feed update

## Phase 32: DHCPv4/v6 Server
- Kea DHCP server config generation from Junos syntax
- systemctl lifecycle management (start/stop/reload)
- Subnet/pool/option configuration

## Phase 33: RPM Probes & ISP Health Monitoring
- HTTP, ICMP, TCP probe types
- Configurable probe/test intervals
- Threshold-based failure detection (successive-loss count)
- Probe results queryable via CLI and gRPC

## Phase 34: ALG Control & Flow Options
- TCP MSS clamping in BPF (ipsec-vpn and all-tcp modes)
- ALG disable flags (dns, ftp, sip, etc.) stored in flow_config map
- Constant-offset MSS option scanning (verifier-safe)

## Phase 35b: systemd Deployment + Daemon Mode + FRR Unified Routing
- TTY detection via TCGETS ioctl for interactive vs daemon mode
- systemd unit file with LimitMEMLOCK=infinity, Restart=on-failure
- HTTP API always-on by default (127.0.0.1:8080)
- All routes via FRR (static, DHCP-learned, per-VRF)
- Managed section markers in frr.conf for non-destructive updates
- setup.sh: start/stop/restart/logs/journal commands
- Makefile: test-start/stop/restart/logs/journal targets
