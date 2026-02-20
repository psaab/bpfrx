# bpfrx Session History

## Project Overview

**bpfrx** is an eBPF-based firewall that clones Juniper vSRX capabilities using native Junos configuration syntax. Go userspace (cilium/ebpf) drives C eBPF programs attached at XDP (ingress) and TC (egress).

| Metric | Value |
|--------|-------|
| Period | February 6 -- February 20, 2026 |
| Total commits | 404 |
| Calendar days | 14 |
| Estimated codebase | ~170K lines (Go + C + Proto) |
| BPF programs | 14 (9 XDP + 5 TC) |
| Test count | 630+ across 20 packages |

---

## February 6, 2026 -- Day 1: Foundation (4 commits)

### Prompt 1: Build the eBPF firewall from scratch

The user asked Claude to build an eBPF-based firewall that mimics Juniper vSRX behavior, using Junos configuration syntax, with XDP for ingress and TC for egress.

**Phase 1 -- eBPF Dataplane + Junos Parser + CLI Shell** (`7d171dd`): Built the entire foundation in a single commit -- BPF C programs for XDP ingress, a Junos configuration parser producing an AST, typed Go config structs, a config compiler to BPF map entries, the cilium/ebpf loader, and an interactive Junos-style CLI shell.

**Phase 2 -- Stateful Firewall** (`c4e0688`): Conntrack hash map with dual session entries (forward + reverse), zone-based policy evaluation, per-CPU scratch map for passing metadata between tail-call stages, session state machine (SYN/ESTABLISHED/CLOSING).

**Phase 3 -- NAT** (`4efae40`): Source NAT (interface mode) and destination NAT with port translation. SNAT pool allocation, DNAT rule lookup with pre-routing in the zone stage.

**Phase 3.5 -- IPv6 Dual-Stack** (`9879f92`): Full IPv6 support -- session_v6 hash map, IPv6 conntrack, ICMPv6 handling, dual-stack policy evaluation. IPv6 sessions use `session_v6_scratch` per-CPU map because the BPF stack is too small (512 bytes).

---

## February 7, 2026 -- Day 2: Pipeline Completion (5 commits)

### Prompt 2: Add TC egress, screen/IDS, NAT improvements, and counters

**Phase 4 -- TC Egress Pipeline** (`88d87c0`): Five TC programs (main, screen_egress, conntrack, nat, forward) with host-inbound-traffic enforcement. TC egress checks ensure return traffic is properly NAT'd.

**Phase 5 -- Screen/IDS** (`f864832`): Eleven screen checks -- land attack, SYN flood, ping of death, teardrop, IP spoofing, ICMP fragment, large ICMP, TCP no-flag, TCP SYN-FIN, unknown protocol, and rate limiting.

**Phase 6 -- NAT Port Allocation + ICMP NAT + SNAT Pools** (`d3014f9`): Port allocation with per-CPU collision avoidance, ICMP query ID translation, source NAT pool support with address ranges.

**Phase 6 Verifier Fix** (`05a6e03`): BPF verifier was rejecting Phase 6 changes due to complexity. Reduced branch depth and used `__noinline` functions to stay under the 512-byte stack limit.

**Phase 7 -- Traffic Counters** (`e12dc7c`): Per-interface, per-zone, and per-policy traffic counters in BPF maps, exposed via CLI `show` commands.

---

## February 8, 2026 -- Day 3: Config Management + Observability (8 commits)

### Prompt 3: Config management, reject action, static NAT, syslog, persistence, multi-address, tab completion

**Phase 8 -- Config Management** (`25ad86e`): `delete` command, `default-policy` support, `show | compare` for candidate vs active diff.

**Phase 9 -- Reject + Static NAT** (`8400e23`): TCP RST and ICMP unreachable generation for REJECT action. Static 1:1 NAT. Fixed SNAT session keying to use pre-NAT source.

**Phase 10 -- Session Close + Clear + Validation** (`fa95550`): Session close events for syslog, `clear security flow session`, DNAT display in CLI, config cross-reference validation (zones reference valid interfaces, policies reference valid zones).

**Phase 11 -- Syslog + Event Buffer** (`ae4e79d`): Syslog export to remote servers, in-memory event ring buffer, `show log` and `show security log` CLI commands.

**Phase 12 -- Config Persistence** (`a842c07`): Atomic config persistence to disk, syslog hot-reload on config change, rollback support with up to 50 slots.

**Phase 13 -- Multi-Address Policies** (`fc0279b`): Multiple source/destination addresses in a single policy term. Multiple SNAT rules per zone pair.

**Phase 14 -- Tab Completion + Rollback** (`91cf43f`): Tab completion for CLI commands, rollback viewing (`show | compare rollback N`), CLI polish.

**Verifier Fix** (`6c04b28`): Reduced xdp_policy complexity to pass the BPF verifier after Phase 13 changes.

---

## February 9, 2026 -- Day 4: Feature Breadth + Test Environment (30 commits)

### Prompt 4: TC NAT, logging, app sets, routing/GRE/IPsec, VLANs, DHCP, REST, gRPC

This was the first marathon day -- the user asked for a massive feature expansion across the entire stack.

**Phase 15 -- TC Egress NAT** (`5d11046`): NAT rewriting in the TC egress path for return traffic, plus egress screen checks.

**Phase 16 -- Per-Rule Logging** (`c1ca7d7`): Per-policy log flags, event filtering, `| match` pipe filter for CLI output, dynamic tab completion for interfaces and zones.

**Phase 17 -- Session Timeouts + Graceful Shutdown** (`e3a518f`): Configurable per-protocol session timeouts (TCP, UDP, ICMP), session filtering by source/dest, clean daemon shutdown.

**Phase 18 -- Application Sets + Commit Confirmed** (`a30ecc3`): Application set grouping (e.g., `junos-web` = HTTP + HTTPS), `commit confirmed` with auto-rollback timer, SYN_FRAG screen check.

**Phase 19 -- Routing/GRE/IPsec/FRR** (`156e50d`): Static routing, GRE tunnel interfaces, FRR integration for dynamic routing (OSPF, BGP), strongSwan IPsec config generation, VRF support.

**Module Rename** (`28e54c7`): Changed Go module path from `github.com/psviderski` to `github.com/psaab`.

### Prompt 5: Set up test environment with Incus VM

**Test Environment** (`c02e313`): Created Incus VM test infrastructure -- `setup.sh` for VM creation, FRR and strongSwan pre-installed, systemd unit file, Makefile targets (`test-vm`, `test-deploy`, `test-ssh`, `test-logs`).

### Prompt 6: VLANs, DNAT fixes, DHCP, REST API, gRPC, remote CLI

**Phase 20 -- VLANs** (`837d8d6`): 802.1Q VLAN tagging in BPF, trunk port support, logical unit interfaces.

**Phase 21 -- DNAT End-to-End** (`ed7448b`): Critical byte-order fixes (discovery that `binary.NativeEndian` must be used for BPF `__be32` fields, not `BigEndian`). DNAT verification through the full pipeline.

**Phases 22-23 -- DHCP + REST + Prometheus** (`83de0d1`): DHCPv4 client, HTTP REST API on port 8080, Prometheus metrics exporter.

**Phase 24 -- gRPC + Remote CLI** (`96a4255`): gRPC server on port 50051, remote CLI client binary (`cli`), protobuf service definition.

### Prompt 7: SR-IOV passthrough, WAN zone, DHCPv6

**SR-IOV Passthrough** (`edd85be`): Switched the internet-facing interface to SR-IOV PCI passthrough for native XDP support.

**WAN Zone + DHCP** (`7b3fccd` -- `acd2190`): Added WAN zone with DHCP/DHCPv6, renamed `bpfrxctl` to `cli`, IPv6 default route discovery, DHCPv6 DUID persistence, enhanced `show interfaces` and `show route` via gRPC.

---

## February 10, 2026 -- Day 5: Massive Feature Expansion (18 commits)

### Prompt 8: Implement phases 25-41

The user asked for a bulk implementation of 17 phases in a single session.

**Phases 25-27** (`6faffc3`): Nested address-sets, routing instances (VRFs), IPv6 Router Advertisements via radvd.

**Phase 28 -- NAT64** (`604dc75`): Full NAT64 translation in the XDP pipeline -- IPv6-to-IPv4 header rewriting, protocol translation, embedded address handling.

**Phase 29 -- Firewall Filters** (`f2917b3`): Firewall filter terms with match conditions, DSCP marking, policy-based routing via `ip rule`.

**Phases 30-34** (`36eae2f`): NetFlow v9 exporter (1-in-N sampling), dynamic address feeds, Kea DHCP server integration, RPM probes, ALG/flow options (DNS reply pass-through, allow-embedded-icmp).

**Phase 35b -- systemd + FRR** (`8ae4762`): systemd unit file, daemon mode (TTY detection), FRR as sole route manager (static, DHCP, per-VRF routes all via `frr.conf`).

### Prompt 9: Fix shutdown hanging, add CLAUDE.md

**Shutdown Fix** (`8bcd265`): FRR reload commands were hanging indefinitely. Added 15-second context timeout, systemd `TimeoutStopSec=20` as safety net.

**CLAUDE.md** (`44bd3fb`): Created project knowledge file for AI-assisted development -- architecture notes, gotchas, build instructions.

### Prompt 10: More phases and real hardware testing

**Phases 36-38** (`c10fc9a`): DHCP relay (Option 82), IP-IP tunnels, RIP/IS-IS routing, `ping`/`traceroute` commands, SNMP agent, scheduler profiles, persistent NAT.

**Phases 39-41** (`1684b1f`): NAT monitoring commands, CLI polish (system commands, interface terse), VRRP high availability via keepalived.

### Prompt 11: Fix deployment issues found during real testing

**BPF Fixes** (`8162f9f`): Stack overflow fix (ICMP reject functions made `__noinline`, scratch map used as byte buffer), interface UP after XDP/TC attachment, display bugs.

**FRR Route Manager** (`8a6e3c9`): Test config fixes -- FRR as sole route manager, suppress management DHCP default route conflict.

**Readline Fix** (`49bed5e`): Set explicit Stdin/Stdout/Stderr in readline config for proper terminal handling.

---

## February 11, 2026 -- Day 6: Performance Crisis + Resolution (19 commits)

### Prompt 12: Fix cross-zone forwarding (traffic not flowing)

**VLAN Tag Restore** (`9f8f32c`): Cross-zone forwarding was broken. Fixed VLAN tag restore in xdp_forward, overlapping memcpy issue, XDP mode consistency across interfaces.

**Cold ARP Fix** (`a1e1aab`): TCP forwarding failed when ARP entries were absent. Fixed CHECKSUM_PARTIAL handling, added ARP resolution path.

**CHECKSUM_PARTIAL NAT** (`0950a1f`): NAT checksum calculation was wrong for virtio-net's CHECKSUM_PARTIAL mode -- pseudoheader seed needs non-complemented update.

**TCP RST Fix** (`05b43a4`): Conntrack was dropping TCP RST packets before forwarding to peer.

### Prompt 13: Performance is terrible -- find and fix

**bpf_printk Discovery** (`e104112`): The `bpf_printk()` debug calls left in the BPF programs were consuming **55%+ CPU**. Disabled all tracing -- massive performance improvement.

**memset/memcpy Optimization** (`299a536`): Reduced per-packet overhead by eliminating unnecessary memset of scratch metadata and minimizing memcpy operations.

**FIB Cache** (`144a3c2`): Cached `bpf_fib_lookup` results in session entries. Established flows skip the FIB lookup entirely -- just read the cached next-hop MAC and egress interface.

**NAT Port Collision Fix** (`7aa77f0`): Per-CPU NAT port allocation to avoid cross-CPU collisions. Skip FIB cache on TCP SYN (need fresh lookup for new connections).

### Prompt 14: Hitless restarts (daemon restart should not drop sessions)

**BPF Map/Link Pinning** (`513339f`): Pinned stateful BPF maps and program links to `/sys/fs/bpf/bpfrx/`. Critical discovery: PROG_ARRAY maps must be pinned or kernel clears all tail-call entries when `usercnt` drops to 0.

**Per-Interface XDP** (`f9edb92`): Native XDP per-interface with `redirect_capable` map. Interfaces without native XDP support (iavf/VF driver) get `XDP_PASS` fallback instead of `bpf_redirect_map`.

### Prompt 15: More fixes and features from testing

**Cross-Zone Non-Native XDP** (`8ba157f`): Fixed forwarding to interfaces that lack native XDP support.

**WAN Interface Rename** (`1b65e01`): Updated for i40e PF passthrough naming (`enp10s0f0np0`).

**CLI Improvements** (`887b3d2`, `1437d22`): Added `| grep` as pipe filter alias, dynamic tab completion for operational show commands.

**Performance Tuning** (`a0aabfd`): Disabled `init_on_alloc` in test VM kernel for XDP performance.

**DHCP Server + IP Forwarding** (`dc3f162`): Wired Kea DHCP server support, enabled IP forwarding in daemon.

**cpumap** (`56fead9`): Added cpumap infrastructure for multi-CPU XDP distribution. Later found to be counterproductive for virtio-net (cross-CPU overhead exceeds benefit).

**ICMP Error Handling** (`459f670`): Embedded ICMP error handling for traceroute/mtr through SNAT -- reverse-translate the inner packet's source IP.

---

## February 12, 2026 -- Day 7: IPv6 Deployment + API Expansion (49 commits)

### Prompt 16: IPv6 dual-stack deployment

**Embedded ICMPv6** (`a958a21`): IPv6 embedded ICMPv6 error handling with unit tests.

**IPsec ESP** (`9e911a5`): IPsec ESP data-path integration in XDP pipeline -- detect ESP protocol, match against XFRM interfaces.

**TTL Checks** (`df28c91`, `5f85bdf`): Moved TTL expiry check before NAT (so ICMP Time Exceeded has original IPs). Added second TTL check in xdp_forward for non-NAT established sessions that skip xdp_nat via conntrack fast-path.

**ICMP Unreachable** (`3fc0a58`): ICMP unreachable generation for policy REJECT action (previously only logged, didn't send response).

**IPv6 Address Assignment** (`71bf47d`, `d907bc6`): Reconcile interface addresses on config changes. Assigned globally routable IPv6 /64s from `3FFF:111:2222:3300::/56`.

**Router Advertisements + DHCPv6** (`feb927f`): RA via radvd for downstream IPv6 auto-configuration. DHCPv6 server support for stateful address assignment.

### Prompt 17: VRF routing, systemd-networkd, hitless restart hardening

**VRF Routing** (`52f2ac5`, `155a71b`, `5a5c21d`): Per-interface VRF routing via `iface_zone_map`, tunnel-vr routing instance, route leaking between VRFs.

**systemd-networkd Management** (`4c56d01`): bpfrxd now manages ALL interfaces on the firewall -- `.link` files (MAC-to-name rename), `.network` files (addresses, DHCP, RA disable). Unconfigured interfaces brought down with `ActivationPolicy=always-down`.

**Hitless Restart Hardening** (`cec07ea`): Deterministic ID assignment (sorted before numbering), populate-before-clear pattern (new entries written first, stale deleted after), FIB cache invalidation on config change.

**SNAT Session Fix** (`a030446`): SNAT TCP sessions were dying on daemon restart. Root cause: `dnat_table` entries needed to be written BEFORE clearing sessions so existing sessions could still resolve their DNAT state.

### Prompt 18: CLI/API expansion for full feature parity

**ECMP + Syslog** (`4fd76f6`): ECMP static routes, syslog severity filtering.

**CLI Commands** (`69684cc`): System commands (reboot, halt), policy brief view.

**gRPC Expansion** (`e41ab4c`, `1d8e757`): 3 new RPCs, remote CLI expanded to full feature parity with local CLI, static NAT show.

**REST API** (`a376dac`, `4f0437d`, `3c8e442`): 15 new REST endpoints for gRPC parity, config management endpoints (load, commit, rollback).

**Prometheus** (`064e486`, `125a3a2`): Session breakdown metrics, NAT pool utilization, DHCP lease counts, prefix-filtered session queries.

**VRRP Runtime** (`6a07fb5`): Detect VRRP state from keepalived data file.

**Load Commands** (`cb09b0f`): `load override` and `load merge` for bulk config import.

**Unit Tests** (`f4a212a`, `2ea0ddf`, `bd7d41e`, `b7eb679`): Tests for FRR, logging, networkd, IPsec, radvd, scheduler, SNMP agent.

**IPsec Compilation** (`c91a9ae`): IPsec gateway compilation, IKE proposals, build-time version info.

**SNMP** (`fb7aaae`): `show version` command, SNMP ifTable MIB support.

**Screen Fixes** (`a2e6113`, `59f3f00`): Fixed teardrop screen check (was checking `TCP.TearDrop` instead of `IP.TearDrop`), OSPF export/cost, screen compilation.

**Config Validation** (`7cf4273`): Cross-reference validation, show version in remote CLI.

**DHCP Server Leases** (`6de466e`): Lease display via CLI and gRPC.

---

## February 13, 2026 -- Day 8: The Marathon (~200 commits)

This was the single most productive day -- roughly half the project's total commits landed in one session. The user drove continuous feature implementation across every subsystem.

### Prompt 19: vsrx.conf feature gap closure

The user provided a real vSRX configuration file and asked Claude to implement every missing feature needed to parse and compile it.

**Prefix Matching + Help** (`d43742d`, `6728254`): Junos-style prefix matching (`sh` = `show`, `sec` = `security`), "Possible completions:" headers.

**Zone Name Display** (`f66c8f0`): Show zone names instead of numeric IDs in session and event display.

**Multi-Term Applications** (`fea0f9c`): Application definitions with multiple terms (e.g., FTP with control + data ports), source-port matching, per-application timeouts.

**Show Configuration Path** (`8972c36`): `show configuration interfaces wan0` filters to a specific config subtree.

**Policy-Options** (`40c90e4`): Prefix-lists and policy-statements for route filtering.

**IKE/IPsec Advanced** (`7231b12`, `a918bc8`): IKE proposals, policies, gateway identity, DPD (dead peer detection). Fixed flat set syntax parsing.

**System Config** (`51254b2`): hostname, timezone, DNS, NTP, login users.

**Bracket Lists** (`b71b56f`): Parser support for `[` `]` syntax (e.g., `from zone [ trust dmz ]`).

**BGP/System Extensions** (`555a63e`): BGP address-family, system syslog/services config.

**Flat Set Syntax Fix** (`fbce8dd`): Comprehensive fix across the entire compiler for flat `set` command parsing.

### Prompt 20: NAT enhancements, firewall filter improvements, show commands

**Security Log + Screen** (`bf80f39`): Security log enhancements, screen destination-threshold.

**Backup Router + SNAT Off** (`0d5ed36`): Backup router config, SNAT "off" mode (disable NAT for specific traffic), bracket list expansion for NAT zones.

**NAT Multi-Zone** (`9360819`): Multi-zone expansion in NAT rules, SNAT off in dataplane, firewall filter hit counters.

**Prometheus Filter Counters** (`166fa01`): Prometheus metrics for firewall filter counters.

**DHCP Relay Stats** (`52e9eab`): Runtime statistics for DHCP relay.

**Config Parsing** (`aecb872` -- `ea017bd`): Massive parsing expansion -- show system users/connections, ARP/IPv6 neighbors, route-filter semantics, GRE tunnel VRF binding, root-auth, archival, license, DNS/NTP integration, security/interface/SNMP config, DHCPv4/DHCPv6 client options.

### Prompt 21: Show commands, interface management, system wiring

**Show Commands** (`c611a1f` -- `0f82b2f`): Route summary, interfaces extensive, rollback compare, flow session summary with protocol/zone breakdown, flow flags, NTP threshold, chassis cluster config parsing, event-options parsing, NAT address-persistent, rib-groups.

**Show Command Wiring** (`6d07c10` -- `7d282c7`): Chassis/environment/hit-count display, policy/services show in remote CLI.

**Config Features** (`0963ac9` -- `187065a`): Preferred address, flow traceoptions, multi-port DNAT (compiled to BPF), IPFIX templates, interface MTU/speed/disable, forwarding-options.

**System NTP + Zone Cross-Refs** (`0f82b2f`): Show system NTP, zone policy cross-references, interface MTU from config.

**Validation** (`067da50`): Cross-reference validation for SNAT pools, zone interfaces, schedulers, routing instances.

### Prompt 22: Wire system config to runtime, screen counters, syslog

**Interface Disable** (`6979d3b`): Apply interface disable flag in dataplane.

**Screen Counters** (`5d37c3a`): Per-screen-type BPF drop counters.

**Syslog Wiring** (`cc39eb4`): Wire system syslog config to forward daemon logs to remote hosts.

**Login/SSH** (`b5e0b0a`, `b54d076`): Wire login users and SSH root-login config, screen stats in remote CLI.

**Timezone/Login** (`5c77032`, `a0118c9`): Timezone application, kernel tuning, no-redirects sysctl.

**Traceoptions + networkd** (`d9cf036`): Flow traceoptions, networkd link properties.

**Show Enhancements** (`240e66f` -- `0fabd72`): Interface details, system services, auth display, routing-instances, IPv6 hop-limit sysctl.

**RFC 5424 Syslog** (`d77b61a`): RFC 5424 structured syslog format, source-address binding.

**DHCP + Events** (`2084c98`, `e25f494`): DHCP renew command, event-options engine for RPM-driven failover.

**HTTPS + MTU** (`aacf7ff`, `f664f24`): HTTPS support for web-management, unit-level MTU on VLAN sub-interfaces.

### Prompt 23: Firewall filters, NAT64, advanced features

**Output Filters** (`ff9e60d`): Firewall output filters in TC egress pipeline.

**Source-Port + Prefix-List** (`e065d15`, `7e872f3`): Source-port matching and prefix-list expansion in firewall filter terms.

**Zone TCP-RST** (`d539070`): Zone-level tcp-rst -- send TCP RST for denied non-SYN packets.

**Address-Persistent NAT** (`66833c5`): Address-persistent NAT, fixed tc_forward verifier (narrowing meta offsets with `& 0x3F`), fixed FilterRule struct size.

**DSCP Rewrite** (`6634db7`): DSCP rewrite action in firewall filters.

**Descriptions + Session Info** (`f50213c`, `a1a149e`): Zone/interface/policy descriptions, session idle time, flow statistics.

**Filtered Session Clearing** (`4c6454e`, `af8a9f5`): Clear sessions with filters (source-prefix, dest-prefix, protocol, zone).

**Global Policies** (`5cd12c0`, `9d3bf75`): Global security policies, zone-pair policy filtering.

**DNAT Hit Counters** (`9df3740`): Destination NAT sub-commands with hit counters.

**Port Ranges** (`245f868`, `ab7c8e4`): Firewall filter port range matching in BPF.

**Per-App Timeout** (`c30ef7b`): Per-application inactivity timeout stored in BPF session entries.

### Prompt 24: Routing, DNS, BPF map utilization

**ECMP Multipath** (`f52f59c`): Wire forwarding-table export policy to FRR ECMP multipath.

**Forwarding-Class DSCP** (`6bfebbc`): Map firewall filter forwarding-class to DSCP rewrite.

**VRF Routes** (`d0e6d4f`, `6e5db2a`): VRF-aware route display via `show route table`.

**Next-Table Leaking** (`d746210`): Inter-VRF static route leaking via `ip rule add to <prefix> lookup <table>`.

**Syslog Category Filter** (`8902a47`): Syslog stream category filtering.

**Route Filtering** (`093016f`): Route filtering by protocol and CIDR prefix.

**DNS Reply Pass-Through** (`1a8b873`): Wire `allow-dns-reply` to BPF conntrack for sessionless DNS.

**BPF Map Utilization** (`fc6ad37`, `be412ae`): `show system buffers` command showing BPF map sizes and utilization.

### Prompt 25: CLI completion overhaul

**Self-Generating Help** (`461cbc8`): CLI help now generated from `operationalTree` -- single source of truth for all commands, descriptions, and completion.

**cmdtree Package** (`b75f047`): Extracted `pkg/cmdtree/tree.go` as single source of truth for all CLI command trees. Both local CLI, remote CLI, and gRPC server import from here.

**Remote CLI Additions** (`fe10762`, `5d36050`): Monitor error, chassis hardware, gRPC alias support, missing show firewall + system sub-entries.

### Prompt 26: Configstore refactor

**DB + Journal** (`5d36050`): Refactored configstore persistence to use a proper database abstraction and JSONL audit journal for all config changes.

**Rib-Group Fixes** (`ff8eeb7`, `aab6dc9`): Fixed rib-group rule priority, added config file bootstrap.

### Prompt 27: Phase 50 sub-phases (fill remaining vsrx.conf gaps)

Nine sub-phases implementing dozens of small features:

| Sub-Phase | Commit | Key Features |
|-----------|--------|--------------|
| 50a | `aab6dc9` | Unit MTU, JFlow source-address, prefix-list except |
| 50b | `672c173` | BPF filter negate, qualified next-hop, PBR, consistent-hash |
| 50c | `134a5ff` | Screen thresholds, sampling direction, show screen/alarms |
| 50d | `3a7e5bd` | GRE MSS split (gre-in/gre-out), show interfaces extensive |
| 50e | `e95475b` | Route detail, CoS display, BGP neighbor, IPsec SA clear |
| 50f | `74ce11e` | Session apps, OSPF/ISIS commands, commit history, buffer stats |
| 50g | `1740678` | Config stanza completion, feed status, RPM stats |
| 50h | `c98f2b1` | Route terse, clear arp/neighbors, NAT rule detail |
| 50i | `46c881b` | Security zones detail, IPsec statistics, screen ids-option detail |

### Prompt 28: DPDK dataplane (23 phases!)

The user asked Claude to implement a full DPDK-based alternative dataplane. This resulted in 23 micro-phases in a single session.

**Architecture Plan** (`fc338d4`, `7884313`): Documented DPDK dataplane architecture with interrupt-driven and adaptive RX modes.

**Phase 1** (`0329a45`): Extracted `DataPlane` interface from concrete eBPF Manager.

**Phase 2-5** (`f00ee7a`): Config parsing, Go DPDK manager, C worker skeleton, build system with CGo.

**Full C Pipeline** (`95b5169`): Complete single-pass C packet processing pipeline (all 9 stages: screen, zone, conntrack, policy, NAT, NAT64, forward, etc.).

**CGo Bridge** (`a8bff8a`): Shared memory bridge for Go-to-DPDK communication.

**CompileConfig Refactor** (`783ad65`): Extracted backend-agnostic `CompileConfig()` function.

**Phases 4-23** (`30a09eb` -- `c16d44d`): EventSource interface, FIB routing tables, worker lifecycle, NAT64 reverse, rejection packets, static NAT, SNAT allocation, MSS clamping, FIB populator, ICMP Time Exceeded, VLAN handling, session FIB cache, DNAT pre-routing, IPv6 conntrack fixes, multi-queue TX/RX, session GC, packet trace facility, latency histogram, link state monitoring, port statistics, session state enforcement, global counters, flood counters, map stats.

**TCP MSS GRE-Out** (`858b695`): Wire tcp-mss gre-out to TC egress pipeline.

**Session Brief** (`e89f475`): Session brief tabular view.

**NetFlow** (`2f68831`): Wire sampling input-rate to NetFlow 1-in-N export.

### Prompt 29: Routing protocol enhancements

**Port-Scan + IP-Sweep** (`39f53d7`): Screen IDS detection for port scanning and IP sweeps.

**OSPF/BGP Auth + BFD** (`f3f6ff3`): OSPF and BGP authentication, BFD support.

**Routing Enhancements** (`060fa52` -- `383173c`): OSPF area types, route-reflector, reference-bandwidth, BGP graceful-restart, IS-IS wide-metrics/overload, BGP multipath/default-originate, passive-interface default, network type, route-map attributes, OSPFv3.

**Firewall Filter Extensions** (`feceef3`): TCP flags and fragment matching, OSPF metric-type, BGP community-lists.

**Advanced Routing** (`3176de1` -- `f541e07`): BGP dampening, AS-path access-lists, prefix-limits, OSPF virtual-links, GRE keepalive runtime.

**Show Commands** (`943674a`): Show protocols routes/database, system info, interface speed/duplex.

### Prompt 30: DHCPv6-PD, SNMPv3

**DHCPv6-PD** (`c56d305`, `230ad51`): DHCPv6 prefix delegation, wire delegated prefixes to radvd for downstream Router Advertisements.

**SNMPv3 USM** (`73a6e95` -- `30ebaf6`): Web management interface binding, SNMPv3 USM authentication (SHA/AES), flat set schema, tests.

### Prompt 31: Sprints 15-24 (feature sprints)

Ten numbered sprints implementing remaining feature gaps:

| Sprint | Commit | Key Features |
|--------|--------|--------------|
| 15 | `d24795e` | ALG types, address book clear, NAT persistent pools, IPFIX, SNMP traps, LAG bonding, rollback compare |
| 16 | `455e895` | Chassis cluster RETH, system config wiring, operational commands |
| 17 | `71f809c` | Port mirroring, LLDP protocol, HTTP API authentication |
| 18 | `a101367` | Session sorting, Prometheus metrics, XML export, ethtool |
| 19 | `cc06f5f` | Apply-groups inheritance, test commands, REST streaming |
| 20 | `9ab1004` | Login class RBAC, show interfaces detail, config archival |
| 21 | `72e1020` | Policy detail view, firewall filter drill-down, config annotate |
| 22 | `26cf1ad` | Interface statistics, protocol detail, system diagnostics |
| 23 | `6af0688` | Load set terminal, port validation, boot messages, configure exclusive |
| 24 | `97b36cd` | REST buffers/zone-pairs, buffers detail, commit descriptions, config search |

---

## February 14, 2026 -- Day 9: Chassis Cluster HA + Sprint Closure (29 commits)

### Prompt 32: Config navigation commands

**Edit/Top/Up** (`b47d903`): `edit` (descend into config hierarchy), `top` (return to root), `up` (go up one level), `copy`/`rename` commands, REST annotate endpoint.

### Prompt 33: Chassis cluster HA state machine

**State Machine** (`c0ee579`): Full chassis cluster implementation -- Manager, NodeState, RedundancyGroupState, weight-based failover, manual failover/reset, Junos-style show/request commands. States: Secondary(0), Primary(1), SecondaryHold(2), Lost(3), Disabled(4).

**Heartbeat + Election + Sync** (`6e4d35c`): UDP heartbeat on port 4784 ("BPFX" magic), preempt/non-preempt election, active/active per-RG primary selection, session sync over TCP ("BPSY" magic, 7 session + 1 config + 1 IPsec SA message types), RETH controller.

**Event Engine Deadlock** (`8dac5bb`): Fixed commit deadlock in event engine, added Ctrl-C handling to CLI.

### Prompt 34: CLI completion polish

**Pipe Filter Completion** (`116610d`): Tab completion and `?` help for pipe filters (`| match`, `| count`, `| display`).

**Config Mode Completion** (`2ddd6cc`, `9566c4b`): Config stanza completion, Ctrl-D ignore (don't exit on Ctrl-D), hostname prompt refresh, dynamic value completion for wildcard schema positions.

**Schema Completion** (`422e13b`, `24bcfa1`): Junos-style schema completion with descriptions and placeholders.

### Prompt 35: Sprint GAP-1/2/3 (vsrx.conf gap closure)

**GAP-1** (`24bcfa1`): Comprehensive vsrx.conf feature gap implementation -- every config stanza that was parsed but not compiled or wired.

**Lo0 Fix** (`5175d07`): Fixed lo0 nftables prefix-list expansion, DPDK source-port byte order.

**Named Ports** (`9c4f820`): Port name resolution for common services (ftp-data, pop3, imap, etc.).

**GAP-2** (`f12d1b2`): nftRuleFromTerm enhancements, NAT64 static-nat inet.

**GAP-3** (`03310a7`): Global screen stats, LLDP per-interface, generate routes.

**NTP** (`a5594d3`, `8daf7ec`): Switched from systemd-timesyncd to chrony for NTP.

### Prompt 36: Two-VM chassis cluster test environment

**Cluster Test Env** (`c2e13f9`): Two-VM HA test environment -- bpfrx-fw0 (node 0, priority 200), bpfrx-fw1 (node 1, priority 100), cluster-lan-host, heartbeat link (10.99.0.0/30), fabric link (10.99.1.0/30).

**Config Sync** (`58efe1d`): Cluster config sync primary-to-secondary, primary-only config writes (secondary is read-only).

### Prompt 37: Sprint FF-1, IF-1, HA-8

**SetPath Fix** (`13daf45`, `b5827da`): Fixed SetPath leaf duplication for single-value and multi-value keywords.

**Sprint FF-1** (`be26cc1`): Firewall filter enhancements -- policer (token bucket), three-color marking, lo0 BPF filter in xdp_forward.c, flexible match (byte-offset from L3 header).

**Sprint IF-1** (`38524ba`): Interface enhancements -- LAG/ae, flexible VLAN tagging, interface bandwidth, point-to-point, primary/preferred address, interface description.

**Sprint HA-8** (`7d42474`): HA enhancements -- ISSU (ForceSecondary drain), NAT state sync (full session install to BPF), IPsec SA sync (periodic push + failover re-initiation), active/active mode (per-RG primary), RETH runtime (IPv6 NA + dual-stack GARP), fabric link redundancy.

### Prompt 38: Incremental session sync + security logging

**Incremental Sync** (`a13f271`): Incremental session sync between cluster nodes -- periodic 1-second sweep + ring buffer real-time SESSION_OPEN sync + GC delete callbacks.

**Sync Protocol Docs** (`dcdb4b5`): Documented the sync protocol and algorithm.

**Sprint SEC-LOG** (`9164b86`): Security logging enhancements -- structured syslog (RT_FLOW with NAT fields, zone names), TCP/TLS transport (RFC 6587 framing, auto-reconnect), per-policy NAT fields in BPF events, event mode (local file with rotation), session aggregation reporting (top-N by bytes).

**Syslog Zone Fix** (`a6e856c`): Use resolved zone names instead of numeric IDs in syslog output.

**Wildcard Groups** (`f4e38e1`): `<*>` wildcard support in Junos groups configuration.

---

## February 15, 2026 -- Day 10: Junos CLI Polish + HA Cluster (22 commits)

### Prompt 39: Junos-style show output formatting

**Match Before Then** (`90b2bbb`): Display match conditions before `then` in policy output (Junos canonical order).

**Groups Compilation Fix** (`73e9ae7`): Fixed CompileConfig stripping groups/apply-groups from config tree.

**Display Inheritance** (`f633178`, `9831202`, `3de2705`): `| display inheritance` pipe filter shows inherited values from Junos groups, with proper path navigation for multi-key nodes (e.g., `from-zone X to-zone Y`).

**Pipe Error Handling** (`2441c07`): Error on unknown pipe commands, fixed config show path handling.

**Display Set/JSON/XML** (`fffd33a`): Path-scoped `| display set`, `| display json`, `| display xml` for show configuration.

### Prompt 40: CLI completion fixes, show route format

**Completion Fixes** (`28a63e1`, `1567b27`): Fixed multi-match completion, policy names in session display, show configuration partial completion for multi-arg schema nodes.

**Show Compare** (`dcb109e`): Hierarchical `show | compare`, policy address completion.

**Application Completion** (`94a2e5a`): Added `any` to policy match application completion.

**Show Route** (`2590554` -- `01cf0af`): Junos-style `show route <destination>` across all tables, destination placeholder in completion.

**Route Format** (`250b69b` -- `74db5f8`): Junos format for all route tables, split IPv6 into inet6.0 tables, fixed VRF route device name prefix.

### Prompt 41: Application matching fix, insert command

**App Matching Fix** (`a0d4d14`): Applications with no protocol specified (like `junos-http`) were not matching any traffic. Fixed to expand to TCP+UDP when protocol is unset.

**Insert Command** (`8818332`): `insert <element-path> before|after <ref-identifier>` for reordering policies, terms, rules in the config AST.

**App Timeout Width** (`af38afd`): Widened `app_timeout` from uint16 to uint32 in BPF session struct to support timeouts >65535 seconds.

### Prompt 42: CLI help display and completion refinement

**Multi-Match Help** (`c6112fd`): Fixed CLI multi-match completion and help display rendering.

**Duplicate Help** (`5c126b2`): Fixed duplicate help display when `?` pressed in complete mode.

**Remote CLI Help** (`0d1bd87`): Fixed remote CLI `?` help treating partial input as complete word.

**Policy Name Completion** (`3a83188`, `4d418b1`): Dynamic policy name completion for `?` and Tab, fixed operational tree walker for DynamicFn leaf nodes.

**Zone-Pair-Aware Completion** (`240e3a9`): Added `ContextDynamicFn` for completions that depend on preceding context (e.g., policy names filtered by the zone pair already typed).

### Prompt 43: HA cluster planning and implementation

**HA Test Plan** (`7133ed9` -- `98b04aa`): Detailed test plan for two-VM SR-IOV HA cluster, refined network topology.

**HA Cluster Configs** (`fb686ba`): bpfrx configs for both HA cluster nodes.

**Single-Config HA** (`c0d5ae2`): `${node}` variable expansion in apply-groups. `CompileConfigForNode(tree, nodeID)` compiles a single config for both HA nodes. Node ID from `/etc/bpfrx/node-id` file.

**Management VRF** (`068d89d`): Management VRF, cluster CLI prompt showing node role, DHCP route isolation.

**Interface Translation** (`96e80ba`): Fixed Junos interface name translation (e.g., `ge-0/0/0` to `trust0`) and VRF-aware cluster communications.

### Prompt 44: VRRP-backed RETH failover

**VRRP RETH** (`cdef7fe`): VRRP-backed RETH failover using keepalived. VRID=100+rgID, priority 200 (primary) / 100 (secondary). No bond devices -- VRRP runs directly on physical member interfaces.

**VRRP Fixes** (`7151a5b`): Idempotent bond creation, link-local base addresses (169.254.RG.NODE/32).

### Prompt 45: Remove bond devices from RETH

**Bondless RETH** (`ed3d708`): Removed bond devices entirely. VRRP runs directly on physical interfaces. `RethToPhysical()` / `ResolveReth()` resolve reth to physical member. `ClearRethInterfaces()` cleans up legacy bonds.

**Stale Bond Cleanup** (`f53cc10`): Scan system interfaces to find and remove stale RETH bond devices.

---

## February 16, 2026 -- Day 11: NPTv6 + Predefined Applications (3 commits)

### Prompt 46: NPTv6 stateless IPv6 prefix translation

**NPTv6 (RFC 6296)** (`875eeaa`): Full implementation of stateless IPv6-to-IPv6 prefix translation. Precompute adjustment value, rewrite prefix words 0-2, apply adjustment to word[3] with carry fold. BPF `nptv6_rules` HASH map (128 entries), key: prefix[6]+direction, value: xlat_prefix[6]+adjustment. Inbound translation in xdp_zone (dst rewrite), outbound in xdp_policy (src rewrite). Session flag `SESS_FLAG_NPTV6 (1<<8)`. Config syntax: `then static-nat nptv6-prefix <internal-prefix>`. CLI: `show security nat nptv6`.

### Prompt 47: Junos predefined applications + max sessions increase

**Predefined Applications** (`f6ba535`): Complete set of Junos predefined applications (junos-http, junos-https, junos-ssh, junos-dns-udp, etc.) and protocol aliases.

**ICMP App Timeout Fix** (`622db6d`): Fixed ICMP application timeout handling, multi-protocol term support.

**Max Sessions** (`342806d`): Increased maximum sessions from 1M to 10M.

---

## February 17-18, 2026 -- Days 12-13: NPTv6 + NAT64 Deep Fixes (5 commits)

### Prompt 48: NPTv6 /64 extension

**NPTv6 /64 Support** (`c673875`): Extended NPTv6 from /48-only to support /64 prefix translation. Fixed static NAT overlap detection.

### Prompt 49: NAT64 end-to-end debugging and fixes

The user was testing NAT64 with traceroute and mtr, discovering multiple issues in the ICMP error translation path.

**NPTv6 Test Config** (`1c17fc1`): Added NPTv6 test config for untrust zone and ICMPv6 policy to enable testing.

**NAT64 End-to-End Fix** (`1cde2af`): Three critical fixes -- zone detection for NAT64 translated packets, reverse path translation (IPv4 reply back to IPv6), ICMPv6 checksum recalculation after NAT64.

**NPTv6 Traceroute Fix** (`851202c`): Reverse-translate the embedded ICMPv6 source address inside ICMP error payloads (Time Exceeded, Destination Unreachable) so that traceroute intermediate hops show correct addresses.

**NAT64 ICMP Traceroute Fix** (`91bdd38`): Three more fixes -- ICMP echo ID (use `meta->dst_port` not `meta->nat_dst_port`), NPTv6 reverse translation in error path, full 4-to-6 ICMP error translation per RFC 7915.

**NAT64 Truncated Payload** (`5fa143b`): Fixed ICMP error payload length calculation for truncated embedded packets (when the inner packet is shorter than a full header).

---

## February 19, 2026 -- Day 14: CLI Polish + VPP Assessment (9 commits)

### Prompt 50: Implement Junos-style CLI help and tab completion plan

**CLI Help/Completion** (`4369c85`): Comprehensive update to `pkg/cmdtree/tree.go` -- added sub-command children to `ping`, `traceroute`, `monitor traffic`; filter sub-commands for session/log/clear commands; full argument chain for `test policy`; ~40 description updates to match Junos wording; DynamicFn closures for zones, interfaces, routing instances; terse/global/policy-name options.

### Prompt 51: Fix ping streaming (output doesn't appear until command finishes)

**Streaming Diagnostics** (`faac503`): Changed gRPC `Ping` and `Traceroute` RPCs from unary to server-streaming. Implemented `streamDiagCmd()` with `bufio.Scanner` for line-by-line output. Updated remote CLI to use `stream.Recv()` loop.

### Prompt 52: VPP dataplane viability assessment

The user asked Claude to assess whether VPP (Vector Packet Processing) could serve as a dataplane for the router, and how it could be integrated with or replace XDP.

**VPP Assessment** (`38ea955`): Created `docs/vpp-dataplane-assessment.md` with 8 initial sections: architecture overview, feature coverage vs bpfrx requirements, performance comparison, integration strategies (4 options: full replacement, hybrid XDP+VPP, selective acceleration, DPDK worker evolution), Go control plane integration via GoVPP, operational considerations, risk assessment, and recommendation.

### Prompt 53: Add WireGuard and VPN/tunnel analysis to VPP assessment

**WireGuard/VPN Analysis** (`925e928`): Added sections 9-12 covering WireGuard performance (VPP: 34-204 Gbps vs kernel: 3-5 Gbps), tunnel technologies and XDP compatibility (the encryption boundary problem -- XDP cannot see decrypted traffic), 5 WireGuard integration options with effort estimates, and impact on VPP adoption decision.

### Prompt 54: Can we implement VRRP using VPP?

**VRRP with VPP** (`7bef3ae`): Added section 13 covering VPP's VRRPv3 plugin (RFC 5798, production since VPP 20.05), comparison with current keepalived architecture, GoVPP API integration examples, implementation approach (backend interface, instance mapping, event-driven failover), and trade-offs table.

### Prompt 55: Could VPP create pseudo-interfaces for FRR?

**VPP Linux CP** (`2e9cc0e`): Added section 14 covering VPP's Linux Control Plane plugin -- TAP mirror interfaces, lcp_itf_pair three-way mapping, traffic split (transit stays in VPP, control-plane punted to kernel), bidirectional sync (VPP-to-Linux and Linux-to-VPP), FRR route installation flow (175K routes/sec), sub-interfaces/VLANs/tunnels, management traffic punt, known limitations, production deployments (IPng, TNSR, Coloclue, VyOS).

### Prompt 56: Update executive summary

**Executive Summary Update** (`dc5314e`): Updated executive summary to reflect all 14 sections including VRRP/HA finding, Linux CP finding, and complete section index table.

### Prompt 57: Fix ping routing-instance and placeholder completion

**VRF Name Fix** (`3ab2a1d`): Two bugs fixed. (1) gRPC/HTTP handlers used routing instance name directly (`tunnel-vr`) but kernel VRF device requires `vrf-` prefix -- added prefix in 4 handlers. (2) Placeholder completion (`<angle-bracket>` nodes) was not recognized as positional wildcards in `CompleteFromTree` / `CompleteFromTreeWithDesc` / `LookupDesc` -- unmatched words now consumed by placeholder nodes so sibling options remain available for `?` help.

### Prompt 58: Session history

**Session History** (`1ca36e3`): Added session history document for Feb 19 development prompts.

---

## Summary by Theme

### Core Dataplane (BPF Pipeline)
- 14 BPF programs (9 XDP ingress + 5 TC egress) with tail-call chaining
- Stateful conntrack with dual session entries
- Full NAT stack: SNAT (interface + pool), DNAT, static 1:1, NAT64, NPTv6
- 11 screen/IDS checks + port-scan/IP-sweep detection
- Firewall filters with policer, three-color marking, DSCP rewrite, PBR
- TCP MSS clamping (ingress + egress, including GRE-specific)
- Per-application inactivity timeouts in session entries
- 10M max sessions

### Configuration System
- Full Junos parser supporting both hierarchical `{ }` and flat `set` syntax
- Bracket list `[ ]` syntax
- Three-phase compilation: AST -> typed Go structs -> BPF map entries
- Candidate/active config with commit model, 50 rollback slots
- `load override` / `load merge` / `load set terminal`
- Config validation with cross-reference checks
- Apply-groups inheritance with `${node}` variable expansion for HA
- Insert command for reordering config elements

### Networking
- IPv4 + IPv6 dual-stack
- VRFs with inter-VRF route leaking (next-table + rib-groups)
- VLANs (802.1Q tagging in BPF)
- GRE tunnels with keepalive
- ECMP multipath routing
- DHCPv4/DHCPv6 clients, DHCPv6-PD
- Router Advertisements via radvd
- FRR integration (static, OSPF, BGP, IS-IS, RIP)

### High Availability
- Chassis cluster state machine with weight-based failover
- VRRP-backed RETH (bondless, keepalived)
- Heartbeat + election + session sync
- Incremental session sync (1s sweep + ring buffer + GC callbacks)
- Config sync primary-to-secondary
- IPsec SA sync
- ISSU (in-service software upgrade)

### Observability
- Syslog (structured RT_FLOW, TCP/TLS transport, event mode)
- NetFlow v9 (1-in-N sampling)
- Prometheus metrics
- RPM probes, dynamic feeds
- SNMP (ifTable + ifXTable MIBs, SNMPv3 USM)
- BPF map utilization (`show system buffers`)
- Session aggregation reporting

### APIs & CLIs
- Junos-style interactive CLI with tab completion, `?` help, pipe filters
- Remote CLI via gRPC
- gRPC server (48+ RPCs)
- HTTP REST API (full gRPC parity)
- Single source of truth: `pkg/cmdtree/tree.go`

### Performance
- Native XDP: 25+ Gbps
- Hitless restarts: zero packet drops
- FIB caching in session entries
- Per-CPU NAT port allocation
- Critical fix: bpf_printk was 55%+ CPU overhead

### Alternative Dataplanes
- DPDK worker: Complete 23-phase C pipeline implementation
- VPP assessment: 14-section viability analysis with integration strategies
