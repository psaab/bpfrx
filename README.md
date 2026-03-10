# bpfrx

eBPF zone-based firewall with native Junos configuration syntax.

bpfrx is a high-performance stateful firewall built on Linux eBPF (XDP + TC) that replicates Juniper vSRX capabilities. It uses the familiar Junos hierarchical configuration syntax and provides a full interactive CLI with tab completion and `?` help.

This branch also carries an experimental userspace dataplane:

- the existing Go control plane still owns config, HA, and runtime reconciliation
- the default dataplane is still the existing eBPF XDP/TC pipeline
- an alternate Rust userspace dataplane is being built around:
  - `userspace-xdp` for the userspace-specific XDP handoff path
  - `userspace-dp` for AF_XDP workers, slow path, and userspace forwarding
  - `pkg/dataplane/userspace` for the Go control-plane bridge

That userspace backend is real and testable on the isolated `loss` userspace lab in
this branch, but it is still experimental. It is not yet feature-parity or
performance-parity with the main eBPF dataplane.

## Architecture

```
XDP Ingress: main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```

Experimental userspace dataplane on this branch:

```text
Rust XDP userspace entry
  -> XSKMAP redirect
  -> Rust AF_XDP workers
  -> AF_XDP TX / bounded slow path
  -> fallback to xdp_main for unsupported traffic or config
```

- **14 BPF programs** (9 XDP ingress + 5 TC egress) chained via tail calls
- **Go userspace** (cilium/ebpf) handles config compilation, session GC, and management APIs
- **Per-CPU scratch maps** pass metadata between pipeline stages
- **Dual session entries** (forward + reverse) in conntrack hash map
- **Three-phase config compilation**: Junos AST → typed Go structs → eBPF map entries
- **Experimental userspace path**: Go control plane + Rust AF_XDP dataplane helper +
  Rust userspace-specific XDP entry, with the legacy XDP/TC firewall kept as the
  guarded fallback and non-userspace dataplane

## Features

### Firewall & Security
- **Zone-based policies** with stateful inspection, address books, application matching, global policies
- **NAT**: source (interface + pool, address-persistent), destination (with hit counters), static 1:1, NAT64 (native BPF), NPTv6 (RFC 6296 stateless prefix translation)
- **Dual-stack**: IPv4 + IPv6, DHCPv4/v6 clients, embedded Router Advertisement sender (replaces radvd), SLAAC
- **Screen/IDS**: 11 checks (land, SYN flood, ping of death, teardrop, SYN-FIN, no-flag, winnuke, FIN-no-ACK, rate-limiting), SYN cookie flood protection (XDP-generated SYN-ACK cookies)
- **Firewall filters**: policer (token bucket + three-color), lo0 filter, flexible match, port ranges, hit counters, logging, forwarding-class DSCP rewrite

### Flow Processing
- **TCP MSS clamping** (ingress XDP + egress TC, including GRE-specific gre-in/gre-out)
- **ALG control**, allow-dns-reply, allow-embedded-icmp
- **Configurable timeouts** (per-application inactivity)
- **Session management**: filtered clearing, idle time tracking, brief tabular view, aggregation reporting

### Routing & Networking
- **FRR integration**: static, OSPF, BGP, IS-IS, RIP, ECMP multipath, export/redistribute
- **VRFs** with inter-VRF route leaking (next-table + rib-group)
- **GRE tunnels**, XFRM interfaces, PBR (policy-based routing)
- **VLANs**: 802.1Q tagging in BPF, trunk ports
- **IPsec**: strongSwan config generation, IKE proposals, gateway compilation
- **Full interface management**: bpfrxd owns ALL interfaces — renames via `.link` files, configures addresses/DHCP via `.network` files, brings down unconfigured interfaces

### High Availability
- **Chassis cluster** with ~60ms failover (30ms VRRP intervals)
- **Native VRRPv3**: Go state machine, AF_PACKET, per-instance sockets, IPv6 NODAD, 30ms RETH advertisements, async GARP burst
- **Bondless RETH**: VRRP on physical member interfaces, per-node virtual MAC (`02:bf:72:CC:RR:NN`), no Linux bonding required
- **Session sync**: incremental 1s sweep + ring buffer + GC delete callbacks, TCP on fabric link
- **Config sync**: primary → secondary with `${node}` variable expansion, reverse-sync on reconnect
- **IPsec SA sync**: shared IKE/ESP state across cluster nodes
- **Dual fabric links**: independent fab0/fab1 for redundancy (no bonding)
- **Fabric cross-chassis forwarding**: `try_fabric_redirect()` redirects to peer when FIB fails for synced sessions
- **BPF watchdog**: fail-closed on daemon crash (SIGKILL/panic) within 2s
- **Readiness gate**: per-RG readiness (interfaces + VRRP) + hold timer gates election
- **Planned shutdown**: near-instant takeover (priority-0 burst), failback ~130ms
- **ISSU**: in-service software upgrade with rolling deploy
- **RA lifecycle**: goodbye RAs (lifetime=0) on failover/startup to prevent stale IPv6 ECMP routes

### Observability
- **Syslog**: facility/severity/category filtering, structured RT_FLOW format, TCP/TLS transport, event mode local file
- **NetFlow v9**: 1-in-N sampling
- **Prometheus metrics** (`/metrics` endpoint)
- **SNMP**: system + ifTable MIB
- **RPM probes**, dynamic address feeds
- **BPF map utilization** (`show system buffers`)
- **LLDP**: link layer discovery protocol

### Management
- **Interactive CLI**: Junos-style prefix matching, tab completion, `?` help, pipe filters (`| match`, `| count`, `| except`)
- **Remote CLI**: `cli` binary connects via gRPC with full tab/`?` parity
- **gRPC API**: 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **REST API**: HTTP on port 8080 (health, Prometheus, config, full gRPC parity)
- **Config management**: candidate/active with commit model, 50 rollback slots, `load override`/`load merge`, `show | display set`
- **Configure mode protection**: blocked on secondary cluster nodes (RG0 primary is config authority)
- **DHCP server**: Kea integration with lease display
- **DHCP relay**: Option 82 support
- **Event engine**: event-driven automation

## Quick Start

```bash
make generate    # Generate Go bindings from BPF C (requires clang + bpf headers)
make build       # Build bpfrxd daemon (embeds version from git)
make build-ctl   # Build remote CLI client
make test        # Run 1020+ tests across 24 packages
```

## Configuration

bpfrx uses Junos-style configuration syntax:

```junos
interfaces {
    trust0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0;
            }
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
```

The config supports both hierarchical `{ }` blocks and flat `set` commands:

```
set interfaces trust0 unit 0 family inet address 10.0.1.1/24
set security zones security-zone trust interfaces trust0
set security policies from-zone trust to-zone untrust policy allow-all match source-address any destination-address any application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
```

## Management Interfaces

- **Local CLI**: run `bpfrxd` in a TTY for interactive Junos-style shell
- **Remote CLI**: `cli -addr <host>:50051` connects via gRPC
- **gRPC API**: 48+ RPCs on port 50051 (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **REST API**: HTTP on port 8080 (health, Prometheus `/metrics`, config endpoints)

## Performance

- **Main eBPF dataplane**
  - **25+ Gbps** with native XDP (i40e/ice PF passthrough)
  - **15.6 Gbps** with virtio-net
  - **Hitless restarts** with zero packet loss
  - **~60ms cluster failover** (30ms VRRP, ~97ms masterDown interval)
  - **Near-instant planned shutdown** (priority-0 burst, peer takes over in ~1ms)
- **Experimental userspace dataplane on this branch**
  - real AF_XDP forwarding exists on the isolated `loss` userspace lab
  - throughput is still under active optimization and should not be treated as at-parity
    with the main XDP dataplane yet
  - the current target is `22-23 Gbps` IPv4 and IPv6 on the isolated userspace lab,
    but this branch does not guarantee that today

## Test Environment

An Incus-based test environment provisions Debian VMs with FRR, strongSwan, and test containers:

```bash
# Single VM (standalone firewall)
make test-env-init   # One-time setup
make test-vm         # Create VM
make test-deploy     # Build + deploy + restart service
make test-logs       # View daemon logs

# Two-VM HA cluster
make cluster-init    # Create networks + profile
make cluster-create  # Launch fw0 + fw1 + LAN host
make cluster-deploy  # Rolling deploy: secondary first, then primary (preserves traffic)
```

Userspace dataplane branch workflow:

```bash
# Isolated userspace HA cluster on loss
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
./scripts/userspace-perf-compare.sh
```

Those workflows operate on the tracked isolated userspace cluster:

- env: `test/incus/loss-userspace-cluster.env`
- config: `docs/ha-cluster-userspace.conf`
- firewalls:
  - `loss:bpfrx-userspace-fw0`
  - `loss:bpfrx-userspace-fw1`
- host:
  - `loss:cluster-userspace-host`

### Cluster Deployment

`make cluster-deploy` performs a **rolling deploy** to maintain traffic continuity:

1. Determines which node is currently secondary
2. Deploys to the secondary (primary continues forwarding traffic)
3. Waits for the secondary to sync sessions from the primary
4. Deploys to the primary (upgraded secondary takes over via VRRP failover)

To deploy to a single node: `make cluster-deploy NODE=0` or `make cluster-deploy NODE=1`.

### Test Suite

| Test | Command | Description |
|------|---------|-------------|
| Unit tests | `make test` | 1020+ Go tests across 24 packages |
| Connectivity | `make test-connectivity` | End-to-end IPv4/IPv6 routing and SNAT |
| Failover | `make test-failover` | iperf3 survives fw0 reboot (session sync + VRRP) |
| Hard crash | `make test-ha-crash` | Force-stop, daemon stop, multi-cycle crash recovery |
| Restart | `make test-restart-connectivity` | Zero packet loss during daemon restart |
| Private RG | `./test/incus/test-private-rg.sh` | VRRP elimination via private-rg-election |

## Code Layout

| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs (common, maps, helpers, conntrack, nat) |
| `bpf/xdp/*.c` | 9 XDP ingress programs (includes cpumap entry) |
| `bpf/tc/*.c` | 5 TC egress programs |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for all CLI command trees |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence |
| `pkg/dataplane/` | eBPF loader, map management, bpf2go bindings |
| `pkg/dataplane/userspace/` | Go bridge for the experimental Rust userspace dataplane |
| `pkg/daemon/` | Daemon lifecycle, reconciliation, interface management |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync) |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, route leaking |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/dhcprelay/` | DHCP relay with Option 82 |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `pkg/snmp/` | SNMP agent (system + ifTable MIB) |
| `pkg/lldp/` | LLDP protocol |
| `proto/bpfrx/v1/` | Protobuf service definition |
| `cmd/bpfrxd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `userspace-xdp/` | Rust userspace-specific XDP entry program |
| `userspace-dp/` | Rust AF_XDP userspace dataplane process |
| `docs/` | Protocol docs, test plans, feature gaps |
| `test/incus/` | Test environment scripts and configs |

## Documentation

See `docs/` for detailed design documents:
- `sync-protocol.md` — Cluster session sync wire protocol and algorithms
- `fabric-cross-chassis-fwd.md` — Fabric link cross-chassis forwarding design
- `ha-cluster.conf` — Unified HA cluster config with `${node}` variable expansion
- `testing-procedures.md` — Test categories, procedures, and debugging tips
- `phases.md` — Development phase history (40+ sprints)
- `bugs.md` — Bug tracker with root cause analysis
- `optimizations.md` — Performance profiling and optimization notes
- `test_env.md` — Test topology and validation steps
- `feature-gaps.md` — vSRX feature parity tracking
- `xdp-io-uring-userspace-dataplane.md` — Userspace dataplane design and current branch status
- `userspace-ha-validation.md` — Required deploy/validate cycle for the isolated userspace lab
- `userspace-perf-compare.md` — Repeatable IPv4/IPv6 `iperf3` + `perf` capture on the isolated userspace lab

## Requirements

- Linux kernel 6.12+ (6.18+ recommended for full NAT64 support)
- Go 1.22+
- clang/llvm (for BPF compilation)
- FRR (for routing protocol integration)
- strongSwan (for IPsec, optional)
- Kea (for DHCP server, optional)
