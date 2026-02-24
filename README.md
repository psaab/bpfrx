# bpfrx

eBPF zone-based firewall with native Junos configuration syntax.

bpfrx is a high-performance stateful firewall built on Linux eBPF (XDP + TC) that replicates Juniper vSRX capabilities. It uses the familiar Junos hierarchical configuration syntax and provides a full interactive CLI with tab completion and `?` help.

## Architecture

```
XDP Ingress: main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```

- **14 BPF programs** (9 XDP ingress + 5 TC egress) chained via tail calls
- **Go userspace** (cilium/ebpf) handles config compilation, session GC, and management APIs
- **Per-CPU scratch maps** pass metadata between pipeline stages
- **Dual session entries** (forward + reverse) in conntrack hash map

## Features

- **Zone-based policies** with stateful inspection, address books, and application matching
- **NAT**: source (interface + pool), destination, static 1:1, NAT64
- **Dual-stack**: IPv4 + IPv6, DHCPv4/v6 clients, embedded Router Advertisement sender
- **Screen/IDS**: land attack, SYN flood, ping of death, teardrop, rate-limiting
- **Firewall filters**: policer (token bucket + three-color), lo0 filter, flexible match
- **Flow**: TCP MSS clamping, ALG control, configurable timeouts, DSCP rewrite
- **Routing**: FRR integration (static, OSPF, BGP, IS-IS, RIP), VRFs, GRE tunnels, ECMP, inter-VRF route leaking
- **VLANs**: 802.1Q tagging in BPF, trunk ports
- **IPsec**: strongSwan config generation, IKE proposals, XFRM interfaces
- **HA**: Chassis cluster with sub-second failover (<1s), native VRRPv3 (250ms advertisements), bondless RETH with per-node virtual MAC, incremental session sync, config sync, IPsec SA sync, fabric cross-chassis forwarding, ISSU
- **Observability**: syslog (structured RT_FLOW format, TCP/TLS transport, event mode), NetFlow v9, Prometheus metrics, SNMP (system + ifTable MIB), RPM probes, session aggregation
- **Management**: interactive CLI, remote CLI (gRPC), REST API, commit/rollback model (50 rollback slots)
- **Performance**: 25+ Gbps with native XDP, hitless restarts with zero packet loss, sub-second cluster failover

## Quick Start

```bash
make generate    # Generate Go bindings from BPF C (requires clang + bpf headers)
make build       # Build bpfrxd daemon (embeds version from git)
make build-ctl   # Build remote CLI client
make test        # Run 640+ tests across 20 packages
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
```

## Management Interfaces

- **Local CLI**: run `bpfrxd` in a TTY for interactive Junos-style shell
- **Remote CLI**: `cli -addr <host>:50051` connects via gRPC
- **gRPC API**: 50+ RPCs on port 50051 (config, sessions, stats, routes, IPsec, DHCP, cluster)
- **REST API**: HTTP on port 8080 (health, Prometheus `/metrics`, config endpoints)

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
make cluster-deploy  # Build + push to both VMs
```

## Documentation

See `docs/` for detailed design documents:
- `sync-protocol.md` — Cluster session sync wire protocol and algorithms
- `fabric-cross-chassis-fwd.md` — Fabric link cross-chassis forwarding design
- `ha-cluster.conf` — Unified HA cluster config with `${node}` variable expansion
- `phases.md` — Development phase history (40+ sprints)
- `bugs.md` — Bug tracker with root cause analysis
- `optimizations.md` — Performance profiling and optimization notes
- `test_env.md` — Test topology, procedures, and validation steps
- `feature-gaps.md` — vSRX feature parity tracking

## Requirements

- Linux kernel 6.12+ (6.18+ recommended for full NAT64 support)
- Go 1.22+
- clang/llvm (for BPF compilation)
- FRR (for routing protocol integration)
