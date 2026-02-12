# bpfrx - eBPF Firewall with Junos Configuration Syntax

## What This Is
An eBPF-based firewall that clones Juniper vSRX capabilities using native Junos configuration syntax. Go userspace (cilium/ebpf) drives C eBPF programs attached at XDP (ingress) and TC (egress).

## Quick Start
```bash
make generate        # Generate Go bindings from BPF C via bpf2go
make build           # Build bpfrxd daemon
make build-ctl       # Build remote CLI client
make test            # Run Go tests (50 tests: 34 config/parser + 16 configstore)
```

## Test Environment (Incus VM)
```bash
make test-env-init   # One-time: install incus, create networks + profiles
make test-vm         # Create Debian 13 VM with FRR, strongSwan
make test-deploy     # Build -> push binary + config + unit -> systemctl enable --now
make test-ssh        # Shell into VM
make test-status     # Instance + service + network info
make test-logs       # journalctl -u bpfrxd -n 50
make test-journal    # journalctl -u bpfrxd -f (follow)
make test-start      # systemctl start bpfrxd
make test-stop       # systemctl stop bpfrxd
make test-restart    # systemctl restart bpfrxd
make test-destroy    # Tear down VM
```

If `incus` commands fail with permission errors, use `sg incus-admin -c "make ..."`.

## Architecture

### BPF Pipeline (14 programs, tail calls)
```
XDP Ingress: main -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```

### Key Design Patterns
- **Per-CPU scratch map** passes metadata between tail-call stages
- **Dual session entries** (forward + reverse) in conntrack HASH map
- **NAT "meta as desired state"**: pipeline stages set meta fields, xdp_nat reconciles packet
- **Three-phase config compilation**: Junos AST -> typed Go structs -> eBPF map entries
- **FRR-managed routing**: all routes (static, DHCP, per-VRF) via managed section in `/etc/frr/frr.conf`
- **Full interface management**: bpfrxd owns ALL interfaces on the firewall — renames them via `.link` files, configures addresses/DHCP via `.network` files, and brings down unconfigured interfaces

### APIs
- **gRPC** on 127.0.0.1:50051 — 42 RPCs (config, sessions, stats, routes, IPsec, DHCP)
- **HTTP REST** on 127.0.0.1:8080 — health, Prometheus metrics, config endpoints
- **CLI** — Interactive Junos-style with tab completion, `?` help, `| match` pipe
- **Remote CLI** — `cli` binary connects via gRPC

## Code Layout
| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs (common, maps, helpers, conntrack, nat) |
| `bpf/xdp/*.c` | 9 XDP ingress programs (includes cpumap entry) |
| `bpf/tc/*.c` | 5 TC egress programs |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/configstore/` | Candidate/active/commit/rollback management |
| `pkg/dataplane/` | eBPF loader, map management, bpf2go bindings |
| `pkg/daemon/` | Daemon lifecycle (TTY detection, signal handling) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnel + VRF management via netlink |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/rpm/` | RPM probe manager |
| `proto/bpfrx/v1/` | Protobuf service definition |
| `cmd/bpfrxd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `test/incus/` | Test environment (setup.sh, config, systemd unit) |

## Critical Patterns to Know

### Byte Order
- Use `binary.NativeEndian.Uint32(ip4)` for BPF `__be32` fields — **NOT** `BigEndian`
- cilium/ebpf serializes map values in native endian; IP bytes are already in network order

### C/Go Struct Alignment
- When mirroring C structs in Go for cilium/ebpf, always match `sizeof` in C
- Add trailing `Pad [N]byte` fields to reach C compiler's struct alignment

### Parser Dual AST Shape
- Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}` with children
- Flat `set interfaces eth0 unit 0 family inet dhcp` → `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`
- Compiler must handle **both** shapes

### BPF Verifier
- Branch merges lose packet range — re-read `ctx->data`/`ctx->data_end` after branches
- Combined stack limit is 512 bytes across call frames — use `__noinline` and scratch maps
- Variable-offset pkt pointer: verifier refuses range tracking when `var_off` is wide (0xffff) — use constant-offset from validated pointer instead
- `__u16` type causes sign-extension (`smin=-32768`) — fails for pkt pointer math
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — always use `var val []byte`
- xdp_zone fails verifier on kernel 6.12 (NAT64 complexity) — passes on 6.18+

### TTY Detection
- Use `unix.IoctlGetTermios(fd, TCGETS)` — **not** `os.ModeCharDevice` (`/dev/null` is a CharDevice)

### Interface Management (networkd)
- **bpfrxd manages ALL interfaces** on the firewall — no external networkd configs needed
- Every interface must be defined in the firewall config and assigned to a security zone
- Interfaces not in the config are brought down and marked `ActivationPolicy=always-down` in networkd
- VRF devices and tunnel interfaces created by the daemon are excluded from unmanaged detection
- **`.link` files**: written per-interface, match by MAC address, rename kernel names (enp6s0→trust0)
- **`.network` files**: configure addresses (static), DHCP avoidance, RA disable, VLAN parent flags
- File prefix `10-bpfrx-` distinguishes daemon-managed files; stale files are auto-removed
- `networkctl reload` is called only when files actually change
- **DHCP interfaces**: daemon's DHCP client manages the address; address reconciliation is skipped
- **Bootstrap**: `setup.sh` writes initial `.link` files for first boot (before daemon has run)
- DHCP-learned default routes get admin distance 200 in FRR (lower priority than static routes)

### Shutdown
- FRR reload commands use 15s context timeout to prevent hanging on `systemctl reload frr`
- systemd unit has `TimeoutStopSec=20` as safety net

## Feature Coverage
- **Firewall**: Stateful inspection, zone-based policies, address books, application matching
- **NAT**: SNAT (interface + pool), DNAT, static 1:1, NAT64 (native BPF)
- **IPv4 + IPv6**: Dual-stack, DHCPv4/v6 clients, Router Advertisements
- **Screen/IDS**: 10 checks (land, syn-flood, ping-death, rate-limiting)
- **Routing**: FRR integration (static, OSPF, BGP), VRFs, GRE tunnels
- **VLANs**: 802.1Q tagging in BPF, trunk ports
- **IPsec**: strongSwan config generation
- **Observability**: Syslog, NetFlow v9, Prometheus, RPM probes, dynamic feeds
- **Flow**: TCP MSS clamping, ALG control, configurable timeouts, firewall filters + DSCP

## Network Topology (Test VM)

All interfaces are managed by bpfrxd — renamed via `.link` files, configured via `.network` files.

```
VM (bpfrx-fw) — Virtio NICs (via Incus bridges), all managed by bpfrxd:
  enp5s0  → mgmt0     DHCP          — mgmt zone (SSH + ping)
  enp6s0  → trust0    10.0.1.10     — trust zone
  enp7s0  → untrust0  10.0.2.10     — untrust zone
  enp8s0  → dmz0      10.0.30.10    — dmz zone
  enp9s0  → tunnel0   10.0.40.10    — tunnel zone

VM (bpfrx-fw) — i40e PCI passthrough, managed by bpfrxd:
  enp10s0f0np0 → wan0  172.16.50.5  — wan zone (VLAN 50, IPv6 2001:559:8585:50::5/64)

Test containers:
  trust-host    10.0.1.102  (2001:559:8585:bf01::102)  — bpfrx-trust bridge
  untrust-host  10.0.2.102  (2001:559:8585:bf02::102)  — bpfrx-untrust bridge
  dmz-host      10.0.30.101 (2001:559:8585:bf03::101)  — bpfrx-dmz bridge
```
