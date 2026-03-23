# bpfrx Testing Documentation

Comprehensive test plans and validation procedures for both the legacy eBPF
dataplane and the userspace AF_XDP dataplane.

## Test Categories

| Document | Scope | Automation |
|----------|-------|------------|
| [unit-tests.md](unit-tests.md) | Go + Rust unit tests | `make test` + `cargo test` |
| [standalone-vm.md](standalone-vm.md) | Single-VM forwarding, NAT, policy | `make test-deploy` |
| [ha-cluster.md](ha-cluster.md) | HA failover, crash recovery, session sync | `make test-failover` |
| [userspace-dataplane.md](userspace-dataplane.md) | AF_XDP forwarding, cold start, neighbor resolution, native GRE | Manual + scripts |
| [performance.md](performance.md) | Throughput, latency, perf profiling | `scripts/userspace-perf-compare.sh` |
| [regression-checklist.md](regression-checklist.md) | Pre-commit validation checklist | Manual |

## Quick Reference

```bash
# Unit tests (must pass before any commit)
make test                          # 880+ Go tests, 26 packages
cd userspace-dp && cargo test      # 356 Rust tests

# Standalone VM
make test-deploy                   # Build + deploy to bpfrx-fw
make test-ssh                      # Shell into VM

# HA Cluster (eBPF)
make cluster-deploy                # Deploy to bpfrx-fw0 + bpfrx-fw1
make test-failover                 # Reboot fw0 during iperf3
make test-ha-crash                 # Force-stop/daemon-stop/multi-cycle

# Userspace HA Cluster
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
scripts/userspace-ha-validation.sh           # Full validation suite
scripts/userspace-ha-failover-validation.sh  # Failover-specific
scripts/userspace-native-gre-validation.sh   # Native GRE transit/failover
```

## Operational Notes

- `test/incus/cluster-setup.sh deploy all` builds, pushes, and restarts
  `bpfrxd` in a rolling sequence. Do not add an extra manual restart unless you
  are explicitly testing restart behavior.
- After a reboot of the remote `loss` host, repair VF trust/VLAN state before
  drawing any dataplane conclusions:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs

BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs
```

- The `.200` / `::200` throughput targets are not local Incus containers. When
  you need captures from the remote endpoint, use the gRPC capture service
  documented in `~/README.md` (`capture-client` / `grpcurl`), not ad-hoc
  `tcpdump` assumptions on unrelated lab hosts.

## Test Environment Topology

See [CLAUDE.md](../CLAUDE.md) for full network topology details.

### Standalone VM (`bpfrx-fw`)
- Virtio interfaces: fxp0 (mgmt), ge-0-0-0 (trust), ge-0-0-1 (untrust), ge-0-0-2 (dmz)
- i40e PCI passthrough: ge-0-0-3 (wan), ge-0-0-4 (loss)
- Test containers: trust-host, untrust-host, dmz-host

### eBPF HA Cluster (`bpfrx-fw0`, `bpfrx-fw1`)
- Two VMs with VRRP, fabric link, session sync
- `cluster-lan-host` container for traffic generation
- Config: `docs/ha-cluster-loss.conf`

### Userspace HA Cluster (`bpfrx-userspace-fw0`, `bpfrx-userspace-fw1`)
- On remote `loss` host with Mellanox SR-IOV VFs (zero-copy AF_XDP)
- `cluster-userspace-host` container
- Config: `docs/ha-cluster-userspace.conf`
- Test targets: 172.16.80.200 (IPv4), 2001:559:8585:80::200 (IPv6)
- Native GRE target: 10.255.192.41 (validated via `scripts/userspace-native-gre-validation.sh`)
