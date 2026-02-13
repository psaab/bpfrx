# Bugs Found During Development & VM Testing

## Critical Bugs

### ipToUint32BE byte order
- `binary.BigEndian.Uint32(ip4)` produced wrong bytes when cilium/ebpf serializes as native-endian
- **Fix:** Use `binary.NativeEndian.Uint32(ip4)` so bytes match raw network order BPF writes to `__be32`
- **Affected:** DNAT, static NAT, NAT pool IPs, NAT64 prefix
- **File:** `pkg/dataplane/maps.go`

### Family inet/inet6 AST shape
- Hierarchical syntax `family inet { dhcp; }` creates `Node{Keys:["family","inet"]}` — AF name is Keys[1]
- Set-command `set interfaces eth0 unit 0 family inet dhcp` creates `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`
- **Fix:** Compiler must handle BOTH shapes
- **File:** `pkg/config/compiler.go`

### SessionValueV6 trailing padding
- C struct is 152 bytes (8-byte aligned due to `__u64`), Go struct was 148 bytes
- **Fix:** Added `Pad2 [4]byte` to match. Compare `sizeof` in C vs Go `unsafe.Sizeof`
- **Pattern:** When mirroring C structs in Go for cilium/ebpf, always add trailing padding to match C alignment

### Host-inbound bypass in XDP policy
- `bpf_fib_lookup` with broadcast/unicast-to-unknown-IP matches default route
- Sends host-bound packets through policy pipeline where deny-all drops them
- **Fix:** xdp_policy checks `host_inbound_flag()` before denying, tail-calls to xdp_forward with `fwd_ifindex=0`

## Important Bugs

### tx_ports devmap value size
- Go wrote 4-byte struct (ifindex only) but BPF DEVMAP_HASH expects 8-byte `bpf_devmap_val` (ifindex + prog_fd)
- **File:** `pkg/dataplane/loader.go`

### SNAT hierarchical syntax
- Config compiler only handled flat `source-nat interface` keys, not hierarchical `source-nat { interface; }` with child nodes
- **Fix:** `FindChild()` fallback in `pkg/config/compiler.go`

### iter.Next(&key, nil) crash
- cilium/ebpf v0.20 panics when iterating non-empty maps with nil value pointer
- **Fix:** Always use `var val []byte; iter.Next(&key, &val)`

### TTY detection for daemon mode
- `os.Stdin.Stat()` with `os.ModeCharDevice` returns true for `/dev/null` (it IS a character device)
- Caused CLI to start under systemd, read EOF from `/dev/null`, exit immediately
- **Fix:** Use `unix.IoctlGetTermios(fd, unix.TCGETS)` — only succeeds on real terminals

### FRR reload hang on shutdown
- `frr.Clear()` during daemon shutdown calls `reload()` which ran `systemctl reload frr` with no timeout
- `frr-reload.py` hung indefinitely, blocking bpfrxd until systemd's 90s `TimeoutStopSec` killed it
- **Fix:** Added `context.WithTimeout(15*time.Second)` to `exec.CommandContext` calls in `reload()`
- Also set `TimeoutStopSec=20` in the systemd unit as safety net

## SR-IOV Bugs

### SR-IOV in Incus VMs
- `nictype: sriov` and `nictype: physical` both fail with `DeviceNotFound` (agent race condition)
- **Fix:** Use `type: pci` with `address=<BDF>` instead — hot-add after boot
- VFs on enp101s0f0np0 (X710) have individual IOMMU groups so VFIO works

### SR-IOV PCI passthrough pattern
```bash
vf_pci=$(readlink -f /sys/class/net/enp101s0f0v0/device | xargs basename)
incus config device add VM internet pci address=$vf_pci
```
VF appears as enp10s0 inside VM.

## BPF Verifier Patterns

### Branch merge packet range loss
- After if/else branches that read packet data, verifier loses packet range on merged paths
- **Fix:** Re-read `ctx->data`/`ctx->data_end` after branches, or avoid packet reads after branch merges

### NAT64 verifier complexity
- xdp_zone fails verifier on kernel 6.12 due to NAT64 loop complexity
- Passes on kernel 6.18+ with larger verifier limits
- **Workaround:** Run on 6.18+ or disable NAT64 config

### TCP MSS clamping verifier
- Cannot use loops or variable offsets from map-derived values (`l4_offset`)
- **Fix:** Use constant-offset checks for common MSS positions + single bounds check (`l4_offset + 60 <= data_end`)

## Performance Bugs

### bpf_printk consuming 55%+ CPU
- Debug `bpf_printk()` calls left in production BPF programs consumed over 55% CPU
- **Fix:** Removed/disabled all `bpf_printk()` calls
- **Commit:** `e104112`

### CHECKSUM_PARTIAL NAT checksum corruption
- NAT checksum update used complemented delta for `CHECKSUM_PARTIAL` pseudo-header seed
- Kernel expects non-complemented update for PH seed — corrupted checksums on offloaded packets
- **Fix:** Use non-complemented `csum_replace4`/`csum_replace16` for PH seed updates
- **Commit:** `0950a1f`

### Cross-zone TCP forwarding with cold ARP
- `bpf_fib_lookup` returns `NO_NEIGH` (rc=7) when ARP entry is absent
- Cannot redirect without destination MAC — packets dropped silently
- **Fix:** XDP_PASS to kernel for ARP resolution; TC egress drops un-NAT'd kernel-forwarded packets
- **Files:** `bpf/xdp/xdp_zone.c`, `bpf/tc/tc_main.c`, `bpf/tc/tc_conntrack.c`
- **Commit:** `a1e1aab`

### VLAN tag restore + overlapping memcpy in cross-zone forwarding
- VLAN tag not restored after cross-zone forwarding when egress interface has VLAN
- `memcpy` with overlapping source/dest regions caused corruption
- **Fix:** Proper VLAN tag push on egress; safe copy ordering
- **Commit:** `9f8f32c`

### Conntrack dropping TCP RST before forwarding to peer
- TCP RST packets matching existing sessions were dropped by conntrack instead of forwarded
- Broke connection resets and half-open connection cleanup
- **Fix:** Allow TCP RST through conntrack for established sessions
- **Commit:** `05b43a4`

### Cross-CPU NAT port collisions
- Multiple CPUs could allocate the same SNAT port simultaneously (per-CPU counters not atomic)
- **Fix:** Per-CPU NAT port counter partitioning; also skip FIB cache on TCP SYN (need full FIB for new connections)
- **Commit:** `7aa77f0`

### Generic XDP 16% CPU overhead
- All interfaces forced to generic (SKB) XDP mode because iavf driver lacks native support
- `bpf_redirect_map()` in native XDP requires target's `ndo_xdp_xmit` — if ANY interface lacks it, all forced generic
- Generic XDP creates full SKB per packet: `memcpy_orig` ~8% + `memset_orig` ~8% = ~16% CPU
- **Fix:** Per-interface native/generic XDP selection with `redirect_capable` BPF map
- **Commit:** `f9edb92`

## Hitless Restart Bugs

### Destructive daemon shutdown kills sessions and routes
- `daemon.Close()` called `d.frr.Clear()` (removes kernel routes), `d.dhcp.StopAll()` (releases DHCP leases + removes IPs), `d.routing.ClearVRFs()`/`ClearTunnels()` (removes VRFs)
- On restart: no routes = no forwarding, no IPs = DHCP re-request, all sessions lost
- **Fix:** Non-destructive SIGTERM shutdown — only close Go file handles, leave all state for next daemon. Full teardown only via `bpfrxd cleanup`
- **File:** `pkg/daemon/daemon.go`
- **Commit:** `f9edb92`

### DHCP context cancellation removes addresses on restart
- DHCP client context derived from daemon context: `context.WithCancel(ctx)`
- When daemon ctx cancelled during SIGTERM, DHCP clients release leases and remove interface IPs
- Even without explicit `StopAll()`, context cancellation triggers cleanup
- **Fix:** DHCP clients use `context.Background()` — only explicit `StopAll()` triggers lease release
- **File:** `pkg/dhcp/dhcp.go`
- **Commit:** `f9edb92`

### Premature link.Update() with empty config maps
- XDP attachment happened during `compileZones()` BEFORE policies/NAT/screen were compiled
- Brief window where new BPF programs run with populated zone maps but empty policy/NAT/screen maps
- During this window: all traffic hits default-deny (no policies loaded)
- **Fix:** Collect pending ifindex lists during compilation; defer all `link.Update()` calls to end of `Compile()` after ALL map populations complete
- **File:** `pkg/dataplane/compiler.go`
- **Commit:** `f9edb92`

### Stale generic XDP pinned links after mode change
- Pinned links from before per-interface XDP were created in generic mode
- `link.Update()` replaces the program but does NOT change XDP attachment mode
- Restarting daemon reuses stale generic links even though native is now supported
- **Fix:** Run `bpfrxd cleanup` once after deploying the per-interface XDP code to create fresh native links
- **Pattern:** Structural changes to XDP/TC attachment require one-time cleanup + fresh start

### SNAT TCP sessions dying on daemon restart
- SNAT sessions had forward + reverse entries pointing to pre-SNAT IPs
- dnat_table entries (reverse SNAT mappings) were cleared before new entries written
- During the window: return traffic lookup fails → session drops
- **Fix:** Write new dnat_table entries BEFORE clearing stale ones (populate-before-clear)
- **File:** `pkg/dataplane/compiler.go`
- **Commit:** `a030446`

### Non-deterministic map IDs breaking hitless restarts
- Zone/screen/address/application IDs assigned in map iteration order (random)
- After restart, same config could get different IDs → stale BPF map entries reference wrong IDs
- **Fix:** Sort map keys alphabetically before ID assignment → deterministic IDs across restarts
- **File:** `pkg/dataplane/compiler.go`
- **Commit:** `cec07ea`

## BPF Flow Config Gotchas

### allow-dns-reply requires BPF check
- `allow_dns_reply` field existed in `flow_config` BPF struct since initial implementation
- Was compiled to BPF map correctly but never checked in any BPF program
- DNS reply packets (UDP src port 53) without sessions were denied by policy
- **Fix:** Added check in xdp_conntrack session-miss path (both IPv4 and IPv6)
- **Commit:** `1a8b873`

### Parsed but NOT used in BPF (known gaps)
- `power_mode_disable` — in flow_config struct, never checked in BPF
- `gre_accel` — in flow_config struct, never checked in BPF (GRE acceleration placeholder)
- `pre-id-default-policy` — parsed in config, not compiled to BPF (requires app identification)
