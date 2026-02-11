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
