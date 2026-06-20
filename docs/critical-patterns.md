# xpf critical patterns / gotchas

Project-specific traps that repeatedly bite when working on xpf. The
broader coding and review discipline (hot-path allocation rules, review
severity, PR discipline) lives in
[`engineering-style.md`](engineering-style.md) — read that first for
non-trivial code. This page is the quick-reference gotcha list.

## Byte order

- Use `binary.NativeEndian.Uint32(ip4)` for BPF `__be32` fields — **NOT**
  `BigEndian`.
- cilium/ebpf serializes map values in native endian; IP bytes are
  already in network order.

## C/Go struct alignment

- When mirroring C structs in Go for cilium/ebpf, always match `sizeof`
  in C.
- Add trailing `Pad [N]byte` fields to reach the C compiler's struct
  alignment.

## Parser dual AST shape & set-syntax testing

- Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}`
  with children.
- Flat `set interfaces eth0 unit 0 family inet dhcp` →
  `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`.
- The compiler must handle **both** shapes.
- **Testing flat set syntax:** ALWAYS use `ParseSetCommand()` +
  `tree.SetPath()` loop, NEVER `NewParser()` — the parser treats newlines
  as whitespace and will merge all set lines into one giant node.

## BPF verifier (retained AF_XDP shim)

- Branch merges lose packet range — re-read `ctx->data`/`ctx->data_end`
  after branches.
- Combined stack limit is 512 bytes across call frames — use
  `__noinline` and scratch maps.
- Variable-offset pkt pointer: the verifier refuses range tracking when
  `var_off` is wide (0xffff) — use a constant-offset from a validated
  pointer instead.
- **Narrowing meta offsets**: when using `meta->l3_offset` (u16) for
  packet pointer math, mask with `& 0x3F` to narrow `var_off` so the
  verifier can track range.
- `__u16` causes sign-extension (`smin=-32768`) — fails for pkt pointer
  math.
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — always use
  `var val []byte`.
- The shim's verifier floor is kernel ≥ 6.18 (NAT64 complexity fails on
  6.12). The image bake asserts this (#1864).

## TTY detection

- Use `unix.IoctlGetTermios(fd, TCGETS)` — **not** `os.ModeCharDevice`
  (`/dev/null` is a CharDevice).

## Interface management (networkd)

- **xpfd manages ALL interfaces** on the firewall — no external networkd
  configs needed. Every interface must be defined in the config and
  assigned to a security zone; interfaces not in the config are brought
  down (`ActivationPolicy=always-down`).
- VRF devices and tunnel interfaces created by the daemon are excluded
  from unmanaged detection.
- **`.link` files** (prefix `10-xpf-`) rename kernel names
  (`enp7s0` → `ge-0-0-0`). Startup naming is
  `enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go`.
  - Non-RETH interfaces match by `MACAddress=` (MAC is stable).
  - RETH member interfaces match by `OriginalName=` (PCI kernel name) —
    MAC alternates between physical (boot) and virtual (daemon), so
    `MACAddress=` is unreliable. `ensureRethLinkOriginalName()`
    auto-fixes stale files.
- **`.network` files** configure addresses, DHCP avoidance, RA disable,
  VLAN parent flags. `KeepConfiguration=static` on RETH interfaces
  preserves VRRP VIPs across `networkctl reload`.
- DHCP interfaces: the daemon's DHCP client manages the address; address
  reconciliation is skipped. DHCP-learned default routes get admin
  distance 200 in FRR.

## XDP on SR-IOV interfaces

The line-rate behavior is coupled to the NIC driver exposed to the VM.

- **iavf (Intel VF driver) has NO native XDP support** — only
  generic/SKB mode works (full `sk_buff` per packet, ~16% CPU overhead).
  Throughput drops from 25+ Gbps to ~6.8 Gbps.
- **i40e/ice/mlx5 (PF driver) have native XDP** — driver-mode XDP
  processes packets before SKB allocation.
- **`bpf_redirect_map` requires `ndo_xdp_xmit` on the target** — you
  cannot redirect from native XDP to an interface that lacks native XDP;
  the redirect silently fails. Mixing native+generic interfaces in a
  redirect set does not work.
- **XDP on a PF does NOT see VF traffic** — SR-IOV hardware switching
  delivers VF packets directly to VFs, bypassing the PF's XDP program.
- **mlx5 SR-IOV VFs DO support native XDP** and exact/masked ntuple
  steering — this is the loss-cluster reference shape (each VF exposes 6
  combined RX queues → 6 workers).
- **PF passthrough claims the whole NIC** — no VFs available to other
  VMs. For multi-VM setups, VF passthrough is the only option (mlx5 VFs
  keep native XDP; Intel VFs fall to generic).

See the deploy backing table in
[`deploy-quickstart.md`](deploy-quickstart.md) for which backing to pick.

## Chassis cluster (HA)

- **Failover timing**: ~60ms with 30ms VRRP intervals
  (`masterDownInterval` ~97ms); configurable via
  `set chassis cluster reth-advertise-interval <ms>`.
- **Planned shutdown**: burst of 3× priority-0 adverts; peer takes over
  in ~1ms.
- **VRRP advertisement**: RETH instances default 30ms; `AdvertiseInterval`
  is milliseconds internally, centiseconds on wire per RFC 5798.
- **Async GARP**: `becomeMaster()` runs GARP in a goroutine; critical
  path is addVIPs → sendAdvert → emitEvent (sync), then
  `go sendGARP(false)`. `sendGARP(force)` has two gates — per-epoch dedup
  and a 500ms time dampener; `force=true` (used by `ReconcileVIPs` after a
  MAC change) bypasses ONLY the dampener so the post-MAC-change GARP is not
  swallowed by a routine burst from the prior 500ms (#2081).
- **Fabric forwarding**: the userspace dataplane redirects packets for
  peer-owned synced sessions over the fabric link
  (`resolve_fabric_redirect()` / `ingress_is_fabric()` in
  `userspace-dp/src/afxdp/forwarding/mod.rs`; see
  [`fabric-cross-chassis-fwd.md`](fabric-cross-chassis-fwd.md)).
- **RETH virtual MAC**: per-node `02:bf:72:CC:RR:NN`; `programRethMAC()`
  does link DOWN → set MAC → link UP, then `ReconcileVIPs()` re-adds
  VRRP VIPs.
- **Sync hold**: VRRP starts with `preempt=false`, released after bulk
  session sync (or 10s timeout); `preemptNowCh` triggers instant
  preemption.
- **Heartbeat**: 200ms interval, threshold 5 (1s detection).

## Shutdown

- FRR reloads run `frr-reload.py` DIRECTLY (15s context per leg) — NEVER
  `systemctl reload frr`: FRR 10.6's ExecReload bounces watchfrr and ends
  with systemd SIGKILLing FRR (#1880).
- The systemd unit has `TimeoutStopSec=20` as a safety net,
  `RestartSec=1`.
