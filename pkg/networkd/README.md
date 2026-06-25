# pkg/networkd

systemd-networkd file generator. Writes `.link`, `.network`, and
`.netdev` files for every xpfd-managed interface, handles MAC-based
rename, VLAN parent flagging, DHCP avoidance, and atomic file
replacement (AtomicGeneratedConfig, #1894: `fsatomic.WriteFileAtomic` —
many small files per reconcile, deliberately no fsync; the procfs
`rp_filter` knob stays a direct write, rename being impossible there).
Triggers `networkctl reload` only when files actually changed.

## Entry points

- `Manager` — `networkd.go`.
- `InterfaceConfig` — `networkd.go`. MAC, addresses, bonding, VLAN
  parent, VRF binding, description.
- `New()` — `networkd.go`.
- `NewInDir(dir)` — `networkd.go`. Test/offline renderer constructor that
  writes xpf-managed files under a caller-provided directory instead of
  `/etc/systemd/network`.
- `Apply(...)` — `networkd.go`.
- `Clear()` — `networkd.go`.
- `FindExternallyManaged(dir string) map[string]bool` — `networkd.go`. Detects networkd files
  the daemon doesn't own.

## Callers

`pkg/daemon`, `pkg/dataplane`.

## Dependencies

Standard library only.

## Naming conventions (CLAUDE.md authoritative)

- File prefix `10-xpf-` distinguishes xpf-managed files from manual
  configs. Anything else is left alone.
- Non-RETH interfaces match by `MACAddress=` — MAC is stable.
- RETH member interfaces match by `OriginalName=` (PCI kernel name)
  because the MAC alternates between physical and virtual at boot. The
  daemon's `ensureRethLinkOriginalName()` auto-fixes stale `.link` files
  that still use `MACAddress=`.
- `KeepConfiguration=static` on RETH interfaces preserves VRRP VIPs
  across `networkctl reload`.

## Gotchas

- `Apply()` only calls `networkctl reload` when files actually changed.
  This matters: a reload bounces interfaces, and an idempotent reapply
  must be cheap.
- Interfaces not in the typed config get `ActivationPolicy=always-down`
  in their `.network` file, so they stay down across reboots.
- **DHCP is gated per-family (#2986).** A static address is suppressed
  ONLY for the family whose DHCP client owns it: `DHCPv4` suppresses the
  static IPv4 address(es), `DHCPv6` suppresses the static IPv6
  address(es). The common WAN shape `DHCPv4 + static IPv6` (and the
  mirror) installs the non-DHCP family's static address; do NOT re-gate
  all addresses on whole-interface DHCP state. `generateNetwork`
  classifies family by `addressIsIPv6` (colon test on the CIDR string).
- VRF and tunnel interfaces created elsewhere are excluded from the
  unmanaged-interface scan via the `daemonOwned` map.
- **`Apply` is fail-closed on write errors (#2987).** `writeIfChanged`
  returns `(changed, err)`; `Apply` aggregates per-file write failures
  (still attempting every generated file), reloads whatever did change,
  then returns a non-nil error. The caller (`pkg/daemon/daemon_apply.go`
  step 2.5) captures this error and returns it at the tail of
  `applyConfigLocked` (mirroring `dhcpServerErr`), so a networkd write
  failure FAILS THE COMMIT (fail-closed) without skipping the downstream
  reconcile steps (RETH MAC, VRRP VIPs, FRR, RA, IPsec). A swallowed
  write (read-only `/etc`, full disk, EACCES, blocked path) used to report
  a clean commit against stale kernel state — a fail-open hole.
- **An empty desired set is NOT a no-op (#2988).** `Apply(nil)` (last
  managed interface removed) still runs the `10-xpf-*` stale-file sweep
  and requests a reload so old addresses/bonds/bridges/renames don't
  resurrect — while preserving the `SetProtectedResolver` lifeline files.
  The daemon caller (`daemon_apply.go` step 2.5) invokes `Apply` whenever
  the dataplane returned a result, NOT only when the managed set is
  non-empty — the old `len(ManagedInterfaces) > 0` guard shadowed the
  sweep on the live reconcile path. The lifeline stays protected
  end-to-end: `resolveProtectedInterfaces` derives the mgmt set from
  `ActiveConfig`, independent of the managed-interface set.
