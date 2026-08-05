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

- `Apply()` calls `networkctl reload` when files actually changed **or**
  a prior activation is still owed (see reload-debt below). This matters:
  a reload bounces interfaces, and an idempotent reapply must be cheap.
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
- **A failed stale-file DELETE also fails the commit (#4900).** The
  `10-xpf-*` stale sweep used to treat `os.Remove` failures as warn-only:
  a removed interface/address/bond/bridge/rename whose generated unit
  could not be deleted (read-only `/etc`, immutable bit, EACCES) survived
  a "successful" commit, and if no other generated file changed, `Apply`
  returned nil with no reload — so the surviving `.network`/`.netdev`
  re-applied the removed config on the next reload or boot (route leak /
  management surprise). `Apply` and `Clear` now aggregate stale-remove
  failures alongside the write errors (still best-effort every delete,
  still reloading whatever DID change) and return a joined error, so a
  stale unit that cannot be removed FAILS THE COMMIT. Distinct from #2987
  (write failure) and #2988 (empty-set skip), neither of which surfaced a
  delete failure.
- **A failed reload/reconfigure owes activation debt (#4954).** The
  generated files are written to disk BEFORE `networkctl reload` runs, so
  a reload that fails leaves the kernel running the pre-failure config
  while the files on disk already match the desired state. Without state,
  an identical re-commit sees `writeIfChanged → (false, nil)` for every
  file (`changed==false`), skips the reload, and returns nil — a FALSE
  success masking a route leak / stranded NIC / management lockout. The
  `Manager` now carries `reloadPending` / `reconfigurePending` debt: a
  failed reload sets `reloadPending` and re-runs the idempotent reload on
  the next `Apply` even with unchanged files, clearing the debt only on
  success (and still returning the error until then). The per-interface
  `networkctl reconfigure` follow-up is best-effort (warn-only, Apply
  still returns nil) but is likewise retried from `reconfigurePending`
  until it succeeds. Distinct from #2987 (write-error-fails-commit) and
  the stale-file sweep.
  **`Clear()` owes the same debt (#5718 A7-b01-C001).** Removing the
  managed files deactivates nothing until the reload lands, so a failed
  reload in `Clear` records `reloadPending` too. The empty-glob case is
  therefore NOT an unconditional `return nil`: with debt outstanding the
  files are already gone but the kernel never re-read them, so `Clear`
  re-runs the idempotent reload and reports failure until it succeeds.
  Without this the SECOND `Clear` found nothing to remove and reported a
  success it had not achieved while the removed addresses / VRFs / bonds
  / renames stayed live.
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
