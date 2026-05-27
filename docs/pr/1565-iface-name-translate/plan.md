# #1565 — pkg/api: translate Junos config names to Linux ifnames before net.InterfaceByName

**Status:** DRAFT v4 — addressing Codex round-3 PLAN-NEEDS-MAJOR (AGY round-3 returned PLAN-NEEDS-MINOR, overlapping fixes)

## Round-3 verdicts (round-3 archived)

- **Codex** task-mpnij29g-ligphz: PLAN-NEEDS-MAJOR. Findings:
  - **`fab0`/`fab0.0` should NOT be resolved via `ResolveFab` in the
    API helper.** `fab0`/`fab1` are real kernel IPVLAN devices
    (created by `daemon_apply.go:298-386` and present as netlink
    links). `snapshotLinuxName` at
    `pkg/dataplane/userspace/interfaces.go:323,331` returns
    `LinuxIfName(ifName)` for bare non-reth refs — it does NOT call
    `ResolveFab`. `ResolveFab` is documented as a fabric-PARENT
    resolver for BPF attachment, not a display-name resolver. API
    helper must keep `fab0` as `fab0`.
  - **`st0.0` is missed.** XFRM secure tunnels: kernel device is
    the full ref preserved via `XFRMIfNameAndID` ('st0.0' stays
    'st0.0'). `compiler_iface.go:44-48` already short-circuits
    dotted st* refs. v3's generic unit-collapse would turn `st0.0`
    into `st0`.
  - **Smoke gate references `reth1.0`** but `allInterfaceNames`
    won't iterate it from the userspace cluster cfg (`reth1.0`
    only appears under `dhcp-local-server`, not in a security zone
    or top-level `interfaces`). The named-row assertion would
    fail post-fix.
  - Loopback handler test is too weak — `lo` resolves identity
    pre-fix. Use a cfg alias resolving to `lo` to actually exercise
    the helper.
  - Prometheus smoke missing reth aliases — needs reth0, reth0.50,
    reth0.80, reth1 in the gate to prove `metrics_counters.go` is
    fixed.
  - Plan text internally contradicts on migration mandatoriness
    (one sentence says "mandatory", another says "do NOT migrate").
    Clean up to a single clear stance.

- **AGY** review-mpnijezy-rbikjh: PLAN-NEEDS-MINOR. Findings overlap:
  - Smoke gates target interfaces not in actual cfg (AGY checked
    `xpf-cluster-fw0.conf` not `ha-cluster-userspace.conf`, so the
    specific names AGY cited differ from Codex's; both reviewers
    agree the gate names need correction).
  - Missing `"fmt"` import in `pkg/config/types.go` for new
    `fmt.Sprintf` calls.
  - Move `SeedLeaseForTesting` to `pkg/dhcp/test_seams.go` to keep
    production file clean.
  - Add `// NOTE: Keep in sync with (*Config).ResolveKernelIfName`
    comments in legacy `snapshotLinuxName` and
    daemon `resolveJunosIfName` to mitigate drift.

## Round-2 verdicts (archived)

- **Codex** task-mpni7vi4-2oacjs: PLAN-NEEDS-MAJOR.
  - Critical: v2 helper preserved the `.unit` suffix unchanged after
    `ResolveReth`/`ResolveFab`. But the **kernel link name uses the
    VLAN tag (`unit.VlanID`)** when set, not the unit number. For
    `reth0.80` with `units { 80 { vlan-id 180 } }`, the kernel link
    is `ge-0-0-0.180`, not `ge-0-0-0.80`. v2 plan would silently
    miss every VLAN-where-vlan-id≠unit case. Cited
    `pkg/daemon/resolve_neighbor_test.go:64`,
    `pkg/dataplane/userspace/manager_test.go:3267-3275`.
  - IRB refs (`irb.0`) resolve via `config.IRBToBridge` to a bridge
    device name, not via ResolveReth/ResolveFab.
  - TunnelNameMap collision is schema-possible: the compiler parses
    `tunnel {}` under any interface (not only `gr-*`/`ip-*`), so
    `reth0.50` can legitimately be a TunnelNameMap key. v2 plan's
    "no collision" claim was unsafe.
  - v2's DHCP integration test wasn't actually designed —
    `dhcp.Manager` fields are unexported and there's no
    `NewForTesting`. Need an explicit mechanism choice.
  - REST smoke `length >= 3` is too weak — `fxp0`, `em0`, `fab0`
    are already non-slash and resolvable pre-fix. Need named-row
    `ifindex > 0` assertions for the slash-containing refs and
    reth aliases specifically.
- **AGY** review-mpni8bxc-masfic: PLAN-READY. (But signed off on
  an incorrect v2 design that fed back `reth0.50` → `ge-0-0-2.50`
  as "correct" — coincidentally right when vlan-id == unit, but
  Codex's broader scan caught the cases where they diverge. v3
  fixes the underlying issue; expecting AGY to ratify v3.)

Round-1 verdicts pinned at commit `e91b9650` (plan v1).
Round-2 plan pinned at commit `3a57fbde` (plan v2).

## Issue framing (unchanged)

Four pkg/api sites pass config-level Junos interface names to
`net.InterfaceByName`, which fails silently because Linux IFNAMSIZ
forbids `/` and RETH/Fab/IRB names have no kernel ifindex:

- `pkg/api/interfaces.go:32` — `interfacesHandler`
- `pkg/api/interfaces.go:210` — `writeInterfacesDetail`
- `pkg/api/stats.go:64` — `ifaceStatsHandler`
- `pkg/api/metrics_counters.go:68` — `collectInterfaceCounters`

Symptoms: zero counters, "Not present" detail rows, silently-dropped
JSON stats rows, missing Prometheus per-interface series.

The terse-mode sites at `:107`, `:130`, `:163` are already correct.

## Honest scope / value framing

Control-plane observability bug fix. No hot path, no dataplane
correctness risk. Win is qualitative: REST + Prometheus see real
counters; JSON `ifindex` populated. PLAN-KILL is acceptable if
reviewers conclude the churn isn't justified.

## What's already shipped (this is the key new section vs v2)

**The codebase already has a correct kernel-name helper** —
`pkg/dataplane/userspace/interfaces.go:303` defines
`snapshotLinuxName(cfg, ifName, iface, unit)`. It implements the
full resolution:

```go
func snapshotLinuxName(cfg *config.Config, ifName string, iface *config.InterfaceConfig, unit *config.InterfaceUnit) string {
    if iface == nil {
        return config.LinuxIfName(ifName)
    }
    if unit != nil {
        if tunnelNames := cfg.TunnelNameMap(); len(tunnelNames) > 0 {
            ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
            if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
                return linuxName
            }
        }
        if unit.VlanID > 0 {
            return fmt.Sprintf("%s.%d", config.LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
        }
        if strings.HasPrefix(ifName, "reth") {
            if unit.Number == 0 {
                return config.LinuxIfName(cfg.ResolveReth(ifName))
            }
            return config.LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
        }
        if unit.Number == 0 {
            return config.LinuxIfName(ifName)
        }
        return config.LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
    }
    if strings.HasPrefix(ifName, "reth") {
        return config.LinuxIfName(cfg.ResolveReth(ifName))
    }
    return config.LinuxIfName(ifName)
}
```

This is the right shape. The v2 plan reinvented (incorrectly) what
this function already does. **v3 lifts `snapshotLinuxName` from
`pkg/dataplane/userspace/` to `pkg/config/types.go` as a public
method, and pkg/api consumes it directly.**

`pkg/daemon/daemon_dhcp.go:138-140` has a separate, simpler private
helper `resolveJunosIfName(cfg, ifName) = LinuxIfName(ResolveReth(ifName))`
that the v3 plan deletes once the canonical helper is centralized.
(Callers in `resolveConfigSubnetLinuxName` already apply the VLAN
suffix on top of this — that pattern is the right one for callers
that already know the unit.)

`pkg/dataplane/compiler_iface.go:20` exposes a richer
`resolveInterfaceRef(ref, cfg) (physName, configName, unitNum, vlanID)`
that includes IRB and st0 handling. **v3 either adapts this for the
public helper, or composes IRB resolution explicitly.**

## Concrete design (v3)

### Public helper: `(*Config).ResolveKernelIfName`

Path: `pkg/config/types.go`. **Note:** add `"fmt"` import (AGY catch).

```go
// ResolveKernelIfName converts a Junos-style interface reference (as
// found in zone declarations and the keys of cfg.Interfaces.Interfaces)
// to the Linux kernel ifname it should resolve to on the LOCAL node.
//
// Important nuance: this is a DISPLAY-name resolver for API readers.
// It is NOT the same as ResolveFab (which returns the fabric overlay's
// parent for BPF attachment). fab0 itself is a real kernel IPVLAN
// device, so API queries on fab0 must look up "fab0", not its parent.
// Similarly, st0.x is the kernel XFRM device name verbatim.
//
// Resolution semantics, in order:
//   1. Bare refs (no "." suffix):
//        - reth0 → ResolveReth → physical member, LinuxIfName.
//        - all others (fxp0, em0, fab0, lo, ge-0/0/0, gr-0/0/0, st0):
//          LinuxIfName(ref). Matches snapshotLinuxName lines 328-331.
//   2. Dotted refs (e.g. "ge-0/0/0.80", "reth0.50", "gr-0/0/0.0",
//      "irb.0", "st0.0"):
//        a. st* short-circuit: any "st<N>.<M>" ref is the kernel
//           XFRM device name; just LinuxIfName(ref). Matches
//           compiler_iface.go:44-48 + XFRMIfNameAndID semantics.
//        b. IRB: look up via config.IRBToBridge(cfg.BridgeDomains)
//           and return the bridge device name (no suffix).
//        c. Tunnel: if TunnelNameMap[ref] is set, return that name
//           verbatim (covers gr-0/0/0.0 → gr-0-0-0 and gr-0/0/0.1 →
//           gr-0-0-0u1).
//        d. Otherwise look up cfg.Interfaces.Interfaces[base].Units[unit]:
//             - If unit has tunnel.Name set, return that (per-unit
//               tunnel override).
//             - If unit.VlanID > 0, return
//               LinuxIfName(ResolveReth(base)) + "." + VlanID.
//             - If unit.Number == 0, return LinuxIfName(ResolveReth(base))
//               (collapse unit 0).
//             - Else return LinuxIfName(ResolveReth(base)) + "." + unit.Number.
//        e. Fallback: LinuxIfName(ResolveReth(ref)) — preserves suffix.
//
// NOTE: Keep in sync with snapshotLinuxName in
// pkg/dataplane/userspace/interfaces.go and resolveJunosIfName in
// pkg/daemon/daemon_dhcp.go. Migration to centralize all callers is
// tracked in a follow-up issue.
func (c *Config) ResolveKernelIfName(ref string) string {
    parts := strings.SplitN(ref, ".", 2)
    base := parts[0]

    // Bare refs
    if len(parts) == 1 {
        if strings.HasPrefix(base, "reth") {
            return LinuxIfName(c.ResolveReth(base))
        }
        return LinuxIfName(base)
    }

    // XFRM (st*) is verbatim — kernel device is the full ref.
    if strings.HasPrefix(base, "st") && len(base) >= 3 {
        // Confirm st<digits> shape (st followed by a number) to avoid
        // catching unrelated "st"-prefixed names.
        if _, err := strconv.Atoi(base[2:]); err == nil {
            return LinuxIfName(ref)
        }
    }

    // IRB
    if base == "irb" {
        if bridges := IRBToBridge(c.BridgeDomains); bridges != nil {
            if bridge, ok := bridges[ref]; ok && bridge != "" {
                return bridge
            }
        }
        // Fall through if no bridge mapping; LinuxIfName(ref) below.
    }

    // Tunnel by ref (per-unit explicit map).
    if tunMap := c.TunnelNameMap(); tunMap != nil {
        if linuxName, ok := tunMap[ref]; ok && linuxName != "" {
            return linuxName
        }
    }

    // Look up the unit by parsed number on the base interface.
    unitNum, _ := strconv.Atoi(parts[1])
    if ifc, ok := c.Interfaces.Interfaces[base]; ok && ifc != nil {
        if unit, ok := ifc.Units[unitNum]; ok && unit != nil {
            if unit.Tunnel != nil && unit.Tunnel.Name != "" {
                return unit.Tunnel.Name
            }
            kernelBase := LinuxIfName(c.ResolveReth(base))
            if unit.VlanID > 0 {
                return fmt.Sprintf("%s.%d", kernelBase, unit.VlanID)
            }
            if unit.Number == 0 {
                return kernelBase
            }
            return fmt.Sprintf("%s.%d", kernelBase, unit.Number)
        }
    }

    // Fallback for refs not modeled in cfg.Interfaces.Interfaces:
    // preserve the suffix and translate slashes only.
    return LinuxIfName(c.ResolveReth(ref))
}
```

This is a port of `snapshotLinuxName` with two enhancements:
- IRB handling (Codex finding #2)
- explicit unit-tunnel branch matching `resolveInterfaceRef`

### Public helper: `(*Config).DHCPLeaseKey`

Same as v2 — the daemon's DHCP lease key shape is independent of
the kernel link name (the daemon's `Start(...)` call passes the
**config-level** RETH name, not the resolved physical member —
see `daemon_dhcp.go:59` `dhcpIface = LinuxIfName(ifName)` where
`ifName` is the cfg key, e.g. `reth0`, then `.VlanID` is appended).

```go
// DHCPLeaseKey returns the lease-lookup key that pkg/dhcp.Manager
// keys leases by for the given config interface and unit number.
// Mirrors the construction in pkg/daemon/daemon_dhcp.go:
//   key = LinuxIfName(physRef) + ("." + strconv(unit.VlanID) when > 0).
// physRef is the CONFIG-LEVEL name (e.g. "reth0"), not the resolved
// physical member — daemon's DHCP Start() is called with the
// config-level name.
// Returns ("", false) when the unit doesn't exist in cfg.
func (c *Config) DHCPLeaseKey(physRef string, unitNum int) (string, bool) {
    physRef = strings.SplitN(physRef, ".", 2)[0]
    ifc, ok := c.Interfaces.Interfaces[physRef]
    if !ok || ifc == nil {
        return "", false
    }
    unit, ok := ifc.Units[unitNum]
    if !ok || unit == nil {
        return "", false
    }
    key := LinuxIfName(physRef)
    if unit.VlanID > 0 {
        key = key + "." + strconv.Itoa(unit.VlanID)
    }
    return key, true
}
```

Note: this intentionally **does NOT** call ResolveReth, because the
DHCP manager keys by the config-level RETH name (e.g. `reth0.50`,
not `ge-0-0-2.50`).

### Migration of `snapshotLinuxName` and `resolveJunosIfName`

**Decision (single stance, v4):** DO NOT migrate the existing private
helpers in this PR. Ship the new public method additively. Migration
to centralize all callers is a follow-up issue.

Rationale: migrating `snapshotLinuxName` would touch the dataplane
interface snapshot path that drives every userspace-dp `Apply()` —
high blast radius for a #1565 observability fix. Migrating
`daemon/resolveJunosIfName` is much smaller but still touches a code
path that's currently green; bundling it adds risk without
proportional value.

**Drift mitigation:** add explicit
`// NOTE: Keep in sync with (*Config).ResolveKernelIfName in pkg/config/types.go`
comments at both legacy helpers. File the migration follow-up issue
on PR merge.

### Call-site rewrites

#### `pkg/api/interfaces.go:32` `interfacesHandler`

```go
for ifName := range allInterfaceNames(cfg) {
    iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
    is := InterfaceStats{Name: ifName, Zone: ifZone[ifName]}
    if err == nil {
        is.Ifindex = iface.Index
        if s.dp != nil && s.dp.IsLoaded() {
            if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
                is.RxPackets, is.RxBytes = ctrs.RxPackets, ctrs.RxBytes
                is.TxPackets, is.TxBytes = ctrs.TxPackets, ctrs.TxBytes
            }
        }
    }
    result = append(result, is)
}
```

#### `pkg/api/interfaces.go:210` `writeInterfacesDetail`

Two distinct translations:
- **kernel link** via `cfg.ResolveKernelIfName(ifName)`
- **DHCP lease key** via `cfg.DHCPLeaseKey(base, unitNum)`

```go
for _, ifName := range ifNames {
    kernel := cfg.ResolveKernelIfName(ifName)
    iface, err := net.InterfaceByName(kernel)
    if err != nil {
        fmt.Fprintf(&b, "Interface: %s, Not present\n\n", ifName)
        continue
    }
    // ... existing MTU/MAC/zone/BPF-counters logic, replacing every
    //     use of ifName as a /sys/class/net/<x>/operstate path with
    //     `kernel`.

    if s.dhcp != nil {
        base := strings.SplitN(ifName, ".", 2)[0]
        unitNum := 0
        if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
            unitNum, _ = strconv.Atoi(parts[1])
        }
        if key, ok := cfg.DHCPLeaseKey(base, unitNum); ok {
            if lease := s.dhcp.LeaseFor(key, dhcp.AFInet); lease != nil {
                fmt.Fprintf(&b, "  DHCPv4: %s (gw %s)\n", lease.Address, lease.Gateway)
            }
            if lease := s.dhcp.LeaseFor(key, dhcp.AFInet6); lease != nil {
                fmt.Fprintf(&b, "  DHCPv6: %s (gw %s)\n", lease.Address, lease.Gateway)
            }
        }
    }
    b.WriteString("\n")
}
```

#### `pkg/api/stats.go:64` and `pkg/api/metrics_counters.go:68`

1-line: `net.InterfaceByName(cfg.ResolveKernelIfName(ifName))`.

### DHCP integration test design

`dhcp.Manager.leases` is unexported. Add a small exported test seam
in a dedicated file **`pkg/dhcp/test_seams.go`** (AGY catch — keeps
production `dhcp.go` clean):

```go
// Package dhcp test-only helpers. Lives in the production package
// so external packages (e.g. pkg/api tests) can use it without
// internal-export tricks. Not for production callers.
package dhcp

// SeedLeaseForTesting installs a lease record for tests.
func (m *Manager) SeedLeaseForTesting(ifaceName string, af AddressFamily, lease *Lease) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.leases == nil {
        m.leases = make(map[clientKey]*Lease)
    }
    m.leases[clientKey{iface: ifaceName, family: af}] = lease
}
```

No build tag — pkg/api tests need it to compile. The "ForTesting"
suffix and dedicated filename make the contract explicit.

### Resolution-order checks (Codex finding #3 — tunnel collisions)

Codex correctly noted that `compiler_interfaces.go:123,202` parses
`tunnel {}` under any interface, so `reth0.50` could theoretically be
a TunnelNameMap key. v3's `ResolveKernelIfName` consults TunnelNameMap
**after** the IRB branch but **before** the unit/VLAN logic, so a
tunnel-mapped ref bypasses the VLAN-tag composition. This is the
right precedence — if a user explicitly configured a tunnel under
`reth0.50`, the tunnel kernel name overrides VLAN composition.
Document this in the helper godoc; add a test:
`TestResolveKernelIfName_TunnelOverridesVlan`.

### Smoke verification (revised v4 — Codex finding #5)

Pre-fix baseline: `fxp0`, `em0`, `fab0`, `lo` are non-slash and
resolvable, so any `length >= K` gate is trivially passed.

**Targeted gates** keyed to the actual `docs/ha-cluster-userspace.conf`
content (REST-only, grpcapi out of scope):

Cluster cfg names that flow through `allInterfaceNames`:
- From `cfg.Interfaces.Interfaces` keys (top-level `interfaces { ... }`):
  `fxp0`, `em0`, `fab0` (node 0)/`fab1` (node 1),
  `ge-0/0/0`, `ge-0/0/1`, `ge-0/0/2`, `reth0`, `reth1`, `gr-0/0/0`.
- From zone `interfaces { ... }` lists: `fxp0`, `em0`, `fab0`, `fab1`,
  `reth0.50`, `reth0.80`, `gr-0/0/0.0`, `reth1`.

Slash-or-virtual rows the fix must populate ifindex>0 for:
`ge-0/0/0`, `ge-0/0/1`, `ge-0/0/2`, `reth0`, `reth0.50`, `reth0.80`,
`reth1`, `gr-0/0/0.0`. (`reth1.0` is NOT in any zone/top-level
iteration — drop from gate.)

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c '
  set -e
  J=$(curl -s http://127.0.0.1:8080/interfaces)
  for n in ge-0/0/0 ge-0/0/1 ge-0/0/2 reth0 reth0.50 reth0.80 reth1 gr-0/0/0.0; do
    ix=$(echo \"$J\" | jq -r --arg n \"$n\" \".data | map(select(.name == \\$n)) | .[0].ifindex // 0\")
    if [ \"$ix\" = \"0\" ]; then
      echo \"FAIL: $n ifindex=0 post-fix\"; exit 1
    fi
    echo \"OK: $n ifindex=$ix\"
  done
'"

# Prometheus exposure: include reth aliases so metrics_counters.go
# is provably exercised.
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c '
  set -e
  M=$(curl -s http://127.0.0.1:8080/metrics)
  for n in ge-0/0/0 ge-0/0/1 ge-0/0/2 reth0 reth0.50 reth0.80 reth1; do
    echo \"$M\" | grep -F \"xpf_iface_packets_total\" | grep -F \"interface=\\\"$n\\\"\" || {
      echo \"FAIL: no Prometheus series for $n\"; exit 1
    }
  done
'"
```

Pre-fix these gates fail for every slash/virtual row. Post-fix they
must pass. `gr-0/0/0.0` exercises the TunnelNameMap branch end-to-end.

CoS per-class smoke runs per protocol.

## Public API preservation (unchanged)

- JSON `name`: Junos.
- Prometheus `interface` label: Junos.
- `ifindex`: now populated (bug fix).
- "Not present" preserved on local-kernel lookup miss.

## Hidden invariants (revised)

1. JSON `name` and Prometheus label stay Junos.
2. DHCP key shape: `LinuxIfName(physRef-as-cfg-key)[. VlanID]`, NOT
   resolved-physical-member.
3. Kernel link name shape: VLAN-tagged subinterface is
   `<base>.<vlan-id>`, NOT `<base>.<unit-number>`.
4. Tunnel resolution overrides VLAN composition.
5. IRB resolves to the bridge device name, with NO suffix.
6. Unit 0 collapses to the base kernel device (no `.0`).
7. Fallback for unknown unit preserves suffix verbatim.
8. Lookup failure non-fatal.
9. `allInterfaceNames` shape unchanged.
10. Helper is pure; no I/O.

## Risk assessment (revised)

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Additive public method; no migration of existing private helpers in this PR. |
| Lifetime / borrow-checker | N/A | Go. |
| Performance regression | NIL | Control plane. Per-call TunnelNameMap + IRBToBridge rebuild — both small; cache out of scope. |
| Architectural mismatch | LOW | Method lives next to existing ResolveReth/ResolveFab/TunnelNameMap. Mirrors snapshotLinuxName which is already battle-tested in userspace dataplane. |
| Helper drift vs existing snapshotLinuxName | MEDIUM | Risk that the new public helper diverges from the private one over time. Mitigation: add explicit cross-reference comments in both functions pointing to the other; file a tracking issue for the migration. |

## Test plan (revised)

`pkg/config/types_test.go`:

1. `TestResolveKernelIfName_Plain` — `em0`, `fxp0`, `lo`, `ge-0/0/0`,
   `ge-0/0/0.80` (vlan-id 180) → `ge-0-0-0.180`.
2. `TestResolveKernelIfName_Reth` — node 0 `reth0`→`ge-0-0-2`,
   `reth0.0` (unit 0 vlan-id 0) → `ge-0-0-2`,
   `reth0.50` (unit 50 vlan-id 50) → `ge-0-0-2.50`,
   `reth0.80` (unit 80 vlan-id 180) → `ge-0-0-2.180`. Repeat node 1.
3. `TestResolveKernelIfName_Fab` — `fab0`→`fab0`, `fab0.0`→`fab0.0`
   (kernel IPVLAN devices, NOT resolved to parent). **Corrected
   in v4** — v3 plan wrongly expected `ge-0-0-7`.
4. `TestResolveKernelIfName_Tunnel` — `gr-0/0/0.0`→`gr-0-0-0`,
   `gr-0/0/0.1`→`gr-0-0-0u1` (per-unit `unit.Tunnel.Name`).
5. `TestResolveKernelIfName_TunnelOverridesVlan` — interface
   `reth0.50` with both `tunnel.Name = "gr-foo"` and `vlan-id 999`:
   tunnel wins, returns `gr-foo`.
6. `TestResolveKernelIfName_IRB` — `irb.0`→`br-bd0`.
7. `TestResolveKernelIfName_UnknownUnit` — ref `ge-0/0/0.99` with
   unit 99 missing from cfg → `ge-0-0-0.99` (fallback preserves
   suffix verbatim).
8. `TestDHCPLeaseKey_Mappings` — covers VlanID=0/positive, unit
   missing, base missing. Crucially: `reth0` keys stay as `reth0`,
   not the resolved physical.

`pkg/dhcp/dhcp.go`:

- Add `SeedLeaseForTesting`.

Add another helper test for interface-level (not per-unit) tunnel
shape (Codex round-3 follow-up):

9. `TestResolveKernelIfName_InterfaceLevelTunnel` — cfg
   `gr-0/0/0 { tunnel { source ...; }; unit 0 {} unit 1 {} }`;
   verify `gr-0/0/0.0`→`gr-0-0-0`, `gr-0/0/0.1`→`gr-0-0-0`
   (interface-level tunnel = unit 0/1 share the base name; matches
   TunnelNameMap construction at types.go:1768).

10. `TestResolveKernelIfName_StXfrm` — `st0.0`→`st0.0`, `st0.5`→
    `st0.5`, `st1`→`st1`. Confirms st* short-circuit.

11. `TestResolveKernelIfName_FabIsKernelDevice` — `fab0`→`fab0`,
    `fab0.0`→`fab0.0` (IPVLAN overlay names are real kernel
    devices; do NOT resolve to parent).

`pkg/api/interfaces_test.go`:

12. `TestInterfacesHandler_ResolvesSlashName` — cfg names
    `lo-0/0/0` as a fake interface that we ALSO add to
    cfg.Interfaces.Interfaces. Then assert: pre-fix-equivalent
    behavior (raw lookup of `lo-0/0/0` fails, ifindex=0) vs
    post-fix behavior (helper translates to `lo-0-0-0` which
    also doesn't exist on the test runner → still ifindex=0).
    Net: the test asserts the row is present with correct
    `name` label whether or not ifindex resolves. **Stronger
    coverage:** cfg.Interfaces.Interfaces with key `whatever`
    where we KNOW the kernel has `lo`: declare the cfg key
    as `lo` literally and verify ifindex matches the loopback
    `net.InterfaceByName("lo").Index`. (Loopback is the only
    interface guaranteed to exist on every Linux test runner.)
13. `TestWriteInterfacesDetail_DHCPLeasePath` — seed a lease keyed
    `reth0.50`, cfg `reth0 { unit 50 { vlan-id 50; dhcp } }`,
    assert output contains `DHCPv4: <addr> (gw <gw>)`. This is the
    end-to-end test of the DHCPLeaseKey + LeaseFor + format path.

5x flake check on the named tests.

## Out of scope (explicitly)

- grpcapi peer fixes (follow-up issue).
- CLI smoke (grpcapi path).
- Migration of `snapshotLinuxName` and `resolveJunosIfName` to
  the new helper (follow-up — keeps this PR contained).
- Caching TunnelNameMap or IRBToBridge on Config.
- Error escalation.

## Open questions for adversarial review

1. Is centralizing as a method on `*Config` correct, or should it
   live in a dedicated `pkg/config/ifname.go` (file already
   ~1900 lines)?
2. Is the `(physRef, unitNum)` shape of `DHCPLeaseKey` better than
   a single `(ref)` argument that the helper parses internally?
3. Is the fallback "preserve suffix verbatim" in `ResolveKernelIfName`
   the right behavior, or should it return `(name, false)` with the
   caller deciding?
4. Should the helper compose `IRBToBridge` even for bare `irb`
   refs (no unit)? Currently bare `irb` falls through to
   `LinuxIfName("irb")` = `"irb"`. Junos may not allow bare
   `irb` without a unit; verify or accept current.
5. Is the `SeedLeaseForTesting` exported method acceptable, or
   should it be in a `_test_helpers.go` build-tagged file?
6. Is the explicit decision to NOT migrate `snapshotLinuxName` /
   `resolveJunosIfName` defensible, or should v3 fold them in?
7. Tunnel-overrides-VLAN precedence: is this the Junos semantic?
   Could a user configure both and expect VLAN? (My read: tunnel
   creates a kernel device, VLAN-tagging is mutually exclusive
   with tunnel-mode at the unit level; verify against
   `compiler_interfaces.go:123-211`.)

## Procedure

1. Add `(*Config).ResolveKernelIfName` and `(*Config).DHCPLeaseKey`
   in `pkg/config/types.go` (add `"fmt"` import).
2. Add `(*Manager).SeedLeaseForTesting` in
   `pkg/dhcp/test_seams.go` (new file).
3. Add `// NOTE: Keep in sync with (*Config).ResolveKernelIfName`
   to legacy `snapshotLinuxName` and `daemon/resolveJunosIfName`.
4. Add 11 helper unit tests in `pkg/config/types_test.go`.
5. Rewrite the 4 pkg/api sites.
6. Add 2 handler tests in `pkg/api/interfaces_test.go`.
7. Smoke per protocol with v4 named-row gates.
8. PR with `Closes #1565`.
