# #1565 — pkg/api: translate Junos config names to Linux ifnames before net.InterfaceByName

**Status:** DRAFT v2 — addressing Codex + AGY round-1 PLAN-NEEDS-MAJOR

## Round-1 verdicts (round-1 archived)

- **Codex** task-mpnhxusx-4yz6hb: PLAN-NEEDS-MAJOR. Findings:
  - Tunnel refs (`gr-0/0/0.0`, `gr-0/0/0.1`) are handled by
    `(*Config).TunnelNameMap()` and do NOT round-trip through a naive
    `LinuxIfName(ResolveReth(name))` composition. Unit 0 → base name,
    unit N>0 → `<base>uN`.
  - DHCP key claim was overbroad: keys are
    `LinuxIfName(physName) + "." + strconv(unit.VlanID)` only when
    `VlanID>0`, otherwise just `LinuxIfName(physName)`. The suffix in
    the zone ref (`.80`, `.0`) does **not** necessarily equal the
    VLAN tag. So `LeaseFor(kernelIfName(ifName))` only works when the
    config name happens to end in the VLAN tag; for `ge-0/0/0.0` with
    `vlan-id 80`, the lookup misses.
  - grpcapi out-of-scope is defensible **only if** the plan stops
    claiming any CLI smoke fix; CLI `show interfaces` routes through
    grpcapi `ShowInterfaces`/`ShowInterfacesDetail`/`ShowText`.
  - Tests are too thin for tunnel + VLAN-vs-unit-suffix cases.
- **AGY** review-mpnhya9y-6rigyy: PLAN-NEEDS-MAJOR. Findings:
  - Fold grpcapi sites in OR drop CLI smoke (same point as Codex).
  - Centralize helper as `(*Config).ResolveJunosIfName(name)` in
    `pkg/config/types.go` so `pkg/api` and `pkg/grpcapi` share it.
  - Chain `ResolveFab` to cover `fab0[.unit]`.
  - Add a `writeInterfacesDetail` integration test that mocks DHCP
    manager + asserts the lease line is printed.

Round-1 verdicts and reviewer prompts are pinned at commit
`e91b9650` (plan v1).

## Issue framing (unchanged from v1)

Pre-existing bug surfaced by Copilot inline review on PR #1564.
Four call sites in `pkg/api/` call `net.InterfaceByName(ifName)`
directly with config-level Junos interface names (`ge-0/0/0`,
`reth0.50`, `fab0`, `gr-0/0/0.0`). These names violate Linux
IFNAMSIZ (`/` is forbidden) or have no kernel ifindex
(`reth`/`fab` are virtual config-only names). The lookups fail
silently and break:

1. Per-interface counters and `Ifindex` in the REST `interfaces`
   view.
2. `show interfaces` detail output (prints "Not present").
3. `/iface-stats` typed JSON (rows silently dropped).
4. Per-interface Prometheus metrics
   (`xpf_iface_packets_total{interface="..."}` missing).

Four sites verbatim from the issue body:

- `pkg/api/interfaces.go:32` — `interfacesHandler`
- `pkg/api/interfaces.go:210` — `writeInterfacesDetail`
- `pkg/api/stats.go:64` — `ifaceStatsHandler`
- `pkg/api/metrics_counters.go:68` — `collectInterfaceCounters`

The three sites at `pkg/api/interfaces.go:107`, `:130`, `:163`
inside `writeInterfacesTerse` are already correct — they call
`config.LinuxIfName` on the physical-member name resolved
through `RethToPhysical()`. Verified by read.

## Honest scope / value framing

Control-plane observability bug fix. No hot path, no allocator,
no HA sync, no dataplane correctness. Win is qualitative: REST
clients and Prometheus scrapers see real counters; JSON
`ifindex` is populated.

If reviewers conclude the work isn't worth the churn, PLAN-KILL
is acceptable. (The bug is real and operator-visible; PLAN-KILL
seems wrong but the explicit hook stays.)

## What's already shipped / partially fixed

- `pkg/api/interfaces.go::writeInterfacesTerse` (lines 100-188):
  already uses `physToReth`, `rethToPhys`, and `config.LinuxIfName`.
  Correct.
- `pkg/grpcapi/server_show_interfaces.go` uses `config.LinuxIfName`
  in lines 502, 547, 586, 623-632 — but not at the top-level
  `GetInterfaces` (line 31) and `ShowInterfacesDetail` physical
  lookup (line 129). Out of scope for this PR per issue body;
  filing a follow-up issue is required (see Out of scope).
- `pkg/daemon/daemon_dhcp.go:56-95` builds DHCP keys as
  `LinuxIfName(physName)` plus `"." + strconv.Itoa(unit.VlanID)`
  when `unit.VlanID > 0`. **This is the canonical key form.**
- `(*Config).TunnelNameMap()` at `pkg/config/types.go:1763` maps
  `gr-0/0/0.0` → `gr-0-0-0` and `gr-0/0/0.1` → `gr-0-0-0u1`.
- `(*Config).ResolveReth(ref)` + `(*Config).ResolveFab(ref)` at
  `types.go:80,95` resolve aliases (and preserve `.unit` suffix).

## Concrete design (revised)

### Single new public helper in `pkg/config/types.go`

```go
// ResolveJunosIfName converts a Junos-style config interface reference
// (e.g. "ge-0/0/0.80", "reth0.50", "fab0.0", "gr-0/0/0.1") to the
// Linux kernel ifname it should resolve to on the LOCAL node.
//
// Resolution order:
//   1. Tunnel refs: if the ref is a key in TunnelNameMap(), return
//      the tunnel's Linux name verbatim (covers "gr-0/0/0.0" → "gr-0-0-0"
//      and "gr-0/0/0.1" → "gr-0-0-0u1"). Tunnel naming is per-unit and
//      does NOT preserve the "." suffix, so this branch must short-circuit
//      before LinuxIfName.
//   2. RETH refs: ResolveReth(ref) maps "reth0[.unit]" → physical
//      member "ge-X/0/Y[.unit]" using local-node scoring.
//   3. Fabric refs: ResolveFab(ref) maps "fab0[.unit]" → the local
//      fabric member from cfg.Interfaces.Interfaces[base].LocalFabricMember.
//   4. LinuxIfName: replace "/" with "-".
//
// For all other refs (em0, fxp0, ge-0/0/0, ge-0/0/0.80) this reduces
// to LinuxIfName(ref).
//
// Note: this returns the kernel link name. For DHCP lease lookups,
// callers must instead build LinuxIfName(physName) + "." + VlanID,
// which is the daemon's DHCP key form; that is NOT the same as the
// link name. See DHCPLeaseKey below.
func (c *Config) ResolveJunosIfName(ref string) string {
    if tunMap := c.TunnelNameMap(); tunMap != nil {
        if linuxName, ok := tunMap[ref]; ok {
            return linuxName
        }
    }
    resolved := c.ResolveReth(ref)
    resolved = c.ResolveFab(resolved)
    return LinuxIfName(resolved)
}

// DHCPLeaseKey returns the lease-lookup key that the DHCP manager
// keys leases by for the given config interface name and unit number.
// Mirrors the construction in pkg/daemon/daemon_dhcp.go: the key is
// LinuxIfName(physName) plus ".<VlanID>" only when the unit's
// VlanID > 0. Returns ("", false) when the config ref cannot be
// resolved to a unit (caller should skip the lease line).
func (c *Config) DHCPLeaseKey(ifName string, unitNum int) (string, bool) {
    physRef := strings.SplitN(ifName, ".", 2)[0]
    ifc, ok := c.Interfaces.Interfaces[physRef]
    if !ok {
        return "", false
    }
    unit, ok := ifc.Units[unitNum]
    if !ok {
        return "", false
    }
    key := LinuxIfName(physRef)
    if unit.VlanID > 0 {
        key = key + "." + strconv.Itoa(unit.VlanID)
    }
    return key, true
}
```

These two helpers exactly mirror the two distinct semantics that
`pkg/daemon/daemon_dhcp.go:56-95` exposed:

- the **kernel link name** for `net.InterfaceByName` / sysfs;
- the **DHCP lease key** for `dhcp.Manager.LeaseFor`.

Conflating them was the round-1 plan's mistake.

### Call-site rewrites

The four pkg/api sites all need the kernel link name. They use the
ref iterated from `allInterfaceNames(cfg)` (which contains raw cfg
keys + raw zone refs).

#### `pkg/api/interfaces.go:32` `interfacesHandler`

```go
for ifName := range allInterfaceNames(cfg) {
    iface, err := net.InterfaceByName(cfg.ResolveJunosIfName(ifName))
    is := InterfaceStats{
        Name: ifName,                    // Junos label, unchanged
        Zone: ifZone[ifName],
    }
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

Two distinct translations needed:

- **kernel link name** for `net.InterfaceByName` AND
  `/sys/class/net/<name>/operstate`.
- **DHCP lease key** for `s.dhcp.LeaseFor(...)`.

The current code uses `ifName` (the Junos ref) for both. The
revised code computes:

```go
for _, ifName := range ifNames {
    kernel := cfg.ResolveJunosIfName(ifName)
    iface, err := net.InterfaceByName(kernel)
    if err != nil {
        fmt.Fprintf(&b, "Interface: %s, Not present\n\n", ifName)
        continue
    }
    // ... print MTU/MAC/zone/BPF-counters as before, using `kernel`
    //     for the /sys/class/net read.

    // DHCP lease annotation — use the daemon's DHCP key shape.
    if s.dhcp != nil {
        base := strings.SplitN(ifName, ".", 2)[0]
        unitNum := 0
        if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
            fmt.Sscanf(parts[1], "%d", &unitNum)
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

This is the only site that needs the DHCP key shape. The other
three pkg/api sites only need the kernel link name.

#### `pkg/api/stats.go:64` and `pkg/api/metrics_counters.go:68`

Identical 1-line translation: replace `net.InterfaceByName(ifName)`
with `net.InterfaceByName(cfg.ResolveJunosIfName(ifName))`.

### Resolution-order rationale

Tunnel-first matters because `gr-0/0/0.1` is a key in TunnelNameMap
but `.1` is the unit number (not a VLAN tag), and the Linux ifname
is `gr-0-0-0u1` — neither LinuxIfName nor ResolveReth/ResolveFab
would produce that. Putting tunnel resolution after the others
would yield `gr-0-0-0.1`, which doesn't exist on the kernel.

RETH-then-Fab order matters because:
- ResolveReth on a non-reth ref is identity.
- ResolveFab on the (post-reth) ref is identity for non-fab refs.

LinuxIfName at the end is the catch-all `/` → `-` replacement.

### Error-handling semantics (unchanged)

- listing-style handlers (`interfacesHandler`, `writeInterfacesDetail`):
  include the row with ifindex=0 / "Not present", same as today.
- stats/metrics handlers (`ifaceStatsHandler`, `collectInterfaceCounters`):
  silently skip on lookup failure, same as today.
- No 500s. Admin-down or peer-only refs are normal.

### Tests (revised — 6 unit tests + 1 integration)

`pkg/config/types_test.go` (helper unit tests):

1. **`TestResolveJunosIfName_Plain`** — `em0`→`em0`, `fxp0`→`fxp0`,
   `ge-0/0/0`→`ge-0-0-0`, `ge-0/0/0.80`→`ge-0-0-0.80`.
2. **`TestResolveJunosIfName_Reth`** — given a cfg with
   `reth0` and physical member `ge-0/0/2` on node 0,
   `reth0`→`ge-0-0-2`, `reth0.50`→`ge-0-0-2.50`. Repeat for node 1
   with `ge-7/0/2`.
3. **`TestResolveJunosIfName_Fab`** — given a cfg with `fab0` whose
   `LocalFabricMember="ge-0/0/0"`, `fab0`→`ge-0-0-0`,
   `fab0.0`→`ge-0-0-0.0`.
4. **`TestResolveJunosIfName_Tunnel`** — given a cfg with
   interface-level tunnel on `gr-0/0/0` and units 0+1,
   `gr-0/0/0.0`→`gr-0-0-0`, `gr-0/0/0.1`→`gr-0-0-0u1` (per-unit
   tunnel with `unit.Tunnel.Name` set yields that name).
5. **`TestDHCPLeaseKey_Mappings`** — cfg with `ge-0/0/0` unit 0
   `vlan-id 0`, unit 1 `vlan-id 80`: `DHCPLeaseKey("ge-0/0/0", 0)` →
   `("ge-0-0-0", true)`. `DHCPLeaseKey("ge-0/0/0", 1)` →
   `("ge-0-0-0.80", true)`. `DHCPLeaseKey("ge-0/0/0", 99)` →
   `("", false)`. Also exercises `reth0` cfg.

`pkg/api/interfaces_test.go` (handler integration):

6. **`TestInterfacesHandler_PopulatesIfindexForLoopback`** —
   stand up a Server with cfg name `lo`; assert Ifindex > 0.
7. **`TestWriteInterfacesDetail_DHCPLeasePath`** — stand up a
   Server with a `dhcp.Manager` pre-populated with a lease
   keyed `ge-0-0-0` (no VLAN); call `writeInterfacesDetail` for
   cfg containing `ge-0/0/0`; assert output contains
   `DHCPv4: <addr> (gw <gw>)`. This protects the DHCP lookup
   path regression that prompted finding #2.

`dhcp.Manager` is concrete: a test helper builds a `*Manager`
with the lease pre-installed via the lowest-friction path
(exported `New(...)` + a `setLeaseForTest` test-only setter
or, if available, an existing constructor that accepts seeded
leases). Implementation step will pick the minimum-touch route.

### Smoke verification

Standard cluster smoke (loss userspace cluster) per protocol.

**REST-only smoke targets** (no CLI claim — grpcapi is out of scope):

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c '
  curl -s http://127.0.0.1:8080/interfaces | \
    jq -e \"map(select(.ifindex > 0)) | length >= 3\"
'"
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c '
  curl -s http://127.0.0.1:8080/metrics | grep -E \"xpf_iface_packets_total.*ge-0/0/\"
'" | head -3
```

The cluster cfg names: `ge-0/0/0` (fabric IPVLAN parent), `reth0`,
`reth0.50`, `reth0.80`, `reth1`, `reth1.0`, etc. Length ≥ 3
guarantees at least the slash-named base + reth aliases populate.

Pre-fix all slash-named rows have ifindex=0; post-fix
`ge-0/0/0`, `reth0`, etc. have ifindex>0 (modulo peer-only
members).

CoS per-class smoke runs per protocol.

## Public API preservation

- JSON `name` field: Junos config name (unchanged).
- Prometheus `interface` label: Junos config name (unchanged —
  operators query by Junos name).
- `ifindex` field: was 0 for slash names, now populated. This is
  the bug fix, not a regression.
- `/iface-stats` rows: previously silently dropped slash-named
  rows now appear. Same — bug fix.
- "Not present" text in detail view: preserved for kernel-side
  lookup failures (peer-only RETH member).

## Hidden invariants the change must preserve

1. JSON `name` and Prometheus label remain the Junos config name.
2. DHCP lease key shape exactly matches `daemon_dhcp.go`:
   `LinuxIfName(physName)[. VlanID-when-positive]`.
3. Tunnel resolution short-circuits before LinuxIfName.
4. RETH and Fabric resolution can compose without aliasing.
5. Lookup failure stays non-fatal (no 500).
6. `allInterfaceNames` output and shape unchanged.
7. The helper is pure; no I/O, no kernel calls.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure additive translation; non-slash, non-RETH, non-fab, non-tunnel refs are identity. Tunnel resolution is short-circuit-by-map. |
| Lifetime / borrow-checker | N/A | Go. |
| Performance regression | NIL | Control plane only. TunnelNameMap allocates a small map each call — same cost as existing callers; cache out of scope. |
| Architectural mismatch | LOW | Plan v2 centralizes the helper at pkg/config — the natural seam grpcapi already imports. |

## Test plan

- [ ] `go vet ./...` clean
- [ ] new `TestResolveJunosIfName_*` (4 tests) pass, 5x flake check
- [ ] new `TestDHCPLeaseKey_Mappings` passes, 5x flake check
- [ ] new `TestInterfacesHandler_PopulatesIfindexForLoopback` passes
- [ ] new `TestWriteInterfacesDetail_DHCPLeasePath` passes
- [ ] `go test ./pkg/api/... ./pkg/config/... ./pkg/grpcapi/... ./pkg/dhcp/...`
- [ ] full Go suite passes
- [ ] cluster deploy on loss userspace cluster
- [ ] Pass A — CoS disabled v4/v6 × push/reverse + 12-stream reverse, 0 retrans
- [ ] Pass B — Per-class CoS 5201-5206 × v4/v6 × push/reverse
- [ ] REST `curl /interfaces | jq` returns ifindex>0 for ge-0/0/0 and reths
- [ ] REST `curl /metrics | grep xpf_iface_packets_total | grep ge-0/0/` returns lines

## Out of scope (explicitly)

- **grpcapi peer fixes** at `pkg/grpcapi/server_show_interfaces.go:31`
  and `:129`. Same bug class, same helper would apply once shipped.
  File a follow-up issue (and a one-paragraph note in this PR body).
- **CLI smoke** for `show interfaces detail`. The grpcapi path is
  out of scope; the CLI smoke claim was a v1 mistake.
- **DHCP key centralization beyond `DHCPLeaseKey`**. Daemon callers
  still construct the key inline. Follow-up.
- **Caching TunnelNameMap on Config**. Out of scope.
- **Error-handling escalation**. No 500s, no log spam.

## Open questions for adversarial review

1. Is `DHCPLeaseKey(physRef, unitNum)` the right helper shape, or
   should the helper take the full Junos ref and parse internally?
2. Should `ResolveJunosIfName` short-circuit on `lo`, `lo0`, `fxp0`,
   `em0`? Currently no — identity through LinuxIfName works.
3. Tunnel resolution: should a bare `gr-0/0/0` (no unit) go through
   TunnelNameMap? Map keys are `<name>.<unit>`, so bare falls
   through to LinuxIfName → `gr-0-0-0`. Confirm this matches the
   kernel link name (compiler creates `gr-0-0-0`, no suffix).
4. Are there other ref shapes I'm missing? `st0.0` (xfrm),
   `lo0.0`, `mt-`, `xe-`? `xe-` is LinuxIfName territory.
   `st0` is xfrm; kernel device is `st0` directly. `lo0` has its
   own quirks in Junos (loopback). Verify identity is correct.
5. Should `writeInterfacesDetail` also print a `(kernel: ge-0-0-0)`
   annotation for ops debugging? Out of scope but flagging.
6. `*Config` method vs free function for `ResolveJunosIfName`?
   Method matches ResolveReth/ResolveFab/TunnelNameMap convention.
7. Should `interfacesHandler` skip rows for non-resolvable refs
   (peer-only RETH members)? Today it lists them with ifindex=0.
   Changing would be a JSON shape regression — keep.

## Procedure

1. Add `(*Config).ResolveJunosIfName` and `(*Config).DHCPLeaseKey`
   in `pkg/config/types.go`.
2. Add 4 + 1 helper unit tests in `pkg/config/types_test.go`.
3. Rewrite the 4 pkg/api sites.
4. Add 2 handler tests in `pkg/api/interfaces_test.go` (or new
   `pkg/api/iface_name_test.go`).
5. Smoke per protocol.
6. PR with `Closes #1565` body. Body includes a "Follow-up" note
   pointing at the grpcapi peer.
