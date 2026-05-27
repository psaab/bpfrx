# #1565 — pkg/api: translate Junos config names to Linux ifnames before net.InterfaceByName

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

Pre-existing bug surfaced by Copilot inline review on PR #1564 (the
`#1540` REST API split). Four call sites in `pkg/api/` call
`net.InterfaceByName(ifName)` directly with config-level interface
names that may contain `/` (e.g. `ge-0/0/0`, `ge-0/0/0.80`) or be
RETH aliases (`reth0`, `reth0.50`). Linux IFNAMSIZ forbids `/`, and
RETH virtual names have no kernel ifindex, so these lookups fail
silently and:

1. Per-interface counters (`Ifindex`, RX/TX packets/bytes) come back
   as zero in the REST `interfaces` view.
2. `show interfaces` detail prints "Not present" for every
   Junos-named interface, then skips MTU/MAC/addresses/DHCP lease.
3. `/iface-stats` skips configured interfaces entirely (silent drop
   from result set, not just zero counters).
4. Per-interface Prometheus metrics (`xpf_iface_packets_total`,
   `xpf_iface_bytes_total`) are simply not emitted for affected
   interfaces — they appear missing from `/metrics` output.

The four sites are listed verbatim in the issue body:

- `pkg/api/interfaces.go:38` — `interfacesHandler` (JSON list)
- `pkg/api/interfaces.go:224` — `writeInterfacesDetail` (text view)
- `pkg/api/stats.go:70` — `ifaceStatsHandler` (typed JSON)
- `pkg/api/metrics_counters.go:74` — Prometheus collector

The repo already ships the primitive: `config.LinuxIfName(name)`
replaces `/` with `-`, and `cfg.ResolveReth(name)` resolves
`reth0[.unit]` to the local physical member. Both are battle-tested
in `pkg/config/compiler_interfaces.go`, `pkg/grpcapi/server_show_interfaces.go`,
`pkg/grpcapi/server_cluster.go`, and the daemon's networkd path.

## Honest scope / value framing

Bug fix on a control-plane observability surface. No hot-path
cycles. No allocator pressure. No HA sync. No correctness risk
to the dataplane. Win is qualitative: REST clients and Prometheus
scrapers see real interface counters and the JSON Ifindex field is
populated for every configured interface, not just for those whose
Junos name happens to also be a valid Linux ifname (i.e. no `/`,
not a reth alias).

If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict. (The "perf gain" here
is observability fidelity, not throughput — PLAN-KILL would
amount to "leave the broken handlers broken", which seems wrong
for a fix tagged on a Copilot reviewer finding.)

## What's already shipped / partially fixed

The grpcapi peer of these handlers (`pkg/grpcapi/server_show_interfaces.go`)
already uses `config.LinuxIfName(...)` and `cfg.ResolveReth(...)` in
several places — see:

- `pkg/grpcapi/server_show_interfaces.go:502` — `kernelIf := config.LinuxIfName(statusIf)`
- `pkg/grpcapi/server_show_interfaces.go:547` — `kernelIf := config.LinuxIfName(u.physName)`
- `pkg/grpcapi/server_show_interfaces.go:623-632` — VLAN-suffix composition
- `pkg/grpcapi/server_cluster.go:45` — `linuxName := config.LinuxIfName(phys)`
- `pkg/grpcapi/server_diag.go:312` — RETH/LinuxIfName composition
- `pkg/grpcapi/server_sessions.go:325` — `cfg.ResolveReth(...)` + LinuxIfName

`pkg/api/interfaces.go` is partially fixed: the `writeInterfacesTerse`
function (lines 105-180) **already** uses `config.LinuxIfName` and
`RethToPhysical()`. Only the non-terse `interfacesHandler` and
`writeInterfacesDetail` halves regressed.

The DHCP manager `LeaseFor()` keys by Linux name with VLAN suffix
(`pkg/daemon/daemon_dhcp.go:56-95` builds `dhcpIface = LinuxIfName(ifName)` +
optional `.VLAN`), so `LeaseFor(ifName, ...)` in `writeInterfacesDetail`
also returns nil for any name with `/`. Same root cause.

## Concrete design

### Sites and fixes

| File | Line | Current | Fix |
|------|------|---------|-----|
| `pkg/api/interfaces.go` | 32 | `iface, err := net.InterfaceByName(ifName)` | Compose `lookupName` via `config.LinuxIfName(cfg.ResolveReth(ifName))` (with VLAN-suffix preservation), then `net.InterfaceByName(lookupName)`. Print original `ifName` in JSON. |
| `pkg/api/interfaces.go` | 210 | `iface, err := net.InterfaceByName(ifName)` | Same as above; also replace inline `/sys/class/net/`+`ifName` reads (line 220) with the resolved kernel name. DHCP lookup uses the LinuxIfName+VLAN form to match daemon's `dhcpIface` key. |
| `pkg/api/stats.go` | 64 | `iface, err := net.InterfaceByName(ifName)` | Same translation. |
| `pkg/api/metrics_counters.go` | 68 | `iface, err := net.InterfaceByName(ifName)` | Same translation. |

### Helper

Introduce one private helper in `pkg/api/api.go` next to
`allInterfaceNames`:

```go
// kernelIfName returns the Linux kernel ifname for a config-level
// interface name. It resolves reth aliases to the local physical
// member (preserving any .unit suffix) then translates "/" to "-"
// to satisfy IFNAMSIZ. The returned name is suitable for
// net.InterfaceByName, /sys/class/net, and DHCP lease lookups (the
// daemon DHCP client keys by this same form).
func kernelIfName(cfg *config.Config, ifName string) string {
    return config.LinuxIfName(cfg.ResolveReth(ifName))
}
```

`ResolveReth` already preserves `.unit`, so a config name like
`reth0.50` round-trips to e.g. `ge-0-0-2.50` on node-0 of the loss
cluster. For non-reth names with VLAN units the input is already
in `ge-0/0/0.80` form, which becomes `ge-0-0-0.80`.

### Site rewrites

`interfacesHandler` (line 32):

```go
for ifName := range allInterfaceNames(cfg) {
    iface, err := net.InterfaceByName(kernelIfName(cfg, ifName))
    is := InterfaceStats{
        Name: ifName,                // unchanged — Junos label
        Zone: ifZone[ifName],
    }
    if err == nil {
        is.Ifindex = iface.Index
        // counters as before
    }
    result = append(result, is)
}
```

`writeInterfacesDetail` (line 210): same translation. Crucially,
replace **all** subsequent uses of `ifName` as a kernel path —
specifically the `/sys/class/net/<ifName>/operstate` read on
line 220, and the DHCP `LeaseFor(ifName, ...)` calls on lines
253 and 256.

The DHCP key form is `dhcpIface` from `daemon_dhcp.go` line 59:
`config.LinuxIfName(ifName)` plus `".%d"` when `unit.VlanID > 0`.
So for a config name like `ge-0/0/0` with unit 0 vlan 80, the
DHCP key is `ge-0-0-0.80`. The detail handler iterates
`allInterfaceNames` which already returns the dotted form (e.g.
`ge-0/0/0.80`) from zone references, so passing
`kernelIfName(cfg, ifName)` is sufficient.

`ifaceStatsHandler` (line 64) and `collectInterfaceCounters` (line
68): identical translation. Both still `continue` on lookup
failure (preserving current "skip unknown" semantics) — see the
error-handling decision below.

### Error-handling semantics

Three plausible behaviors when `net.InterfaceByName` fails:

| Mode | interfacesHandler | writeInterfacesDetail | ifaceStatsHandler | metrics_counters |
|------|--------------------|-----------------------|--------------------|------------------|
| current | include with zero ifindex | print "Not present" | skip | skip |
| log+skip | same + slog.Debug | same + slog.Debug | same + slog.Debug | same + slog.Debug |
| 500 the handler | no | no | no | no |

**Decision:** keep current per-site semantics (each handler already
made a deliberate choice — listing-style endpoints include the row
with zero counters, stats endpoints drop unknown rows, Prometheus
skips the metric). Add `slog.Debug` for visibility but never escalate
to `slog.Info` or to a 500 — admin-down or not-yet-renamed interfaces
are a normal transient on boot and on RETH member flips.

This matches the grpcapi peer's behavior at
`server_show_interfaces.go:31-46` (`err == nil` guards counters,
ifindex stays unpopulated). No 500.

### Tests

Add a single new test file `pkg/api/iface_name_test.go`. Three tests:

1. **`TestKernelIfName_TranslatesSlash`** — config name `ge-0/0/0`
   produces `ge-0-0-0`; with unit/VLAN `.80` produces `ge-0-0-0.80`.
   No live netlink — pure config helper test.

2. **`TestKernelIfName_ResolvesReth`** — given a cfg with
   `interfaces { ge-0/0/0 { redundant-parent reth0 }; reth0; }`
   on node 0, `kernelIfName(cfg, "reth0")` returns `ge-0-0-0`
   and `kernelIfName(cfg, "reth0.50")` returns `ge-0-0-0.50`.

3. **`TestInterfacesHandler_PopulatesIfindexForLoopback`** —
   spin up a Server with a cfg that names `lo` (a real Linux
   ifname), call `interfacesHandler`, assert Ifindex > 0. Then
   spin up a second Server with cfg-level name `ge-0/0/0` and
   assert the JSON row is present with Ifindex == 0 (handler
   doesn't 500, doesn't omit, and exercises the translation
   code path even when the resolved name isn't present on the
   test runner).

The third test exists to prove the **handler does not regress**
on the no-such-interface path — not to assert positive ifindex
for a name that won't be present in CI. Positive ifindex
verification on real Junos names is the smoke step.

### Smoke verification

Standard cluster smoke (loss userspace cluster). Plus one
control-plane check that is targeted at this bug:

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c '
  curl -s http://127.0.0.1:8080/interfaces | \
    jq -e \"map(select(.ifindex > 0)) | length >= 4\"
'"
```

The cluster cfg names interfaces with `/` (`ge-0/0/0`, `reth0`,
`reth0.50`, `reth0.80`), so `length >= 4` is a meaningful gate.
Pre-fix, the JSON has every row but only `lo`-style rows (none
in the cfg) would have ifindex > 0; post-fix all configured
rows have ifindex > 0.

Per-class CoS smoke is not affected by this change but still
runs to satisfy refactor protocol.

## Public API preservation

- `interfacesHandler` JSON shape: unchanged. `name`, `ifindex`,
  `zone`, counters — same fields, just correctly populated.
- `writeInterfacesDetail` text output: unchanged for any interface
  whose Junos name was already a valid Linux ifname (`em0`, `fxp0`,
  `lo`). For names with `/` or RETH aliases, "Not present" is
  replaced with the populated form — fixing the symptom.
- `ifaceStatsHandler`: same JSON shape; rows that were previously
  silently dropped now appear.
- Prometheus metrics: `xpf_iface_packets_total{interface="ge-0/0/0",direction="rx"}`
  is now emitted (was missing). Label is the **Junos** name (the
  ifName from cfg loop). This matches existing label usage —
  operators query by Junos name.

## Hidden invariants the change must preserve

1. **JSON `name` label stays as the Junos config name.** Operators
   query by `ge-0/0/0`, not `ge-0-0-0`. The kernel form is an
   implementation detail used only for kernel-side lookups.
2. **Prometheus label stays as Junos name.** Same reason. Changing
   the label would break dashboards.
3. **DHCP lease key form.** The daemon writes lease keys as
   `LinuxIfName(ifName)[.VLAN]` (verified at
   `pkg/daemon/daemon_dhcp.go:56-95`). The API lookup must use
   the same form. `ResolveReth` is a no-op for non-RETH names
   so it doesn't disturb the DHCP key on, say, `ge-0/0/0.80`.
4. **No mutation of `allInterfaceNames` output.** That function
   is shared with the terse handler; mutating its semantics would
   ripple. The fix is confined to the per-iteration translation.
5. **No new allocations on hot paths.** This is control plane —
   irrelevant — but worth stating for the reviewer who checks.
6. **Lookup failure must remain non-fatal** (no 500). Operators
   bring interfaces up/down; transient absence is normal.
7. **Behavior on names that happen to contain `/` but aren't reth
   aliases** must still go through `LinuxIfName`. `ResolveReth`
   returns input unchanged when no RETH match; then `LinuxIfName`
   replaces `/` with `-`. Composition order matters and is
   documented in the helper.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Pure additive translation. Non-`/`, non-RETH names (e.g. `em0`, `fxp0`, `lo`) are unchanged by `LinuxIfName(ResolveReth(name))` — both helpers are identity for such names. |
| Lifetime / borrow-checker | N/A | Go, no borrow checker. No new shared state. |
| Performance regression | NIL | Control-plane code path. `LinuxIfName` is `strings.ReplaceAll`; `ResolveReth` builds a small map from `c.Interfaces.Interfaces` — already called by grpcapi peers many times per request. |
| Architectural mismatch (#961/#946-Phase-2) | NIL | This is a 1-line-per-site bug fix using a pre-existing helper. No new abstraction. |

## Test plan

- [ ] `go vet ./...` clean
- [ ] `go test ./pkg/api/... ./pkg/config/... ./pkg/grpcapi/...` pass
- [ ] new `TestKernelIfName_*` pass (5x flake check)
- [ ] full Go test suite: 30 packages pass
- [ ] cluster deploy on loss userspace cluster
- [ ] Pass A — CoS disabled — v4 + v6 × push + reverse + 12-stream reverse, 0 retrans
- [ ] Pass B — Per-class CoS — 5201-5206 × v4/v6 × push/reverse
- [ ] **Targeted check:** `curl /interfaces | jq` returns rows with
      `ifindex > 0` for `ge-0/0/0`, `reth0`, `reth0.50`, `reth0.80`
- [ ] **Targeted check:** `curl /metrics | grep xpf_iface_packets_total | grep 'ge-0/0/0'` returns lines (pre-fix: empty)
- [ ] **Targeted check:** `cli> show interfaces detail ge-0/0/0`
      does not print "Not present"

## Out of scope (explicitly)

- **grpcapi peer fixes.** The peer file `pkg/grpcapi/server_show_interfaces.go`
  has a similar bug on lines 31-46 (the `ShowInterfaces` RPC), which
  feeds the CLI `show interfaces` listing. The issue body lists only
  the four `pkg/api/` sites. Fixing grpcapi belongs to a separate
  issue — same translation pattern but different test surface (gRPC
  vs HTTP). If the reviewers want it folded in, the diff is small
  enough; opening the door but defaulting to scoped.
- **DHCP key normalization.** Could push the `LinuxIfName` translation
  inside `LeaseFor` so callers never have to think about it. Out of
  scope — the daemon already writes keys consistently and other
  callers (grpcapi) already translate at the call site. Centralizing
  is a refactor, not a fix.
- **Stats endpoint semantics change.** Whether `/iface-stats` should
  include zero-counter rows for unrenamed interfaces vs. dropping
  them silently is a UX call. Keep current (drop) — different change.
- **Error-handling escalation.** No 500s, no log-spam. Same as now.

## Open questions for adversarial review

1. **Is `ResolveReth` correct for the cluster-peer case?** On node 0
   `reth0` resolves to (e.g.) `ge-0/0/2`; on node 1 the same reth
   resolves to `ge-7/0/2`. The peer node's physical member has no
   kernel ifindex on this node. `kernelIfName(cfg, "reth0")` will
   return e.g. `ge-7-0-2` on node 0 — which won't exist locally —
   and the lookup will fail. Is "fail with ifindex=0" the right
   behavior? (My answer: yes, same as today, but flag for review.)
2. **VLAN suffix handling for non-RETH:** does
   `LinuxIfName("ge-0/0/0.80")` actually produce `ge-0-0-0.80`?
   (Quick check: yes — `ReplaceAll` only touches `/`, not `.`.)
3. **Test coverage for `writeInterfacesDetail` DHCP lease path.**
   Worth a Server-level integration test that runs a real DHCP
   manager with a pre-installed lease and asserts the detail
   output contains the lease? Or is the unit test of the helper
   sufficient given the daemon's keying contract?
4. **Should the fix also handle `fab0`/`fab1` overlay names?**
   `ResolveFab` exists. Same bug class. The issue body doesn't
   mention fabric — but operators may put fab names in
   `interfaces { }`. Worth resolving in this PR or deferring?
5. **Why not a centralized helper that returns ifindex directly?**
   E.g. `cfg.IfindexFor(ifName) (int, bool)`. Cleaner caller code,
   but adds API to `config` package. Asking reviewers whether the
   indirection is worth it for 4 sites.
6. **Should `interfacesHandler` skip the row when the kernel lookup
   fails on a config name that doesn't exist locally** (e.g. peer's
   RETH member) instead of returning ifindex=0? Today it includes.
   Changing this is a JSON-shape regression I'd rather not gamble
   on without operator input.
7. **Are there other `pkg/api/` sites that should fold in?**
   Quick grep: zone counters key by zoneName not ifName; policy
   counters key by zone-pair; filter counters key by filter name.
   No other `InterfaceByName` callers in `pkg/api/` per the grep
   in step 1 above. Confirm.

## Procedure (sketch)

1. Add `kernelIfName` helper in `pkg/api/api.go`.
2. Rewrite the 4 sites.
3. Replace bare `ifName` references in `/sys/class/net/...` and
   `LeaseFor(...)` paths inside `writeInterfacesDetail` with the
   resolved kernel name (for sys) and the `LinuxIfName(...)+.VLAN`
   form (for DHCP — the daemon's exact construction).
4. Add tests.
5. Smoke per protocol. Per-class CoS smoke required.
6. PR with `Closes #1565`.
