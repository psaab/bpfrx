# #844 Idempotent VRF reconcile in applyConfig

## Problem (see #844 for full repro)

Each call to `applyConfig` in `pkg/daemon/daemon.go`:

1. Calls `d.routing.ClearVRFs()` — unconditional `LinkDel` of every
   VRF in `m.vrfs`.
2. Loops `cfg.RoutingInstances` and calls `d.routing.CreateVRF(...)`
   for each.
3. Separately creates a `vrf-mgmt` via `CreateVRF("mgmt", 999)`
   (daemon.go:1615).

On startup the sequence runs at least twice in quick succession —
once from local-config load, once ~6 s later when the cluster-sync
peer pushes its config (`syncMsgConfig` → `OnConfigReceived` →
`applyConfig`). It runs again for every HTTP/gRPC commit, DHCP
callback, and config-poll hit.

Between the two startup passes the cluster-sync TCP listener
binds to `vrf-mgmt` via `SO_BINDTODEVICE` (`pkg/cluster/sync_conn.go:577`).
`setsockopt(SO_BINDTODEVICE)` stores the ifindex *at bind time*.
The second `applyConfig` deletes vrf-mgmt, the recreate gives it a
new ifindex, and the listener is orphaned to a dead ifindex.
Incoming SYNs hit no socket → kernel RST → "Connection refused"
from peer's dial.

Kernel 6.19 reproduces this reliably; older kernels may have held
the ifindex alive long enough or reused it on recreate, hiding the
bug. The daemon behavior is wrong regardless — churning every VRF
on every config apply disrupts routing tables for no reason.

## Fix

Replace `ClearVRFs`+`CreateVRF`-loop in `applyConfig` with a single
idempotent `ReconcileVRFs(desired []VRFSpec)` pass. Delete
`ClearVRFs` — it has no remaining callers after this change
(`xpfd cleanup` does not invoke it).

### API

```go
// pkg/routing/routing.go
type VRFSpec struct {
    Name    string  // logical name without "vrf-" prefix, e.g. "sfmix"
    TableID int
}
```

```go
// ReconcileVRFs brings the manager's owned-VRF set to match desired.
//
// Ownership: the manager only manages VRFs it created itself (tracked
// in m.vrfs). External VRFs — those created by an operator or a
// prior xpfd instance without cleanup — are visible via LinkByName
// but are NEVER deleted by this call and are NEVER added to m.vrfs.
// If the desired set includes such a VRF with the right TableID,
// ReconcileVRFs leaves it alone without adopting it. If the TableID
// disagrees, ReconcileVRFs logs a warning and leaves it alone (do
// not destroy operator state).
//
// Behavior for each name in desired:
//   - in m.vrfs with matching TableID   → no-op (preserve ifindex)
//   - in m.vrfs with different TableID  → LinkDel + LinkAdd, update m.vrfs
//   - not in m.vrfs, exists externally  → no-op + warn if TableID mismatches
//   - not in m.vrfs, does not exist     → LinkAdd + LinkSetUp, append m.vrfs
//
// Behavior for each name in m.vrfs not in desired:
//   - LinkDel; remove from m.vrfs.
//
// After the call, m.vrfs contains exactly the set of desired names
// that ReconcileVRFs created or already owned (i.e. m.vrfs ⊆ desired).
// It may be a strict subset if some desired VRFs were pre-existing
// external devices.
func (m *Manager) ReconcileVRFs(desired []VRFSpec) error
```

### Behavior matrix

| Current kernel state              | In m.vrfs | Desired   | Action                    |
|-----------------------------------|-----------|-----------|---------------------------|
| absent                            | no        | present T | LinkAdd+Up; add m.vrfs    |
| present, table T (match)          | yes       | present T | no-op                     |
| present, table T' (mismatch)      | yes       | present T | LinkDel+LinkAdd           |
| present, table T (match)          | no        | present T | no-op (external, keep)    |
| present, table T' (mismatch)      | no        | present T | no-op + warn (external)   |
| present                           | yes       | absent    | LinkDel; remove m.vrfs    |
| present                           | no        | absent    | no-op (external)          |

### Concurrency

Two independent concerns.

**1. Intra-ReconcileVRFs consistency (fix in this PR).**
`m.vrfs` is currently mutated without any lock (`routing.go:45`).
Add `vrfsMu sync.Mutex` to `routing.Manager` and hold it for the
**full** `ReconcileVRFs` body — including the `LinkAdd`/`LinkDel`/
`LinkByName` netlink calls, not just the slice updates. Dropping
the lock around netlink would open a TOCTOU window where two
callers compute diffs off the same pre-state, each issue their
own LinkDel/LinkAdd, and race on the post-update slice write.

Holding the mutex across netlink is acceptable because
`ReconcileVRFs` is rare (once per `applyConfig`, which itself is
low-frequency) and netlink VRF ops are microseconds. The same
mutex covers the existing `CreateVRF` (which will be retained for
any caller that still wants single-VRF semantics, though none
remain in production after this change).

**2. Inter-applyConfig serialization (out of scope; pre-existing).**
`applyConfig` is called from six places with no overarching lock:
HTTP commit (`pkg/api/handlers.go:1528`, `:1686`), gRPC commit
(`pkg/grpcapi/server_config.go:155`, `:178`), cluster-sync receive
(`pkg/cluster/sync_conn.go:947` → `pkg/daemon/daemon_ha_sync.go:342`),
DHCP callbacks (`pkg/daemon/daemon.go:801`), and config-poll
(`pkg/daemon/daemon.go:2533`). Two concurrent calls could
interleave *across* steps of applyConfig — one goroutine runs
ReconcileVRFs then pauses before FRR reload, the other runs its
own ReconcileVRFs with a different desired set, and when the first
resumes, FRR sees a VRF state that doesn't match the config it's
about to apply.

`vrfsMu` inside `ReconcileVRFs` doesn't fix this — the ordering
between `applyConfig`'s own steps is what matters. This is a
pre-existing condition; scoping it into #844 would balloon the
change. **Filed as a follow-up before merge** (see the end-of-plan
follow-ups list). In practice the race window is tiny (Go's
scheduler usually runs applyConfig to completion without
preempting across syscalls) and no user-visible symptom has been
attributed to it — but it is a real latent issue.

Other slice fields on `routing.Manager` (`tunnels`, `xfrmis`,
`bonds`, `reths`) have the same "no mutex around mutation"
pattern. Out of scope for #844; same follow-up issue.

### Call site in `applyConfig`

Replace the block at `pkg/daemon/daemon.go:1568-1598` (VRF create
for routing instances) and `:1604-1624` (mgmt VRF create) with a
single build-desired + reconcile + bind sequence. Hoist the
mgmt-interface computation into a small helper:

```go
func computeMgmtInterfaces(cfg *config.Config) map[string]bool {
    out := make(map[string]bool)
    for name := range cfg.Interfaces.Interfaces {
        if strings.HasPrefix(name, "fxp") ||
           strings.HasPrefix(name, "fab") ||
           strings.HasPrefix(name, "em") {
            out[config.LinuxIfName(name)] = true
        }
    }
    return out
}
```

Replacement in applyConfig:

```go
// 0. Reconcile VRFs: routing-instance VRFs + management VRF.
var desiredVRFs []routing.VRFSpec
for _, ri := range cfg.RoutingInstances {
    if ri.InstanceType == "forwarding" {
        slog.Info("forwarding instance, skipping VRF creation", "instance", ri.Name)
        continue
    }
    desiredVRFs = append(desiredVRFs, routing.VRFSpec{
        Name: ri.Name, TableID: ri.TableID,
    })
}
mgmtIfaces := computeMgmtInterfaces(cfg)
if len(mgmtIfaces) > 0 {
    desiredVRFs = append(desiredVRFs, routing.VRFSpec{Name: "mgmt", TableID: 999})
}
if d.routing != nil {
    if err := d.routing.ReconcileVRFs(desiredVRFs); err != nil {
        slog.Warn("failed to reconcile VRFs", "err", err)
    }
}

// 0a. Bind routing-instance interfaces.
if d.routing != nil {
    for _, ri := range cfg.RoutingInstances {
        if ri.InstanceType == "forwarding" { continue }
        for _, ifaceName := range ri.Interfaces {
            linux := strings.TrimSuffix(config.LinuxIfName(ifaceName), ".0")
            if err := d.routing.BindInterfaceToVRF(linux, ri.Name); err != nil {
                slog.Warn("failed to bind interface to VRF",
                    "interface", ifaceName, "instance", ri.Name, "err", err)
            }
        }
    }
}

// 0b. Bind management interfaces.
d.mgmtVRFInterfaces = nil
if d.routing != nil && len(mgmtIfaces) > 0 {
    for ifName := range mgmtIfaces {
        if err := d.routing.BindInterfaceToVRF(ifName, "mgmt"); err != nil {
            slog.Warn("failed to bind interface to mgmt VRF",
                "interface", ifName, "err", err)
        }
    }
    d.mgmtVRFInterfaces = mgmtIfaces
}
```

**`BindInterfaceToVRF` idempotency** — asserted, not verified from
kernel source. Already proven in production: the daemon rebinds
management interfaces on every apply (`pkg/daemon/daemon.go:2066-2084`)
and has for a long time without neighbor/DAD regressions. Keep
that empirical assumption; don't attempt to prove the kernel
behavior from first principles.

### Files to change

- **`pkg/routing/routing.go`**
  - Add `VRFSpec`, `ReconcileVRFs`.
  - Add `vrfsMu sync.Mutex` to `Manager`; lock it in `CreateVRF`
    and `ReconcileVRFs`.
  - Delete `ClearVRFs` — no callers after this change
    (`xpfd cleanup` doesn't call it; only `applyConfig` did).

- **`pkg/daemon/daemon.go`**
  - Replace the two VRF-create blocks in `applyConfig` with
    `desiredVRFs` build → `ReconcileVRFs` → bind loops.
  - Keep `CreateVRF` available for tests or future callers but
    make sure `applyConfig` stops calling it directly.

- **`pkg/routing/routing_test.go`**
  - Unit tests for `ReconcileVRFs`. Cover the 7 rows of the
    behavior matrix with a mock `nlHandle`.

### Ordering

`ReconcileVRFs` replaces the existing VRF block at the top of
`applyConfig` (step 0). Position unchanged:
1. ReconcileVRFs (step 0)
2. Bind routing-instance interfaces (step 0a)
3. Bind management interfaces (step 0b)
4. Tunnels, FRR, IPsec, etc. (unchanged)

Tunnel self-binding in `ApplyTunnels` (`routing.go:371-377`) and
the second mgmt rebind pass (`daemon.go:2066-2084`) stay where
they are. These pass their own ifaceName → instanceName and don't
depend on `m.vrfs` semantics.

### Table-ID mismatch

`vrf-mgmt` is hard-coded to table 999 in the compiler
(`pkg/config/compiler_routing.go:274`) and management-route
programming (`pkg/daemon/daemon_flow.go:45-89`). It cannot change
live. For ordinary routing-instance VRFs, table IDs are
auto-assigned from 100 upward by declaration order — a
declaration reorder could change IDs. `ReconcileVRFs` handles
that by LinkDel+LinkAdd with a warn-level log. This is
disruptive (sessions bound to the old VRF lose their master
briefly) but not incorrect; the operator changed the config.

### External VRFs

An external VRF is any device whose name matches a `vrf-*` we
care about but which the daemon did not create (`LinkByName`
succeeds before our `LinkAdd`). `ReconcileVRFs` never deletes
external VRFs and never adopts them into `m.vrfs`. If the
desired set includes such a name with a matching table, we use
it as-is. If the table mismatches, we warn and skip — do not
destroy operator state.

This mirrors the existing early-return in `CreateVRF`
(`routing.go:87-93`) and is safe by construction: since external
VRFs aren't in `m.vrfs`, a later reconcile won't delete them
either.

### Cross-restart VRF leaks (pre-existing, not fixed here)

After a daemon restart `m.vrfs` is empty. If a routing instance
was renamed (or deleted from config) while xpfd was down, the old
`vrf-<oldname>` device persists in the kernel. On startup
`ReconcileVRFs` sees it as external (not in m.vrfs, not in
desired) and leaves it alone. Result: the old VRF leaks until
`xpfd cleanup` is run.

This scenario already leaks on current `master`: `ClearVRFs` is
a no-op when `m.vrfs == []` (empty slice iteration), so the first
`applyConfig` after restart creates the new VRF without touching
the old one. **This PR does not regress the behavior; it does not
fix it either.** A proper fix would enumerate `vrf-*` devices on
startup and adopt those matching configured instance names — out
of scope for #844, filed as a follow-up.

## Risk

Low.
- The idempotent path is strictly safer than delete+recreate: fewer
  netlink calls, no ifindex churn, no route-table blackhole window.
- `CreateVRF` already has the "already exists" short-circuit so the
  underlying primitive supports this today.
- The added mutex fixes a latent race. `vrfsMu` is held for the
  full `ReconcileVRFs` body including the netlink operations. This
  serializes VRF reconciliation across manager callers, which is
  the intended behavior — concurrent diffs against the same
  pre-state would otherwise race. The perf cost is negligible
  (VRF reconcile is a low-frequency path).
- ClearVRFs deletion is safe — grep confirms the sole caller is
  `applyConfig`.

## Test plan

1. **Unit** — `TestReconcileVRFs` in `pkg/routing/routing_test.go`:
   - empty → [{A,100}]: creates A, m.vrfs = [vrf-A].
   - [{A,100},{B,200}] → [{A,100},{B,200}]: zero netlink calls.
   - [{A,100}] → [{A,101}]: delete + recreate; m.vrfs = [vrf-A].
   - [{A,100}] → []: delete A; m.vrfs = [].
   - [{A,100}] → [{A,100},{B,200}]: preserve A, create B.
   - [{A,100},{B,200}] → [{A,100},{C,300}]: delete B, keep A, add C.
   - External vrf-X exists, desired [{X,500}]: no create, not added
     to m.vrfs.
   - External vrf-X exists with wrong table, desired [{X,500}]:
     no-op + warn; not added to m.vrfs.

   Use a mock `nlHandle` (interface-satisfied) that counts LinkAdd,
   LinkDel, LinkByName calls. Keep the tests hermetic — no real
   netlink.

2. **Integration** — on the loss cluster:
   - `make cluster-destroy && make cluster-create && make cluster-deploy`.
   - Verify both nodes show `%vrf-mgmt` in `ss -tlnp '( sport = :4785 )'`
     output (not `%if<N>`).
   - Verify `show chassis cluster` reports `Transfer ready: yes` on
     all RGs on both nodes within ~10 s of cold boot.
   - Verify `journalctl -u xpfd` shows zero `"VRF removed"` entries
     on a steady-state config apply after startup (a churn counter
     would be nice but is out of scope).

3. **Regression**:
   - `make test` — all existing routing tests pass.
   - `make test-failover` — chassis failover/failback still works.

## Out of scope / follow-ups

Filed as separate issues before this PR merges:

- **applyConfig-level serialization.** Two concurrent callers can
  interleave steps of `applyConfig` and leave the system in a
  state neither config fully describes. Needs a daemon-level
  `applyMu sync.Mutex` around the entire function. Pre-existing.
- **Cross-restart VRF adoption.** Enumerate `vrf-*` devices on
  startup and adopt those whose names match configured routing
  instances (or mgmt), so that old VRFs from a previous config
  get cleaned up by the next `ReconcileVRFs` pass. Pre-existing.
- **Other slice fields without mutex.** `tunnels`, `xfrmis`,
  `bonds`, `reths` on `routing.Manager` have the same latent race
  as `vrfs`. No known user-visible symptom.
- **Broader idempotent reconcile** for tunnels/xfrmi/bonds/reth.
  They follow the same create-on-apply pattern as VRFs pre-fix
  but don't currently cause a user-visible bug. Flag for future.
- **Cluster-sync listener defense-in-depth.** Subscribe to
  netlink `RTM_DELLINK`/`RTM_NEWLINK` for `vrf-mgmt` and rebind
  the listener if the ifindex changes. Desirable for
  operator-driven recreation; not required once ReconcileVRFs
  stops churning the VRF.
