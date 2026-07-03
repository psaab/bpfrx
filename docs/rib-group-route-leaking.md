# rib-group interface-route leaking (#3876)

Junos `routing-instances <ri> { routing-options { interface-routes { rib-group
inet <rg>; } } }` with a `rib-groups { <rg> { import-rib [ <ri>.inet.0 inet.0 ];
} }` installs the source instance's **direct/interface (connected)** routes into
every secondary rib in the import list. xpf realizes the **import-into-main**
case (the common one) with Linux policy-routing rules.

## Mechanism (Phase 1: import into main)

For each source routing instance whose `interface-routes` rib-group imports the
**main table** (`inet.0` / `inet6.0`), the daemon installs one ip rule **per
connected prefix** of that instance:

```
ip rule to <connected-prefix> lookup <sourceTable> pref 30000
```

These rules sit at priority band **30000-30999**, which is **BEFORE** the main
table's rule (32766) and before the PBR band (31000-31999). Because the rule
matches a *specific* destination prefix, a main-table **default route no longer
shadows it** — a lookup for the leaked prefix consults the source instance's
table (where the connected route lives), while everything else still falls
through to main.

- Source: `pkg/routing/rules.go` — `ribGroupManager.Apply` +
  `ribGroupLeaksIntoMain`; band constant `ribGroupLeakRulePriority = 30000`,
  cap `maxRibGroupLeakRules = 1000`.
- Connected-prefix derivation: `config.RibGroupConnectedPrefixes`
  (`pkg/config/compiler_routing.go`), which walks each instance's member
  interface units and masks their static addresses to network prefixes via
  the shared `config.ConnectedNetworkPrefix`. The **same** helper backs the
  userspace FIB's connected-route builder
  (`pkg/dataplane/userspace/routes.go`), so the leaked ip-rule set matches the
  connected routes actually installed in the source table.
- Plumbing: `pkg/daemon/daemon_apply.go` step 3c passes the derived prefix map
  into `Manager.ApplyRibGroupRules`.

### Both FIBs, by construction

The per-prefix rules carry a `Dst`, so the userspace snapshot builder's
existing `rule.Dst != nil` + table→instance loop auto-captures each as a
`NextTable` leak into the main table (`pkg/dataplane/userspace/routes.go`) —
putting the leak into the **userspace FIB** as well as the kernel FIB.

## Why the pre-#3876 behavior was a no-op

The old applier installed a single blanket rule per leaking source table:

```
ip rule from all lookup <sourceTable> pref 33000
```

This was broken two ways:

1. **Shadowed by any default route** — priority 33000 sits *after* main
   (32766), so a main-table default route matched first and the rule was never
   consulted. In any deployment carrying a default route (i.e. essentially all
   of them) the advertised feature was a silent no-op.
2. **Over-broad** — `from all lookup <sourceTable>` leaked the *entire* source
   table as a catch-all fall-through, far broader than Junos, which leaks only
   the interface/connected routes.

The blanket rule was also `Dst`-less, so the userspace snapshot builder skipped
it — the leak was absent from **both** FIBs.

### Upgrade cleanup

`ribGroupManager.clear()` scans three priority windows on every reconcile: the
current `[30000, 31000)` per-prefix band, the legacy `[33000, 33100)` blanket
band, and the original `[200, 300)` band. An in-place binary upgrade therefore
**removes the stale pref-33000 blanket rule** so the box is never left with the
broken blanket rule alongside the new per-prefix rules.

## Fail-loud diagnostics (commit-time warnings)

`config.ValidateConfig` (`validateRibGroupLeakWarnings`) warns — rather than
silently no-op — for the cases Phase 1 cannot fully realize:

- **No enumerable static connected prefix**: a source instance whose rib-group
  imports main but whose member interfaces carry no static address (DHCP-only /
  unaddressed). No ip rule is installed because there is no static prefix to
  enumerate at commit.
- **VRF→VRF import target**: a rib-group importing another instance's rib (not
  main). Phase 1 leaks only into the main table; a non-main import target is not
  yet installed.

The window warn (`validateRoutingRuleWindowWarnings`) additionally flags a
config that would leak more than `maxRibGroupLeakRules` (1000) connected
prefixes.

## Deferred (Phase 2 and beyond)

- **VRF→VRF import targets** — need `iif`-scoped rules or true route-copy;
  warned + deferred.
- **route-copy (Option 1)** — installing real copies of the source's direct
  routes into the target table (à la FRR `import`) would give
  `show route table inet.0` cosmetic parity but requires a new churn-tracking
  reconciler that collides with FRR's ownership of the managed section. It is
  forwarding-equivalent to the per-prefix rules for the dataplane and is
  deferred entirely.
- **Dynamically learned (DHCP) source addresses** — per-prefix cannot enumerate
  them at commit; warned now, would need Phase-2 route-copy or a runtime
  address-watch.
