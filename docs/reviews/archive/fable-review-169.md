# fable-review-169 — reth drop-in parity: the flat vSRX chassis-cluster config mis-resolves reth members on node 1

**Focus (operator-directed):** can an existing vSRX chassis-cluster config
be dropped into xpf as-is? Specifically the `redundant-parent` (reth
member) model. Answer: **no — not today.** A canonical vSRX flat config
silently binds every reth to the **node-0** physical member on **node 1**
(the secondary), breaking reth on the secondary. Reviewed at
`origin/master` `ba4553bfa`.

## 0. Bottom line

vSRX expresses reth members **flat**, with node ownership encoded in the
FPC number (`ge-0/0/N` = node 0 / fpc 0, `ge-7/0/N` = node 1 / fpc 7),
and the same config runs on both nodes:

```
set interfaces ge-0/0/0 gigether-options redundant-parent reth0
set interfaces ge-7/0/0 gigether-options redundant-parent reth0
```

xpf **accepts** this (commit passes on both nodes) but **mis-resolves it
on node 1**: `reth0` resolves to `ge-0/0/0` — node 0's interface, which
does not exist on node 1's hardware. Every reth-dependent runtime path
(VIP placement, DHCP, RA, IP-monitoring, RPM, HA group membership) then
targets a non-existent local interface on the secondary. The reth on
node 1 is effectively dead; a failover to node 1 loses the reth.

The only reason the loss cluster works is that its config was hand-restructured
into the xpf-specific `groups node0/node1` + `apply-groups "${node}"` form,
which sidesteps the bug by giving each node a config that contains **only
its own** member. That restructuring is a mandatory, undocumented
migration step — the direct answer to "how do I drop in a vSRX config": you
currently can't, for a cluster, without rewriting the entire interfaces
hierarchy.

## 1. Reproduction (probe against real parser+compiler, HEAD)

Compiling identical reth models through `CompileConfigForNode` for each
node:

```
[FLAT   node0]  RethToPhysical: reth0:ge-0/0/0   ✓ local member
[FLAT   node1]  RethToPhysical: reth0:ge-0/0/0   ✗ WRONG — must be ge-7/0/0
[GROUPS node0]  RethToPhysical: reth0:ge-0/0/0   ✓
[GROUPS node1]  RethToPhysical: reth0:ge-7/0/0   ✓
```

- **FLAT** = canonical vSRX (both `ge-0/0/0` and `ge-7/0/0` carry
  `redundant-parent reth0`, no groups, no `chassis cluster node` leaf).
  Node 1 mis-resolves.
- **GROUPS** = the xpf loss form (`groups node0 { ge-0/0/0 … }` /
  `groups node1 { ge-7/0/0 … }` + `apply-groups "${node}"`). Works —
  because each node's expanded config has a single candidate member.
- `xpfd check-config -node-id {0,1}` **PASSES** the flat form on both
  nodes — the mis-resolution is silent (no commit error, no warning).

Confirming the fix hypothesis — add the `chassis cluster node 1` leaf to
the flat form and compile for node 1:

```
[FLAT+node1-leaf node1]  RethToPhysical: reth0:ge-7/0/0   ✓ correct
```

So the resolution logic is correct **when `Cluster.NodeID` is right** —
the bug is that `Cluster.NodeID` is wrong for a leaf-less flat config.

## 2. Root cause (verified in code)

The reth→member resolver is node-scoped, but it keys off the wrong node
identity:

1. `Config.RethToPhysical()` (`pkg/config/types.go:64`) scores each
   candidate member by `SlotToNodeID(InterfaceSlot(name)) ==
   c.Chassis.Cluster.NodeID` (local member → score 2, remote → 0). With
   both members present it should pick the local one.
2. But **`Cluster.NodeID` is populated ONLY from the config leaf `chassis
   cluster node <id>`** (`compiler_system.go:1566`, guarded by
   `NodeIDSet`). Canonical vSRX configs do **not** carry that leaf — node
   identity there is intrinsic to the chassis. So `Cluster.NodeID`
   defaults to **0 on both nodes**.
3. **`CompileConfigForNode(tree, nodeID)` never stamps `Cluster.NodeID`
   from `nodeID`** — `compileConfigForNodeWithOpts`
   (`compiler.go`) uses `nodeID` solely to set the `${node}` group-
   expansion variable (`vars := {"node": "node%d"}`), not the compiled
   cluster identity. The `/etc/xpf/node-id` file flows through
   `Store.SetNodeID` → `${node}` expansion only (`store.go:239-244`).
4. `crossCheckNodeID` (`store.go:293-314`) **explicitly allows** a
   leaf-less config on a node-1 box ("an absent leaf on a node-1 box must
   [pass]"), so nothing forces the leaf to exist.
5. With `localNodeID == 0` on node 1, both members score by the fallback
   (`score == bestScore && ifc.Name < prev`) → alphabetical → `ge-0/0/0`
   wins on both nodes.

Blast radius — `RethToPhysical`/`ResolveReth` drive the whole reth
runtime, all of which then target `ge-0/0/0` on node 1:
`daemon_ha_vip.go:309,373,606` (VIP placement), `daemon_dhcp.go:225`,
`daemon_ra.go:94`, `daemon_ddns_surface_a.go:368`, `daemon_ipmon.go:141`,
`daemon_rpm.go:351`, `daemon_ha.go:790,1341` (HA group interfaces).

## 3. Why vSRX needs none of this (the parity gap)

On vSRX the two nodes are one logical chassis; each node knows its own
node-id from hardware, and `ge-0/0/N` vs `ge-7/0/N` encodes node
ownership. A flat `redundant-parent reth0` on both members resolves
per-node automatically — **no `groups`, no `apply-groups "${node}"`, no
`chassis cluster node` leaf.** xpf instead depends on all three, and its
reth resolver trusts the optional config leaf rather than the node's
actual runtime identity — so the flat form breaks on the secondary.

## 4. Fix direction

Make the compiled config's node identity reflect the node it is compiled
**for**, so reth resolution works on the canonical flat form:

1. In `compileConfigForNodeWithOpts`, when `nodeID >= 0` and the config
   carries no explicit `chassis cluster node` leaf (`!NodeIDSet`), stamp
   `cfg.Chassis.Cluster.NodeID = nodeID` (creating `Cluster` if absent).
   This is the runtime SSOT identity (`/etc/xpf/node-id` / the
   `-node-id` flag) that `Store.compileTree` already threads in. With it,
   `RethToPhysical` scores the local member correctly on both nodes and
   the flat vSRX form becomes a drop-in — confirmed by the
   `FLAT+node1-leaf` probe above (correct once `NodeID==1`).
2. Add a regression test: the flat two-member form must resolve
   `reth0 → ge-0/0/0` on node 0 and `reth0 → ge-7/0/0` on node 1. None
   exists — `TestRethToPhysical_PrefersLocalClusterMember` only exercises
   the case where `Cluster.NodeID` is already set, which is exactly the
   condition the leaf-less flat config fails to establish.
3. Keep the alphabetical tiebreak only as a last resort for a genuinely
   ambiguous single-node config; it must never decide between two nodes'
   members.

This is a small, localized change (one stamp at compile + a test) that
turns "must rewrite every interface into node groups" into "load the
vSRX config as-is."

## 5. Broader drop-in-migration implications (answering the operator)

Even with the reth fix above, a true vSRX drop-in for a **chassis
cluster** still needs the flat-vs-groups model reconciled across the
board, because the same FPC-encodes-node convention applies to any
per-node interface config (unit addresses, fxp0, etc.), not just
`redundant-parent`. Two coherent paths:

- **(recommended) Teach xpf the vSRX FPC convention at compile time:** on
  node N, treat interfaces whose FPC slot maps to the *other* node as
  peer-owned — resolve reth members to the local slot (the §4 fix) and
  node-scope interface *management* so node 0 does not try to own
  `ge-7/0/N` (today there is no FPC→node filter in `pkg/networkd` /
  `pkg/daemon/linksetup.go`; the flat config leaves each node carrying
  the peer's phantom interfaces — harmless only because
  `RethToPhysical` returns a single member, but it means the compiled
  interface set is not node-clean). This makes the flat vSRX config a
  genuine drop-in.
- **(fallback) Ship a migration transform:** a documented, tool-assisted
  rewrite that lifts per-node `ge-0/0/N` / `ge-7/0/N` interface stanzas
  into `groups node0/node1 { … } apply-groups "${node}"`. This is what
  was done by hand for the loss cluster; formalizing it at least makes
  the burden explicit instead of a silent mis-resolution.

Without one of these, the honest status is: **xpf is not a drop-in
replacement for a vSRX chassis cluster** — the canonical config commits
clean and then mis-binds reth on the secondary.

## 6. Dedup / relationship to prior findings

- Distinct from fable-review-168 (the `show interfaces reth<N>` "Not
  present" operational-visibility bug) — that is a display gap; this is a
  **forwarding/HA correctness** bug on the secondary.
- Related to but not the same as the campaign-166 "dual node identity
  (`/etc/xpf/node-id` file vs `chassis cluster node` leaf)" note: this
  pins a concrete, high-severity consequence of that split —
  `RethToPhysical` trusting the leaf-only `Cluster.NodeID`, so a
  leaf-less (i.e. real vSRX) config mis-resolves reth on node 1.
- Not previously reported. `TestRethToPhysical_PrefersLocalClusterMember`
  exists but presumes `Cluster.NodeID` is set, masking the leaf-less gap.

## 7. Verification performed

- Probe (real `NewParser` → `CompileConfigForNode`) comparing flat vs
  groups per node, and flat+node-leaf — dumps in §1.
- `xpfd check-config -node-id {0,1}` on the flat form (loss box) — PASS
  both, confirming the mis-resolution is silent.
- Code trace: `RethToPhysical` (types.go:64), `SlotToNodeID` (types.go:55),
  `Cluster.NodeID` population (compiler_system.go:1566),
  `compileConfigForNodeWithOpts` node-var handling (compiler.go),
  `SetNodeID`/`crossCheckNodeID` (store.go:239-314), and the runtime
  `RethToPhysical`/`ResolveReth` consumers. No repo files modified; loss
  candidate not touched (locked by another agent — #1875 respected).
