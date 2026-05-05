---
status: REVISED v2 — Codex round-1 PLAN-NEEDS-MAJOR; 5 findings addressed
issue: #1197
phase: Plan + fix design
prior:
  - v1 commit 2709752f — only fixed second loop; missed first-loop promotion, authority model, A1 mandatory, neighlist primitive choice, IPv6 NDP
---

## 1. Issue framing

Issue #1197: xpfd preinstalls stale neighbor MAC into kernel ARP
every 15s. When peer's MAC changes, kernel briefly learns fresh
MAC via normal ARP, then xpfd reverts kernel back to stale snapshot
MAC. Self-heals only via xpfd restart.

Live repro 2026-05-05: cluster-userspace-host → 172.16.80.200 broken;
xpfd kept reverting kernel ARP from fresh `52:9a:10:65:d8:7d` to
stale `56:4a:e8:1e:a8:32`.

## 2. Codex round-1 findings (all blocking)

1. **First loop also broken.** `daemon_neighbor.go:33-74` reads
   every kernel neighbor (including STALE) and reinstalls them as
   `NUD_REACHABLE`. So a stale STALE entry gets promoted to
   REACHABLE before the snapshot loop runs. v1's skip-on-conflict
   in the second loop misses this because by the time it runs,
   the kernel ALREADY has REACHABLE — synthesized from STALE.

2. **No authority model.** Steady-state vs takeover need
   different semantics:
   - **Steady-state periodic:** kernel-learned REACHABLE/STALE/
     PROBE/DELAY beats cached snapshot. Snapshot fills gaps only.
   - **Takeover:** peer snapshot may legitimately beat standby's
     stale STALE. But this code currently fires periodically
     regardless of context.

3. **A1 (snapshot regeneration) is MANDATORY, not optional.** The
   userspace-dp Rust forwarding path
   (`forwarding/mod.rs:1464-1483`) checks **static snapshot**
   neighbors **before** dynamic netlink-learned. Even if Go stops
   reverting kernel ARP, stale `state.neighbors` still wins for
   forwarding decisions. The snapshot must be regenerated to pick
   up fresh kernel data and pushed via `update_neighbors`. Closest
   existing path: `Manager.BumpFIBGeneration()` →
   `buildNeighborSnapshots()`. Need explicit neighbor-refresh API.

4. **NeighListExecute is gratuitous.** `NeighList(linkIndex,
   family)` wraps it. Dump per `(ifindex, family)` ONCE, not per
   snapshot entry. Use state bitmasks (`state & (REACHABLE|STALE|...)`).
   Decide PERMANENT semantics explicitly.

5. **IPv6 NDP in scope.** Current code processes both v4 and v6
   identically; v4-only fix leaves NDP staleness class identical.
   `SnapshotNeighbors()` strips state/router/link-local detail
   regardless of family.

## 3. Code paths affected (revised)

### Bug source 1: `pkg/daemon/daemon_neighbor.go:33-74`

The kernel-list reinstall loop. Reads every neighbor from
kernel, filters out FAILED/NOARP, **promotes everything else
(including STALE) to REACHABLE**. Need to either remove this
loop or make it state-preserving (only re-confirm REACHABLE,
let STALE/DELAY/PROBE remain in their current kernel state).

### Bug source 2: `pkg/daemon/daemon_neighbor.go:78-101`

The snapshot reinstall loop. Unconditionally `NeighSet`s with
snapshot's MAC. Need authority-aware logic.

### Snapshot consumer (userspace-dp): `userspace-dp/src/afxdp/forwarding/mod.rs:1464`

```rust
pub(super) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ifindex: i32, target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);  // ← static snapshot WINS
    }
    ...
}
```

### Snapshot regeneration: `pkg/dataplane/userspace/manager.go`

- `BumpFIBGeneration()` (line 421) regenerates via
  `buildNeighborSnapshots()` and publishes. Need a sibling
  `RegenerateNeighborSnapshot()` method that does the same scope
  but is named for the use case.
- `buildNeighborSnapshots(cfg)` reads kernel ARP; after the Go
  side stops reverting, this picks up the fresh MAC.

### Snapshot publish path: `update_neighbors` control message

- After regeneration, the snapshot is pushed to userspace-dp via
  the control socket so `state.neighbors` updates with fresh data.

### HA-context check: `pkg/dataplane/userspace/manager_ha.go:405`

Comment confirms HA transitions do NOT start neighbor repair —
periodic IS the readiness mechanism. So Option D (event-driven
only) requires more groundwork. Keep periodic, fix authority.

## 4. Concrete design — Option A+ (revised)

### 4.1 First loop (kernel-list reinstall): make state-preserving

Remove the indiscriminate promotion to NUD_REACHABLE. Only
re-confirm entries that are ALREADY REACHABLE (not STALE):

```go
for _, neigh := range neighs {
    if neigh.HardwareAddr == nil || len(neigh.HardwareAddr) == 0 {
        continue
    }
    // Only re-confirm entries the kernel already considers REACHABLE.
    // STALE/DELAY/PROBE means kernel is in the middle of resolution
    // or aging — let kernel handle that, don't force REACHABLE.
    // PERMANENT entries are operator-installed; preserve as-is.
    if neigh.State&netlink.NUD_REACHABLE == 0 {
        continue
    }
    entry := netlink.Neigh{
        LinkIndex:    link.Attrs().Index,
        Family:       family,
        State:        netlink.NUD_REACHABLE,
        IP:           neigh.IP,
        HardwareAddr: neigh.HardwareAddr,
    }
    if err := netlink.NeighSet(&entry); err == nil {
        installed++
    }
}
```

Open question: is the kernel-list reinstall actually doing
useful work? If we read REACHABLE and write REACHABLE with the
same MAC, the only effect is resetting the timer. That may
matter for keeping the entry from aging out, but it's also
exactly what normal kernel ARP timekeeping does. **Possible
follow-up: remove this loop entirely.** Out of scope for this
PR — minimal fix is "stop the STALE→REACHABLE promotion".

### 4.2 Second loop (snapshot reinstall): authority-aware + batched

```go
if provider, ok := d.dp.(snapshotNeighborProvider); ok {
    // Group snapshot entries by (ifindex, family) so we dump
    // kernel ARP once per group, not per entry.
    type groupKey struct{ ifindex, family int }
    groups := map[groupKey][]snapshotEntry{}
    for _, sn := range provider.SnapshotNeighbors() {
        groups[groupKey{sn.Ifindex, sn.Family}] =
            append(groups[groupKey{sn.Ifindex, sn.Family}], sn)
    }

    var conflicts int
    for key, entries := range groups {
        // One kernel dump per (ifindex, family).
        kernelMap := map[string]netlink.Neigh{}
        kernels, err := netlink.NeighList(key.ifindex, key.family)
        if err == nil {
            for _, k := range kernels {
                if k.IP != nil {
                    kernelMap[k.IP.String()] = k
                }
            }
        }
        const learnedMask = netlink.NUD_REACHABLE |
            netlink.NUD_STALE | netlink.NUD_DELAY |
            netlink.NUD_PROBE | netlink.NUD_PERMANENT
        for _, sn := range entries {
            if existing, ok := kernelMap[sn.IP.String()]; ok {
                // Kernel has an entry. If it's in any LEARNED state
                // (not NONE/INCOMPLETE/FAILED) and the MAC differs,
                // skip — kernel is the authority on the current MAC.
                if existing.State&learnedMask != 0 &&
                    existing.HardwareAddr != nil &&
                    !bytes.Equal(existing.HardwareAddr, sn.MAC) {
                    conflicts++
                    continue
                }
                // Kernel agrees on MAC, or is in INCOMPLETE/FAILED.
                // Falling through writes our snapshot MAC, which is
                // correct in both cases.
            }
            entry := netlink.Neigh{
                LinkIndex:    sn.Ifindex,
                Family:       sn.Family,
                State:        netlink.NUD_REACHABLE,
                IP:           sn.IP,
                HardwareAddr: sn.MAC,
            }
            if err := netlink.NeighSet(&entry); err == nil {
                installed++
            }
        }
    }
    if conflicts > 0 {
        // Kernel has fresher data than our snapshot for at least
        // one entry. Trigger snapshot regeneration so userspace-dp
        // also picks up the fresh data; without this the data plane
        // forwards via stale state.neighbors regardless of kernel.
        if rgr, ok := d.dp.(neighborRegenerator); ok {
            rgr.RegenerateNeighborSnapshot()
        }
        slog.Info("snapshot vs kernel ARP conflict; regenerated",
            "conflicts", conflicts)
    }
}
```

### 4.3 Snapshot regeneration API

Add to `pkg/dataplane/userspace/manager.go`:

```go
// RegenerateNeighborSnapshot rebuilds neighbors[] from current
// kernel ARP/NDP state and publishes the result to userspace-dp.
// Called when the daemon detects kernel ARP has fresher data than
// our cached snapshot.
func (m *Manager) RegenerateNeighborSnapshot() {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
        return
    }
    newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
    if neighborsEqual(m.lastSnapshot.Neighbors, newNeighbors) {
        return
    }
    m.lastSnapshot.Neighbors = newNeighbors
    m.lastSnapshot.Generation = m.generation
    // Publish via update_neighbors so userspace-dp picks it up.
    m.publishUpdateNeighbors(newNeighbors)
}
```

Reuse the existing publish path (whatever
`BumpFIBGeneration()` triggers; check at impl time).

### 4.4 IPv6 NDP

Same code applies to IPv6 because the loops already iterate
over both families. The state machine for NDP is the same NUD_*
constants; bitmask works identically. No v6-specific changes
needed.

## 5. Risk assessment (revised)

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **MEDIUM** | First-loop change skips STALE entries; if standby relies on STALE→REACHABLE promotion for failover warmth, that's a regression. Mitigation: failover smoke test catches this. |
| Lifetime / borrow | LOW | Pure Go; no new ownership. |
| Performance regression | LOW | Replaces N×NeighListExecute with M×NeighList where M = #(ifindex,family) groups, much smaller; net win. |
| Architectural mismatch | LOW | Steady-state authority model is the right shape; takeover-context is left for follow-up. |
| HA correctness | **MEDIUM** | A standby with cold neighbor cache + skip-on-conflict + no failover takeover hook = NO_NEIGH on first packet. Need to verify activation path warms via existing mechanisms (resolveNeighbors at activation time). |

## 6. Test plan (revised)

**Unit (pkg/daemon):**
- `TestPreinstallKernelListSkipsStale`: kernel has STALE entry;
  preinstall runs; kernel state stays STALE (not promoted).
- `TestPreinstallKernelListReconfirmsReachable`: kernel has
  REACHABLE entry; preinstall runs; kernel state stays REACHABLE.
- `TestPreinstallSnapshotSkipsConflict`: kernel has REACHABLE
  with MAC A; snapshot has MAC B; preinstall runs; kernel still
  has MAC A. Snapshot regenerated.
- `TestPreinstallSnapshotFillsMissing`: kernel has no entry;
  snapshot has MAC; preinstall runs; kernel learns snapshot MAC.
- `TestPreinstallSnapshotFillsIncomplete`: kernel has INCOMPLETE
  entry (no MAC); snapshot has MAC; preinstall fills.
- `TestPreinstallSnapshotKernelFailed`: kernel has FAILED entry;
  snapshot has MAC; preinstall writes MAC (kernel "doesn't know").
- `TestPreinstallSnapshotBatched`: 10 entries, 2 ifindex/family
  groups; verify only 2 NeighList calls.

**Unit (pkg/dataplane/userspace):**
- `TestRegenerateNeighborSnapshot`: kernel ARP has MAC A; manager
  has snapshot with MAC B; call RegenerateNeighborSnapshot; assert
  snapshot now has MAC A and update_neighbors was published.

**Cargo build clean** + 952+ cargo tests pass.

**Go test full suite (~880 tests across 30 packages):** zero regressions.

**Manual repro (live cluster):**
1. `make test-deploy` on loss userspace cluster
2. Force a stale-MAC scenario:
   - Note current MAC of 172.16.80.200 in fw0's ARP table
   - Manually `ip neigh replace 172.16.80.200 lladdr <fake_mac>
     dev ge-0-0-2.80 nud reachable`
   - Wait 30s
3. Verify: `ip neigh show 172.16.80.200` shows the REAL MAC
   re-learned by kernel ARP (not the fake one we injected).
   Verify userspace-dp snapshot also has real MAC via
   `cat /run/xpf/userspace-dp.json`.
4. `cluster-userspace-host -> 172.16.80.200` ping works.

**Smoke matrix on loss userspace cluster:**
- Full 30-cell smoke (v4+v6, push+reverse, CoS-off+CoS-on,
  per-class 5201-5206) — confirms forwarding throughput preserved.
- Failover test: trigger RG1 failover (fw0 → fw1); verify TCP
  survives takeover; verify standby's neighbor cache is warm
  enough that first-packet doesn't NO_NEIGH.

## 7. Out of scope

- Removing the periodic preinstall entirely (Option D) — keep
  periodic for now; only fix authority model.
- Removing the kernel-list reinstall loop entirely — minimal fix
  is "stop STALE→REACHABLE promotion."
- RTM_NEWNEIGH netlink subscription (Option B) — follow-up.
- TTL-based snapshot expiry (Option C) — follow-up.
- Refactoring snapshot publish path — reuse existing.

## 8. Open questions for adversarial review v2

1. Is the first-loop change (skip STALE) correct, or does the
   standby specifically need STALE→REACHABLE promotion for
   failover warmth? Needs HA-test verification.

2. Is `learnedMask = REACHABLE|STALE|DELAY|PROBE|PERMANENT` the
   right authority bitmask, or should PERMANENT be excluded
   (operator-installed; we shouldn't second-guess)?

3. Does triggering `RegenerateNeighborSnapshot` from the periodic
   preinstall create a loop hazard? (Periodic preinstall fires
   every 15s; if regen takes >15s, two could overlap.) Mitigation:
   make `RegenerateNeighborSnapshot` idempotent + cheap, or guard
   with a "regen-in-flight" flag.

4. Is the publish path for `update_neighbors` already exposed via
   the manager's existing public API, or does it need a new helper?

5. For takeover scenarios (where peer snapshot SHOULD beat
   standby's STALE), is the right design a separate
   `preinstallOnTakeover()` method that's called by `UpdateRGActive`,
   leaving the periodic path missing-only forever? Out of scope
   for this PR but worth flagging the design direction.

## 9. Verdict request

PLAN-READY → implement v2.
PLAN-NEEDS-MINOR → tweak rationale/code, then implement.
PLAN-NEEDS-MAJOR → still wrong; revise.
PLAN-KILL → premise wrong; preinstall model itself needs redesign.
