---
status: DRAFT v1 — pending adversarial plan review
issue: #1197
phase: Plan + fix design
---

## 1. Issue framing

Issue #1197: xpfd preinstalls stale neighbor MAC into kernel ARP
every 15s. When a peer's MAC changes, kernel briefly learns the
fresh MAC via normal ARP, then xpfd reverts kernel back to stale
snapshot MAC. Self-heals only via xpfd restart.

Live repro on 2026-05-05: cluster-userspace-host → 172.16.80.200
broken; xpfd kept reverting kernel ARP from fresh
`52:9a:10:65:d8:7d` to stale `56:4a:e8:1e:a8:32`.

## 2. Honest scope/value framing

This is a real correctness bug. Severity: connectivity-breaking
when any peer's MAC changes (peer reboot, NIC swap, eviction +
re-resolution to different endpoint). High-likelihood trigger:
**failover** itself — the very scenario the preinstall mechanism
exists for.

Win at fix time: zero false-positive ARP-revert events; failover
neighbor warmth preserved without the staleness-amplification bug.

Cost: small focused fix (single function plus tests). Smoke matrix
verifies failover doesn't regress.

If reviewers conclude the fix would regress failover behavior or
the bug is structural (i.e., the snapshot model itself is wrong),
PLAN-KILL is acceptable and would route to a larger redesign.

## 3. Code paths affected

### Bug source: `pkg/daemon/daemon_neighbor.go:78-101`

The second loop in `preinstallSnapshotNeighbors` unconditionally
calls `netlink.NeighSet` for each entry in
`provider.SnapshotNeighbors()`. No check whether kernel already
has a different MAC.

### Snapshot build: `pkg/dataplane/userspace/snapshot.go:1757-1850`

`buildNeighborSnapshots(cfg)` reads kernel ARP at snapshot build
time. The snapshot is a point-in-time photo of kernel ARP.

### Snapshot consumer:
`pkg/dataplane/userspace/manager.go:788-830` — `SnapshotNeighbors()`
returns the latest cached snapshot's neighbor entries.

### When snapshot regenerates:
`pkg/dataplane/userspace/manager.go:440` — only when the dataplane
regenerates the full snapshot (config commit, FIB regen, etc.). NOT
periodically; NOT in response to RTM_NEWNEIGH.

### Preinstall caller:
`pkg/daemon/daemon_neighbor.go:468` — fires from periodic
maintenance loop (15s tick).

## 4. Concrete design — Option A (minimal/defensive)

**Skip preinstall when kernel already has a different MAC in
REACHABLE state.**

```go
// In preinstallSnapshotNeighbors, replace the unconditional
// NeighSet block (lines 87-100) with a check-before-write:

if provider, ok := d.dp.(snapshotNeighborProvider); ok {
    for _, sn := range provider.SnapshotNeighbors() {
        // Skip if kernel already has a REACHABLE entry with a
        // different MAC. This avoids overwriting a fresher kernel
        // ARP entry with our cached snapshot MAC. The kernel's
        // ARP machinery is the authority on the current MAC; we
        // only fill gaps it hasn't filled yet.
        existing, err := netlink.NeighListExecute(netlink.Ndmsg{
            Family:  uint8(sn.Family),
            Index:   uint32(sn.Ifindex),
        })
        var skip bool
        if err == nil {
            for _, e := range existing {
                if e.IP == nil || !e.IP.Equal(sn.IP) {
                    continue
                }
                if e.HardwareAddr != nil &&
                    !bytes.Equal(e.HardwareAddr, sn.MAC) &&
                    (e.State == netlink.NUD_REACHABLE ||
                     e.State == netlink.NUD_STALE ||
                     e.State == netlink.NUD_PROBE ||
                     e.State == netlink.NUD_DELAY) {
                    skip = true
                    break
                }
            }
        }
        if skip {
            continue
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
```

Plus: invalidate the snapshot entry when this skip fires, so the
next `buildNeighborSnapshots` picks up the fresher kernel MAC.
Pseudocode for that step is in section 5.

## 5. Snapshot self-healing

The skip logic above prevents the **revert**, but doesn't refresh
the **snapshot** so it stays correct for the future.

Two options for keeping the snapshot fresh:

**Option A1:** trigger a `Manager.RegenerateNeighborSnapshot()`
from the daemon's preinstall loop when a skip fires. This pulls
fresh kernel ARP into the snapshot so the next preinstall is
correct.

**Option A2:** subscribe to RTM_NEWNEIGH netlink events in the
manager and update the snapshot's `Neighbors` slice on each event.
More principled but adds a long-lived netlink subscription.

A1 is sufficient for this fix (snapshot self-heals on next
preinstall tick after a skip). A2 is a follow-up enhancement.

## 6. Public API preservation

- `Daemon.preinstallSnapshotNeighbors()` — internal method, no
  external callers; signature unchanged.
- `Manager.SnapshotNeighbors()` — public API; signature unchanged.
- `Manager.RegenerateNeighborSnapshot()` — new method needed for
  A1; pure additive, no breakage.

## 7. Hidden invariants the change must preserve

1. **Failover neighbor warmth.** If the standby has snapshot
   entries the kernel doesn't yet have (because they expired
   while peer owned the RG), preinstall must still fill those in.
   — The skip only fires when kernel has a *different* MAC, not
   when kernel is missing the entry entirely. Failover path
   preserved.

2. **First-packet-after-failover correctness.** When the standby
   takes over an RG, it needs neighbor entries pre-warmed so
   bpf_fib_lookup returns SUCCESS instead of NO_NEIGH. — Same;
   skip only fires on conflict, not on missing.

3. **HA snapshot sync portability.** The snapshot is sent peer→peer
   as part of cluster sync. Snapshot's internal format unchanged
   here.

4. **No allocation on hot path.** Preinstall runs at 15s tick, off
   the data-plane fast path. Allocation cost not a concern.

5. **Stale-handle hazards.** None — `netlink.NeighListExecute` is
   self-contained; ifindex is from the snapshot itself.

6. **Lifetime / borrow-checker shape.** Pure Go; standard
   netlink primitives.

## 8. Risk assessment

| Risk class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Skip only fires on conflict; missing-entry path unchanged |
| Lifetime / borrow | LOW | No new ownership transfer; just an extra read before write |
| Performance regression | LOW | Adds one `NeighListExecute` per snapshot entry per 15s tick; negligible |
| Architectural mismatch | LOW | Same model as before; just adds defensive read |

If risk is higher than estimated, the most-likely failure mode is
that `NeighListExecute` returns subtly different entries than
`NeighSet` would consult, and we falsely skip. Mitigation: log
each skip with kernel-MAC vs snapshot-MAC at slog.Debug for
operator visibility.

## 9. Test plan

**Unit (pkg/daemon):**
- `TestPreinstallSnapshotNeighborsSkipsConflict`: kernel has MAC
  A REACHABLE; snapshot has MAC B; preinstall runs; assert
  kernel still has MAC A.
- `TestPreinstallSnapshotNeighborsFillsMissing`: kernel has no
  entry for IP X; snapshot has MAC for IP X; preinstall runs;
  assert kernel now has snapshot's MAC.
- `TestPreinstallSnapshotNeighborsAgreement`: kernel and snapshot
  agree on MAC; preinstall runs; assert kernel unchanged (or
  re-confirmed REACHABLE).
- `TestPreinstallSnapshotNeighborsKernelHasFailed`: kernel has
  MAC FAILED state; snapshot has different MAC; preinstall runs;
  assert kernel learns snapshot's MAC (since FAILED is "we don't
  know").

**Build + cargo + Go test full suite:** zero regressions.

**Manual repro:**
1. `make test-deploy` on loss userspace cluster
2. Modify a neighbor's MAC (e.g., via `ip neigh replace` on a peer)
3. Verify kernel ARP doesn't revert at next 15s tick
4. Verify journal logs the skip event

**Smoke matrix on loss userspace cluster:**
- 30-cell smoke (v4+v6, push+reverse, CoS-off+CoS-on, per-class
  5201-5206) — confirms the change doesn't break the throughput
  path.
- Failover test (`make test-failover` if available against this
  cluster) — confirms standby preinstall still works on takeover.

## 10. Out of scope (explicitly)

- RTM_NEWNEIGH netlink subscription (Option A2) — track as
  follow-up if needed.
- Removing the periodic preinstall entirely (Option D in #1197) —
  more invasive; defer until A is shipped and proven.
- IPv6 NDP-specific paths — same logic applies but out of scope
  for this PR if v4 fix lands first.

## 11. Open questions for adversarial review

1. Is the skip-on-conflict logic actually safe during failover?
   Specifically: at takeover time, the standby's *kernel* may
   have a STALE entry with a different MAC than the *snapshot*.
   The snapshot is the authoritative "what the active peer last
   saw" view. Should preinstall force-overwrite STALE in that
   specific case?
2. Is `netlink.NeighListExecute` the right primitive, or should
   we use `netlink.NeighList` per-link?
3. Is 15s the right preinstall cadence at all? Should it be event-
   driven (RG transition) instead of periodic? (Option D — out of
   scope here, but reviewers should flag if they think periodic
   is fundamentally wrong.)
4. Does the dataplane manager's snapshot regeneration actually
   pick up fresh kernel ARP if we trigger it? Or is there a
   caching layer that needs invalidating too?
5. Does the IPv6 path (NDP) need any different treatment than the
   IPv4 ARP path?

## 12. Verdict request

PLAN-READY → implement Option A.
PLAN-NEEDS-MINOR → tweak rationale/code, then implement.
PLAN-NEEDS-MAJOR → revise; possibly switch to D.
PLAN-KILL → premise wrong; preinstall model itself needs redesign.
