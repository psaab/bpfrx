# Claude SMR hostile plan-review — #6746 round 1 (plan v1 @ cc6860d5d)

**Verdict: DEMAND-REVISION** — the falsification's central claim survives
every break I attempted, but the plan-as-proof has one substantive
completeness gap (MAJOR-1) and three smaller ones. None reopens the window;
all are folds the v2 must make so the falsification document is
self-contained and does not depend on reviewer goodwill.

## How I attacked it

I independently re-walked the apply path at `ad9591177` and tried to break
the plan in the seven places a falsification of this shape is usually
wrong: (a) an unexamined permit branch in the packet gate, (b) a deferred
or sub-apply path that skips the closing mechanism, (c) an
empty-`update_ha_state` sender outside the two the plan names, (d) an
arming authority outside `desiredForwardingArmedLocked`, (e) a helper-side
reset of `rg_runtime` on snapshot apply, (f) a pairing/tearing read
between forwarding state and `ha_state`, (g) the operator override
surface. I also spot-checked the plan's anchors and re-ran its two
load-bearing tests
(`TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap`,
`TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup` — both
pass at base, confirmed during this research).

## Break attempts that FAILED (the falsification holds)

1. **Empty-sender audit.** The only sender of an empty `update_ha_state`
   is `clearHelperHAStateLocked`. Its call sites are all
   `!m.clusterHA`-gated: `manager_compile.go:391` (non-cluster else
   branch), the `pendingXSKStartup` `!m.clusterHA` branch at
   `manager_compile.go:296`, and `retryPendingHAStateClearLocked`
   (`manager_ha.go:145`: `if !m.pendingHAStateClear || m.clusterHA {
   return }`). On a clustered node no empty publish is reachable. HOLDS.
2. **Helper-side reset.** `rg_runtime` is constructed empty once
   (`coordinator/ha_state.rs:39`) and stored only from
   `afxdp/ha/state.rs:4` (`update_ha_state`). `apply_snapshot`
   (`server/handlers/snapshot.rs`) never touches it. A worker can pair NEW
   forwarding with OLD `ha_state`, but OLD is the phantom-populated map —
   fail-closed. HOLDS.
3. **Arming authorities.** Every `set_forwarding_state{Armed:true}` path
   funnels through `syncDesiredForwardingStateLocked` /
   `SetForwardingArmed`, both of which evaluate
   `desiredForwardingArmedLocked` (false on zero-RG) or are gated
   operator verbs. HOLDS (but see MINOR-3).
4. **Deferred first-RG commit.** If the first-RG apply takes the
   `pendingXSKStartup` early return (`manager_compile.go:269-309`), the
   publish resumes via the poll's `syncSnapshotLocked`
   (`process_status.go:10`) which sends no HA state — but the helper
   already holds `{0..15 inactive}` from the boot apply, nothing clears
   it, and the poll-tail arm
   (`process_status.go:243`) therefore never precedes an empty map. The
   watchdog-sync skip (`newActiveSig == ""`) does not matter because no
   publish is needed: the map is already non-empty. HOLDS.
5. **Sub-apply paths.** `manager_overlay.go:236` and
   `manager_worker_arm_5134.go:76` republish the same snapshot (overlay /
   DeferWorkers=false); neither sends HA state nor arms independently of
   the desired-state reconcile, and neither can run before the full apply
   that populates the phantom map. HOLDS.
6. **Anchor spot-check.** 12 anchors checked against source at
   `ad9591177`; all match (same set AGY independently verified).

## Findings

### MAJOR-1 — the M1 proof has an unstated premise: that the framed interface-NAT resolution resolves `owner_rg > 0`

`enforce_ha_resolution_snapshot` permits `LocalDelivery` UNCONDITIONALLY
when `owner_rg_id <= 0` (`forwarding/ha.rs:86-94`) — non-empty map or not.
The plan's M1 argument ("the phantom RG1-inactive entry resolves first-RG
LocalDelivery to HAInactive") is true ONLY because the framed
"RG-owned interface-NAT local address" resolves with `owner_rg = 1`:
`interface_nat_local_resolution` (`forwarding/nat.rs:137-160`) keys the
address to the owning interface's ifindex (populated at
`forwarding_build/interfaces.rs:157` with `iface.ifindex`), and
`owner_rg_for_flow` reads the egress row's `redundancy_group`, populated
from the snapshot at `forwarding_build/interfaces.rs:334`
(`redundancy_group: iface.redundancy_group`). For a reth in RG1 that is 1.
The plan asserts this chain in one clause and never evidences it.

This matters for two reasons, not one:

- **Proof soundness.** A falsification doc must not rest on an unproven
  premise. If any snapshot path recorded an RG-owned interface-NAT address
  against an ifindex whose egress row carries `redundancy_group = 0`
  (e.g., a RETH VLAN sub-unit whose logical-ifindex row missed RG
  propagation — the `ha.rs:83-85` comment itself references a historical
  "RETH RG propagation fix"), then LocalDelivery to that address would be
  permitted on EVERY standby node at ALL times — a strictly worse live
  defect than the framed window, hiding inside the plan's blind spot.
- **Blast-radius honesty.** The plan should state the dual fact
  explicitly: `owner_rg_id <= 0` LocalDelivery is permitted BY DESIGN
  (node-local addresses are not owner-gated), which is what bounds the
  framed scenario to genuinely RG-owned addresses.

Fold for v2: add the three-link evidence chain (nat.rs keying →
interfaces.rs:157 ifindex → interfaces.rs:334 egress RG) to §3.1, plus an
explicit statement of the `owner_rg_id <= 0` design-permit and why it is
out of frame; add to §9 a Rust test arm asserting an interface-NAT
resolution on an RG1 reth yields `owner_rg == 1` (guards future RG-
propagation regressions).

### MINOR-1 — §3.4 does not trace the deferred (`pendingXSKStartup`) first-RG commit

The plan names the deferred path in one parenthetical but never walks it.
My trace (break attempt 4 above) shows it closes, but via a NON-obvious
route (boot-apply phantoms persist; `syncSnapshotLocked` publishes no HA
state at all; the watchdog-sync skip is irrelevant). A hostile reader
should not have to redo this. Fold: one paragraph in §3.4 with the trace.

### MINOR-2 — the empty-sender audit belongs IN the plan, not just in this review

The falsification's C2 conjunct ("helper ha_state is never empty on a
clustered node") rests as much on "nobody sends an empty update while
clustered" as on the phantom fabrication. The plan cites
`clearHelperHAStateLocked` only in passing (§3.4 last bullet). Fold:
state the audit with the three call-site gates (`manager_compile.go:391`,
`:296`; `manager_ha.go:145`) as a named sub-point under §3.1 or §3.4.

### MINOR-3 — operator-arm interleaving is unaddressed

`request chassis ... forwarding arm` (`cli_request_chassis.go:151-158`)
and the gRPC diag action (`server_diag_system_action.go:395-415`) let an
operator arm forwarding directly. On a zero-RG node this defeats M2 by
definition (operator override). The window still does not open — M1's
phantom map is non-empty, and the ctrl gate adds a 15s `clusterHA` prewarm
delay (`maps_sync.go:420-424`) before any packet reaches a worker — but
the plan should say so rather than leave the surface unexamined. Fold:
one paragraph under §3.2 or §3.4.

### NIT-1 — §9 test plan: pin the M2 disarm assertion explicitly (concurs with AGY r1 MINOR)

§9.1 should assert `desiredForwardingArmedLocked() == false` after the
zero-RG apply AND before/after the first-RG apply's HA publish (not just
the ordering), and add a Go assertion that no empty `update_ha_state` is
sent while `m.clusterHA` is true (guards MINOR-2's audit).

## What I did NOT find

No reachable armed-with-empty-`ha_state` path on a clustered node; no
helper-side `rg_runtime` reset; no third empty-sender; no reading of the
issue that survives M1–M3 jointly. If Codex (infra-blocked this round)
later produces one, the round reopens.

## Required for round 2

Fold MAJOR-1, MINOR-1, MINOR-2, MINOR-3, NIT-1 into plan v2. With those
folds (proof-completeness only — no design change, Path A recommendation
unchanged), my expected round-2 verdict is PLAN-READY.
