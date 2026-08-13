# Consistent RETH MAC Addresses

## Problem

In the HA cluster, RETH interfaces use VRRP on physical member interfaces (no bond devices). Each node has a different physical MAC on its RETH member interface, causing problems during failover:

1. **IPv6 link-local addresses differ** -- EUI-64 link-local (`fe80::...`) is derived from MAC. After failover, the new primary has a different link-local address, breaking neighbor caches on LAN hosts.
2. **Neighbor cache invalidation** -- Clients must update both VIP->MAC and gateway link-local->MAC mappings. Unsolicited NA only covers the VIP.
3. **`bpf_fib_lookup` smac** -- XDP forwarding uses `fib.smac` from the kernel. Different MACs mean forwarded packets have different source MACs after failover.

## Solution

Program a deterministic virtual MAC on RETH physical member interfaces at daemon startup. Both nodes present the same MAC for each RETH, making IPv6 link-local addresses identical and eliminating neighbor cache issues.

## MAC Format

```
02:bf:72:CC:RR:00
```

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `02` | Locally-administered unicast (U/L bit set) |
| 1 | `bf` | xpf identifier |
| 2 | `72` | ASCII 'r' (bpf**r**x) |
| 3 | `CC` | cluster_id (from config) |
| 4 | `RR` | redundancy_group_id |
| 5 | `00` | Reserved |

Example for cluster_id=1:
- reth0 (RG1): `02:bf:72:01:01:00` -> link-local `fe80::bf:72ff:fe01:100`
- reth1 (RG2): `02:bf:72:01:02:00` -> link-local `fe80::bf:72ff:fe01:200`

## Ordering

1. **`.link` files** (udev/networkd) -- match physical MAC for interface rename (e.g. enp6s0 -> ge-0-0-0)
2. **`networkctl reload`** -- applies the rename
3. **Virtual MAC** -- `netlink.LinkSetHardwareAddr()` programs the deterministic MAC
4. **VRRP `UpdateInstances()`** -- picks up new MAC via `net.InterfaceByName()`
5. **GARP/NA** -- automatically use the kernel MAC (called at send time)
6. **`bpf_fib_lookup`** -- automatically returns new MAC as `fib.smac`

## Rename Owns the Link UP (#3920)

A RETH member must be administratively DOWN to be renamed (kernel
requirement). `renameRethMember` therefore downs the link, renames it,
and then brings it back UP — the function that downs a link owns
bringing it back up.

It must NOT delegate the UP to the subsequent `programRethMAC`.
`programRethMAC` early-returns (no UP) when the virtual MAC already
matches, and that is precisely the situation after a rename:
`renameRethMember` locates the interface by matching that same virtual
MAC, so on a just-renamed member the MAC always already matches and
`programRethMAC` always no-ops. (A second facet: even in the MAC-change
path, `programRethMAC`'s fast path sets the MAC while the link is still
DOWN, which succeeds without a cycle and returns without an UP.) If the
UP were skipped, the RETH data link would be left DOWN → the interface
track detects link-down → the redundancy group demotes → traffic
blackhole.

There is no flap: whenever a rename happens the MAC already matches so
`programRethMAC` no-ops, leaving `renameRethMember`'s UP as the final
state; and even in the defensive case where `programRethMAC` does cycle,
the member still ends UP. Bringing the member UP before `programRethMAC`
also restores that function's live-address-change detection, which
requires an UP link to distinguish `IFF_LIVE_ADDR_CHANGE` drivers from
those that need a cycle.

## The AF_XDP Worker Join Precedes the Link Cycle (#5103)

`PrepareLinkCycle`'s contract is that **no thread touches UMEM once it
returns** — it disables `ctrl` so the XDP shim stops redirecting to XSK, then
sends `stop_workers` so the Rust helper joins every worker thread. That barrier
therefore has to land **before** the NIC tears down its queues, not after: a
worker still reading UMEM while the driver unmaps those pages is a
use-after-unmap.

It cannot simply be hoisted above `programRethMAC`. Whether a cycle happens at
all is only knowable by **attempting** the live MAC set — success means the
driver has `IFF_LIVE_ADDR_CHANGE` and no cycle occurs. Joining unconditionally
would impose a forwarding outage on every RETH MAC apply on mlx5 and virtio (the
cluster's own NICs), to protect a path they never take.

So the join is a hook. `programRethMAC` takes a `beforeCycle func() error` and
invokes it **at most once, on the fallback path only** — after the live set has
been rejected, before `setDown`:

```
set-mac-live (rejected) → beforeCycle (stop_workers) → link-down → set-mac → link-up → rebind
```

`PrepareLinkCycle` returns an `error` across `LinkController` and every
implementation. A void return made a failed join indistinguishable from a
successful one, so the link cycled with workers still live.

**Abort semantics.** A rejected live set does not change link state — the kernel
refuses the address change outright — so when `beforeCycle` returns an error the
link is exactly as it was found. `programRethMAC` returns `(false, err)` **without
touching the link**: the member keeps its previous MAC, which the next apply
retries; cycling out from under live workers is not recoverable.

**The abort is not side-effect-free, and owns its own rollback.** By the time the
hook fails, `PrepareLinkCycle` has already disabled `ctrl` (and cleared every
binding row if that disable could not be verified), and the helper may or may not
have joined its workers. Nothing downstream re-arms that: the post-cycle rebind is
gated on `linkCycled` (false — the cycle was aborted), and
`reapplyAfterDeferredMAC` is gated on `rethMACPending`, which is computed *before*
`networkd.Apply` — so it is false for an apply whose only member needing a MAC was
renamed into its config name by that same `networkd.Apply`. (`rethMACPending` is
one bool for the whole apply, not per member: a multi-RETH apply where a
*different* member was already present with the wrong MAC does set it, and that
apply does re-apply.) `programRethMACWithWorkerJoin` therefore sends the documented
inverse of `stop_workers` — `rebind`, via `NotifyLinkCycle()` — and returns a
`errRethPrepareLinkCycle`-classified error. Its caller, `programRethMemberMAC`,
`errors.Join`s that into the accumulated commit error (the same `networkdErr`
channel the device-map teardown (#5309) and the management-VRF rebind (#5700)
use), so the commit reports FAILURE instead of success over a half-torn-down
dataplane. Ordinary netlink MAC-set failures stay warn-only, as they always have.

`programRethMemberMAC` exists as a function, rather than as three statements
inline in step 2.6's loop, so that fold is unit-testable: inline it was reachable
only through `applyDataplaneAndHACore`, which needs a live cluster manager, a
wired dataplane, a networkd writer and real netlink members, and the only
available guard was an AST canary over the call site — which is satisfied by an
assignment that is unreachable, shadowed, or jumped over.
`reth_commit_fold_5103_test.go` drives it against the same fake link seam and
fake dataplane the wrapper's own tests use. It folds BOTH per-member
accumulators: the commit error (joined, so an earlier step's error survives) and
`needLinkCycleRecovery` (ORed, so a member needing no cycle cannot clear a gate
an earlier member armed).

**The gate is "the hook RAN", not "the hook FAILED".** `PrepareLinkCycle` drives
`ctrl` to 0 *before* it can fail on `stop_workers`, so by the time it returns —
either way — the member is no longer forwarding. On success the workers are
additionally joined; on failure their state is simply **unknown**, which is why
the link must not be cycled (#6871: an earlier revision of this sentence said it
"stops the workers whether it then succeeds or fails", which overstates the
failure path — a `stop_workers` that never reaches the helper joins nothing). A
*successful* join therefore leaves the member just as un-forwarding as a failed
one — and
`setDown` and the cycled `setHardwareAddr` are both still fallible after it
returns. Both of those yield `linkCycled=false`, i.e. exactly the state above:
prepare applied, cycle not completed, and neither `linkCycled` nor
`rethMACPending` able to re-arm it. Keying the rollback on the hook's own error
let those two escape with a nil commit error and no rebind — `ctrl` off, transit
dropped, commit green. So `programRethMACWithWorkerJoin` records that the hook
ran (after its `d.dp == nil` guard, which keeps the rollback unreachable with no
dataplane attached) and rolls back on any subsequent failure:

| outcome | `linkCycled` | rollback here | commit |
|---------|--------------|---------------|--------|
| live set accepted — no cycle | false | no (hook never ran) | OK |
| member lookup failed | false | no (hook never ran) | OK — warn-only |
| join failed | false | `NotifyLinkCycle()` | FAIL |
| join OK, `setDown` failed | false | `NotifyLinkCycle()` | FAIL |
| join OK, cycled MAC write failed | false | `NotifyLinkCycle()` | FAIL |
| join OK, cycle ran, `link-up` failed | **true** | no — step 2.6b2 owns it | FAIL |
| join OK, cycle completed | true | no — step 2.6b2 owns it | OK |

The last-but-one row is the only failure in the class that does *not* roll back
here: the cycle completed, so step 2.6b2 already rebinds off `linkCycled`, and
firing `NotifyLinkCycle()` too would be the double rebind that gets `EBUSY` on
mlx5 zero-copy queues. It still fails the commit — the member is left
administratively DOWN after a deliberate teardown. Note that step 2.6b's VIP
reconcile is likewise gated on `linkCycled`, so a cycled-MAC-write failure still
skips it; that gap predates #5103 and is unchanged here.

Suppression is per-MEMBER, while step 2.6b2's gate is a per-APPLY accumulator, so
an apply that mixes an aborted member with a cycled one pays two rebinds. Which
of the two arms the 500ms zero-copy quiesce depends on the order step 2.6 visits
the members in, and that order is a Go map range — so both orders hold. Every
`stop_workers` **that reaches its handler** empties `coord.workers.records`
(`WorkerManager::stop_and_clear` joins each worker thread, then `clear()`s), and
`tear_down` samples `had_live_workers` from exactly that. The qualifier is
load-bearing and #6871 added it: a prepare can fail on the *dial* or the *write*,
before the helper ever runs the handler — precisely the failure class the
rollback exists for — and then records are NOT cleared, so the sample is `true`
and the quiesce is PAID rather than skipped. That costs an extra 500ms and
nothing else; the two orders below describe the handler-ran case. If the ABORTED member
is visited first, its rollback rebind recreates the workers but the cycled
member's own `stop_workers` clears them again, so step 2.6b2's rebind sees
`had_live_workers == false` and SKIPS the quiesce; if the CYCLED member is
visited first, nothing recreates workers before the aborted member's rollback
rebind does, so step 2.6b2's rebind sees `true` and arms it. Both are safe, and
not because of the quiesce: it covers a rebind that rebuilds the same queue set
immediately after a teardown it did not itself wait on, and here every rebind
follows a `stop_workers` that joined the worker threads synchronously plus
`NotifyLinkCycle`'s own unconditional 1s NIC settle — twice the 500ms it may
skip.

The rollback's `NotifyLinkCycle()` sits inside the per-member RETH loop and opens
with a 1s NIC-settle sleep, where step 2.6b2 pays that second at most once
outside the loop — worst case *N* extra seconds of `applySem` hold when every
member aborts (*N* = RETH count; 2 on the loss cluster). Bounded, and only on a
path where this node's forwarding is already down.

| File | Function |
|------|----------|
| `pkg/daemon/daemon_reth.go` | `programRethMAC(ifName, mac, beforeCycle)` — invokes the hook on the cycle path only, aborts without touching the link |
| `pkg/daemon/daemon_apply_dataplane.go` | `programRethMACWithWorkerJoin()` — builds the hook, rolls back a prepare whose cycle then failed, classifies the commit error |
| `pkg/daemon/daemon_apply_dataplane.go` | `programRethMemberMAC()` — step 2.6's per-member fold: joins the classified error into the commit error, ORs `linkCycled` into step 2.6b2's rebind gate |
| `pkg/dataplane/userspace/process_linkcycle.go` | `Manager.PrepareLinkCycle()` — ctrl disable + `stop_workers`, returns the join error |
| `pkg/dataplane/userspace/controllers.go` | `userspaceLinkController.PrepareLinkCycle()` — the live production adapter from the daemon hook to the manager |
| `userspace-dp/src/server/handlers/stop_workers.rs` | helper side of the join; `rebind.rs` is its inverse |

## The Link-Cycle Lease Holds the Join Across the Cycle (#6871)

The join above is a **moment, not a barrier**. `PrepareLinkCycle` takes `m.mu`,
joins the workers, and releases it on return — and the daemon does not reach
`setDown` until several netlink calls later. Every other holder of `m.mu` runs in
that window, so "no thread touches UMEM once it returns" was true only for the
instant it returned.

The busiest producer in that window is the 1 Hz status tick, which undoes the
join five different ways:

| producer | file | what it does mid-cycle |
|---|---|---|
| plan-key restart | `process_status.go` (`syncSnapshotLocked`) | `stopLocked()` + `ensureProcessLocked()` — respawns the **helper process** |
| #5134 worker arm | `manager_worker_arm_5134.go` | republishes the snapshot with `DeferWorkers=false` — starts the workers |
| busy-binding auto-rebind | `maps_sync.go` (`maybeAutoRebindBusyBindingsLocked`) | sends `rebind` — the exact inverse of the `stop_workers` just issued |
| bindings watchdog | `maps_sync.go` (`verifyBindingsMapLocked`) | repopulates binding rows a fail-closed ctrl disable had just cleared |
| ctrl gate | `maps_sync.go` (`applyHelperStatusLocked`) | re-enables `ctrl`, steering transit into XSK sockets whose queues are being destroyed |

`stop_workers` preserves registered bindings and `forwarding_armed`, so the Rust
same-plan predicate sees runnable-but-not-live bindings and reconciles by
restarting workers — which is why the first three are not hypothetical.

**The lease.** `Manager.linkCycleLeaseUntil` is an `atomic.Int64` deadline, taken
by `PrepareLinkCycle` and released by `NotifyLinkCycle`. It is atomic for the
same reason `rgTransitionInFlight` is: the guard has to survive `m.mu` being
released. It is consulted in exactly three places:

- **at the top of the status tick's critical section**, which skips its *whole
  body*. Nothing is lost — every action in that body is level-triggered on
  persistent manager state (`publishedSnapshot` vs `lastSnapshot.Generation`,
  `pendingWorkerArm`, `pendingHAStateClear`, `lastStatus.ForwardingArmed` vs
  desired), so the next tick after the lease ends services whatever is still
  outstanding.
- **at the ctrl write in `applyHelperStatusLocked`**, alongside the existing
  `rgTransitionInFlight` check. This is not redundant with the tick guard:
  `UpdateRGActive` also ends in `applyHelperStatusLocked`, and it runs off VRRP
  events and `reconcileRGStateLoop`'s 2s pass (`daemon_ha.go`, which also wakes
  early on dropped-event notifications) — **neither serialized on the daemon's
  `applySem`** — so it lands mid-cycle on its own schedule. Its own
  `rgTransitionInFlight` guard does not help: a demotion never sets the flag, and
  an activation clears it before the status apply.
- **at the three operator worker-affecting verbs** in `manager_status.go`
  (`SetForwardingArmed`, `SetQueueState`, `SetBindingState`), which return
  `errLinkCycleInFlight`. This is the sixth producer, and the only one reachable
  from *outside* the daemon: `request chassis cluster data-plane userspace
  forwarding|queue|binding ...` in the CLI (`cli_request_chassis.go`) and gRPC
  `SystemAction` (`server_diag_system_action.go`). Neither call site is
  serialized on `applySem` — there is no `applySem` use anywhere in `pkg/cli` or
  `pkg/grpcapi` — so an operator or an automation can fire one into the middle
  of a cycle. Each lands in a helper handler that reaches `afxdp.reconcile` and
  **spawns worker threads** (`handlers/forwarding.rs` calls
  `reconcile_status_bindings` unconditionally; `handlers/binding.rs` and
  `handlers/queue.rs` on `registration_changed`). The ctrl gate above cannot
  cover it: the spawn happens *inside the helper*, before the status this
  manager applies, so the gate has nothing left to un-spawn.

  Gated at the verbs rather than centrally in `requestLocked` because
  `requestLocked` also carries the cycle's own `stop_workers`, sent *after* the
  lease is taken — a central gate would need an exemption list for exactly the
  requests that take and release the lease. Both directions are refused, not
  only arming: a disarm does not spawn, but it still drives `afxdp.reconcile`'s
  teardown arm over sockets the cycle has quiesced, and nothing inside the
  daemon calls these three, so the broader scope blocks no internal path.

**Acquire point:** before the ctrl disable, not after a successful join. The
window that needs covering opens at the first mutation of dataplane state, and a
`stop_workers` can fail *after* the ctrl disable has already cleared binding rows.

**Release point:** the top of `NotifyLinkCycle`'s critical section — the earliest
correct point (from there we hold `m.mu` for the rest of the function, so no
producer can interleave anyway) and the latest (it precedes every `return`,
including the rebind failure, so a lease cannot be stranded on exactly the paths
where forwarding is already down). Releasing there also keeps the ctrl gate out
of the way of `NotifyLinkCycle`'s own post-rebind status apply, so a completed
cycle re-enables `ctrl` on that call instead of costing an extra reconcile tick.

**TTL backstop:** `linkCycleLeaseTTL` (60s). Every path that takes a lease reaches
a `NotifyLinkCycle`, so the TTL is only for a caller that dies in between — but a
stranded lease would suppress the reconcile loop permanently, which is worse than
the race. 60s is derived from the Prepare→Notify gap **at the deployed N=2
topology**, and that assumption is the load-bearing part: the dominant term is the
15s `externalCommandTimeout` on step 2.6's per-member `ethtool -K rxvlan off`,
plus `NotifyLinkCycle`'s own 1s NIC settle. A cycling member re-arms the lease
itself, so exposure is 15s × (1 + members visited *after* the last cycling one) —
30s on a 2-RETH node, half the TTL. It is **not** a general bound: four or more
wedging members visited after the last cycle exceed it, and since that traversal
is a Go map range, which members land in the tail is nondeterministic between
runs. Overrunning is bounded and loud rather than silent — `linkCycleInFlight`
logs a `Warn` under the CAS when it clears an expired lease, and the behaviour it
degrades to is master's, where the tick was never suppressed at all.

**The rollback now reports.** `NotifyLinkCycle` returns an `error`. Its rebind is
the documented inverse of `stop_workers`, and a failure used to be a `slog.Warn`
and a bare return on a void function — so a clean cycle whose rebind failed left
every worker stopped **while the commit reported success**, a silent total
dataplane outage. Both call sites now fold it into the commit under the same
`errRethPrepareLinkCycle` class as a failed join: the per-member rollback joins it
onto the abort cause (which stays, being the more actionable of the two), and step
2.6b2 joins it into the apply's commit error. The error's scope is deliberately
narrow, mirroring `PrepareLinkCycle`'s: it reports whether the **rebind** landed,
not whether the subsequent status apply did — `applyHelperStatusLocked` fails with
"userspace_ctrl map not loaded" whenever no shim is attached, and failing a commit
on that would be an over-rejection.

| file | role |
|------|------|
| `pkg/dataplane/userspace/manager.go` | `linkCycleLeaseUntil` — the atomic deadline |
| `pkg/dataplane/userspace/process_linkcycle.go` | `acquireLinkCycleLease` / `releaseLinkCycleLease` / `linkCycleInFlight` + the TTL |
| `pkg/dataplane/userspace/process_status.go` | the tick-wide skip |
| `pkg/dataplane/userspace/maps_sync.go` | the ctrl-write gate (covers `UpdateRGActive`) |
| `pkg/dataplane/userspace/manager_status.go` | `errLinkCycleInFlight` + the three operator-verb gates |
| `pkg/dataplane/apply.go` | `LinkController.NotifyLinkCycle() error` |
| `pkg/dataplane/userspace/controllers.go` | `userspaceLinkController.NotifyLinkCycle()` — the live adapter carrying the rebind error to the daemon |

## Deferred AF_XDP Worker Arming After a Live MAC Change (#5134)

Programming the virtual MAC can happen two ways:

- **Link cycle** (`programRethMAC` had to bring the member DOWN/UP): the old
  AF_XDP sockets die with the cycle. The daemon calls `NotifyLinkCycle()`,
  which sends `rebind` to the helper and recreates the workers with fresh
  sockets. This path arms the workers via the rebind, independent of the
  published snapshot's `DeferWorkers` flag.
- **Live MAC set** (`IFF_LIVE_ADDR_CHANGE` driver, or the fast path that sets
  the MAC while the link is still DOWN — no cycle): the initial dataplane
  apply of the commit ran with `SetDeferWorkers(true)` so worker startup was
  skipped (avoids the mlx5 zero-copy double-bind EBUSY). The published
  snapshot therefore carries `DeferWorkers=true` and is **workerless /
  non-forwarding**. The daemon then issues a MANDATORY second `ApplyConfig`
  (`reapplyAfterDeferredMAC`) with the correct MAC and `DeferWorkers` cleared —
  that re-apply is what actually starts the workers.

The re-apply is failure-critical. The userspace manager only advances its
snapshot bookkeeping (`lastSnapshot` / `publishedSnapshot` / `lastSnapshotHash`)
on a **successful** `apply_snapshot` publish. If the re-apply's publish fails
(helper rejects it, control-socket error, resource pressure) and the daemon
swallows the error, the manager keeps the workerless `DeferWorkers=true`
snapshot as the published/last state, status reconciliation replays it, the
workers never bind, and the commit still reports success — a silent forwarding
outage on that node.

**Contract:** `reapplyAfterDeferredMAC` never swallows the re-apply error. On
failure it records **generation debt** via `RecordDeferredWorkerArmDebt()`
(`Manager.pendingWorkerArm`). The 1 Hz status reconcile loop calls
`retryDeferredWorkerArmLocked()`, which republishes the retained snapshot with
`DeferWorkers=false` and a bumped generation until the workers bind, then clears
the debt. A transient helper error self-heals without failing the commit; the
node never terminally publishes a workerless snapshot while reporting success.

| File | Function |
|------|----------|
| `pkg/daemon/daemon_apply_dataplane.go` | `reapplyAfterDeferredMAC()` — mandatory re-apply; records debt on failure (moved from `daemon_apply.go` in #4407) |
| `pkg/daemon/daemon_apply_dataplane.go` | `recordDataplaneWorkerArmDebt()` — routes the debt to the dataplane |
| `pkg/dataplane/userspace/manager_worker_arm_5134.go` | `RecordDeferredWorkerArmDebt()` / `retryDeferredWorkerArmLocked()` |
| `pkg/dataplane/userspace/process_status.go` | status loop drives the retry each tick |

## Reboot Safety

- Bootstrap `.link` files (from `setup.sh`) use the physical MAC for udev rename
- After daemon programs the virtual MAC, the kernel MAC changes
- On next `applyConfig()`, if the kernel MAC is a virtual RETH MAC (`02:bf:72:...`), the compiler skips writing a `.link` file for that interface
- This preserves the bootstrap `.link` file with the physical MAC
- On reboot, udev matches the physical MAC (NIC resets to factory MAC) and renames correctly
- Daemon starts and re-programs the virtual MAC

## Implementation

| File | Function |
|------|----------|
| `pkg/cluster/reth.go` | `RethMAC(clusterID, rgID)` -- returns deterministic MAC |
| `pkg/cluster/reth.go` | `IsVirtualRethMAC(mac)` -- detects virtual RETH pattern |
| `pkg/daemon/daemon_reth.go` | `renameRethMember()` -- renames a member found by virtual MAC (down → rename → **up**, #3920) |
| `pkg/daemon/daemon_reth.go` | `programRethMAC()` -- sets MAC via netlink (step 2.6 in applyConfig); takes the mandatory `beforeCycle` AF_XDP worker-join hook (#5103) |
| `pkg/dataplane/compiler.go` | Skips `.link` file when RETH member has virtual MAC |

## Impact

- **XDP forwarding**: `bpf_fib_lookup` automatically returns the virtual MAC as `fib.smac` -- no BPF changes needed
- **GARP/NA**: `net.InterfaceByName()` returns the virtual MAC -- no code changes needed
- **VRRP**: advertisements use the virtual MAC -- neighbor caches stay valid across failover
- **IPv6 link-local**: both nodes derive the same `fe80::bf:72ff:fe01:RR00` -- seamless failover
