# #1666 — Gate the BPF READY write on helper-reported binding liveness

**Status:** v2 — PLAN-READY (AGY) + NEEDS-MAJOR findings from Codex/SMR
applied. Round-1 verdicts: AGY PLAN-READY, Codex PLAN-NEEDS-MAJOR
(framing corrections), Claude SMR NEEDS-MAJOR (self-corrected magnitude).
All three converge: the gate is correct, deadlock-free, strictly safer;
NOT a kill. v2 fixes the two framing errors and adopts the faster `Dead`
crash signal. See §13 for the round-1 dispositions.

## 1. Issue framing

`pkg/dataplane/userspace/maps_sync.go` writes the `userspace_bindings`
BPF-array READY flag (`userspaceBindingReady = 1`) at four sites. The
flag is what the `userspace-xdp` shim checks to decide whether to steer
a packet into the AF_XDP socket for a given (ifindex, queue) slot. The
issue's hypothesis: two of those sites mark a binding forwarding-ready
on `Registered && Armed` alone, *without* gating on the helper-reported
`Bound`/`XSKRegistered`/`Ready` liveness. If a worker crashes (panics)
or never finishes XSK registration, the control plane can keep
advertising the slot as forwarding-ready while no worker drains its RX
ring — transit packets steer to a socket nobody is servicing and are
silently dropped. The issue calls this a "crash-blind blackhole" and
proposes gating the READY write on `binding.Ready && XSKRegistered`.

## 2. The four sites (verified against current master, 3f47f0b33)

Issue cited lines 596/634/1101/1147; verified exact behaviour:

| # | Location | Current gate | Path |
|---|----------|--------------|------|
| 1 | `applyHelperStatusLocked`, maps_sync.go:596–602 | `Registered && Armed` (NOT Bound) — has an explicit anti-deadlock comment | primary per-binding apply |
| 2 | `applyHelperStatusLocked`, maps_sync.go:633–635 | `Registered && Armed && Bound` | VLAN-alias child apply |
| 3 | `verifyBindingsMapLocked` (watchdog), maps_sync.go:1076 + 1101 | `Registered && Armed` (NOT Bound) | primary stale-entry repair |
| 4 | `verifyBindingsMapLocked` (watchdog), maps_sync.go:1122 + 1147 | `Registered && Armed && Bound` | VLAN-alias stale-entry repair |

**Asymmetry already in the tree:** the alias sites (2, 4) already gate
on `Bound`; the primary sites (1, 3) deliberately do not, with the
comment at 597–601 claiming a chicken-and-egg if `Bound` is required.

## 3. The READY field is already strictly stronger than the proposal

`binding.Ready` is **derived**, not helper-asserted. In
`userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:225`:

```rust
binding.ready = binding.registered
    && binding.bound
    && binding.xsk_registered
    && heartbeat_fresh(snap.last_heartbeat);
```

Consequences:

- `Ready` already implies `Registered`, `Bound`, `XSKRegistered`, and a
  fresh heartbeat. The issue's proposed `Ready && XSKRegistered` is
  redundant in the XSKRegistered leg.
- **But `Ready` does NOT imply `Armed`** (Codex round-2 finding). The
  Rust derivation omits `armed`; `armed = armed_req && registered` is a
  separate control-plane flag (server/handlers/binding.rs:29). A
  Ready-but-disarmed binding (control plane disarmed it while it is
  otherwise live) must NOT forward, and the historical sites required
  `Armed`. So the gate must keep `Registered && Armed` AND add `Ready`
  — it is **`Registered && Armed && Ready && !Dead`**, NOT `Ready`
  alone. With `Armed` retained, the gate is then strictly stronger than
  the historical `Registered && Armed` predicate (adds bound +
  xsk_registered + heartbeat-fresh + not-dead).

## 4. Deadlock analysis (Open question #1 — the gating risk)

The hard question: does gating the binding-array READY on `binding.Ready`
withhold READY from a legitimately-live binding, given that `Ready`
requires `Bound`/`XSKRegistered`, and the shim must steer packets for
RX to flow?

### 4.1 When do Bound / XSKRegistered / heartbeat flip true?

Traced through the worker bringup, **all three become true from worker
bringup alone, with no dependency on inbound packets**:

- `bound`: set in `BindingWorker::new` immediately after
  `open_binding_worker_rings` returns — `live.set_bound(user_fd)` at
  `worker/mod.rs:328`. Socket creation only; no RX.
- `xsk_registered`: set in `register_binding_xsk` →
  `live.set_xsk_registered(true)` at `worker/mod.rs:746`, called from
  `worker_loop` bringup at `worker/mod.rs:472` (and the shared-UMEM path
  at :950) **before** the RX poll loop. This is the syscall that inserts
  the socket FD into the XSKMAP — i.e. it is itself the precondition for
  the kernel to deliver to the socket, and it happens unconditionally.
- heartbeat: touched once at init (`worker/mod.rs:355`) and then at the
  top of **every** `poll_binding` iteration via `maybe_touch_heartbeat`
  (`worker/lifecycle.rs:57`), before the RX batch loop. `heartbeat_fresh`
  (`bpf_map/mod.rs:209`) is true within `HEARTBEAT_STALE_AFTER` (5s) of
  the last touch.

The chronology for a healthy worker is therefore:

```
spawn worker thread
  → open rings           → set_bound(true)
  → register_binding_xsk → set_xsk_registered(true)   [FD now in XSKMAP]
  → enter poll loop      → maybe_touch_heartbeat (every tick)
next coordinator status poll → refresh_bindings → ready = true
```

`ready` flips true after roughly one helper status-poll cycle following
worker spawn, with **zero dependency on RX traffic**. This is exactly the
#1648 Gate-B research finding that **refutes** the maps_sync.go:597
"Bound never becomes true" comment.

### 4.2 Does the shim/liveness probe deadlock?

The ctrl-enable + liveness probe (`maps_sync.go:340–457`) gates
`ctrl.Enabled = 1` on `probeBindingsReady` = `Registered && Armed`
(NOT Bound, NOT Ready). So:

1. ctrl enables and the shim is swapped in as soon as `Registered &&
   Armed` — **unchanged by this plan** (we touch only the binding-array
   READY write, not the ctrl gate).
2. Worker bringup independently flips `Ready` true (per §4.1) within a
   poll cycle.
3. Once `Ready`, the binding-array READY flag is written → shim steers
   RX into XSK → `xskReceiveLive` → `xskLivenessProven`.

No circular dependency: `Ready` does not require the binding-array flag
to be set first; it requires only that the worker completed its own
bringup syscalls. **No deadlock for the steady-state bringup path.**

### 4.3 The one genuine behavioural change — a narrow startup window

There is a real, narrow window where behaviour changes: between
"ctrl enabled (`Registered && Armed`)" and "worker finished bringup
(`Ready` true)". Today site 1 writes READY=1 the instant `Registered &&
Armed`. Under the gate, the binding-array flag stays 0 until `Ready`,
i.e. until the worker has (a) created the socket, (b) registered the FD
in XSKMAP, and (c) had one heartbeat-fresh poll cycle observed by the
coordinator status path.

- **Lower bound today:** READY=1 may be written ~1 poll cycle before the
  socket can actually receive (FD not yet in XSKMAP). In that sub-window
  today's behaviour is itself a micro-blackhole — the shim steers to a
  slot whose FD isn't in the XSKMAP and `bpf_redirect_map` fails
  (`USERSPACE_XSK_MAP.redirect(binding.slot, 0)`, lib.rs:635). The gate
  *removes* that sub-window.
- **Upper bound under the gate:** READY is withheld until `xsk_registered`
  + one fresh heartbeat are observed — bounded by worker bringup latency
  + one helper status-poll interval (sub-second in practice). It cannot
  be withheld forever for a legitimately-live binding because none of the
  three sub-conditions depend on the flag.

**Honest first-transit-latency framing (Codex round-1 finding #1 — the v1
"near zero" claim was WRONG).** Transit is NOT fail-closed until
`xskLivenessProven`. The shim has no liveness gate: once ctrl is enabled
(maps_sync.go:389, on `Registered && Armed`), READY is set, and the
heartbeat is fresh, the shim redirects transit at lib.rs:635 —
*before* Go observes `xskLivenessProven` (which is set only later, after
RX moves, at maps_sync.go:396). So gating on `Ready` adds a real
first-transit delay of up to the next Go status/apply cycle after the
worker becomes XSK-ready (sub-second to ~1 poll interval). That delay is
acceptable — it is precisely the interval during which steering would
otherwise hit a not-yet-registered FD — but it is NOT zero, and the plan
states it as a real (small) cost rather than a wash.

## 5. Crash-detection → READY-clear (Open question #3)

The blackhole the issue targets is the **mid-life** crash: a worker that
was Ready, then panics. This plan must define how READY is *cleared*, not
just gated at write time.

### 5.0 What "blackhole" actually means today (corrected magnitude)

Round-1 reviews (Codex finding #2, AGY finding #2, SMR self-correction)
established that the mid-life crash is **NOT a permanent blackhole** — it
is a **~30s** one, and the control plane actively keeps it open:

- The XDP shim independently fail-closes transit to a slot whose
  heartbeat is stale: lib.rs:425 reads `USERSPACE_HEARTBEAT`, lib.rs:449
  compares against `ctrl.heartbeat_timeout_ms`, and on staleness calls
  `drop_degraded_transit` → `XDP_DROP` (lib.rs:463, 939–946; transit
  drops in both compat and strict). **But** Go programs
  `HeartbeatTimeoutMS: 30000` (maps_sync.go:98/223/291), so the shim's
  in-band clear is **~30s**, not the 5s the shim default would give.
- Worse, the Go control plane keeps the binding-array READY=1 the whole
  time: on master site 1 writes READY from `Registered && Armed`
  (maps_sync.go:596), which stay true after a worker panic, and the
  watchdog (verifyBindingsMapLocked) *re-asserts* READY=1 for any zeroed
  slot whose helper status still shows `Registered && Armed`
  (maps_sync.go:1076 + 1101) — so even if something cleared the flag,
  the watchdog would fight it back to 1. The system cannot fail the slot
  out of the blackhole.

**So the honest win is: reduce dead-worker transit exposure from ~30s
(shim heartbeat timeout, with the watchdog pinning READY=1) to ~5s — or
near-instant with the `Dead` signal below.** This is a real correctness
improvement, NOT redundant; the v1 "permanent → bounded" framing was an
overstatement and the SMR "redundant on same 5s timescale" conclusion was
based on the wrong (5s) shim timeout.

### 5.1 The clear mechanisms this plan installs

1. On panic, `spawn_supervised_worker` (`coordinator/supervisor.rs:98`)
   catches the unwind, sets `runtime_atomics.dead = true`, and the
   thread exits. The worker stops calling `maybe_touch_heartbeat`.
2. The `live` `BindingLiveState` Arc **stays** in `coord.workers.live`
   (it is removed only on explicit reconcile/reset, not on panic). So
   `refresh_bindings` keeps taking `live.snapshot()`, which now returns
   the last-written `bound=true`, `xsk_registered=true`, and a
   **frozen** `last_heartbeat`.
3. Within `HEARTBEAT_STALE_AFTER` (5s) of the worker's last poll tick,
   `heartbeat_fresh(snap.last_heartbeat)` returns false →
   `binding.ready = false` (refresh_bindings.rs:228).
4. The next `applyHelperStatusLocked` / watchdog pass (site 1/3) then
   writes flags=0 for that slot — **READY cleared**, blackhole closed,
   within ≤5s + one poll cycle.

Without this plan, sites 1/3 key on `Registered && Armed`, which is set
in the binding handler and is **never cleared on worker panic** — so the
flag stays 1 forever after a crash. That permanent-vs-bounded difference
is the entire correctness win.

Caveat to surface for review: the explicit rebind/stop_workers handlers
(`server/handlers/rebind.rs`, `stop_workers.rs`,
`coordinator/reconcile/reset.rs`) already clear `ready=false`
synchronously, so orchestrated teardown clears the flag immediately;
only an *unorchestrated panic with no respawn* relies on the
heartbeat-staleness path. (#925 explicitly deferred worker respawn.)

### 5.2 Faster crash signal: gate also on `!Dead` (Codex round-1 finding #3)

There is an immediate, already-parsed crash signal that beats the ~5s
heartbeat path. On panic, `spawn_supervised_worker` sets
`runtime_atomics.dead = true` synchronously (supervisor.rs:114). This is
published per-worker in `ProcessStatus.WorkerRuntime[]` as
`WorkerRuntimeStatus.Dead` (protocol.go:858; surfaced as the
`xpf_userspace_worker_dead` Prometheus gauge, #925 Phase 2). Go already
parses it.

v2 therefore gates the four sites on **`binding.Ready` AND the binding's
worker is not Dead** — `binding.Ready && !deadWorkerIDs[binding.WorkerID]`,
where `deadWorkerIDs` is built once per apply from
`status.WorkerRuntime[]`. `WorkerRuntimeStatus` is keyed by `WorkerID`
(protocol.go:835) and `BindingStatus.WorkerID` (protocol.go:1009) joins
them; multiple bindings may share a worker, so a dead worker clears all
its bindings at once. This collapses the unorchestrated-panic clear from
~5s (heartbeat staleness) to one status-poll cycle (~1s).

`!Dead` is a latency optimization layered on the correctness gate
(`Ready` self-clears in ~5s regardless), but it reuses an already-shipped,
already-parsed field at near-zero cost and directly addresses the
"mid-life crash still blackholes" concern, so it is folded into this PR
rather than deferred. `Dead` is set-only until daemon restart (#925), so
it can never *spuriously* withhold READY from a live binding — it only
ever fires for a worker that genuinely panicked.

## 6. Concrete design

A small helper computes the gate once per apply/watchdog pass:

```go
// bindingForwardingLive reports whether a binding is safe to mark
// READY in the XDP binding array: the helper derived it Ready
// (registered && bound && xsk_registered && heartbeat_fresh) AND its
// worker has not panicked. deadWorkers is built once per pass from
// status.WorkerRuntime[] (keyed by WorkerID).
func bindingForwardingLive(b BindingStatus, deadWorkers map[uint32]bool) bool {
    // Registered && Armed retained: Ready does not imply Armed.
    return b.Registered && b.Armed && b.Ready && !deadWorkers[b.WorkerID]
}
```

`deadWorkers` is assembled at the top of `applyHelperStatusLocked` and
`verifyBindingsMapLocked` from `status.WorkerRuntime` / `m.lastStatus.
WorkerRuntime` (a few entries; cheap). Then at each site:

- **Site 1** (maps_sync.go:596): `if binding.Registered && binding.Armed`
  → `if bindingForwardingLive(binding, deadWorkers)`. Replace the
  now-stale anti-deadlock comment with one documenting the #1648/#1666
  finding (Ready already implies bound+xsk_registered+heartbeat-fresh;
  `!Dead` adds the fast panic clear).
- **Site 2** (maps_sync.go:633): `if binding.Registered && binding.Armed
  && binding.Bound` → `if bindingForwardingLive(binding, deadWorkers)`.
  Tightens and unifies with site 1.
- **Site 3** (maps_sync.go:1076 guard): `if !binding.Registered ||
  !binding.Armed { continue }` → `if !bindingForwardingLive(binding,
  deadWorkers) { continue }`. Flag literal at :1101 unchanged.
- **Site 4** (maps_sync.go:1122 guard): `if !binding.Registered ||
  !binding.Armed || !binding.Bound { continue }` → `if
  !bindingForwardingLive(binding, deadWorkers) { continue }`.

No new fields, no protocol change, no Rust change. The gate reuses the
already-shipped, already-wire-exposed `BindingStatus.Ready`,
`BindingStatus.WorkerID`, and `WorkerRuntimeStatus.Dead`.

**Crash-clear is apply-driven, not watchdog-driven (Codex finding #4).**
`verifyBindingsMapLocked` only *repairs zeroed* entries (it skips entries
where `Flags != 0 || Slot != 0`, maps_sync.go:1095); it never zeros a
populated slot. The actual READY=0 write for a dead worker comes from
`applyHelperStatusLocked`, which writes `Flags: flags` for *every*
binding each pass (maps_sync.go:616/649) with `flags` computed from the
gate. Tightening site 3/4 prevents the watchdog from *re-asserting*
READY=1 for a dead slot (the watchdog-fighting problem in §5.0); the
clear itself is the next `applyHelperStatusLocked` pass.

## 7. Public API preservation

No exported signatures change. `userspaceBindingReady` constant, map
layout, `BindingStatus` wire shape — all unchanged. This is purely the
Go control plane choosing a stronger predicate before an existing map
write.

## 8. Hidden invariants the change must preserve

- **Fail-closed bringup (Open question #2):** the change only ever makes
  the binding-array flag *harder* to set (never easier). It cannot weaken
  fail-closed; worst case it withholds READY slightly longer (§4.3). The
  ctrl-enable path and `drop_degraded_transit`/W-CTRL guard at
  `lib.rs` are untouched.
- **Liveness probe still terminates:** the probe needs RX to flow, which
  needs the flag, which now needs `Ready`. Since `Ready` is reached from
  bringup alone (§4.1), the probe still reaches its RX-flowing state; the
  60s hard-timeout fallback (maps_sync.go:449) remains as the backstop.
- **Watchdog semantics:** site 3/4 repair only rewrites entries the
  helper reports live; tightening to `Ready` means the watchdog will no
  longer "repair" (re-assert READY for) a slot whose worker has died —
  which is precisely the desired blackhole-clear, not a regression.
- **Idle standby (`shouldAutoProveIdleStandbyXSKLocked`):** uses
  `allBindingsBound`, not the binding-array flag; unaffected.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioural regression | LOW–MED | Main change is the §4.3 sub-second startup delay before READY is first written (transit is NOT fail-closed there — the gate adds a real, poll-cycle-bounded first-transit delay, see corrected §4.3). Reviewer judgement needed on whether that window is acceptable. |
| Lifetime / borrow | N/A | Go-side predicate swap; no Rust change. |
| Performance | NONE | One bool read replaces two/three bool reads per binding per poll. |
| Architectural mismatch | LOW | Reuses shipped `Ready` derivation; no new abstraction. The risk is that the issue is solving an already-mitigated problem (Open question #2). |

## 10. Test plan

- `go build ./...`, `go test ./...` (note: `pkg/dataplane/userspace`
  socket tests need `TMPDIR=/tmp` for the <108-char sun_path artifact).
- **Existing test update:** `TestNotifyLinkCycleRebindsAndAppliesHelper
  StatusCompat` (link_cycle_test.go:97) seeds `Registered/Armed/Bound`
  but `Ready:false, XSKRegistered:false` and asserts the array flag ==
  `userspaceBindingReady`. Under the gate this fixture must set
  `Ready:true` to remain a genuinely-live binding. This is a correct
  fixture fix, and demonstrates the gate is exercised.
- **New unit tests:**
  - READY withheld when `Registered && Armed` but `!Ready` (e.g.
    `XSKRegistered:false`) → array flag stays 0 at site 1.
  - READY written when `Ready:true` and worker not Dead → array flag ==
    `userspaceBindingReady`.
  - READY withheld when `Ready:true` but the binding's worker is Dead
    (`WorkerRuntime[WorkerID].Dead == true`) → array flag stays 0
    (the fast panic clear).
  - Watchdog (site 3) does NOT repair/re-assert a slot with `!Ready` or a
    Dead worker.
  - Crash-clear via apply: a binding previously written READY=1, whose
    worker is now Dead (or `Ready:false`), gets flags=0 on the next
    `applyHelperStatusLocked` pass.
- **`make test-failover` — HARD GATE** (touches HA forwarding-ready
  path). VRRP ~60ms, zero-drop failover.
- **Full smoke matrix** on loss userspace cluster: v4+v6 × push+reverse ×
  CoS-off/CoS-on, per-class 5201-5206.
- **No-deadlock proof:** confirm a normal bringup reaches READY promptly
  (cluster comes up, traffic flows) and a simulated XSK-unregistered
  binding does not get READY.

## 11. PLAN-KILL criteria (explicitly on the table)

Kill this plan if any reviewer establishes:

- **(a)** A path where `Ready` is permanently withheld from a
  legitimately-live binding (a real deadlock, not the bounded §4.3
  window). Would be worse than the blackhole. *Current analysis: no such
  path — see §4.1/4.2.*
- **(b)** The blackhole is already fully mitigated elsewhere (e.g. the
  watchdog already clears it, or `drop_degraded_transit`/liveness already
  fails the slot closed on worker death) such that the §4.3 startup-window
  cost buys nothing. *This is the strongest kill candidate — Open
  question #2. Reviewers must verify whether a dead worker's slot is
  already driven READY=0 by some other existing mechanism within a
  comparable window.*
- **(c)** The 5s heartbeat-staleness crash-clear is too slow to matter
  and no faster signal exists, making the "mid-life crash" half of the
  win illusory while the startup window is a real (if small) cost.

## 13. Round-1 plan-review verdicts and dispositions

**AGY (`review-mpre0wvf-wq0j4q`): PLAN-READY.** Verified all function
bodies; confirmed no deadlock, live-Arc-stays-after-panic, watchdog would
fight an out-of-band clear (hence gating site 3/4 is mandatory), and the
gate is strictly safer (avoids steering to a not-yet-registered FD).
Confirmed the shim's in-band timeout is the Go-configured **30s**, so the
fix is real (not mitigated today).

**Codex (`task-mpre0hw1-i0d2rj`): PLAN-NEEDS-MAJOR.** No deadlock, no
existing Go clear path. Four findings, all applied:
- *#1 (applied, §4.3):* v1's "near-zero first-transit latency" was wrong —
  transit is not fail-closed until `xskLivenessProven`; the shim
  redirects at lib.rs:635 once ctrl+READY+heartbeat hold. Reframed as a
  real sub-second/poll-cycle delay.
- *#2 (applied, §5.0):* reframe win as 30s (shim heartbeat) → ~5s
  (`Ready`), not "permanent → bounded."
- *#3 (applied, §5.2, §6):* use the faster `WorkerRuntimeStatus.Dead`
  signal; gate on `Ready && !Dead`.
- *#4 (applied, §6):* crash-clear is apply-driven, not watchdog-driven;
  watchdog only repairs zeroed entries.

**Claude SMR (in-conversation): NEEDS-MAJOR, self-corrected.** Initially
trended KILL on the belief the shim self-heals in 5s (criterion b), which
would make the gate redundant. Codex's verification that Go programs the
shim timeout to **30s** (maps_sync.go:291) invalidated that: the in-band
clear is ~30s and the watchdog pins READY=1 the whole time, so the
~5s/`!Dead` Go gate is a genuine improvement. SMR kill withdrawn.

**Convergence:** NOT a PLAN-KILL. The PLAN-KILL criteria in §11 are
recorded but none fired — (a) no deadlock exists, (b) the blackhole is
NOT already mitigated on a comparable timescale (30s + watchdog-pinned),
(c) the crash-clear is real and `!Dead` makes it near-instant. v2 is
PLAN-READY pending a confirmation pass on the two framing fixes.

## 12. Out of scope

- Worker respawn after panic (#925 deferred indefinitely).
- Any faster-than-heartbeat crash-detection signal (would be a separate
  issue if 5s proves too slow).
- Touching the ctrl-enable / liveness-probe gates themselves.
