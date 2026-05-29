# #1666 — Gate the BPF READY write on helper-reported binding liveness

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY +
Claude SMR). PLAN-KILL is an acceptable verdict and is explicitly on
the table for this work (see §11).

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

- `Ready` already implies `Bound` **and** `XSKRegistered` **and** a
  fresh heartbeat. The issue's proposed `Ready && XSKRegistered` is
  redundant — `Ready` alone is the right and complete gate. The plan
  uses **`binding.Ready`** as the single gate at all four sites.
- Gating sites 1/3 on `Ready` is strictly more conservative than the
  current `Registered && Armed`, and strictly more conservative than
  the alias sites' `Registered && Armed && Bound` (it adds
  `xsk_registered` + heartbeat freshness on top of `Bound`).

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
  slot whose FD isn't in the XSKMAP. The gate *removes* that sub-window.
- **Upper bound under the gate:** READY is withheld until `xsk_registered`
  + one fresh heartbeat are observed — bounded by worker bringup latency
  + one helper status-poll interval (sub-second in practice). It cannot
  be withheld forever for a legitimately-live binding because none of the
  three sub-conditions depend on the flag.

This window is the crux reviewers must weigh: it is **strictly safer**
(READY now means "a worker can actually receive"), at the cost of a
sub-second-longer "transit fail-closed" startup window. Because transit
is *already* fail-closed until `xskLivenessProven` (which itself needs
RX, which needs the flag), the practical net change to first-transit
latency is near zero — the flag must be set before RX can be proven
either way.

## 5. Crash-detection → READY-clear (Open question #3)

The blackhole the issue targets is the **mid-life** crash: a worker that
was Ready, then panics. This plan must define how READY is *cleared*, not
just gated at write time.

**An existing signal already drives the clear — no new mechanism needed:**

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
only an *unorchestrated panic with no respawn* relies on the 5s
heartbeat-staleness path. (#925 explicitly deferred worker respawn.)

## 6. Concrete design

Single-line gate change at each of the four sites — replace the
liveness predicate with `binding.Ready`:

- **Site 1** (maps_sync.go:596): `if binding.Registered && binding.Armed`
  → `if binding.Ready`. Replace the now-stale anti-deadlock comment with
  a comment documenting the #1648/#1666 finding (Ready already implies
  bound+xsk_registered+heartbeat-fresh; this is the crash-clear gate).
- **Site 2** (maps_sync.go:633): `if binding.Registered && binding.Armed
  && binding.Bound` → `if binding.Ready`. Tightens (adds xsk_registered
  + heartbeat) and unifies with site 1.
- **Site 3** (maps_sync.go:1076 guard): `if !binding.Registered ||
  !binding.Armed { continue }` → `if !binding.Ready { continue }`. The
  flag literal at :1101 is unchanged.
- **Site 4** (maps_sync.go:1122 guard): `if !binding.Registered ||
  !binding.Armed || !binding.Bound { continue }` → `if !binding.Ready {
  continue }`.

No new fields, no protocol change, no Rust change. The gate reuses the
already-shipped, already-wire-exposed `BindingStatus.Ready`.

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
| Behavioural regression | LOW–MED | Only change is the §4.3 sub-second startup window; transit is already fail-closed there. Reviewer judgement needed on whether that window is acceptable. |
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
  - READY written when `Ready:true` → array flag == `userspaceBindingReady`.
  - Watchdog (site 3) does NOT repair/re-assert a slot with `!Ready`.
  - Crash-clear: a binding that was Ready then reports `Ready:false`
    (heartbeat-stale proxy) → next apply writes flags=0.
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

## 12. Out of scope

- Worker respawn after panic (#925 deferred indefinitely).
- Any faster-than-heartbeat crash-detection signal (would be a separate
  issue if 5s proves too slow).
- Touching the ctrl-enable / liveness-probe gates themselves.
