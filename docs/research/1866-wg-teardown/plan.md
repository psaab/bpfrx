# #1866 — WG tunnel removal must tear down the control thread + listen port (research plan)

## 1. Status

DRAFT v2 — round-1 findings folded (Codex task-mq9cqldt-fmkk2t,
AGY adversarial-review-mq9bdtem-nlsdwi, Claude SMR r1 — all three
PLAN-NEEDS-CHANGES on v1; every required finding addressed below).
Pending round-2 adversarial review.

Round-1 fold summary:
- Tombstone backoff (Codex 1 / AGY 1 / SMR F4) → §5 Change 1 redesigned.
- Respawn-while-stopped gate (SMR F1) + real `refresh_status` cadence +
  bind/TUN-in-aux-thread invariant (Codex 2) → §5 Change 2, §7.
- Defer-workers reconciliation gap (AGY 2) → new §5 Change 2b (D4).
- Endpoint-set transition logging at BOTH Go publish and Rust apply +
  stale-snapshot republisher suspects (Codex 3 / SMR F3) → §5 Change 3,
  §4c.
- D1 "forever" overstated (Codex 4 / SMR F2) → §4b wording.
- #1868 sequencing mandatory (Codex 5 / AGY Q6) → §4, §11 Q6.
- Tunnel-ID instability (AGY 3) → §10 follow-up issue to file.

## 2. Issue framing

#1703 S2a follow-up, found live during #1736 S2b: committing a config that
removes the `wgN` WireGuard stanza left the userspace WG control thread
running — `ss -uln` still showed `*:51820` with no stanza in the active
config — and the thread kept its engine plus any confirmed session. Hit
twice live. Downstream consequence: a later re-add of the SAME WG identity
spawned a fresh control thread whose `bind_wg_socket` got EADDRINUSE
(correctly no SO_REUSEADDR), the new engine never initiated, and the leaked
thread held a stale confirmed session it will never re-initiate from (S5:
no timers) — tunnel dead until an xpfd restart. The #1736 harness works
around it (fresh keys per run + port-release check + xpfd-restart
fallback); this issue asks for the real teardown: removal-commit ⇒
coordinator stop+join ⇒ socket released. (TUN deletion stays with S6
#1434 per the issue text and the documented S2a limitation in
`pkg/routing/tunnel.go` `applyWireguardTunLocked`.)

## 3. Honest scope/value framing

This is a correctness/lifecycle bug with operator-visible impact (a WG
tunnel that can become permanently dead until daemon restart), not a perf
win. The proposed change is small (~150 LOC of coordinator lifecycle code
+ tests) and entirely off the packet hot path. *If reviewers conclude the
change is wrong-shaped or the residual-unknown stance (see §4c) is
unacceptable, PLAN-KILL is an acceptable verdict.*

## 4. What's already shipped / partially batched

- **#1432 S2a (PR #1739, merged)** — `spawn_wg_control_threads`
  (`userspace-dp/src/afxdp/coordinator/mod.rs:496`) already implements a
  desired-set diff with stop+join for vanished/identity-changed endpoints,
  runs from BOTH initial bring-up (`reconcile/bringup.rs:446`) and
  `refresh_runtime_snapshot` (mod.rs:727, Copilot C1). `stop_inner`
  (mod.rs:254-262) stops+joins+clears all WG control threads on teardown
  (the #1769 JOIN-in-stop-paths precedent is already honored).
- **#1868 (open, 3-of-4 MERGE-READY)** — #1736 S2b harness + three S2a
  datapath fixes. **Sequencing is MANDATORY, not cosmetic (Codex 5)**:
  master still drops interface-level WG tunnels in
  `collectAppliedTunnels` (`pkg/daemon/daemon_run.go:93`) so the TUN is
  never created on the live path without #1868; and #1868 changes
  `bind_wg_socket` to return `(UdpSocket, bool)` and adds
  `wg_send_to`/`canonicalize_endpoint`. The #1866 implementation lands
  ONLY after #1868 merges, rebased over those signatures (the factored
  spawn helper must thread `socket_is_v6` through unchanged).
- **#1865 (queued behind this merge)** — WG telemetry counters. This plan
  adds NO counters; what it adds is *lifecycle logging* (not telemetry —
  Codex Q6 wording), so #1865 rebases cleanly.

### 4b. Evidence inventory from this research pass (what is verified vs unknown)

Verified in-process (scratch tests, run on this branch, not committed):

- **V1 — coordinator prune works.** A `Coordinator` given a snapshot with
  one WG endpoint spawns the control thread (map entry present); a second
  `refresh_runtime_snapshot` with the endpoint removed prunes the map AND
  the listen port becomes bindable again (thread joined, socket dropped).
  Test sketch formalized in §9 test 1.
- **V2 — config compile drops the tunnel.** `delete groups node0
  interfaces wg0` + `CompileConfigForNode(tree, 0)` removes `wg0` from
  `cfg.Interfaces.Interfaces`; `buildTunnelEndpointSnapshots` builds only
  from cfg, so the published snapshot loses the endpoint.
- **V3 — removal is a same-plan apply.** Tunnel interfaces are excluded
  from the binding-plan key on both sides (`userspaceSkipsIngressInterface`
  in `pkg/dataplane/userspace/maps_sync.go:1497`,
  `include_userspace_binding_interface` in
  `userspace-dp/src/server/helpers.rs:618`), so a wg-only change takes the
  `refresh_runtime_snapshot` path in `server/handlers/snapshot.rs` — the
  exact path V1 proves correct.
- **V4 — Go→helper delivery did not fail live.** Every commit reaches
  `d.dp.ApplyConfig` unconditionally (`pkg/daemon/daemon_apply.go:457`);
  fw0's journal for the S2b window (Jun 9–11) contains ZERO
  "apply config failed" and a continuous `CTRL_REQ: apply_snapshot`
  generation stream. (Codex note: could not independently re-verify the
  journal from its sandbox; the grep commands and outputs are recorded in
  the research transcript.)
- **V5 — Arc-identity ABA reviewed and cleared.** The stale check compares
  `Arc::as_ptr` identities; a new engine is always allocated while the
  previous one is still alive in `self.forwarding` (build-with-previous
  ordering in `refresh_runtime_snapshot`), so cross-generation address
  reuse cannot produce a false "unchanged" match.

Confirmed defects (by code reading, independently re-verified by Codex +
AGY in round 1 with quoted lines):

- **D1 — a dead thread's map entry blocks respawn under unchanged
  identity.** `wg_control_loop` exits early on `bind_wg_socket`
  EADDRINUSE, `open_tun` failure, or nonblocking-setup failure
  (wg_control.rs:93-127), but its `wg_control_threads` entry (with the
  recorded engine ptr) remains. On every later refresh with an unchanged
  identity, `populate_wg_engines` reuses the engine Arc ⇒
  `desired.get(id) == recorded ptr` ⇒ not stale; `contains_key` ⇒ no
  spawn. The tunnel stays dead **until an identity change, a
  binding-plan-changing commit (full reconcile heals via
  `tear_down → stop_inner` clearing the map, teardown.rs:28 +
  mod.rs:262), or a daemon restart** (Codex 4 / SMR F2 precision) — none
  of which normally happen, so operationally this matches the observed
  "new engine never initiates" persistence after one EADDRINUSE.
- **D2 — lifecycle reconciles only at snapshot applies.** Between applies
  nothing re-checks thread liveness; a transient bind/TUN failure is never
  retried.
- **D3 — zero teardown observability.** Stop+join, spawn, and early-exit
  produce no logs (bind/TUN failures go only to the bounded exception
  ring). This is why the live triage could only say the snapshot
  "appears to retain" the endpoint.
- **D4 — defer-workers reconciliation gap (AGY 2).** On a NOT-same-plan
  apply with `defer_workers == true`, `handlers/snapshot.rs:109-115`
  stores the snapshot but skips `reconcile_status_bindings`, so the
  coordinator's forwarding (and therefore the WG desired set) is never
  updated. A WG endpoint removed in such an apply leaks its thread+port
  at least until the deferred bring-up's full reconcile — and indefinitely
  if the follow-up apply never comes.

### 4c. Residual unknown (stated honestly) + diagnosis levers

The exact live mechanism by which the delete-commit left the ORIGINAL
thread running is NOT reproduced in-process: every layer I could isolate
(compile, snapshot build, same-plan routing, coordinator prune, delivery)
passes. Codex r1 concurs the ordinary prune path is deterministic and the
live evidence therefore points at a **stale snapshot/publisher path**.
Suspect inventory for a recurrence:

- D4 (defer-workers gap) — closed by Change 2b.
- The two `*m.lastSnapshot`-copying republishers, which can re-publish
  STALE `TunnelEndpoints` under a HIGHER generation if interleaved with a
  failed/partial apply: `UpdatePolicyScheduleState`
  (`pkg/dataplane/userspace/manager.go:725`) and the ip-monitoring
  route-overlay publisher (`manager.go:840`) (Codex 3).
- Config-DB stanza revival at boot (documented by the #1736 harness
  preflight) re-spawning an engine the operator believed deleted.

The plan therefore (a) ships deterministic self-healing so the
user-visible contract — *re-add with the same identity must succeed* —
holds under ANY upstream trigger, and (b) adds endpoint-set transition
logging at BOTH the Go publish boundary and the Rust apply boundary
(Change 3), so ONE journal capture of a recurrence pins the layer
(snapshot-content vs prune-skip vs stale-republisher). Reviewers who find
this inversion (harden before full root-cause) unacceptable should say so
— PLAN-KILL or "diagnose-first" reshaping are both on the table.

## 5. Concrete design

Production changes confined to
`userspace-dp/src/afxdp/coordinator/` (mod.rs, wg_control.rs),
`userspace-dp/src/server/` (helpers.rs / handlers/snapshot.rs call
sites), and ~10 lines of Go logging in
`pkg/dataplane/userspace/manager.go`. No wire/protocol changes.

### Change 1 (fixes D1) — tombstone entries: liveness-aware prune + respawn with durable backoff

Map value becomes a tombstone-capable entry; **the entry is removed ONLY
when the endpoint leaves the desired set** — a finished thread leaves a
tombstone that preserves the backoff stamp (Codex 1 / AGY 1):

```rust
struct WgControlEntry {
    /// Live (or finished-but-unswept) thread + the engine Arc address it
    /// was spawned against. None = tombstone: no thread, entry retained
    /// for backoff continuity.
    thread: Option<(LocalTunnelSourceHandle, usize)>,
    /// Stamped at EVERY spawn attempt (success or failure), before the
    /// outcome is known.
    last_spawn_attempt_ns: u64,
}
// wg_control_threads: BTreeMap<u16, WgControlEntry>
```

`spawn_wg_control_threads` (apply-time) becomes three passes, in order:

1. **Finished sweep**: for entries whose `thread` is Some but
   `JoinHandle::is_finished()` (or join handle already taken) — join
   (instant: thread done), set `thread = None`, keep the entry + stamp,
   log per Change 3.
2. **Stale prune** (existing semantics): entries whose id is absent from
   the desired set, or whose recorded engine ptr differs — stop+join the
   thread if live, then **remove the entry entirely** (tombstones for
   vanished endpoints are removed here too, so the map cannot grow
   unboundedly).
3. **Spawn pass**: for desired endpoints whose entry is missing or a
   tombstone — respect the backoff (`now - last_spawn_attempt_ns >= 3s`;
   a missing entry has no backoff and spawns immediately), stamp, spawn
   via the factored `spawn_one_wg_control_thread(&mut self, id)`.

Backoff applies to apply-time respawns as well (SMR F4: applies arrive in
bursts during route churn; a persistently-failing bind must not attempt
per-FIB-bump).

### Change 2 (fixes D2) — periodic self-heal, correctly gated (Option 2)

`Coordinator::reconcile_wg_control_liveness(&mut self)` = passes 1+3 of
Change 1 (finished sweep + backoff-gated spawn; the stale prune stays
apply-time-only because desired-set changes only arrive with snapshots).
Call site is the SERVER layer, NOT inside `refresh_bindings`:

```rust
// server/helpers.rs refresh_status():
if should_run_afxdp(&state.status) {
    state.afxdp.reconcile_wg_control_liveness();
}
```

- **Stop-gate (SMR F1)**: `should_run_afxdp` false ⇒ no sweep ⇒ a
  disarmed/stopped helper never re-binds WG ports. Preserves the existing
  `reconcile_status_bindings → stop()` semantics exactly.
- **Real cadence (Codex 2)**: `refresh_status` runs on EVERY
  non-suppressed control response (handlers/mod.rs:164), not just the 1/s
  Go status poll — so the sweep itself must be (and is) O(#wg endpoints)
  of `is_finished()` checks with no syscalls, the respawn is backoff-gated
  per id, AND at most one spawn attempt fires per invocation.
- **Thread-work invariant (Codex 2)**: the coordinator only ever calls
  `thread::spawn` (via `spawn_supervised_aux`); `bind_wg_socket` +
  `open_tun` continue to run INSIDE the spawned aux thread
  (wg_control.rs:93/115), never on the control-socket thread. This is
  already the shipped shape; the plan pins it as an invariant (§7).

**Option 1 (fallback if reviewers reject the tick):** Change 1 only —
self-heal at the next snapshot apply. **Recommendation: Option 2.**

### Change 2b (fixes D4) — removal propagation on the defer-workers path

In `handlers/snapshot.rs`, the NOT-same-plan + `defer_workers` branch
(currently: store snapshot, log, skip reconcile) additionally calls a
NARROW coordinator method:

```rust
guard.afxdp.prune_wg_control_threads_for_snapshot(&snapshot);
```

which stops+joins+removes entries whose endpoint id is absent from (or no
longer a hydratable WG endpoint in) `snapshot.tunnel_endpoints` —
mirroring the populate gates (mode == "wireguard", id != 0, ifindex > 0,
listen_port != 0, decodable keys). It does NOT touch `self.forwarding`,
does NOT spawn (bring-up stays deferred — workers AND new WG threads wait
for the real reconcile), and does NOT mutate any worker-visible state —
so the reason defer_workers exists (no worker churn while RETH MAC is
pending) is untouched, while a REMOVED tunnel's thread+port still die at
the apply that removed it.

### Change 3 (fixes D3) — lifecycle + endpoint-set transition logging (no counters)

Rare, state-transition-only logging (complies with the logging rules):

- **Rust apply boundary**: in `refresh_runtime_snapshot` (and the
  reconcile snapshot phase), when the WG endpoint id set (id +
  listen_port pairs) differs from the previous forwarding state, eprintln
  `old ⇒ new`. Silent when unchanged (the common case).
- **Rust lifecycle**: eprintln on stale stop+join (id, tunnel, reason:
  `removed|engine_changed|finished`), on spawn attempt, on spawn-side
  early exit (wg_control_loop logs its own exit reason — bind/TUN
  failures additionally still land in the exception ring), and on
  tombstone-respawn.
- **Go publish boundary (Codex 3)**: in the snapshot-publish paths of
  `pkg/dataplane/userspace` (Apply, syncSnapshotLocked, and the two
  `*m.lastSnapshot` republishers), `slog.Info` when the WG endpoint set
  of the outgoing snapshot differs from the previously published one.
  This is what disambiguates "Go published a stale set" from "Rust
  skipped the prune" in one capture.

Counters are explicitly deferred to #1865.

## 6. Public API preservation

No public/wire surface changes. `ControlRequest`/`ControlResponse`,
`ConfigSnapshot`, and all Go DTOs untouched. Coordinator-internal map type
changes only (`wg_control_threads: BTreeMap<u16, WgControlEntry>`);
`spawn_wg_control_threads` keeps its signature; `stop_inner` keeps its
stop→join→clear ordering (clearing removes tombstones too — restart from
a clean slate is correct there).

## 7. Hidden invariants the change must preserve

- **Single-mutex lifecycle**: ALL lifecycle mutation (apply handlers,
  reconcile, the new sweep) runs under the single
  `Arc<Mutex<ServerState>>` guard (handlers/mod.rs:82) on the
  control-socket thread — this is the structural reason two live threads
  can never race one port in-process (SMR F5 / Codex Q5).
- **Join-before-bind ordering**: a stale/finished entry is joined before
  any spawn for the same id, within the same guarded critical section.
- **Bind/TUN work stays in the aux thread** (Codex 2): the control-socket
  thread only does `thread::spawn`; socket bind + TUN open run inside the
  spawned thread. Never move them onto the control thread.
- **Stop-gate**: no WG lifecycle activity (sweep/respawn) while
  `should_run_afxdp` is false; `stop_inner`'s stop→join→clear contract
  (#1769) retained verbatim.
- **Status-path latency**: the sweep is `is_finished()`-only (no
  syscalls); joins only on finished threads (instant); ≤1 spawn attempt
  per invocation, 3s-backoff-gated per id.
- **wgN TUN ownership**: helper never deletes the TUN (Go owns it; AGY
  Hazard B reload stability). Unchanged.
- **Engine Arc reuse / TAI64N**: respawn binds the CURRENT engine Arc from
  `forwarding.wg_engines` — never constructs an engine; TAI64N
  monotonicity and session-state semantics untouched.
- **No hot-path involvement**: workers never touch the map; no allocation
  on any per-packet path.
- **Exception-ring discipline**: bounded ring; backoff prevents flooding;
  transition logs fire only on set changes.
- **defer_workers contract**: Change 2b removes only; it must not spawn,
  must not touch `self.forwarding`, must not mutate worker-visible state.

## 8. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Additive lifecycle handling; existing prune/spawn flows preserved; stop-gate keeps disarmed semantics; identity semantics untouched |
| Lifetime / borrow-checker | LOW | `&mut self` coordinator methods over an owned map; no new shared state |
| Performance regression | NONE→LOW | O(few) `is_finished()` checks per control response + bounded respawns; zero hot-path code |
| Architectural mismatch | LOW | Follows the existing reconcile-against-desired-set pattern (#1432 S2a) and the #1769 join-in-stop discipline |

## 9. Test plan

New Rust tests (in-process, no root needed — V1 sketch validated this
session):

1. **Removal prune** (validated): snapshot-with-WG → thread spawned →
   empty snapshot → map empty AND port bindable again.
2. **EADDRINUSE regression (rigged old behavior)**: pre-bind the listen
   port from the test → refresh spawns a thread that exits on EADDRINUSE
   → assert tombstone (entry present, `thread == None` after sweep) →
   drop the test socket → next refresh/tick (past backoff) respawns and
   the new thread binds (assert via map + exception-ring contents where a
   port probe would race).
3. **Tombstone backoff**: with the port still externally held, repeated
   `reconcile_wg_control_liveness` calls within 3s produce NO additional
   spawn attempts (assert spawn-attempt stamp unchanged / exception count
   stable); after 3s, exactly one more attempt.
4. **Remove→re-add same identity**: WG snapshot → empty snapshot → same
   WG snapshot; assert a fresh entry + spawn attempt (the #1866 headline
   contract).
5. **Stop-gate**: after `stop()`, `refresh_status`-equivalent sweeps must
   NOT respawn (no map entries, no bind) while stopped.
6. **Defer-workers prune (Change 2b)**: simulate the defer branch — WG
   thread running, apply a defer_workers snapshot WITHOUT the endpoint →
   thread stopped+joined, port released, forwarding untouched, nothing
   spawned.
7. Existing wg/coordinator suites green; reconcile_peers_snapshot and
   worker_queue concurrent_recovery are known ledger flakes —
   standalone-prove before attributing; `install_session_serializes`
   wedge precedent (>10min ⇒ stuck-futex check, kill, rerun, document).

Go tests: `buildTunnelEndpointSnapshots` drops a removed wg interface;
group-delete compile regression (V2 sketch formalized) if not already
covered; WG endpoint-set transition log fires on publish-set change
(table test on the diff helper, not on slog output).

Gates (unmasked): `cargo build --release`; FULL `cargo test --release`
awk-aggregated over ALL "test result" lines; plain debug `cargo test` for
the wg module; `go test ./...` with `echo $?` each. Never `cargo fmt` the
focused files.

Live validation (parent's smoke, post-merge): a wg add→remove→re-add
cycle on a VM — after #1868 merges the `test/incus/wg-interop.sh`
teardown port-release check is the canary, and its P1 leak-workaround
restart should become UNNECESSARY (taint counter stays 0). Standalone VM
preferred; loss cluster only under
`flock /tmp/xpf-cluster.lock sg incus-admin -c "..."` and only when the
#1736 lane is idle.

## 10. Out of scope (explicitly)

- wgN TUN deletion on config removal — S6 grammar/teardown work (#1434),
  per the issue text and the documented S2a limitation.
- WG telemetry counters — #1865 (queued behind this merge; this plan adds
  lifecycle logs only).
- S5 timers / engine-driven re-initiation of stale sessions.
- **Tunnel-endpoint ID instability (AGY 3)**: `buildTunnelEndpointSnapshots`
  assigns sequential ids over alphabetically-sorted interfaces, so
  adding/removing one tunnel renumbers the others; for WG that defeats
  the identity-reuse check (engine rebuilt ⇒ sessions reset on UNRELATED
  commits), and for GRE it shifts the id HA session sync carries.
  Pre-existing, multi-tunnel-scope defect — **file a follow-up issue at
  /engineer time** (name-keyed or stable-id allocation); not fixed here.
- Go-side apply-error retry semantics (a failed `Manager.Apply` leaves
  `lastSnapshot` at the previous generation so the status loop never
  retries the new content) and the stale-`*m.lastSnapshot` republisher
  hardening — general robustness; the Change-3 publish-boundary logging
  will catch them in the act if they are the live trigger; file follow-up
  on evidence.
- Kernel-wg port-collision semantics (EADDRINUSE against a host wgX
  remains a hard error per attempt — durable 3s backoff retries it
  indefinitely; all three reviewers endorsed no give-up cap).

## 11. Open questions for adversarial review (each may justify PLAN-KILL)

1. **Tick placement (round-2 check)**: with the stop-gate at
   `refresh_status`, the per-response cadence bound (≤1 spawn/invocation,
   3s/id backoff, `is_finished()`-only sweep), is any latency or
   reentrancy hazard left on the control-socket thread?
2. **Residual-unknown stance** (§4c): with D4 closed, the two stale
   republisher suspects named, and transition logging at both boundaries,
   is harden+instrument now sufficient, or does any reviewer still see a
   concrete path the plan neither fixes nor would catch in one capture?
3. **Tombstone lifecycle**: tombstones are removed when the endpoint
   leaves the desired set (pass 2). Any leak/growth path left (e.g.
   endpoint flapping in/out under backoff)?
4. **Change 2b gates**: is mirroring the populate gates (mode/id/ifindex/
   port/keys) in `prune_wg_control_threads_for_snapshot` the right
   desired-set definition for the defer branch, or should it prune ONLY
   on absent id (narrower) to avoid killing a thread for a transiently
   malformed snapshot row?
5. **Backoff constant**: 3s per id — too aggressive/lax for the
   EADDRINUSE-against-kernel-wgX misconfiguration case (one exception
   entry per 3s, forever)?
6. **Sequencing vs #1868**: rebase plan confirmed against its
   `(UdpSocket, bool)` bind signature + `wg_send_to`; anything else in
   #1868's final form the factored spawn helper must preserve?
