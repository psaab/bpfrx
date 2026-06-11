# #1866 — WG tunnel removal must tear down the control thread + listen port (research plan)

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR, research mode — no PR).

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
win. The proposed change is small (~100 LOC of coordinator lifecycle code
+ tests) and entirely off the packet hot path. *If reviewers conclude the
change is wrong-shaped or the residual-unknown stance (see §5.0) is
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
  datapath fixes, including the `collectAppliedTunnels` fix without which
  the wgN TUN was never created on the live path. **This plan's
  implementation PR must land AFTER #1868** (same-file `wg_control.rs`
  proximity; and the live repro needs its TUN fix).
- **#1865 (queued behind this merge)** — WG telemetry. This plan
  deliberately adds NO new counters so #1865 rebases cleanly; lifecycle
  observability here is `eprintln!` + the existing exception ring only.

### 4b. Evidence inventory from this research pass (what is verified vs unknown)

Verified in-process (scratch tests, run on this branch, not committed):

- **V1 — coordinator prune works.** A `Coordinator` given a snapshot with
  one WG endpoint spawns the control thread (map entry present); a second
  `refresh_runtime_snapshot` with the endpoint removed prunes the map AND
  the listen port becomes bindable again (thread joined, socket dropped).
  Test sketch reproduced in §9.
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
  generation stream.
- **V5 — Arc-identity ABA reviewed and cleared.** The stale check compares
  `Arc::as_ptr` identities; a new engine is always allocated while the
  previous one is still alive in `self.forwarding` (build-with-previous
  ordering in `refresh_runtime_snapshot`), so cross-generation address
  reuse cannot produce a false "unchanged" match.

Confirmed defects (by code reading, regardless of the live trigger):

- **D1 — a dead thread's map entry permanently blocks respawn.**
  `wg_control_loop` exits early on `bind_wg_socket` EADDRINUSE,
  `open_tun` failure, or nonblocking-setup failure (wg_control.rs:93-127),
  but its `wg_control_threads` entry (with the recorded engine ptr)
  remains. On every later refresh with an unchanged identity,
  `populate_wg_engines` reuses the engine Arc ⇒ `desired.get(id) ==
  recorded ptr` ⇒ not stale; `contains_key` ⇒ no spawn. The tunnel is
  dead until an identity change or daemon restart. This is exactly the
  observed "the NEW engine never initiates" persistence after one
  EADDRINUSE.
- **D2 — lifecycle reconciles only at snapshot applies.** Between commits
  nothing re-checks thread liveness; a transient bind/TUN failure is never
  retried.
- **D3 — zero teardown observability.** Stop+join, spawn, and early-exit
  produce no logs (bind/TUN failures go only to the bounded exception
  ring). This is why the live triage could only say the snapshot
  "appears to retain" the endpoint.

### 4c. Residual unknown (stated honestly)

The exact live mechanism by which the delete-commit left the ORIGINAL
thread running is NOT reproduced in-process: every layer I could isolate
(compile, snapshot build, same-plan routing, coordinator prune, delivery)
passes. Plausible remaining triggers are environmental sequences the
S2b runs are known to have hit (config-DB revival of the stanza at boot,
helper restarts mid-run, rapid commit interleavings) compounded by D1/D3
making any single transient permanent and invisible. The plan therefore
(a) ships deterministic self-healing so the user-visible contract —
*re-add with the same identity must succeed* — holds under ANY upstream
trigger, and (b) adds the lifecycle logging + a live diagnosis runbook so
a recurrence pins the layer in one capture. Reviewers who find this
inversion (harden before full root-cause) unacceptable should say so —
PLAN-KILL or "diagnose-first" reshaping are both on the table.

## 5. Concrete design

Three production changes, all confined to
`userspace-dp/src/afxdp/coordinator/` (mod.rs + wg_control.rs); no wire,
protocol, or Go changes.

### Change 1 (fixes D1) — liveness-aware prune + respawn at apply time

Extend the map value to a named struct and sweep finished threads before
the desired-set diff:

```rust
struct WgControlThread {
    handle: LocalTunnelSourceHandle,
    engine_ptr: usize,
    last_spawn_attempt_ns: u64,  // Change 2 backoff
}
// in spawn_wg_control_threads, BEFORE the stale diff:
let finished: Vec<u16> = self.wg_control_threads.iter()
    .filter(|(_, t)| t.handle.join.as_ref().is_none_or(|j| j.is_finished()))
    .map(|(id, _)| *id).collect();
for id in finished {
    if let Some(mut t) = self.wg_control_threads.remove(&id) {
        if let Some(join) = t.handle.join.take() { let _ = join.join(); } // instant: thread done
        eprintln!("xpf-userspace-dp: wg control thread for endpoint {id} exited; will respawn if still configured");
    }
}
```

The existing stale diff and spawn loop then run unchanged — a finished
thread whose endpoint is still desired respawns naturally; one whose
endpoint vanished is simply dropped.

### Change 2 (fixes D2) — periodic self-heal on the status poll (Option 2)

A new `Coordinator::reconcile_wg_control_liveness(&mut self)` containing
the finished-sweep + spawn loop factored from Change 1 (shared helper
`spawn_one_wg_control_thread(&mut self, id)`), called from
`refresh_bindings` (already `&mut self`, driven by the existing 1/s
status poll — NO new control-socket request, honoring the
control-socket-contention rule). Per-id backoff: skip respawn unless
`now - last_spawn_attempt_ns >= 3s`, so a persistently-held port produces
at most one bind attempt + one exception entry per 3s, not a storm. The
sweep is O(#wg endpoints) with `is_finished()` only — no syscalls unless
a respawn fires.

**Option 1 (fallback if reviewers reject the tick):** Change 1 only —
self-heal happens at the next snapshot apply (any commit / FIB refresh)
instead of within seconds. Cheaper, but an EADDRINUSE'd tunnel stays dead
until some other commit lands. **Recommendation: Option 2.**

### Change 3 (fixes D3) — lifecycle logging (no counters)

`eprintln!` (journald via stderr; rare, state-transition-only — complies
with logging rules) at: stale stop+join (id, tunnel, reason:
`removed|engine_changed|finished`), spawn attempt, spawn failure (bind /
TUN reasons already recorded in the exception ring — add the stderr
line), and thread clean exit (in `wg_control_loop` itself on loop exit).
Counters are explicitly deferred to #1865.

### Out-of-scope-but-recorded upstream candidates

- `UpdatePolicyScheduleState` republishes `*m.lastSnapshot` (stale
  `TunnelEndpoints` if interleaved with a tunnel-removal commit) — narrow
  race, self-corrects at the next apply once D1 is fixed; noted for the
  reviewers, not fixed here.
- Go-side apply-error retry semantics (a failed `Manager.Apply` leaves
  `lastSnapshot` at the previous generation so the status loop never
  retries the new content) — general robustness issue, not WG-specific;
  V4 shows it did not fire live. File separately if reviewers want it.

## 6. Public API preservation

No public/wire surface changes. `ControlRequest`/`ControlResponse`,
`ConfigSnapshot`, and all Go DTOs untouched. Coordinator-internal map type
changes only (`wg_control_threads: BTreeMap<u16, WgControlThread>`);
`spawn_wg_control_threads` keeps its signature; `stop_inner` keeps its
stop→join→clear ordering.

## 7. Hidden invariants the change must preserve

- **Join-before-bind ordering**: a stale/finished entry is joined before
  any spawn for the same id, so the port is provably released before the
  new bind (within one process).
- **Status-poll latency**: the 1/s liveness sweep must not block — joins
  happen only on `is_finished()` threads (instant) and respawn is
  backoff-gated; the apply-time stale join is bounded by the control
  loop's 1ms idle sleep + nonblocking I/O (no unbounded blocking sites in
  `wg_control_loop`).
- **wgN TUN ownership**: helper never deletes the TUN (Go owns it; AGY
  Hazard B reload stability). Unchanged.
- **Engine Arc reuse / TAI64N**: respawn binds the CURRENT engine Arc from
  `forwarding.wg_engines` — never constructs an engine; TAI64N
  monotonicity and session state semantics are untouched.
- **No hot-path involvement**: workers never touch the map; all changes
  are coordinator-thread-only; no allocation on any per-packet path.
- **Exception-ring discipline**: bounded ring, backoff prevents flooding.
- **stop_inner contract (#1769)**: stop+join+clear retained verbatim;
  Change 1/2 only ADD detection of already-exited threads.

## 8. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Additive lifecycle handling; existing prune/spawn flows preserved; identity semantics untouched |
| Lifetime / borrow-checker | LOW | `&mut self` coordinator methods over an owned map; no new shared state |
| Performance regression | NONE | O(few) `is_finished()` checks at 1/s + at applies; zero hot-path code |
| Architectural mismatch | LOW | Follows the existing reconcile-against-desired-set pattern (#1432 S2a) and the #1769 join-in-stop discipline |

## 9. Test plan

New Rust tests (in-process, no root needed — sketches V1-validated today):

1. **Removal prune** (validated): snapshot-with-WG → thread spawned →
   empty snapshot → map empty AND port bindable again.
2. **EADDRINUSE regression (rigged old behavior)**: pre-bind the listen
   port from the test → refresh spawns a thread that exits on EADDRINUSE
   → assert the entry is swept (Change 1) and a respawn attempt occurs on
   the next refresh/tick → drop the test socket → assert the next attempt
   binds (port now held by the helper thread until it fails `open_tun`;
   assert via the map + exception-ring contents rather than a racy port
   probe where needed).
3. **Remove→re-add same identity**: WG snapshot → empty snapshot → same
   WG snapshot; assert a fresh thread entry exists and the port is
   re-held/observably re-bound.
4. **Liveness-tick respawn (Option 2)**: kill path via a finished thread
   (EADDRINUSE rig), call `refresh_bindings`, assert backoff-gated respawn.
5. Existing wg/coordinator suites green; reconcile_peers_snapshot and
   worker_queue concurrent_recovery are known ledger flakes —
   standalone-prove before attributing; `install_session_serializes`
   wedge precedent (>10min ⇒ stuck futex check) honored.

Go tests: `buildTunnelEndpointSnapshots` drops a removed wg interface;
group-delete compile regression (V2 sketch formalized) if not already
covered.

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
  logs only to avoid rebase friction).
- S5 timers / engine-driven re-initiation of stale sessions.
- Go-side apply-error retry semantics (general; V4 shows not the live
  trigger).
- Kernel-wg port-collision semantics (EADDRINUSE against a host wgX
  remains a correct hard error — backoff means we retry it, which is
  acceptable: one exception per 3s while misconfigured; reviewers see Q3).

## 11. Open questions for adversarial review (each may justify PLAN-KILL)

1. **Tick placement**: is riding `refresh_bindings` (1/s status poll,
   coordinator `&mut`) acceptable for the liveness sweep, or does respawn
   work (socket bind + TUN open, rare) on the control-socket thread
   violate a latency budget I'm not seeing? If so: Option 1 only?
2. **Residual-unknown stance** (§4c): is hardening+observability without
   a pinned live root cause the right lean, or must a live repro come
   first? A diagnose-first verdict reshapes this into an
   instrumentation-only PR (#1782 PR-1 precedent).
3. **Retry-forever on EADDRINUSE**: with a host kernel wgX legitimately
   holding the port, the 3s backoff retries indefinitely (one exception
   entry per attempt). Should there be a give-up cap, or is
   retry-until-config-changes the correct Junos-like behavior?
4. **`is_finished()` sufficiency**: any scenario where the supervised
   thread is logically dead but `is_finished()` is false (e.g. wedged in
   a nonblocking loop)? I claim no blocking sites exist in
   `wg_control_loop`; verify.
5. **Map-entry semantics for spawn-failure**: Change 1 removes the entry
   only at the NEXT sweep; should the spawn path instead probe-join
   immediately after spawn (racy) or record a tombstone? I argue the
   sweep is the clean shape; verify no window where two live threads can
   race one port (join-before-spawn must hold across BOTH Change-1 and
   Change-2 call sites).
6. **Sequencing vs #1868**: implementation lands after #1868 merges and
   rebases onto its `wg_control.rs`; any conflict hazard the plan misses
   (e.g. its `wg_send_to`/`canonicalize_endpoint` refactors)?
