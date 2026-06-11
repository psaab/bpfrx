# PR #1872 — Claude SMR hostile code review, round 1

Reviewer: Claude (domain SMR: dataplane lifecycle, OS/CPU, SW design).
Target: engineer/1866-wg-teardown @ 5f3a63d5bac6 vs origin/master.
Method: full-diff read, plan-v5 conformance check, worked traces,
behavioral-parity audit of the populate refactor, test-race audit.

## Mandatory worked traces

1. **Remove-while-handshaking.** Thread mid `drive_initiation` (all
   sends on the nonblocking socket — no blocking site). Delete-commit →
   same-plan apply → `refresh_runtime_snapshot` → pass-2 stale
   ("removed") → `stop` stored, `join()`. The loop iteration completes
   in bounded work (≤ WG_RX_BURST ops per direction + 1ms idle sleep),
   observes `stop`, logs the clean exit, returns; join returns; socket
   drops; port released. Bounded ms; identical joining discipline to
   pre-PR code. PASS.
2. **Remove-while-traffic.** Worst case the thread is inside both burst
   loops (64+64 nonblocking ops) when `stop` is set — one iteration of
   bounded work before the flag check. The join happens under the
   ServerState mutex exactly as the pre-existing stale prune did; no
   new blocking class. PASS.
3. **Rapid add/remove/add same identity.** Apply1 spawns T1; Apply2
   pass-2 stops+joins T1 and removes the entry (port provably released
   before any later bind — same mutex, same thread); Apply3 builds a
   fresh engine (previous forwarding lost the endpoint), map is empty ⇒
   pass-3 spawns immediately (missing entry carries no backoff — fresh
   identity semantics). Pinned by `wg1866_remove_then_readd_same_identity_respawns`.
   PASS — this is the #1866 headline contract.
4. **Defer-window counterexamples (plan rounds 2-4) closed in CODE:**
   F7 — `prune_wg_control_threads_for_snapshot` removes the entry and
   `reconcile_wg_control_liveness` iterates only existing tombstones
   (`filter(|(_, e)| e.handle.is_none())` over the map) — no creation
   path exists (test 6/6b). Stale identity — `wg_tombstone_respawn_coherent`
   requires `hydrate_wg_identity(row).matches_endpoint(endpoint)`
   (test 6c). Stale attachment — requires `row.ifindex ==
   endpoint.logical_ifindex && row_label == name` (test 6d). PASS.
5. **stop/stop_inner with tombstones.** Tombstones have `handle: None`
   — the stop/join loops skip them, `clear()` removes them; post-stop
   sweeps cannot create entries (test 5). Losing backoff across a full
   stop is the plan-endorsed clean-slate semantics. PASS.

## Invariant conformance (plan §7)

- Single-mutex lifecycle: all new call sites (`refresh_status`,
  `handlers/snapshot.rs` defer branch, apply paths) run under the one
  `Arc<Mutex<ServerState>>` guard. VERIFIED.
- Join-before-bind: pass order (sweep → stale prune → spawn) inside one
  guarded call; the sweep joins finished threads before any respawn of
  the same id. VERIFIED.
- Bind/TUN in aux thread only: `spawn_one_wg_control_thread` does
  `thread::spawn` only; bind/open remain in `wg_control_loop`. VERIFIED.
- Stop-gate: `should_run_afxdp` guards the `refresh_status` call; the
  disjoint-field borrow (`state.afxdp` &mut + `state.snapshot` &) is
  sound. VERIFIED.
- Backoff stamped per ATTEMPT including spawn-failure (entry inserted
  with `handle: None` on `spawn_supervised_aux` Err). VERIFIED.
- Logging cadence: every new eprintln/slog fires on a state transition
  only (exit logged once via `handle.take()`; spawn ≤1/3s/id;
  endpoint-set lines only on set change; Go side records only after a
  SUCCESSFUL publish). VERIFIED.
- Defer prune touches no forwarding state — asserted by test 6 against
  `coordinator.forwarding.tunnel_endpoints`. VERIFIED.

## Behavioral-parity audit (populate refactor)

`hydrate_wg_identity` gates == pre-refactor inline gates byte-for-byte
(mode/listen_port/key decodes; allowed-ips skip-invalid per CIDR keeps
the row; empty/unparsable `wg_endpoint` → None). `wg_keepalive_secs`
initialization preserves the non-WG arm's pass-through (`let mut ... =
endpoint.wg_keepalive_secs` before the WG overwrite with the identical
source value). The `id != 0 && ifindex > 0` top gates remain at the
loop head, and the prune's desired-set filter re-applies them
explicitly. NO behavioral change found.

## Test-race audit

- `handle.is_some()` asserts immediately after a refresh are
  deterministic: the entry is inserted with `Some` and no sweep runs
  between the insert and the assert (pass-1 precedes pass-3 within the
  same call; nothing else runs under the test's single thread).
- `wait_tombstone` polls the sweep via `reconcile_wg_control_liveness(None)`
  (sweep-only — cannot spawn) with a 2s deadline; the thread exit is
  fast (failed bind / failed open_tun).
- Unique ports 51871-51878 per test; the EADDRINUSE rig uses one
  dual-stack `[::]` blocker covering both bind attempts.
- No sleeps for backoff — tests force `last_spawn_attempt_ns = 0`
  (same-crate field access), keeping the suite fast and deterministic.

## Findings

None blocking. Two notes, both deliberate and documented: (a) a full
stop clears tombstones (backoff resets) — plan §6 semantics; (b) the
defer-window live-thread-keeps-old-params behavior for UNCHANGED ids is
pre-existing master behavior, out of scope by plan §4c/§11.

## Verdict

**MERGE-READY.** Implementation matches plan v5 exactly; all five
defects (D1-D5) are closed with regression pins; gates ran unmasked
(release suite 1963/0, debug wg 133/0, go 36-ok/0).
