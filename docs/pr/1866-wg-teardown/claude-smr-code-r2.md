# PR #1872 — Claude SMR hostile code review, round 2

Target: engineer/1866-wg-teardown @ 9f36e88b86b4 (fold of code-r1).

## Fold verification

- Codex r1 F1 (disarmed same-plan spawn): the same-plan refresh leg now
  calls `stop_all_wg_control_threads("disarmed")` under
  `!should_run_afxdp`. Worked trace: disarmed apply1 (not-same-plan) →
  `reconcile_status_bindings` → `stop()` (pre-existing); disarmed
  apply2 (same-plan) → `refresh_runtime_snapshot` spawns per C1, then
  the gate stops+joins+removes within the SAME guarded critical
  section — the port is released before the handler returns, no
  observable window (control socket serialized). Pinned by the
  server-level test driving real `handle_stream` round-trips.
- Completeness audit — every WG spawn path and its arming gate:
  (a) same-plan refresh leg — gated by this fold; (b) reconcile
  bringup — reachable only via `reconcile_status_bindings`, which
  stops everything when disarmed; (c) the liveness sweep — gated at
  `refresh_status`; (d) prune paths — never spawn. COMPLETE.
- Same-plan + defer_workers + ARMED keeping C1 spawn behavior: correct
  — that leg refreshes forwarding first, so WG reconciliation there is
  coherent by construction; this has been shipped behavior since
  #1432 and the #1866 defer concern (D4) was specifically about the
  NOT-same-plan branch, which Change 2b covers.
- Codex r1 F2 / AGY r1 F1 (empty-linux_name fallback): committed; the
  coherence check now derives `row_label` exactly as
  `forwarding_build/interfaces.rs` derives the forwarding label.
  Pinned by `wg1866_sweep_respawns_with_empty_linux_name_rows`.
- `WgControlEntry` → `pub(crate)`: visibility now consistent with the
  `pub(crate)` field that exposes it (removes one instance of the
  pre-existing private-type-in-public-field warning class).

## Gates at this head

FULL `cargo test --release`: 1965/0/2, exit 0 (earlier run hit the
documented pre-existing `reconcile_peers_snapshot` ledger flake —
`wg/engine.rs` internals untouched by this PR — standalone-proved
8/8). Debug `cargo test wg`: 135/0. `wg1866` suite: 10/10.
`go test ./...`: unchanged since the green run (no Go changes in the
fold).

## Verdict

**MERGE-READY.**
