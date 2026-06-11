# PR #1872 — Claude SMR hostile code review, round 3

Target: engineer/1866-wg-teardown @ cee8d7094e0e (fold of code-r2).

## Fold verification

- Codex r2 F1 (transient disarmed spawn/bind): structurally closed.
  `refresh_runtime_snapshot` is a thin wrapper over
  `refresh_runtime_snapshot_inner(snapshot, spawn_wg)`; the disarmed
  variant substitutes `stop_all_wg_control_threads("disarmed")` for the
  WG spawn pass; the same-plan apply leg selects on
  `should_run_afxdp(&guard.status)`. The refactor was a pure
  wrap-and-gate (single substitution at the spawn call) — the rest of
  the inner body is byte-identical to the previous
  `refresh_runtime_snapshot`, verified by diff inspection: forwarding
  preflight, neighbor manager-key swap, validation store, fabric
  preservation/merge, shared stores, CoS owner map, warm pass — all
  unchanged and still executed in the disarmed case (a later arming
  must start from current state).
- Test discrimination: the WG port is pre-bound by the test for the
  full run. Old fold: the spawn happens, the thread deterministically
  EADDRINUSEs and records `wg_bind_listen_port` BEFORE exiting, and the
  round-1 cleanup JOINED that thread inside the same handler — so the
  exception is present at assert time and the old code FAILS the
  zero-exception assert. New code never spawns — PASSES. Deterministic
  in both directions; no sleeps.
- Spawn-path arming gates (re-enumerated at this head): same-plan
  refresh leg — variant-selected; NOT-same-plan — `reconcile_status_bindings`
  stops everything when disarmed; bringup — reachable only via that
  gated reconcile; liveness sweep — gated at `refresh_status`; prune
  paths — never spawn; no other `refresh_runtime_snapshot` callers
  exist outside tests. COMPLETE.

## Gates at this head

wg1866 suite 10/10; FULL release suite 1965/0/2 exit 0 (one run hit
the second documented pre-existing ledger flake,
`worker_queue::concurrent_recovery_processes_each_command_exactly_once`
— untouched by this PR — standalone-proved 6/6); debug `cargo test wg`
135/0; `go build ./pkg/...` clean (no Go change this round). Both
flakes encountered across all runs are exactly the two the dispatch
pre-identified as known ledger flakes.

## Verdict

**MERGE-READY.**
