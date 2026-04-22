# Codex Hostile Code Review — PR #825

Two-angle review of commit `32e5bdd30c308438b630cc5a9855935c232c2f40`
on branch `worktree-agent-adf2fa9f`.

## Round 1

### Rust second-angle (specialist reviewer)

**MERGE YES** — 4 non-blocking LOWs. Plumb-through of
`tx_kick_latency_hist`, `tx_kick_latency_count`,
`tx_kick_latency_sum_ns`, and `tx_kick_retry_count` through
`OwnerProfileOwnerWrites` → `BindingLiveSnapshot` → coordinator copy
paths → `protocol::BindingStatus` + `BindingCountersSnapshot` → Go
mirror is correctly wired. `cargo test` passes. LOWs logged but
non-blocking.

### Codex (hostile reviewer)

**MERGE NO** — 1 HIGH, 2 MED, 1 LOW.

- **HIGH-1** — `tx.rs` sentinel `if kick_end >= kick_start` does not
  catch the asymmetric clock-failure case (`kick_start == 0` from
  `monotonic_nanos()` failure with `kick_end > 0`). Those records
  would saturate bucket 15 with a bogus-huge delta.
  **Fix applied**: guard strengthened to
  `if kick_start != 0 && kick_end >= kick_start`.

- **MED-2** — The `3b` sentinel test pins helper behaviour on
  pre-computed bogus deltas, but does not pin the caller-site guard
  with an executable test that observes `maybe_wake_tx` itself.
  **Response**: plan §3.8 option (b) doc-only — the guard is
  documented in both the `tx.rs` call site and the test comment
  block. `BindingWorker` fixture is not reachable from a unit test;
  an integration test is out of scope for this PR.

- **MED-3** — `tx_kick_retry_count` has no direct automated pin.
  **Fix applied**: new test `tx_kick_retry_count_observable_via_snapshot`
  at `umem.rs` drives the production atomic shape
  (`fetch_add(1, Ordering::Relaxed)`) and reads back via
  `BindingLiveState::snapshot()`.

- **LOW-4** — `K_skew` bound `ceil(λ_obs × W_read_max) + 2` is used
  without an explicit derivation comment (the deviation note had a
  stale `2λW+4` claim).
  **Fix applied**: expanded comment at `umem.rs` derives the bound
  from #812 §3.6 R2, names both `+1` sources (record-in-flight at
  window start and end), and explicitly carries the derivation
  through because `record_kick_latency` has the same single-writer /
  Relaxed / count-then-bucket shape.

## Round 2

**MERGE NO** — 2 LOW documentation-consistency blockers (no runtime
bug):

- **Blocker 1** — `tx.rs:6489` comment bullet for `kick_end >=
  kick_start` did not explicitly name backwards-clock /
  end-before-start.
  **Fix applied**: bullet now reads "`kick_end >= kick_start`
  catches the backwards-clock / end-before-start case (wraparound
  in the `kick_end - kick_start` subtraction would otherwise
  saturate bucket 15 with a bogus-huge delta). Both conditions
  must hold."

- **Blocker 2** — `umem.rs:1549/1557/1576` test comments still
  referenced the old single-condition guard shape after the HIGH-1
  update.
  **Fix applied**: all three sites now reflect the two-condition
  guard `kick_start != 0 && kick_end >= kick_start`. The third
  site explains both halves: `>=` catches backwards-clock /
  end-before-start; `!= 0` catches the asymmetric clock-failure
  case.

**R1 fix verification in R2**: HIGH-1 FAIL (comment gap above),
MED-3 PASS, LOW-4 PASS.

## Round 3

**MERGE YES** — both R2 blockers verified fixed at commit
`32e5bdd30c308438b630cc5a9855935c232c2f40`. No remaining blockers.
Branch clear to merge.

## Test evidence

```
$ cargo test
test result: ok. 760 passed; 1 ignored; 0 failed; 0 measured
```

All 9 `tx_kick*` tests pass, including the new MED-3 pin
`tx_kick_retry_count_observable_via_snapshot`.
