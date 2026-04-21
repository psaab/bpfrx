# PR #804 — Rust-quality review (per-binding ring-pressure counters)

Branch: `pr/802-ring-counter-instrumentation`
Reviewer focus: Rust idioms, types, test quality, plumbing cleanliness.
(Correctness of aggregation semantics is the Codex reviewer's lane; I
agree at a glance but do not deep-dive it here.)

**ROUND 1 verdict: merge-ready with minor polish.** No blockers. A
handful of LOW/INFO polish items and one MEDIUM-quality observation
about test coverage. Listed below in severity order.

---

## MEDIUM — Wire-shape test is a substring check, not a cross-language pin

- **Summary**: `binding_counters_snapshot_serializes_with_expected_wire_keys`
  asserts keys via `json.contains(&format!("\"{}\"", key))`. Substring
  matching on the whole serialized blob passes even if a key is nested
  inside a different field name (e.g. a hypothetical
  `"foo_outstanding_tx"` field would still make the test think
  `outstanding_tx` is present). It also does not cover the real failure
  mode the comment warns about — "the daemon's poll path parses these
  JSON keys" — because the daemon is Go, not Rust.
- **Citation**: `userspace-dp/src/main.rs:1782-1824`
  ```rust
  let json = serde_json::to_string(&snap).expect("serialize snapshot");
  for key in [ "worker_id", "ifindex", /* ... */ ] {
      assert!(
          json.contains(&format!("\"{}\"", key)),
          "wire key `{key}` missing from snapshot JSON: {json}"
      );
  }
  ```
- **Mitigation** (pick one):
  1. Parse into `serde_json::Value`, then assert keys exist at the
     top level (`v.as_object().unwrap().contains_key(key)`). That's the
     robust version of what this test is trying to say.
  2. Add a Go-side test in `pkg/dataplane/userspace/protocol_test.go`
     that decodes a canned JSON sample (the exact one the Rust side
     would produce) into `BindingCountersSnapshot` and asserts every
     field populates correctly. That's the real cross-binding pin.
  3. Keep the substring check but also round-trip through the Go
     struct via `encoding/json` in a Go test — the only way to catch
     silent Rust↔Go drift is to exercise both sides.
  The test comment explicitly names the daemon as the consumer, so a
  Go-side decode test is the right level.

## LOW — `BindingCountersSnapshot::ifindex` lacks the explicit `rename`

- **Summary**: Every other field in `BindingCountersSnapshot` has an
  explicit `#[serde(rename = "...", default)]` even when the rename
  would be a no-op (e.g. `dbg_tx_ring_full`). `ifindex` alone uses
  `#[serde(default)]` without `rename`. Harmless — serde defaults the
  name to the field ident — but the inconsistency reads as an
  oversight.
- **Citation**: `userspace-dp/src/protocol.rs:1345-1347`
  ```rust
  #[serde(default)]
  pub ifindex: i32,
  ```
- **Mitigation**: either add `#[serde(rename = "ifindex", default)]`
  for consistency with the rest of the struct, or drop the redundant
  renames from the other fields (they're all already snake_case
  Rust idents). The existing `BindingStatus` struct uses explicit
  renames on every field; mirror that.

## LOW — Go-side casing inconsistency within `BindingCountersSnapshot`

- **Summary**: The new Go struct mixes `TX` and `Tx` casing for TX
  acronyms: `TXErrors`, `OutstandingTX` (uppercase) vs
  `TxSubmitErrorDrops`, `PendingTxLocalOverflowDrops`,
  `DbgTxRingFull`, `RxFillRingEmptyDescs` (mixed-case). The existing
  `BindingStatus` is not itself consistent (`DebugPendingTXLocal`,
  `DebugOutstandingTX`, `TXErrors` — all uppercase `TX`), so this PR
  introduces a new divergence within one type.
- **Citation**: `pkg/dataplane/userspace/protocol.go:678-690`
- **Mitigation**: pick a rule and stick to it. Go convention per
  Effective Go / Uber style is to uppercase acronyms (`TX`, `RX`,
  `ID`), so `TXSubmitErrorDrops`, `PendingTXLocalOverflowDrops`,
  `DbgTXRingFull`, `RXFillRingEmptyDescs` would match the
  adjacent `TXErrors` / `OutstandingTX`. JSON tags are the load-bearing
  wire contract — renaming Go field idents is cheap.

## LOW — `BindingCountersSnapshot::from_binding_status` would read more
idiomatically as `From<&BindingStatus>`

- **Summary**: A named constructor `from_binding_status(&BindingStatus)`
  is fine but `impl From<&BindingStatus> for BindingCountersSnapshot`
  is the idiomatic Rust shape, and lets callers use
  `.map(Into::into)` on the iterator chain in `refresh_status`.
- **Citation**: `userspace-dp/src/protocol.rs:1366-1385`,
  `userspace-dp/src/main.rs:803-807`
  ```rust
  state.status.per_binding = state
      .status
      .bindings
      .iter()
      .map(BindingCountersSnapshot::from_binding_status)
      .collect();
  ```
- **Mitigation**: replace with `impl From<&BindingStatus> for
  BindingCountersSnapshot`, then the call site becomes
  `.map(BindingCountersSnapshot::from)` or `.map(Into::into)`. Purely
  idiomatic, no functional change.

## LOW — New `pub(super)` atomics are exposed cross-module via snapshot,
which is the existing convention (note only)

- **Summary**: `BindingLiveState` adds four new `pub(super) AtomicU64`
  fields. Consistent with the rest of the struct; `pub(super)` is used
  throughout and crossed through `BindingLiveSnapshot` into
  `coordinator.rs`. No leak of `pub(super)` to `pub`. Public API
  surface growth is limited to the two new `pub(crate)` types
  (`BindingCountersSnapshot` at struct level, and the new serde fields
  on `BindingStatus` / `ProcessStatus`).
- **Citation**: `userspace-dp/src/afxdp/umem.rs:944-961`
- **Mitigation**: none — this is the existing convention. Flagged so
  the reviewer can confirm intent.

## INFO — Pre-existing bug silently fixed: `debug_outstanding_tx` was
never published by the worker before this PR

- **Summary**: The new `b.live.debug_outstanding_tx.store(...)` in
  the worker's per-second tick is the first writer to this atomic.
  Every other site (`new()`, `snapshot()`, coordinator read) treats it
  as a value that someone else populates, but before this PR no code
  path actually wrote it. So the operator-facing
  `BindingStatus.debug_outstanding_tx` was always zero, and the new
  `BindingStatus.outstanding_tx` (aliased from it) is the value the
  old field was supposed to have shown. Worth calling out in the PR
  description or a follow-up note, because it changes observed field
  behavior for anyone already consuming `debug_outstanding_tx`.
- **Citation**:
  - Old read path: `userspace-dp/src/afxdp/coordinator.rs:1411`
  - New writer: `userspace-dp/src/afxdp/worker.rs:1368-1370`
  - No other writer in the tree (verified via grep for
    `debug_outstanding_tx.store`/`.fetch_add`).
- **Mitigation**: none needed for this PR (the fix is strictly
  better), but flag it in the commit message so consumers don't think
  something changed semantics.

## INFO — Double `statistics_v2()` syscall per binding per tick

- **Summary**: The debug-summary block at
  `userspace-dp/src/afxdp/worker.rs:952` calls `statistics_v2()` to
  build a log string (log text is cfg-gated under `debug-log`, but the
  syscall itself is unconditional). The new publish path at line 1358
  calls `statistics_v2()` a second time. Both are per-tick (~1 Hz),
  so the cost is negligible, but it's a pointless duplicate.
- **Citation**:
  - `userspace-dp/src/afxdp/worker.rs:952` (existing)
  - `userspace-dp/src/afxdp/worker.rs:1358-1362` (new)
- **Mitigation**: capture the `Result<XdpStatistics, _>` once at the
  top of the per-binding loop, reuse it for both the log-formatting
  path and the atomic publish. Or leave it — 1 Hz syscall is free.

## INFO — `ring_pressure_counters_round_trip_through_snapshot` is
strictly a publish-contract test, not a round-trip

- **Summary**: The test name says "round_trip_through_snapshot" but it
  only exercises `BindingLiveState::snapshot()` — no serialize, no
  deserialize, no projection into `BindingCountersSnapshot`. The
  other two tests cover those paths. Misleading name.
- **Citation**: `userspace-dp/src/afxdp/coordinator.rs:2720-2739`
- **Mitigation**: rename to something like
  `snapshot_surfaces_ring_pressure_atomics` or
  `ring_pressure_atomics_publish_via_snapshot`. One-liner.

---

## Summary

- No blocker, no data-race concern, no public-API leak.
- Atomic ordering choices (`fetch_add` for worker-local cumulative
  deltas, `store` for kernel-absolute / gauge values) are correct and
  the code comments explain the decision.
- The `skip_serializing_if = "Vec::is_empty"` on `ProcessStatus::per_binding`
  pairs cleanly with the Go `omitempty` tag — backward-compat on the
  wire.
- Go struct naming within `BindingCountersSnapshot` is internally
  inconsistent (`TX`/`Tx`/`Rx`) and warrants a cleanup pass before
  other consumers copy the style.
- The most useful additional test would be a Go-side decode of a
  canned JSON blob, which is the only way to catch silent wire-shape
  drift between the two bindings.

MERGE: **YES**, land after addressing the MEDIUM test-quality point
(either upgrade the substring check to a `serde_json::Value` key check
or add a Go-side decode test). LOW items are polish; can ride a
follow-up.
