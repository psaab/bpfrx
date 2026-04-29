# #921: ifindex→zone and EgressInterface.zone string→u16

Plan v2 — 2026-04-29. Addresses Codex round-1 (task-mojw27u8-zcmsih):
GRE decap is per-packet not miss-path; unknown-zone-collapses-to-0
invariant + tests; corrected churn inventory; second debug-log line;
narrower EgressInterface read-site list.

## Investigation findings (Claude, on commit e4c4cc8e)

The #921 issue body lists three remaining string-heavy items:

1. **`SessionMetadata` zone fields**: ALREADY fixed by #919 (PR #970).
   `ingress_zone`, `egress_zone` are `u16`. ✓
2. **`zone_pair_for_flow` returns `(String, String)`**: ALREADY fixed
   by #922 (PR #970) via `zone_pair_ids_for_flow_with_override` which
   returns `(u16, u16)` zero-allocation. The String-returning legacy
   helper is `#[cfg_attr(not(test), allow(dead_code))]`. ✓
3. **`ifindex_to_zone: HashMap<i32, String>`**: NOT fixed. Still
   `FastMap<i32, String>` in `types.rs:236`. The hot-path lookup at
   `forwarding.rs:166-170` does:

   ```rust
   forwarding.ifindex_to_zone.get(&ingress_ifindex)
       .and_then(|name| forwarding.zone_name_to_id.get(name.as_str()).copied())
   ```

   Two HashMap lookups: one ifindex→String, one String→u16. The
   intermediate String is heap-allocated (set at config build time)
   and the second lookup hashes the string.

Plus a related find:

4. **`EgressInterface.zone: String`** in `types.rs` is set at config
   build, then read at `forwarding.rs:173-177`:

   ```rust
   forwarding.egress.get(&egress_ifindex)
       .and_then(|iface| forwarding.zone_name_to_id.get(iface.zone.as_str()).copied())
   ```

   Same shape: HashMap lookup → String value → second HashMap lookup
   on the String. Single u16 field replacement saves the second hash.

5. **Wire-protocol fields `SessionSyncRequest.{ingress,egress}_zone`
   and `SessionDeltaInfo.{ingress,egress}_zone`**: stay String for
   wire compat per #919's additive design. NOT in scope.

## Approach

Two field-type changes, both internal-only (no wire-protocol
changes):

### Change A: `ifindex_to_zone` value type

`types.rs:236`:
```rust
pub(super) ifindex_to_zone: FastMap<i32, String>,
```
→
```rust
pub(super) ifindex_to_zone_id: FastMap<i32, u16>,
```

The map is populated in `forwarding_build.rs` from
`iface.zone` (String snapshot field) by translating through
`state.zone_name_to_id`. After this PR the translation happens at
build time (once per config commit) instead of on every session
miss.

Renaming the field from `ifindex_to_zone` to `ifindex_to_zone_id`
makes the type change self-documenting and forces every call site
to be updated (compiler-driven migration).

### Change B: `EgressInterface.zone` field type

`EgressInterface` (in types.rs around L210-220):
```rust
pub(super) struct EgressInterface {
    ...
    pub(super) zone: String,
    ...
}
```
→
```rust
pub(super) struct EgressInterface {
    ...
    pub(super) zone_id: u16,
    ...
}
```

Same compiler-driven rename. All call sites currently do
`zone_name_to_id.get(iface.zone.as_str())`; they become
`iface.zone_id` directly.

### Where strings are still needed

The CLI / debug-log surfaces still want zone NAMES. Those callers
look up `zone_id_to_name.get(&id)` on the slow path. Examples:
- `forwarding_build.rs:440` debug-log line `FWD_STATE:
  ifindex_to_zone={:?}` — render via `(ifindex, zone_name)` pairs
  built from `state.zone_id_to_name`.
- `forwarding_build.rs:445-451` per-egress debug-log line that
  prints `eg.zone` directly — translate `eg.zone_id` via
  `zone_id_to_name` at log time (Codex round-1 finding #5).
- Any log statement that prints zone information.

These are slow-path; the lookup cost is fine. A small helper
`forwarding.zone_name_for(id)` can centralize this if it shows up
in many places.

### Unknown / skipped-zone invariant (Codex round-1 finding #2)

Today, `forwarding_build.rs:76-106` already drops zones whose IDs
land in the reserved range (≥ZONE_ID_RESERVED_MIN) or > u8::MAX.
After this PR, an interface whose `iface.zone` snapshot field
points at a zone that was dropped during the zone-build phase
collapses to `zone_id = 0` in both `ifindex_to_zone_id` and
`EgressInterface.zone_id`. Downstream string consumers (screen
profile lookup, DNAT, static NAT) will see an empty string after
translating `zone_id_to_name.get(&0)` → `None` → `""`, matching
today's behavior when an interface points at an unknown zone (the
old `ifindex_to_zone.get(...)` returned `None` and downstream
treated that the same as empty).

**Documented invariant**: `zone_id == 0` means "unknown / unmapped"
in both maps. Two new tests pin this:

- `interface_pointing_at_skipped_zone_collapses_to_zone_id_zero`:
  build a snapshot where one zone has a reserved ID (so it's
  dropped at config build) AND an interface references it by
  name. Assert `state.ifindex_to_zone_id.get(&iface.ifindex)`
  returns `Some(0)` (the canonical "unknown") rather than the
  reserved ID itself or `None` (which would be a different bug).
- `egress_with_unknown_zone_name_collapses_to_zone_id_zero`:
  build a snapshot where an interface's zone string isn't in the
  `zones` list. Assert `EgressInterface.zone_id == 0`.

## Files touched

- `userspace-dp/src/afxdp/types.rs`:
  - `ifindex_to_zone: FastMap<i32, String>` →
    `ifindex_to_zone_id: FastMap<i32, u16>`.
  - `EgressInterface.zone: String` → `zone_id: u16`.
- `userspace-dp/src/afxdp/forwarding_build.rs`:
  - At ifindex_to_zone insertion, translate `iface.zone` →
    `zone_name_to_id.get(...)` → u16; insert into the new map.
  - At EgressInterface construction, set `zone_id`.
  - The debug-log `FWD_STATE: ifindex_to_zone={:?}` line: render
    `(ifindex, zone_name)` pairs by translating IDs via
    `state.zone_id_to_name`.
  - Existing zone-id reservation gate at L83 still applies.
- `userspace-dp/src/afxdp/forwarding.rs:166-178`
  (`zone_pair_ids_for_flow_with_override`): drop the
  `zone_name_to_id` second hop; just `forwarding.ifindex_to_zone_id
  .get(&ingress_ifindex).copied()` and `egress.zone_id`.
- `userspace-dp/src/afxdp/forwarding.rs:142`
  (`zone_pair_for_flow_with_override` legacy String-returning helper):
  build the `from_zone` string lazily by chasing
  `ifindex_to_zone_id.get(&ifindex).and_then(|id| zone_id_to_name.get(id).cloned())`.
  This helper is `#[cfg_attr(not(test), allow(dead_code))]` so the
  perf cost is irrelevant — it's only called in tests.
- `userspace-dp/src/afxdp.rs:995, 1465, 2398`: ifindex_to_zone reads
  used for screen profile lookup, DNAT zone lookup, debug log. All
  read the String for downstream consumption that still expects
  `&str` (DNAT table, screen lookup). Translate at the call site
  via `zone_id_to_name.get(...)`.
- `userspace-dp/src/afxdp/gre.rs:260-265`: this site already
  produces a `u16 ingress_zone` for `UserspaceDpMeta`. Today it
  does TWO HashMap lookups (ifindex→String → String→u16). After
  this PR it becomes a single `forwarding.ifindex_to_zone_id
  .get(&endpoint.logical_ifindex).copied().unwrap_or_default()`.
  **Important**: GRE decap fires from `afxdp.rs:947-955` BEFORE
  the flow cache, so this is a **per-packet** path for matching
  native GRE traffic, not just the session-miss path. The
  per-packet hash saved here is a real win on GRE-tunnel
  workloads (Codex round-1 finding #1).
- `userspace-dp/src/afxdp/tunnel.rs:184-188`: `egress.zone` string
  read → translate via `zone_id_to_name` if a String is still
  needed downstream.
- `userspace-dp/src/afxdp/frame.rs:3625` (test-only assertion):
  update for `zone_id` field rename.
- **EgressInterface constructors** (per Codex round-1 finding #3):
  31 ctor sites across 9 files — `coordinator.rs`, `flow_cache.rs`,
  `frame.rs`, `frame_tx.rs`, `tests.rs`, `worker.rs`, plus
  `forwarding_build.rs` (the production source) and a couple of
  test-helper sites in `forwarding.rs`/`session_glue.rs`. Each
  ctor changes `zone: "lan".to_string()` → `zone_id: TEST_LAN_ZONE_ID`.
- **Inventory correction**: `test_fixtures.rs` does NOT construct
  `EgressInterface` (it uses `InterfaceSnapshot` for config
  fixtures); the v1 plan was wrong about that file. Real
  EgressInterface ctors are scattered across the test files
  listed above.

### Churn inventory (Codex round-1 finding #3)

- `ifindex_to_zone` references: **12 in 5 Rust files**
  (`afxdp.rs:995, 1465, 2398`, `forwarding.rs:142, 168, 407`,
  `forwarding_build.rs:166, 169, 173, 440`, `gre.rs:261`,
  `types.rs:236`).
- `EgressInterface` constructors: **31 across 9 files** (see above).
- Total touched files: ~14.
- Estimated diff: <300 LOC. Most lines are mechanical field
  renames; only a handful of call sites need actual logic
  changes (the 5 read sites above, the 2 debug-log lines, and the
  3 hot-path lookups).

## Performance estimate

For each session miss the saving is one String hash + one HashMap
lookup. At 1M session-setups per second:
- Current: ~50 ns per String hash (16-byte zone name) + 5 ns hashmap
  walk = ~55 ns × 2 (ingress + egress) = ~110 ns/miss.
- After: ~5 ns × 2 = ~10 ns/miss.
- Saving: ~100 ns × 1M = 100 ms/sec = 10% of one core's budget.

Order-of-magnitude. The actual win depends on session-setup rate;
this is the worst-case bookkeeping cost shaved off the miss path.

## Tests

- All existing tests pass through unchanged after the type
  migration (compile-driven).
- Add 4 unit tests in `forwarding_build.rs::tests`:
  - `ifindex_to_zone_id_populated_from_snapshot_at_build_time`:
    build a ConfigSnapshot with one interface and one zone,
    `build_forwarding_state(...)`, assert
    `state.ifindex_to_zone_id.get(&ifindex) == Some(zone.id)`.
  - `egress_interface_zone_id_set_from_snapshot`: same shape for
    `EgressInterface.zone_id`.
  - `interface_pointing_at_skipped_zone_collapses_to_zone_id_zero`:
    snapshot has a zone with reserved ID (dropped at build) AND an
    interface naming it. Assert
    `state.ifindex_to_zone_id.get(&iface.ifindex) == Some(0)`.
  - `egress_with_unknown_zone_name_collapses_to_zone_id_zero`:
    snapshot interface references a zone name not in `zones`.
    Assert `EgressInterface.zone_id == 0`.
- Smoke gates: same as #923/#925.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ baseline (847 post-#923) + 4 new = 851.
3. Cluster smoke (HARD): no regression — only path changes are
   strictly faster.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
4. Codex hostile review: AGREE-TO-MERGE.

## Risk

**Low.**

- Compile-driven migration; missed sites fail to build.
- No new dependencies, no wire-protocol changes.
- Only the build-time translation is added; no runtime behavior
  change beyond the saving.
- Field renames (ifindex_to_zone → ifindex_to_zone_id; zone →
  zone_id) make every call site grep-discoverable.

## Out of scope

- Wire-protocol fields `SessionSyncRequest.{ingress,egress}_zone`
  and `SessionDeltaInfo.{ingress,egress}_zone` — kept String for
  cross-version compat per #919's additive design.
- DNAT / static-NAT / screen lookup signatures that take `&str` —
  changing those is its own refactor.
- `zone_id_to_name` map itself — already the right shape (u16 → String).
