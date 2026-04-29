# #919 + #922: zone strings → integer IDs

Plan v3 — 2026-04-29. Addresses Codex round-2 review (task-mojk78nr-8xwzo3): HA/session-sync import path missed; `_by_id` helper location.

## Combined scope

Two issues, one data-flow change. They share the same fix: stop
storing zone names as `Arc<str>` / `String` on the fast and warm
paths; use the existing `u16` zone ID instead. Slow-path consumers
that need a name look it up via the **already-existing**
`zone_id_to_name` reverse map.

- **#919**: `SessionMetadata.{ingress,egress}_zone: Arc<str>` triggers
  `LOCK XADD` on every `metadata.clone()`. `SessionTable::lookup`
  clones metadata on every session hit (`session.rs:340-393`), so
  the Arc refcount cost is on the packet path. At 25 Gb/s this is
  ~2M pps (corrected from the issue's overstated "14.8M pps"),
  still material at higher PPS / smaller-MTU workloads.
- **#922**: `ZonePairKey { from: String, to: String }` is built per
  `evaluate_policy` call (per session miss, NOT per packet) by
  cloning two `String`s. Real cost only under miss-heavy floods
  (SYN flood, new-app churn).

## Existing infrastructure (corrected per Codex review)

- `forwarding.zone_name_to_id: FastMap<String, u16>` —
  `types.rs:237`, populated at `forwarding_build.rs:80`.
- **`forwarding.zone_id_to_name: FastMap<u16, String>` ALREADY
  EXISTS** — `types.rs:238`, populated at `forwarding_build.rs:81`.
  v1 plan incorrectly proposed adding it. We just use it.
- `UserspaceDpMeta.ingress_zone: u16` — `types.rs:64`. **No
  `egress_zone` u16 in this struct** (corrected from v1's false
  claim). The egress zone is computed at session-install time from
  `forwarding.egress[ifindex].zone` (a String) or `ifindex_to_zone`.
- BPF-side `pkt_meta` has both `ingress_zone` and `egress_zone`
  (`bpf/headers/xpf_common.h:451-452`); BPF zone cap is 64
  (`MAX_ZONES`).
- Go config compiler assigns zone IDs as `i + 1`
  (`pkg/dataplane/userspace/snapshot.go:183-187`), so IDs are dense
  starting at 1. `0` is the "unset" sentinel.

## Why `u16::MAX` for `junos-global` needs validation

Codex Q3: Rust accepts any nonzero `ZoneSnapshot.id` into
`zone_name_to_id` (`forwarding_build.rs:80`). A malformed snapshot
with id == `u16::MAX` would collide with the `JUNOS_GLOBAL_ZONE_ID`
sentinel.

**Fix**: at `forwarding_build.rs:80`, reject `zone.id >= u16::MAX - 1`
with a logged warning and skip. Document the reservation in a
`pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;` comment.

## Investigation findings (Claude, first-hand)

### `SessionMetadata` (session.rs:101-111)

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: Arc<str>,  // → u16
    pub(crate) egress_zone: Arc<str>,   // → u16
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}
```

After change: 28 bytes saved per `SessionMetadata` plus eliminates
the per-clone atomic.

### Sites that construct `SessionMetadata` (corrected scope)

Codex grep finds **80 `SessionMetadata {` occurrences** and **73
`ingress_zone: ...` / `egress_zone: ...` field lines** across:

- `userspace-dp/src/afxdp.rs`
- `userspace-dp/src/afxdp/bpf_map.rs`
- `userspace-dp/src/afxdp/flow_cache.rs`
- `userspace-dp/src/afxdp/forwarding.rs`
- `userspace-dp/src/afxdp/ha.rs`
- `userspace-dp/src/afxdp/session_glue.rs`
- `userspace-dp/src/afxdp/shared_ops.rs`
- `userspace-dp/src/afxdp/tests.rs`
- `userspace-dp/src/event_stream/codec.rs`
- `userspace-dp/src/main.rs`
- `userspace-dp/src/session.rs`
- `userspace-dp/src/afxdp/tunnel.rs`

Most are tests. Production constructors are at:
`forwarding.rs:362-363, 2692`, `session_glue.rs:1271, 896`,
`flow_cache.rs:202`, `ha.rs:595`, `shared_ops.rs:470-471`, plus a
few in forwarding-state-build paths.

### Where `evaluate_policy` callers get their zones (corrected)

Production callers at `afxdp.rs:1891-1899` and
`afxdp.rs:2812-2821` get their zones from
`zone_pair_for_flow_with_override` (`forwarding.rs:134-150`):

```rust
fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())                    // alloc 1
        .or_else(|| forwarding.ifindex_to_zone.get(&ingress_ifindex).cloned())  // alloc 2 if no override
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone.clone())                  // alloc 3
        .unwrap_or_default();
    (from_zone, to_zone)
}
```

The function builds and returns `(String, String)` allocating up to
3 strings per call, then hands them to `evaluate_policy` which
allocates 2 more in `ZonePairKey`. **Five allocations per session
miss.** All eliminable.

### `ZonePairKey` (policy.rs:163-178) and `evaluate_policy` (policy.rs:233-279)

Same as v1 — change `(String, String)` to packed `u32` key.

### `parse_policy_state` (policy.rs:191-231)

Called from `forwarding_build.rs:335`, where `zone_name_to_id` is
already populated by line 80. Plumbing it in is straightforward.

**Unknown-zone behavior** (Codex Q7): current code indexes any
string without validation. After the change, an unknown zone
becomes "no ID; skip from index but keep in `rules`". This is
behavior-equivalent to today (a rule referencing an unknown zone
becomes a dead rule) plus a WARN log. Don't drop from `rules` —
that would break the `hit_count` reporting at `policy.rs:29-42`.

## Design

### `JUNOS_GLOBAL_ZONE_ID` constant + validation

```rust
// In policy.rs:
pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;
pub(crate) const ZONE_ID_RESERVED_MIN: u16 = u16::MAX - 1;
```

In `forwarding_build.rs:80`, before inserting:

```rust
if zone.id >= ZONE_ID_RESERVED_MIN {
    log::warn!("zone {:?} has reserved id {}; skipping", zone.name, zone.id);
    continue;
}
```

### `SessionMetadata` change

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,
    pub(crate) egress_zone: u16,
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}
```

`0` = "unset / unknown" (matches `UserspaceDpMeta.ingress_zone`'s
existing default). The `shared_ops.rs:470-471` swap stays correct:
`u16` copy.

### `ZonePairKey` change

```rust
type ZonePairKey = u32;

#[inline]
fn zone_pair_key(from: u16, to: u16) -> u32 {
    ((from as u32) << 16) | (to as u32)
}
```

`PolicyState.zone_pair_index: FxHashMap<u32, Vec<usize>>`.

### New `zone_pair_ids_for_flow_with_override`

To replace `zone_pair_for_flow_with_override` at production call
sites:

```rust
pub(super) fn zone_pair_ids_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<u16>,   // u16 because session metadata
                                          // is u16 after this refactor
    egress_ifindex: i32,
) -> (u16, u16) {
    let from = ingress_zone_override
        .or_else(|| {
            let name = forwarding.ifindex_to_zone.get(&ingress_ifindex)?;
            forwarding.zone_name_to_id.get(name.as_str()).copied()
        })
        .unwrap_or(0);
    let to = forwarding
        .egress
        .get(&egress_ifindex)
        .and_then(|iface| forwarding.zone_name_to_id.get(iface.zone.as_str()).copied())
        .unwrap_or(0);
    (from, to)
}
```

Zero allocations on the hot path. Existing
`zone_pair_for_flow_with_override` (returning Strings) stays only
for any test fixture that demands it; production callers move to
the new function.

### `evaluate_policy` signature

```rust
pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_id: u16,
    to_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> PolicyAction { ... }
```

### `parse_policy_state` signature

```rust
pub(crate) fn parse_policy_state(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zone_name_to_id: &FastMap<String, u16>,
) -> PolicyState
```

`junos-global` references in snapshots are translated to
`JUNOS_GLOBAL_ZONE_ID` and stored in `global_indices` as today.

### Slow-path consumers that need names

Codex Q5: `bpf_map.rs:457-464` and `event_stream/codec.rs:134-145`
currently round-trip `name → zone_name_to_id → ID`. These become
trivial: just use the metadata's u16 directly.

`icmp_embed.rs:755`, `session_glue.rs:201,409,501,1087,1165` pass
zone strings to fabric redirect helpers
(`resolve_zone_encoded_fabric_redirect` at `shared_ops.rs:528`).
Those helpers are downstream of session metadata and need either:
- (a) a `_by_id` variant that takes u16 (preferred — eliminates the
  string lookup); OR
- (b) a name lookup via `forwarding.zone_id_to_name.get(&id)` at the
  caller boundary.

This plan does (a): adds `resolve_zone_encoded_fabric_redirect_by_id`.

### HA / session-sync import path (added in v3)

Codex round-2 caught: `userspace-dp/src/main.rs:857` builds
`SessionMetadata` from a `SessionSyncRequest` whose
`ingress_zone` / `egress_zone` fields are `String`. After this
refactor, those need to become `u16` IDs.

The wire protocol struct is `SessionSyncRequest`
(`userspace-dp/src/protocol.rs:1664`):

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionSyncRequest {
    // ... existing fields ...
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    // ... + a near-duplicate struct around L1740-1760 ...
}
```

**Approach** — additive wire change with backward compat:

Add new `u16` fields beside the strings, both with
`#[serde(default)]`:

```rust
pub struct SessionSyncRequest {
    // ... existing fields ...
    /// LEGACY (kept for HA peer compat): zone name. Populated by
    /// older peers; new peers populate `ingress_zone_id` and may
    /// leave this empty.
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919: zone IDs preferred over names. Populated by post-#919
    /// peers. Older peers populate the string fields.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
}
```

**Build logic** in `main.rs:857`:

```rust
fn build_synced_session_entry(
    req: &SessionSyncRequest,
    forwarding: &ForwardingState,
) -> Result<SyncedSessionEntry, String> {
    let ingress_zone = if req.ingress_zone_id != 0 {
        req.ingress_zone_id
    } else {
        forwarding
            .zone_name_to_id
            .get(req.ingress_zone.as_str())
            .copied()
            .unwrap_or(0)
    };
    let egress_zone = /* same */;
    // ...
}
```

**Compatibility window**: helper emits BOTH the legacy string AND
the new u16 fields for one release cycle. Receiving side prefers
ID when nonzero, falls back to name lookup. After all peers are on
the new schema (operationally observable), the strings can be
dropped in a follow-up PR.

**Go side**: `pkg/dataplane/userspace/` builds and consumes
`SessionSyncRequest` JSON. Need matching Go field additions.
Affected files (Codex grep):

- `pkg/dataplane/userspace/protocol.go` — Go mirror of
  `SessionSyncRequest`. Add `IngressZoneID uint16` /
  `EgressZoneID uint16`.
- Any builder of `SessionSyncRequest` on the Go side. Go already
  has the zone IDs available pre-stringify, so wiring them in is
  small.

This is **+~30 LOC + Go wire changes** beyond the v2 scope. Worth
calling out as a separate "wire-protocol" sub-deliverable.

### `event_stream/codec.rs` u8 caveat

Codex notes the codec writes a `u8` for zone IDs. At max 64 zones
(MAX_ZONES BPF cap) this is safe today. The plan documents the
invariant: zone IDs that need to cross the wire MUST fit in u8 (i.e.,
< 256). `forwarding_build.rs` already enforces by-construction
(IDs are `i+1` in Go, capped at 64).

## Implementation steps

1. **`policy.rs`**: add `JUNOS_GLOBAL_ZONE_ID` and `ZONE_ID_RESERVED_MIN` constants. Change `ZonePairKey` to `u32`. Change `evaluate_policy` and `parse_policy_state` signatures.
2. **`forwarding_build.rs:80`**: reject zone IDs >= `ZONE_ID_RESERVED_MIN`. Pass `zone_name_to_id` to `parse_policy_state`.
3. **`session.rs`**: change `SessionMetadata.{ingress,egress}_zone` to u16.
4. **`forwarding.rs`**: add `zone_pair_ids_for_flow_with_override`. Convert `SessionMetadata` constructors at lines 362, 2692.
5. **`forwarding.rs`** (per Codex round-2 minor): add
   `resolve_zone_encoded_fabric_redirect_by_id` here, NOT in
   `shared_ops.rs` — it lives beside the existing string variant.
   Update `shared_ops.rs:463-471` to call the new id variant.
6. **`session_glue.rs`**: update production callers (`:201, 409, 501, 1087, 1165`) and `SessionMetadata` constructors at `:896, 1271`.
7. **`afxdp.rs`**: update `evaluate_policy` callers at `:1891, :2812`. Update debug logging at `:1335-1338` (look up name via `forwarding.zone_id_to_name` only for the actual log emit). Update gRPC export at `:3405-3406` (look up name).
8. **`flow_cache.rs`**: update line 149 (`Option<Arc<str>>` parameter) → `Option<u16>`. Update constructors.
9. **`bpf_map.rs:457-464`**: replace `zone_name_to_id.get(metadata.ingress_zone.as_ref())` round-trip with direct u16 use.
10. **`event_stream/codec.rs:134-145`**: same.
11. **`protocol.rs`** (added in v3): add `ingress_zone_id: u16` /
    `egress_zone_id: u16` fields to `SessionSyncRequest` (both
    instances around L1664 and L1740). Keep legacy string fields
    for backward compat for one release.
12. **`main.rs:857`** (added in v3): rewrite
    `build_synced_session_entry` to prefer the new ID fields, fall
    back to name lookup via `forwarding.zone_name_to_id`. Pass
    `&forwarding` through.
13. **Go side** (added in v3):
    `pkg/dataplane/userspace/protocol.go` Go mirror — add
    `IngressZoneID uint16` / `EgressZoneID uint16` fields. Update
    any session-sync builder in `pkg/dataplane/userspace/` to emit
    them. Go already has the IDs available pre-stringify.
14. **`tests`**: ~73 test sites construct `SessionMetadata` with `Arc::<str>::from("name")` literals. Update each. Some tests construct a `forwarding` state with custom zones — those tests need to populate `zone_name_to_id` and `zone_id_to_name` accordingly.

## Test plan

- **Unit tests (new)**:
  - `evaluate_policy_returns_correct_action_for_zone_id_pair`
  - `parse_policy_state_translates_snapshot_zones_to_ids`
  - `parse_policy_state_skips_unknown_zone_with_warning`
  - `parse_policy_state_routes_junos_global_to_global_indices`
  - `forwarding_build_rejects_reserved_zone_id`
  - `zone_pair_key_packing_round_trip`
  - `forwarding_state_zone_id_to_name_round_trip`
- **Compile gate**: many test sites construct `SessionMetadata`
  with literal `Arc::<str>::from`; the compiler enforces every site
  is updated. Expect ~73 mechanical edits.
- **Cluster smoke** (HARD gate):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 comparable to master 3-run baseline
- **Session-setup throughput** (NEW gate): run a session-churn
  workload (e.g. `iperf3 -P 256` reconnect loop) and confirm
  new-session rate is at least at master baseline. Without this
  gate, the perf-motivation in the issues is unverified.

## Risk

**High** (corrected from v1's "Medium" per Codex Q11). Once data
flow is corrected per this v2, implementation risk drops to
Medium.

- 80 SessionMetadata sites, 73 zone field lines, ~5 production
  evaluate_policy / fabric redirect call paths.
- Same-type-swap hazard (ingress vs egress, both u16). Reviewer
  checklist at impl time. Plus `shared_ops.rs:470-471` deliberately
  swaps them — preserve.
- Sentinel validation must land BEFORE any code starts treating
  `u16::MAX` as JUNOS_GLOBAL_ZONE_ID. Otherwise a malformed
  snapshot can cause a global-policy collision.
- Test surface is large (~80 sites). Compile-driven, but reviewer
  must verify the spot-checked production paths.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ 825 + ~7 new = 832/832 pass.
3. Cluster smoke: all four gates green.
4. Session-setup rate gate: ≥ master baseline.
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Out of scope (follow-ups)

- Removing `Arc<str>` more broadly (e.g., other `Arc<str>` fields on
  `SessionDecision`, `ForwardingResolution`).
- `ifindex_to_zone` String → ID (would close another string churn
  path; separate cleanup).
- `forwarding.egress[ifindex].zone` String → ID (same).
- The full data-oriented SessionTable redesign (#964).
