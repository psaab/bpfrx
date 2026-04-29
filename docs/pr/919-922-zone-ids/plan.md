# #919 + #922: zone strings → integer IDs

Plan v1 — 2026-04-29.

## Combined scope

Two issues, one data-flow change. They share the same fix: stop
storing zone names as `Arc<str>` / `String` on the fast and warm
paths; use the existing `u16` zone ID instead. Slow-path consumers
that need a name look it up via a new `zone_id_to_name` reverse map.

- **#919**: `SessionMetadata.{ingress,egress}_zone: Arc<str>` triggers
  `LOCK XADD` on every `metadata.clone()` and `ingress_zone.clone()`.
  At 14.8M pps these atomic increments saturate the cross-core
  coherency bus.
- **#922**: `ZonePairKey { from: String, to: String }` is built per
  `evaluate_policy` call (per session miss) by cloning two `String`s.
  At 10K new sessions/s under SYN flood, that's 20K heap allocations.

## Existing infrastructure (already there)

- `forwarding.zone_name_to_id: FastMap<String, u16>` — name → ID
  (`userspace-dp/src/afxdp/types.rs:237`). Populated at config-compile
  time; consumed by `event_stream/codec.rs:135-143`,
  `bpf_map.rs:458-462`, `ha.rs:389,440`.
- `UserspaceDpMeta.ingress_zone: u16` (`types.rs:64`) — the BPF
  metadata struct ALREADY uses u16 zone IDs. So `SessionMetadata`'s
  `Arc<str>` is the odd one out.
- `forwarding.ifindex_to_zone: FastMap<i32, String>` (`types.rs:236`)
  — stores zone NAMES indexed by ifindex. Used at session-install
  time to resolve egress zone (`forwarding.rs:357`).

What's missing: a **u16 → name** reverse map for slow-path consumers
(logging, gRPC export). I'll add `zone_id_to_name: Vec<Arc<str>>`
indexed by `u16`.

## Investigation findings (Claude, first-hand)

### `SessionMetadata` (session.rs:101-111)

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: Arc<str>,  // ← target for #919
    pub(crate) egress_zone: Arc<str>,   // ← target for #919
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}
```

After change: replace `Arc<str>` (16 bytes each) with `u16` (2 bytes
each) — saves **28 bytes per SessionMetadata**, plus eliminates the
per-clone atomic refcount op.

### Clone sites

`metadata.clone()` / `ingress_zone.clone()` / `egress_zone.clone()`
appear at (production paths only):

- `session_glue.rs:418, 435, 505, 518, 588, 864, 1407, 1452, 1477` —
  session install/lookup paths
- `flow_cache.rs:886` — flow cache promotion
- `ha.rs:431` — HA session sync
- `shared_ops.rs:470, 471` — shared session manipulation (currently
  swaps ingress/egress for reverse sessions)
- `afxdp.rs:1335-1338` — debug logging, clones into a debug struct

After change: each clone becomes a `u16` copy. No atomic op. ~10×
faster per clone, plus removes the cross-core MESI coherency traffic.

### Consumer sites that need the NAME

(These need `zone_id_to_name` reverse lookup or to take ID directly.)

- `bpf_map.rs:458, 462` — `forwarding.zone_name_to_id.get(metadata.ingress_zone.as_ref())` — already calling `zone_name_to_id`! This is gratuitous: passes a NAME to look up an ID that we already have. Direct simplification: just use `metadata.ingress_zone` (u16).
- `event_stream/codec.rs:135, 143` — same pattern, `zone_name_to_id.get(metadata.ingress_zone.as_ref())`. Same simplification.
- `icmp_embed.rs:755` — passes `metadata.ingress_zone.as_ref()` to a `&str`-typed API. Need name lookup OR change downstream API to take u16.
- `session_glue.rs:201, 409, 501, 1087, 1165` — same pattern (passes &str to downstream). Need name lookup.
- `shared_ops.rs:463` — same.
- `forwarding.rs:357-363` — at session-install time, builds metadata
  from `ifindex_to_zone` (returns String). Need to look up `u16` from
  the name via `zone_name_to_id`.
- `afxdp.rs:1335-1338` — `debug.from_zone = Some(resolved.metadata.ingress_zone.clone())` — debug logging path. Lookup name only when actually emitting.
- `afxdp.rs:3405-3406` — gRPC delta export `delta.metadata.ingress_zone.to_string()`. Slow path, name lookup OK.

### `ZonePairKey` (policy.rs:163-178)

```rust
struct ZonePairKey {
    from: String,
    to: String,
}

pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    pub(crate) rules: Vec<PolicyRule>,
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    global_indices: Vec<usize>,
}
```

After change: `ZonePairKey = u32` packed (`(from as u32) << 16 | to as u32`).

### `evaluate_policy` (policy.rs:233-279)

Currently takes `from_zone: &str, to_zone: &str` and builds
`ZonePairKey { from: from_zone.to_string(), to: to_zone.to_string() }`
on every call.

After change: takes `from_id: u16, to_id: u16` and packs the key
inline — no allocation.

Callers:

- `afxdp.rs:1891-1899, 2812-...` — passes `&from_zone, &to_zone` as
  `&str`. After: pass `meta.ingress_zone, meta.egress_zone` (already
  u16 in `UserspaceDpMeta`).
- `forwarding.rs:3379, 3410` — same.

### `parse_policy_state` (policy.rs:191-231)

Builds the index from `PolicyRuleSnapshot` strings at
config-compile time. The function needs access to `zone_name_to_id`
to translate snapshot names to IDs.

After change: signature becomes
`parse_policy_state(default_policy: &str, rules: &[PolicyRuleSnapshot], zone_name_to_id: &FastMap<String, u16>) -> PolicyState`.

### `junos-global` policies

Currently detected by `from_zone == "junos-global" || to_zone == "junos-global"` (policy.rs:217). After change: reserve a sentinel
`u16` (e.g. `0xFFFF` or a reserved ID at a known position) for
`junos-global`. Or look it up at parse time and store as
`Option<u16>` in PolicyState.

## Design

### `ForwardingState` change

Add a reverse-lookup vector built whenever `zone_name_to_id` is
populated:

```rust
pub(super) struct ForwardingState {
    // ... existing fields ...
    pub(super) ifindex_to_zone: FastMap<i32, String>,   // unchanged
    pub(super) zone_name_to_id: FastMap<String, u16>,   // unchanged
    // NEW: indexed by u16 zone ID; entry at index i is the name
    // of zone with ID i. Sized to max(zone_name_to_id values)+1.
    pub(super) zone_id_to_name: Vec<Arc<str>>,
    // ... existing fields ...
}
```

Helper method:

```rust
impl ForwardingState {
    pub(super) fn zone_name(&self, id: u16) -> Option<&str> {
        self.zone_id_to_name.get(id as usize).map(|s| s.as_ref())
    }
}
```

Built in the same place `zone_name_to_id` is populated (the
forwarding compiler / `forwarding_build.rs`).

### `SessionMetadata` change

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,    // was Arc<str>
    pub(crate) egress_zone: u16,     // was Arc<str>
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
}
```

Sentinel: `0` for "unknown / not-set" (matches the existing
`UserspaceDpMeta.ingress_zone: u16` default). Tests at
`forwarding.rs:2495-2496` etc. need to update assertions from
`metadata.ingress_zone.as_ref() == "lan"` to
`metadata.ingress_zone == ZONE_LAN_ID`.

### `ZonePairKey` change

```rust
type ZonePairKey = u32;

#[inline]
fn zone_pair_key(from: u16, to: u16) -> u32 {
    ((from as u32) << 16) | (to as u32)
}
```

`PolicyState.zone_pair_index: FxHashMap<u32, Vec<usize>>`.

### `evaluate_policy` signature

```rust
pub(crate) fn evaluate_policy(
    state: &PolicyState,
    from_id: u16,           // was &str
    to_id: u16,             // was &str
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
    zone_name_to_id: &FastMap<String, u16>,  // NEW
) -> PolicyState
```

Translates `snap.from_zone` / `snap.to_zone` strings to IDs at parse
time. If a rule references an unknown zone, log a warning and skip.

`junos-global` is a special sentinel — reserve a constant
`pub(crate) const JUNOS_GLOBAL_ZONE_ID: u16 = u16::MAX;` and the
policy compiler stamps that ID on `junos-global` references.

## Implementation steps

1. **Add `zone_id_to_name`** to `ForwardingState` and populate it
   wherever `zone_name_to_id` is populated (one site in the
   forwarding compiler).
2. **Reserve `JUNOS_GLOBAL_ZONE_ID`** constant in `policy.rs`.
3. **Change `SessionMetadata`** to u16 zones.
4. **Update all `SessionMetadata` constructors** (forwarding.rs,
   session_glue.rs, flow_cache.rs, ha.rs, bpf_map.rs, tests).
5. **Update consumer sites** that need a name string — `&str` API
   downstream becomes name lookup via `forwarding.zone_name(id)`.
6. **Change `ZonePairKey`** to u32 and `evaluate_policy` signature.
7. **Update `parse_policy_state`** to take `zone_name_to_id`.
8. **Update all `evaluate_policy` callers** (afxdp.rs:1891, 2812;
   forwarding.rs:3379, 3410). Already have u16 IDs available via
   `meta.ingress_zone` (UserspaceDpMeta).
9. **Update tests**. ~30 test sites construct `SessionMetadata` with
   `Arc::<str>::from("...")` literals; replace with named constants
   or `to_id` lookups.

## Risk

**Medium.**

- ~30-50 site updates, but mostly mechanical (same data, different
  type).
- Compile gate catches missed conversions (the compiler enforces u16
  vs Arc<str>).
- Same-type-swap hazard: ingress vs egress are both u16; reviewer
  checklist at impl time, plus `shared_ops.rs:470-471` deliberately
  swaps them for reverse sessions (preserve that).
- Slow-path consumers that need names need to thread `&forwarding`
  (or a name-lookup closure) through to the call site. Most already
  have it.

## Test plan

- `cargo test --release` (819 tests): some test fixtures construct
  SessionMetadata directly with `Arc<str>` literals. Need to update
  tests in `session_glue.rs`, `flow_cache.rs`, `forwarding.rs`,
  `bpf_map.rs`. Compile-driven.
- **New tests**:
  - `evaluate_policy_returns_correct_action_for_zone_id_pair`
  - `parse_policy_state_translates_snapshot_zones_to_ids`
  - `parse_policy_state_warns_on_unknown_zone` (skip + warn, not panic)
  - `zone_pair_key_packing_round_trip`
  - `forwarding_state_zone_name_round_trip` (id → name → id)
  - `junos_global_sentinel_id_routes_through_global_indices`
- **Cluster smoke** (HARD gate):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 comparable to master 3-run baseline
- **Session-setup throughput** (NEW gate, motivated by #922):
  measure new-session establishment rate under SYN burst (e.g.
  `iperf3 -P 256` or a SYN-flood-shaped microbenchmark) and confirm
  no regression vs master. The whole point of #922 is that
  session-setup-rate improves; if smoke shows no change, we measured
  wrong.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ 825 + 6 new = 831/831 pass.
3. Cluster smoke: all four gates green.
4. Session-setup rate: ≥ master baseline (no regression; ideally improvement).
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Out of scope

- `ifindex_to_zone` still returns `String` — separate cleanup; this
  PR doesn't need it.
- The full data-oriented SessionTable redesign (#964) — separate
  long-term work.
- Other `Arc<str>` cleanups (e.g. fabric zones #924) — separate PRs.
