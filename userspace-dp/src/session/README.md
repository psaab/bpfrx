# userspace-dp/src/session/

Userspace session table and timer-wheel garbage collector. Each worker
owns its `SessionTable` by value (`afxdp/worker/loop_body/setup.rs`); all
mutation goes through `&mut self` on the worker thread — single-writer by
construction. (The `Arc<Mutex<FastMap<...>>>` maps in `session_glue` /
`tunnel.rs` are the separate synced-session side tables, not this
structure.)

## Files

- `mod.rs` — `SessionTable`: slab-allocated `SessionEntry`s, three
  `FxHashMap`s indexing by canonical / forward / reverse key. Slab +
  integer-handle layout shipped in #964 Step 1.
- `key.rs` — `SessionKey`, `forward_wire_key` (ingress 5-tuple),
  `reverse_canonical_key` (post-NAT lookup), and
  `reply_matches_forward_session` (the predicate used to detect "this
  inbound packet matches an existing outbound flow").
- `entry.rs` — `SessionEntry`: decision, metadata, origin, timestamps,
  expiry tick, wheel bucket.
- `wheel.rs` — bucketed timer wheel (1 s per tick, 256 buckets). Each
  worker sweeps its own table once per second from its poll loop
  (`expire_stale_entries` in `afxdp/worker/loop_body/mod.rs`);
  lazy-delete on lookup picks up stragglers.
- `tests.rs` — co-located unit tests.

## Timeouts

| Class | Default |
|-------|---------|
| TCP   | 300 s |
| UDP   | 60 s |
| ICMP  | 60 s |
| TCP closing | 30 s |

Per-application overrides come from the typed config and land here as
per-entry `expires_after_ns`.

## GC

`SESSION_GC_INTERVAL_NS = 1_000_000_000` (1 s). Single-threaded per-worker
sweep walks the wheel bucket for the current tick; stale entries get
lazy-deleted on the next lookup if they slip past the sweep (e.g.
because they were re-bucketed mid-sweep).

## Corruption contract (#1855)

A `key_to_handle` mapping that points at a vacant or reused slab slot is
impossible-by-construction: installs pair the map insert with a freshly
allocated slab handle, and every removal funnels through `remove_entry`'s
#964 eager-cleanup (map remove first, all secondary indices value-guarded,
`no_index_points_at` debug scan before the slot is freed). The guard arms
in `update_session`, `refresh_for_ha_transition`, and `remove_entry`
therefore follow one contract:

- **debug builds**: `debug_assert!` fires — a loud logic-bug detector
  (the `*_asserts_in_debug` tests in `tests.rs` document each arm);
- **release builds**: tolerate and return `false`/`None` without touching
  the session occupying the reused slot (the
  `*_returns_false_no_panic` tests, compiled only under
  `cfg(not(debug_assertions))`, run via `cargo test --release`).

No counter/log on these arms: they are unreachable absent a logic bug,
and `update_session` is the per-packet refresh path (an unthrottled log
would flood under a real bug). Decision record:
`docs/research/1855-inplace-contract/plan.md`.

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path took a 2× regression on a rare HA codepath
that's known and accepted; see PR #1182 for the trade-off.
