# userspace-dp/src/session/

Userspace session table and timer-wheel garbage collector. Each worker
owns its `SessionTable` by value (`afxdp/worker/loop_body/setup.rs`); all
mutation goes through `&mut self` on the worker thread — single-writer by
construction. (The `Arc<Mutex<FastMap<...>>>` maps in `session_glue` /
`tunnel.rs` are the separate synced-session side tables, not this
structure.)

## Files

- `mod.rs` — `SessionTable` coordinator: the slab + `FxHashMap`
  secondary indices (canonical / forward / reverse key), the delta
  queue, and the #1752/#1855 in-place-refresh contract
  (`update_session` / `refresh_for_ha_transition` + the secondary-index
  re-assert + the #964 eager-cleanup `remove_entry`/`index_*` helpers).
  Slab + integer-handle layout shipped in #964 Step 1; the impl is
  split across `lookup.rs` / `install.rs` / `expire.rs` (#2005,
  pure code-motion — all submodules attach `impl SessionTable` blocks).
- `lookup.rs` — forward/reverse tuple match read path: the `lookup`
  family (primary + NAT-translated-reverse alias), the NAT/wire reverse
  finders (`find_forward_nat_match` / `find_forward_wire_match`), the
  single-entry / owner-RG / iteration read accessors, and
  `take_synced_local`.
- `install.rs` — session-creation path: the #1861 capacity preflight
  (`can_admit` + counters), the new-flow installs
  (`install_with_protocol*` / `upsert_synced*`), and the delta-emit /
  `delete` / owner-RG demotion helpers. These build fresh records; the
  in-place-refresh path stays in `mod.rs`.
- `expire.rs` — timer-wheel sweeps + eviction: `expire_stale_entries`
  (the per-tick bucket drain / lazy-delete GC pass), the throttled
  `push_to_wheel` scheduler, and `wheel_observe`.
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

## Admission / transaction boundary (#1861)

`install_with_protocol_with_origin` refuses an install when
`len() >= max_sessions` (131,072 per worker table) — the ONLY install
failure mode. The new-flow path in `poll_descriptor` installs a
forward+reverse pair, and pre-#1861 the two halves were independent:
at cap, a refused forward still forwarded (and flow-cached) the trigger
packet on a rolled-back SNAT decision, and a refused reverse left a
one-sided forward session.

The transaction boundary is a preflight: `can_admit(needed)` checks
capacity for the whole install group BEFORE the first install. Because
the table is single-writer (`&mut`, worker thread; GC and worker
commands run between poll phases, never mid-descriptor), a passing
preflight makes the subsequent installs infallible — no reservation or
rollback machinery is needed. `can_admit` is deliberately conservative:
it charges a full slot per entry even when the key already exists,
matching the install's own cap check (which also refuses replacements
at cap), so the preflight can never pass where the install would fail.
On refusal the caller drops the trigger packet (Junos parity), rolls
back the SNAT allocation, and counts via `note_admission_refused`.

Counters (all plain worker-owned u64s like `create_drops`, exported
since #1861 via the worker-runtime status path as
`xpf_userspace[_worker]_session_*_total`):

- `create_drops` — at-cap refusals from the install itself (repair,
  seed, fabric-return, LocalMiss sites);
- `admission_refused` — preflight refusals (one per refused flow);
- `install_partial` — post-preflight residuals, expected 0 forever
  (the call sites pair the count with `debug_assert!` per the #1855
  contract above).

Decision record: `docs/research/1861-install-txn/plan.md`.

### UpsertLocal is in the uncapped sync family (#1870)

`upsert_synced_with_origin` has NO cap check (the #1861 plan's row
I11): HA sync, replica fan-out, and reactive shared-hit
materialization all install past `max_sessions` by design. Since
#1870 the local-tunnel prewarm (`WorkerCommand::UpsertLocal`,
`session_glue`) joins that family with `allow_replace_local=true` —
the entries are coordinator-authoritative `SyncImport` replicas of
state already published to the shared maps, and the capped install
previously refused the worker-table copy at cap while the reactive
materializer reinstalled the reverse entry uncapped on the next reply
packet anyway (futile cap; polluted `create_drops`; cap-1 partial
pairs). Consequently `create_drops` no longer counts `UpsertLocal`
installs — they cannot fail. The future cap arbitration for the sync
family (row I11) now covers `UpsertLocal` automatically. Decision
record: `docs/research/1870-local-tunnel-pair/plan.md`.

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path took a 2× regression on a rare HA codepath
that's known and accepted; see PR #1182 for the trade-off.
