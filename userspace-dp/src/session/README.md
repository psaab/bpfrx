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
  `push_to_wheel` scheduler, `wheel_observe`, and the #2120 standby
  retention gate (`expire_stale_entries_ha` + `standby_gate_decision` +
  `rebucket_alive_entry`).
- `entry.rs` — the PUBLIC session data types: `SessionDecision`,
  `SessionMetadata`, `SessionLookup`, `ForwardSessionMatch`,
  `SessionOrigin`, `SessionDeltaKind`, `SessionDelta`, and
  `ExpiredSession`. The internal per-entry `SessionEntry` (and its #2120
  standby-gate fields `seen_rg_epoch` / `first_held_ns`, see "Standby
  retention" below) stays file-private in `mod.rs`, NOT here.
- `key.rs` — `SessionKey`, `forward_wire_key` (ingress 5-tuple),
  `reverse_canonical_key` (post-NAT lookup), and
  `reply_matches_forward_session` (the predicate used to detect "this
  inbound packet matches an existing outbound flow").
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

## Standby retention (#2120)

The Rust wheel now owns HA standby session retention — the contract the
eBPF Go-GC `IsLocalPrimary` gate used to enforce before the eBPF dataplane
was retired (#1373/#1476). Without it, the STANDBY node silently expired
long-lived peer-synced sessions whose idle timeout elapsed with no local
refresh, and the newly-promoted primary then dropped their return traffic
as a brand-new connection (#131, reintroduced by the eBPF→userspace
migration).

`expire_stale_entries_ha(now_ns, Some(ctx))` makes a three-way decision
for each idle-crossed entry before removing it (the plain
`expire_stale_entries(now_ns)` / `ha = None` path is standalone behavior —
every idle entry ages, exactly as before):

- **SELF-HEAL** (edge) — peer-synced, this node now FORWARDS the entry's
  RG, but `seen_rg_epoch` predates the activation (`RefreshOwnerRGS` may
  not have landed). Re-stamp `last_seen_ns`, record the new epoch,
  re-bucket; fires once per activation, then the entry ages normally.
  `first_held_ns` is left UNTOUCHED so a flapping RG cannot reset the leak
  ceiling.
- **HOLD** — this node does NOT forward the entry (standby / demotion
  window) and it is peer-synced or this node forwards something
  (`peer_synced || node_active`, the "in a cluster" guard that excludes a
  standalone node). Held unless held past the stale-synced ceiling.
- **AGE** — normal removal: active-node-owned, standalone, fabric-ingress,
  or a held entry past the ceiling.

The HOLD keys on FORWARDING, not origin, so a still-`ForwardFlow`
demotion-window entry (the demote flip not yet applied) is held too.
`owner_rg_id <= 0` (fabric / unresolved-owner reverse) uses the
node-level `rg_epochs[0]` activation edge so the self-heal fires for
those entries.

`seen_rg_epoch` changes ONLY on install/refresh (→ 0) and SELF-HEAL
(→ current epoch). The HOLD branch does **not** stamp it. This is
load-bearing: the worker reads the HA map and `rg_epochs` as two separate
loads, so a HOLD can observe an OLD (inactive) map with a NEW (already
bumped) epoch. If HOLD stamped that new epoch, the next pass — which sees
the new ACTIVE map with the same epoch — would find
`current_epoch == seen_rg_epoch` and SKIP the self-heal, aging the synced
session. Leaving `seen_rg_epoch` at its install/refresh value guarantees
the first forwarding pass after any epoch-bumping activation fires the
self-heal; the self-heal arm then records the epoch, so it does not
re-fire perpetually.

The **stale-synced ceiling** is
`min(STALE_SYNCED_CEILING_MULT × expires_after_ns,
STALE_SYNCED_CEILING_ABS_NS)` (MULT = 3, ABS ≈ 7 days), measured from
`first_held_ns` (when the entry FIRST entered the held state). It bounds
the lost-primary-delete leak: a held entry whose Close delta AND journal
entry were both lost is reaped without a primary delete. RELATIVE so a
live long-`inactivity-timeout` session is never reaped on the standby
before failover; ABS-capped to bound the pathological `MaxDurationSeconds`
config; `first_held_ns`-based so self-heal re-stamps on a flapping RG
cannot reset the clock.

The HA-forwarding predicate (`HAGroupRuntime::is_forwarding_active`, which
includes the watchdog lease and so fails CLOSED — a node that lost cluster
state reads inactive → holds) lives on the `afxdp` side and is handed in
as `ExpireHaContext` closures (`forwards_rg`, `epoch_of`, `node_active`)
so the afxdp-private HA types never leak into `crate::session`. The
context is built in `afxdp/worker/loop_body/mod.rs` right before the
expire call.

The self-heal edge is made airtight by the **epoch-before-publish
ordering** in `afxdp/ha.rs::update_ha_state`: `rg_epochs` for every
activated/demoted RG (and the node-level `rg_epochs[0]` on any activation)
is bumped BEFORE `rg_runtime.store`, so a worker that observes the active
`rg_runtime` always observes the bumped epoch (never new-rg + old-epoch).

`WheelPopStats` exposes `held_standby`, `reaped_stale_synced`,
`healed_on_promote`, and `aged_owner_rg_zero_active_node` (the last makes
the known active/active `owner_rg_id == 0` under-retention residual
observable — a `==0` entry for a standby RG path on an otherwise-active
node ages and is re-derived on promotion via the reverse-synced prewarm).

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

## Per-IP session-limit lifecycle (#2134, fixes #2128)

Junos `set security screen ids-option <name> limit-session
source-ip-based <n>` / `destination-ip-based <n>` caps the concurrent
locally-admitted sessions one source / destination IP may hold. The
per-IP count is owned by `SessionTable` (`session_limit_src_counts` /
`session_limit_dst_counts`), NOT by `ScreenState` — the count must track
the real session lifecycle, and `SessionTable` is the choke point every
create/remove already passes through.

**Counted-class predicate.** A session counts iff it is locally-admitted,
forward-direction, real (not a transient seed), and not imported from the
HA peer: `!is_reverse && !origin.is_peer_synced() &&
!origin.is_transient_local_seed()`. This is exactly the predicate that
gates the HA Open delta, so the count and the delta stay in lockstep.

**Maintenance sites (all OFF-gated by `session_limit_active`).** The
count is incremented at the two create transitions and decremented at the
two remove transitions:

| Transition | Site | Action |
|---|---|---|
| fresh install | `install_with_protocol_with_origin` (next to the Open-delta push) | increment |
| in-place HA promote synced→local | `update_session` promote branch (`mod.rs`) | increment |
| any removal (expire / clear / RST / fabric-cancel / take_synced_local) | `remove_entry` success path (the sole removal sink) | decrement |
| in-place HA demote local→synced | `demote_owner_rg` (before the origin flip) | decrement |

Removals are structurally exhaustive through `remove_entry`, so a future
delete site cannot forget the decrement. The two in-place HA transitions
bypass the install/remove sinks, so they carry explicit, enumerated
count adjustments. Every decrement uses `saturating_sub` and **evicts the
map entry the moment its count reaches 0** — so the maps are bounded by
distinct IPs with ≥1 live counted session (this is the #2128 fix: the
read path never inserts a phantom zero entry).

**Where the limit is CHECKED.** At the NEW-FLOW / session-MISS decision
in `afxdp/poll_descriptor` (`new_flow_session_limit_drop`), NOT in the
per-packet screen stage. The screen stage runs on every data packet of
every flow and before the session lookup; checking `count >= limit`
there would re-evaluate an established flow's own counted session and
self-drop it at the limit boundary. The new-flow check fires exactly once
per new flow, before its session exists, via a non-mutating
`session_limit_{src,dst}_count` query, and emits the
`session-limit-src` / `session-limit-dst` screen-drop event + counter.

**OFF-gate + clear-on-disable.** `set_session_limit_active(active)` is
driven from the applied screen-profile snapshot (startup +
runtime-reload, next to `set_timeouts` /
`ScreenState::update_profiles`). When no zone configures `limit-session`
the gate is OFF and every maintenance op short-circuits, so the ~99% of
deployments pay nothing. On an ON→OFF runtime transition the gate setter
**clears both count maps** — otherwise the decrement paths stop firing
and a later re-enable would resume from stale, over-counted values and
spuriously block an under-limit IP. After a re-enable the maps start
empty and re-populate from new installs; pre-existing live sessions are
not back-counted (benign, Junos-approximate).

**Per-worker scoping.** Each worker owns its `SessionTable`, so the count
is per-worker — a single IP spreading flows across N RX queues sees an
effective limit up to N×limit. This is a pre-existing property (same
under the eBPF per-CPU map), not introduced by this change.

Decision record: `docs/research/2128-2134-screen-session-limit/plan.md`.

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path took a 2× regression on a rare HA codepath
that's known and accepted; see PR #1182 for the trade-off.
