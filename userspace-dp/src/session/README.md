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

**Seconds→nanoseconds bound (#2441).** Configured TCP/UDP/ICMP timeouts
arrive in the snapshot as `u64` seconds and are converted in
`SessionTimeouts::from_seconds`. The conversion uses `checked_mul` and
**saturates** at `MAX_SESSION_TIMEOUT_NS`
(`MAX_SESSION_TIMEOUT_SECS == i64::MAX / 1e9 == 9_223_372_036` s, the same
value as the Go `config.MaxDurationSeconds` commit gate) — it never wraps
and never panics. A snapshot-boundary helper must do neither, and
saturating fails toward a *longer*-lived session, the opposite of the
wrap bug it replaces (a huge configured timeout wrapping to a tiny one →
premature expiry). The bound is defense-in-depth: the Go commit gate
(`ValidateInteger(0, MaxDurationSeconds)` in `schema_security.go` +
`coerceWireSessionTimeout` build-time coercion) is the operator-facing
reject and is load-bearing for the normal in-band config path; this
saturation is the runtime backstop for an out-of-band snapshot or a
future caller that bypasses the Go gate.

## GC

`SESSION_GC_INTERVAL_NS = 1_000_000_000` (1 s). Single-threaded per-worker
sweep walks the wheel bucket for the current tick; stale entries get
lazy-deleted on the next lookup if they slip past the sweep (e.g.
because they were re-bucketed mid-sweep).

## Flow-cache keepalive (#2220)

The flow-cache fast path (`afxdp/poll_descriptor/flow_cache_hit.rs`) is
the ONLY code path that refreshes a forwarded flow's `last_seen_ns` — a
flow served entirely from the per-worker flow cache never re-runs the
slow path that would otherwise touch the session. `touch_if_stale` is
the keepalive it calls on every cache hit: it re-stamps the matched
session ONLY once that session has gone idle for at least
`expires_after_ns / SESSION_KEEPALIVE_DIVISOR` (a quarter of its OWN
timeout). An actively-forwarding cached flow is thus re-stamped whenever
its idle time crosses `expires_after_ns / N`, keeping its age ~`T/N` in
steady state regardless of co-resident flow rates, so it can never be
GC'd mid-flow (reaped only if a real inter-packet gap exceeds `T`). The
steady-state per-hit cost is one `key_to_handle` probe plus an integer
compare (the `last_seen_ns` write + throttled `push_to_wheel` run only
when actually stale); allocation-free.

This replaced the pre-#2220 binding-GLOBAL modulo-64 counter
(`flow_cache_session_touch`), which incremented across ALL flows on the
binding and touched only the flow whose hit happened to land on a global
multiple of 64. A low-rate flow co-resident with a saturating flow could
be served from the cache for a whole timeout window without its session
ever being touched, then be reaped while still forwarding (an HA Close
delta to the peer + BPF redirect-key deletion + a stale flow-cache
descriptor out-living its session). UDP (60 s) was the most exposed.

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

## "Current sessions" gauge accounting (#2428)

The `session_creates` / `session_expires` BindingLiveState counters feed
the Go-side `show security flow statistics` "Current sessions" gauge,
which Go derives as `dataplane.CurrentSessions(session_creates,
session_expires)` — a **local-forwarding** gauge.

`SessionOrigin` has **8 variants**. `session_creates` is incremented ONLY
on the four local poll-descriptor install paths —
`SessionOrigin::{ForwardFlow, ReverseFlow, LocalMiss, MissingNeighborSeed}`.
The other four are **synced-derived and never create-counted**:

- `SyncImport` / `SharedMaterialize` / `WorkerLocalImport` — installed via
  the HA sync path (`upsert_synced_with_origin` /
  `WorkerCommand::UpsertLocal`);
- `SharedPromote` — a re-tag of an already-synced (uncounted) entry by
  `maybe_promote_synced_session` (`session_glue/promote.rs`), whose
  `promote_synced_with_origin` install does NOT touch `session_creates`.
  Note `is_peer_synced()` returns **false** for `SharedPromote`, so it must
  be excluded by name, not via `is_peer_synced()`. `shared_ops.rs` already
  groups `SharedPromote` with the peer-synced set for the wire-alias
  contract — this counter is consistent with that.

The expire pass therefore must count **only the four create-counted
locals** in `session_expires`, otherwise a node that reaps synced or
promoted sessions (the standby always; any node post-failover for
`SharedPromote`) drives `session_expires` past `session_creates`, wrapping
the unsigned Go subtraction to ~1.8e19. `worker_loop`'s
`count_local_session_expiries` does this with an **exhaustive `match` (no
wildcard)** over all 8 variants — so a future 9th variant forces a
compile-time decision instead of silently defaulting to "counted" — before
the `fetch_add`. The standby thus reports `Current sessions: 0`. The
Go-side `CurrentSessions` saturating floor (clamp at 0) is the
defense-in-depth backstop against any future imbalance.

### Metric-semantics note (#2428)

`session_expires` is the SAME counter the Go control plane reads as
`dataplane.GlobalCtrSessionsClosed` (mapped 1:1 from `cur.sessionExpires`
in `pkg/dataplane/userspace/manager_ha.go`). That global counter feeds the
exported `sessions_closed` surfaces — `pkg/api/stats.go`,
`pkg/api/metrics_counters.go` (`xpf_sessions_closed_total` Prometheus
metric), and `pkg/grpcapi/server_show_status.go`. So after this fix
`sessions_closed` (like `sessions_created`) means **LOCAL sessions
closed** — it excludes peer-synced / promoted reaps, matching
`sessions_created` which never counted those installs. This is a
deliberate semantics tightening, not a regression: the two counters are
now consistently local-only, so their difference (the "Current sessions"
gauge) is a coherent local-forwarding metric on every node.

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

### HA install-generation guard on SyncedSessionEntry (#2170)

`SyncedSessionEntry` (`afxdp/worker/mod.rs`) carries a `generation: u64`
mirrored from the Go cluster apply layer via `SessionSyncRequest.generation`.
Only peer `SyncImport` entries carry a meaningful (non-zero) generation;
local-origin entries (forward/reverse learn, tunnel decap, promote,
missing-neighbor seed) leave it 0. The synthesized reverse companion inherits
the forward entry's generation so a delete refusal is consistent across both
halves.

`upsert_synced_session` (`afxdp/ha.rs`) refuses a strictly-older-generation
install (both generations non-zero) so the helper's stored generation never
regresses (`SESSION_INSTALL_STALE_IGNORED`), mirroring the Go install guard.
`delete_synced_session_gen(key, delete_gen)` refuses a strictly-older-generation
delete (`SESSION_DELETE_STALE_IGNORED`); the plain `delete_synced_session(key)`
wrapper passes `delete_gen = 0` so helper-local purges (tunnel-remap, GC) stay
unconditional. These helper-side guards are **belt-and-suspenders** — the
authoritative guard lives in the Go cluster apply layer (`deleteClusterSynced*`),
which short-circuits both the BPF map delete and the helper. The counters are
surfaced via `Coordinator::session_install_stale_ignored_total()` /
`session_delete_stale_ignored_total()`. See `docs/sync-protocol.md` and
`docs/research/2170-ha-deferred-delete/plan.md`.

## Per-IP session-limit lifecycle (#2134; #2128 leak-fix preserved)

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

**Per-worker scoping — the effective cap is `configured × num_workers`
(#2186).** Each worker owns its `SessionTable` by value, so the per-IP
count is maintained *independently per worker (per RX queue)*. With RSS
spreading the flows of a single source/destination across all N RX
queues, the limit is enforced N times in parallel, so the **effective
admitted cap ≈ `configured_limit × number_of_RX_queues/workers`**, not a
single global cap. The configured value is the per-worker ceiling.

Worked example (loss userspace cluster, 6 mlx5 RX queues → 6 workers):
`limit-session source-ip-based 2` admitted **12** sessions (2 × 6) from
one source before screen-drops engaged. Enforcement is correct and fires
on every worker; the cap is just per-worker-multiplied. This is a
pre-existing property of the per-worker dataplane (the same was true of
the eBPF per-CPU map), not introduced by #2134, and it is consistent
with Junos-approximate multi-queue semantics. Operators sizing a cap
should divide the desired global ceiling by the worker count, or treat
the configured value as an approximate per-source/destination bound that
scales with queue count.

Decision record: `docs/research/2128-2134-screen-session-limit/plan.md`.

## Scan/sweep detection on the new-flow path (#2210; per-zone + bounded #2209)

Port-scan and IP-sweep follow the SAME structural rule as the per-IP
session limit above: the scan/sweep MUTATION runs at the NEW-FLOW /
session-MISS decision in `afxdp/poll_descriptor`
(`ScreenState::scan_sweep_drop_on_new_flow`), NOT on the per-packet
pre-session screen stage.

- **#2210 (count-after-lookup).** The pre-#2210 code ran IP-sweep on the
  per-packet stage, which executes BEFORE the session lookup and on every
  protocol — so mid-stream established TCP ACKs/data and UDP all counted
  toward the sweep. A single legitimate high-fan-out client (one host with
  live connections to many backends) would trip IP-sweep without ever
  sending a probe, and the original #867 ACK-evasion contract ("an ACK
  that matches a live session is not a sweep probe") was lost. Moving the
  mutation to the session-MISS hook means an established flow's packets are
  session HITS and never reach it, so only a genuinely-new flow counts.
  Port-scan keeps its TCP-initial-SYN gate; IP-sweep counts the new flow
  on any protocol (a session-miss ACK to many destinations is the
  ACK-evasion sweep it is meant to catch).

- **#2209 (per-zone + bounded).** The trackers are keyed by
  `(zone_id, src_ip)` (was a single global per-`src_ip` instance), so a
  source scanning zone `wan` no longer bleeds its count into the `dmz`
  threshold evaluation. The backing maps are bounded on both
  attacker-driven axes: `MAX_SOURCES_PER_ZONE` distinct sources per zone
  and `MAX_UNIQUE_PER_SOURCE` unique entries per source. On a SOURCE-axis
  overflow the tracker SKIPS the new source (degrades to not-counting that
  source) and bumps a `skipped_pressure` counter — that can only make a
  drop verdict LESS likely, never grow without bound. The per-tick cleanup
  walks the source table (`HashMap::retain`, O(sources)) but removes at
  most `CLEANUP_BUDGET` entries per call, so the per-tick MUTATION cost is
  bounded; the real ceiling on the walk is the `MAX_SOURCES_PER_ZONE` cap
  on the table itself, with the budget spreading reclamation across ticks
  (`screen/scan.rs`). This mirrors the #2134/#2177 session-limit
  skip-on-full discipline.

- **#2227 MAJOR-1 (fail-CLOSED on over-cap thresholds).** The
  unique-entry set tops out at `MAX_UNIQUE_PER_SOURCE` (1024), but the
  operator threshold is unbounded (`strconv.Atoi`, no clamp — e.g.
  `port-scan threshold 5000`). The detection compares
  `set.len() > threshold`, and `len()` can never exceed the cap, so an
  un-clamped threshold `>= MAX_UNIQUE_PER_SOURCE` could NEVER be crossed:
  the scanner would never be dropped (silent fail-OPEN). The dataplane
  therefore CLAMPS the effective comparison threshold to
  `MAX_UNIQUE_PER_SOURCE - 1`, so a source that fills the bounded set
  always crosses it — **detection fires AT THE CAP rather than never**.
  Each clamp is counted in `scan_sweep_threshold_clamped`. The config
  value is preserved unchanged (operator intent is kept); the Go control
  plane (`pkg/config/compiler_security.go`, constant
  `maxScanSweepThreshold` kept in sync with the Rust `MAX_UNIQUE_PER_SOURCE`)
  emits a commit-time WARNING when a port-scan/ip-sweep threshold exceeds
  the supported maximum, telling the operator it will be clamped. The
  effective contract is: scan/sweep detection NEVER silently fail-opens for
  any parseable config — at worst it detects at the cap.

- **Perf (#2209).** The per-packet `check_packet_with_zone_id` no longer
  clones the whole `ScreenProfile` per screened packet — it borrows it and
  copies only the small scalar thresholds it needs. The scan/sweep stage
  reads the profile by zone name only on the cold session-miss path.

Per-worker scoping applies identically to scan/sweep (each worker owns its
`ScreenState`), so the effective unique-entry count is multiplied by the
worker count, exactly as documented for the session limit above.

**Source-table saturation — bounded stalest-eviction (#2234, was MINOR-2).**
The per-zone source table is still capped at `MAX_SOURCES_PER_ZONE = 4096`
(memory never grows without bound), but the cap is no longer a HARD cliff. The
pre-#2234 behaviour SKIPPED a brand-new source once the zone was full, so a
high-cardinality spoofed-source flood that filled the table could prevent a
*subsequently-arriving* genuine scanner from being tracked — and therefore
from being detected — until entries expired (which the attacker could defer
indefinitely by keeping its 4096 sources fresh). That was a detection-DoS: it
never fail-opened the *forwarding* path, but it suppressed scan/sweep
*detection*.

The new-source path now makes BOUNDED room instead of skipping. When a brand-
new `(zone, src_ip)` arrives at a full zone, the tracker scans a FIXED PREFIX
of the source table (`iter().take(EVICT_SCAN_LIMIT)`, `EVICT_SCAN_LIMIT = 64`
— the budget counts EVERY iterated entry, same-zone or not), reclaims the
first expired same-zone window it finds, and if none is expired evicts the
STALEST (oldest `window_start`) same-zone entry within that prefix. This
branch only runs when the TARGET zone alone holds `>= MAX_SOURCES_PER_ZONE`
keys, so same-zone entries are dense in the table and the prefix reliably
contains a victim — a fresh real scanner is therefore admissible and the
detection-suppression cliff is gone. The per-new-flow worst case is
O(`EVICT_SCAN_LIMIT`), NOT an O(sources) min-scan over 4096 entries, which
under a saturation flood would itself be an O(n)-per-packet amplifier. The
per-zone source count is maintained incrementally (`per_zone_count`) so the
cap test is O(1); the only walk is the bounded prefix. In the pathological
many-zones-sparsely-interleaved case where the prefix holds no same-zone
victim, the path degrades back to skip-on-full (`skipped_pressure`) — still
bounded, still never fail-open.

Each eviction bumps `evicted_pressure` (surfaced via
`ScreenState::scan_sweep_evicted_pressure`), and a rare LOGARITHMIC threshold
crossing (powers of two in the cumulative eviction count) emits a
`scan-table-pressure` screen event so the operator is told the detector is
saturated — at a handful of alarms under a sustained flood, never per-flow
(honouring the no-per-packet-logging rule). Defence-in-depth mitigations still
apply: anti-spoofing / uRPF upstream reduces the spoofed-source axis, and the
`skipped_pressure` / `evicted_pressure` signals surface the pressure.

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path took a 2× regression on a rare HA codepath
that's known and accepted; see PR #1182 for the trade-off.
