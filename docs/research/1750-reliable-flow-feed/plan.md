# #1750 — reliable per-flow 5-tuple feed for the #1748 rebalance controller

- **Status**: PLAN v2 — r1 hostile round folded (Codex PLAN-NEEDS-MAJOR, AGY
  PLAN-NEEDS-MAJOR, Claude-SMR PLAN-NEEDS-MAJOR self-corrected). v1's
  "atomic publish" claim was FALSE; a second independent zero-install root
  cause (slot vs worker_id keying) was missed; §6.3 carry-forward was dead
  code. All three folded below.
- **Issue**: #1750
- **Mode**: `/research` — stops at PLAN-READY / PLAN-KILL. No PR, no production
  code touched in this skill.
- **Branch (docs only)**: `research/1750-reliable-flow-feed`
- **Predecessor**: PR #1749 / `engineer/1748-ntuple-rebalance`; #1748 plan
  `docs/pr/1748-ntuple-rebalance/plan.md` (PLAN-READY v7); R1 spike PASS
  (CoV 16.8%→2.3–4.2%); live-gate ledger
  `docs/pr/1748-ntuple-rebalance/reviewer-ids.md` (round-1 + round-2 failures).

---

## 1. Issue framing

The #1748 reactive ntuple rebalancer is protocol-/ioctl-/activation-correct
(R1 manual ethtool: per-flow CoV 16.8%→3.8% with aggregate preserved), but on
the live `-P12 -p5210` CoV gate it **installs zero rules** because its per-flow
data feed is judged unreliable on two layers:

1. **5-tuple list (the blocker):** the controller sources flows-to-move from
   `Coordinator::flow_worker_map()`
   (`userspace-dp/src/afxdp/coordinator/status.rs:168`, consumed at
   `coordinator/rebalance.rs:243`). Under load it returns sparse/empty rows for
   workers that `xpf_userspace_binding_active_flow_count` simultaneously reports
   as having ≥1 active flow → `select_move` finds an empty `candidates` vec →
   `moves_skipped_total{reason="no_eligible_flow"}` → `installs_total=0`
   (`rebalance/controller.rs:484-600`).

2. **Per-flow byte-RATE (already worked around on the branch):** the rate is
   derived from `FlowCacheEntry.observed_bytes`, which is **reset to one
   packet's length on flow-cache eviction+re-insert**
   (`flow_cache.rs:370` insert sets `observed_bytes = pkt_len`; `:669`
   accumulates on hit). `cumulative_to_rate` then sees `cur < prev` →
   `saturating_sub` → rate 0. The branch already added a worker-rate fallback
   (`controller.rs` `fallback_per_flow_rate = hottest.byte_rate /
   candidate_count`) so RATE is no longer the blocker; the **5-tuple list** is.

This research answers the principled data-source question. A parallel targeted
patch is being attempted on the branch; this plan is the design answer
(what feed, why, at what cost), not the patch.

## 2. Key code-grounded finding (changes the framing)

**The active-flow COUNT and the 5-tuple ROW LIST are produced by the *same*
single scan, but they are published to readers as TWO INDEPENDENT atomics — so a
reader CAN observe a fresh count with stale (or empty) rows.** (v1 wrongly
claimed they are "published atomically together"; Codex + AGY r1 both quoted the
two-store reality. Corrected below.) Evidence (all on `origin/master`, identical
on the engineer branch):

- `FlowCache::active_flow_debug_entries(limit)`
  (`flow_cache.rs:465`) iterates the cache once and returns
  `(active_count, rows, cos_counts, truncated)` — `active_count` is incremented
  in the **same loop** that pushes `rows` (`flow_cache.rs:479-490`), gated by
  the identical `active_entry_age(entry).is_some()` predicate. The production
  count comes from here; `count_active_flows()` is `#[cfg(test)]`-only
  (`flow_cache.rs:441`).
- `publish_binding_debug_state` (`umem/debug_state.rs:216-249`) calls that scan
  once with `limit = FLOW_WORKER_MAP_MAX_PER_BINDING = 256`
  (`flow_cache.rs:18`). It then performs **two separate atomic publishes** from
  the one returned tuple: `binding.live.active_flow_count.store(active_flow_count,
  Ordering::Relaxed)` (an `AtomicU32`, `debug_state.rs:223-224`) and
  `binding.live.publish_flow_worker_map(rows, truncated)` →
  `self.flow_worker_map.store(Arc::new(FlowWorkerMapSnapshot{rows, truncated}))`
  (a separate `ArcSwap`, `umem/mod.rs:817-824`). `FlowWorkerMapSnapshot` carries
  **only rows + truncated** — NOT the count (`umem/mod.rs:250-255`). So
  `xpf_userspace_binding_active_flow_count` and the `flow_worker_map` rows are
  two projections of one scan but two independent stores → a reader (coordinator
  tick or Prometheus scrape) can read a fresh count with a stale/empty row
  snapshot. **This non-atomic dual-publish is the actual skew, and the fix is to
  bundle the count INTO the row snapshot (Path 1).**
- The row cap is **256/binding**; a worker carrying 3 flows cannot be truncated
  below 3. `truncated` only drops rows *above* 256.
- `active_entry_age` (`flow_cache.rs:453`) returns `None` for
  `last_used_epoch == 0` ("never touched") OR age ≥ `ACTIVE_WINDOW_EPOCHS`
  (10 epochs ≈ 650 ms). A freshly-inserted entry has `last_used_epoch = 0`
  (`flow_cache.rs:370`); its first lookup-HIT stamps the epoch
  (`flow_cache.rs:663`, via `lookup_counted` on the hot path
  `poll_descriptor/flow_cache_hit.rs:94`). So an entry is **invisible to BOTH
  count and rows** between (re-)insert and its next hit, and visible to BOTH
  thereafter — they move together.

**Consequence:** the issue's literal symptom ("count says 3, rows say empty") is
a *non-atomic dual-publish / cross-snapshot skew* and/or a *consumer-side keying
or filter bug*, NOT a fundamental flow_cache enumeration deficiency. The
flow_cache scan IS the reliable per-worker enumeration the issue's Q1 is asking
for; it is the very mechanism that makes the count reliable. The defect is in
(a) how the count and rows are published (two atomics) and (b) how the
controller consumes/keys them.

### 2.1 Where the consumer-side skew/loss actually comes from

The controller does NOT read count and rows from one atomic snapshot. It reads:
- per-worker rate from `live.tx_bytes()` (`rebalance.rs:210`),
- flow rows from `self.flow_worker_map()` (`rebalance.rs:243`) — an `ArcSwap`
  load (`umem/mod.rs:826` / `coordinator/status.rs:168`),
- and the human/operator compares against the *separately scraped* Prometheus
  `binding_active_flow_count` (a third read instant).

Four candidate consumer-side causes (D added in r1):

- **(D) Slot-vs-worker_id keying mismatch (Codex r1 — independent zero-install
  bug).** `Coordinator::tick_rebalance` iterates `for (&worker_id, live) in
  &self.workers.live` (`coordinator/rebalance.rs:209`) and labels the key
  `worker_id` — but `workers.live` is **keyed by `binding.slot`**
  (`worker_manager.rs:6` doc: "`live` and `identities` are keyed by binding
  `slot`"; `bringup.rs:47` `coord.workers.live.insert(binding.slot, ...)`). The
  published flow rows carry the REAL `binding.worker_id`
  (`debug_state.rs`/`poll_descriptor/mod.rs:434-436`), and `select_move`
  filters `f.worker_id == hottest.worker_id` (`controller.rs:507-511`). When
  `slot != worker_id` (shared-UMEM / multi-binding-per-worker configs), the
  per-worker rate vector is keyed by SLOT while the flow rows are keyed by
  WORKER_ID → the equality filter yields `candidate_count == 0` →
  `no_eligible_flow` → zero installs, **independent of any feed-reliability
  fix.** On the 6-queue/6-worker mlx5 smoke cluster `slot == worker_id` (1:1)
  is likely, making the bug *latent there* but real elsewhere. The increment
  MUST make worker-identity keying consistent end-to-end (key the rate vector
  by the published `worker_id`, OR carry `slot` on the rows and key both by
  slot — pick ONE and apply it through `WorkerByteRate`, `FlowSample`, and the
  `select_move` filter). The live trace MUST check the worker-id match, not
  just row presence.

- **(A) Empty-on-first-publish / publish-cadence skew.** The row `ArcSwap`
  starts empty (`umem/mod.rs:636`, `ArcSwap::from_pointee(Vec::new())`) and is
  only refreshed every `DEBUG_STATE_PUBLISH_MASK = 0xFFFF` poll-iterations
  (`debug_state.rs:26`, ~65 ms at line rate) or the 65 ms idle wall-clock
  (`debug_state.rs:34`). If the eval reads before the first hot publish, or the
  poll counter has not wrapped on a low-PPS worker, rows are empty while a
  later-scraped Prometheus count is non-zero. This is a genuine *timing* skew,
  not a flow_cache fault.

- **(B) The `last_used_epoch == 0` window vs steady hits.** Under steady
  forward traffic every post-first packet is a HIT (`lookup_counted` stamps the
  epoch each packet), so the 12 flows are continuously inside the 650 ms
  window. For this NOT to hold there must be a recurring eviction. Under
  `-P12` (≤24 forward+reverse cache entries) in a 1024-set / 4-way cache,
  capacity/collision eviction is statistically negligible; generation eviction
  (`config_generation`/`fib_generation`, `flow_cache.rs:625-651`) fires only on
  a control-socket `bump_fib_generation` (`server/handlers/mod.rs:110`) i.e. a
  config/route change, and `owner_rg_epoch` only on HA failover — neither
  recurs under steady iperf. So eviction-driven (B) is unlikely at P12 line
  rate, but MUST be verified live (it would dominate at high flow-count /
  hot-set workloads, the controller's real target regime). **Additional (B)
  mechanism (AGY r1): age-out at low PPS.** `active_entry_age` counts an entry
  active only for `< ACTIVE_WINDOW_EPOCHS = 10` epochs ≈ 650 ms
  (`flow_cache.rs:453-459`); a flow quieter than ~1 pkt / 650 ms ages out
  between packets and drops from BOTH count and rows periodically — a real
  "rows empty for a live flow" mechanism the consumer must tolerate (defer one
  tick, not terminal `no_eligible_flow`).

- **(C) Consumer filter drop.** `rebalance.rs:248-300` drops a row if
  `ifindex <= 0 || !per_iface_workers.contains_key(&ifindex)` (ifindex is
  `binding.ifindex`, which equals `socket_ifindex` — `worker/mod.rs:333` — so
  this should match), if `session_key_from_tuple` fails to parse the
  IP strings (`rebalance.rs:547`), or if `protocol` is not TCP/UDP. A
  silent parse failure or an unexpected `addr_family`/proto on the published
  `session_key` would drop rows the count still includes. Must be ruled out
  with the `REBALANCE_FLOW` debug-log already on the branch.

**The plan's job is to (i) identify which of A/B/C is live, and (ii) make the
feed structurally immune to it**, not to keep patching `select_move`.

## 3. Honest scope/value framing

- **Value:** unblock the only lever that lifts slow flows AND preserves
  aggregate (R1: CoV→2.3–4.2%, aggregate up). Without a trustworthy feed the
  entire #1748 controller is inert and the PR cannot land its live gate.
- **Scope of the eventual `/engineer` increment (this plan picks the path):**
  a *reliable, eviction-independent, single-snapshot* per-worker live-flow
  feed for the controller, plus the consumer change to use it. Default-OFF
  semantics of #1748 are unchanged (no feed work runs unless the knob is set).
- **PLAN-KILL is acceptable** if the only reliable feed costs unacceptable
  hot-path work AND a reliable 5-tuple list + worker-rate fallback cannot
  achieve fair placement — say so with evidence.

## 4. Research answers

### Q1 — most reliable per-worker live-flow 5-tuple source
**Answer: the flow_cache active-flow scan (`active_flow_debug_entries`) IS the
right source — it is exactly what makes `binding_active_flow_count` reliable.**
The fix is to consume *count and rows from one atomic snapshot* and to close
the publish-cadence / first-publish skew, NOT to invent a new table. There is
no cheaper authoritative source:
- `flow_worker_map` already enumerates the live per-worker forward 5-tuples
  with NAT-aware `forward_wire_key` and the pre-NAT `session_key`.
- A *separate sampled flow table* (e.g. sketch / reservoir on the hot path)
  duplicates state the flow_cache already holds and adds per-packet cost —
  rejected unless A/B/C proves the cache scan is unfixable.
- *Kernel-side flow enumeration* (`ethtool`/`tc`/conntrack) does not see the
  AF_XDP fast-path flows (they bypass the kernel stack) — not viable.

The session table (`session/mod.rs`) is an alternative authoritative store, but
it is keyed globally (not per-worker/per-RX-queue) and the worker→queue
attribution the controller needs is precisely what the flow_cache (owner-scan,
per-binding) already provides. So flow_cache wins on attribution.

### Q2 — does the controller need per-flow byte-RATES?
**Answer: NO for the homogeneous (equal-flow RSS-skew) case, which is the
measured symptom; conditionally for heterogeneous (elephant+mice).**
- Homogeneous P12: all flows ≈ equal rate; the per-worker-rate fallback
  (`hottest.byte_rate / candidate_count`) is the physically-correct per-flow
  estimate and R1 proved equal round-robin re-pin alone takes CoV to 3.8%. A
  reliable 5-tuple **list** + worker-rate fallback is sufficient. The problem
  reduces to "reliable 5-tuple enumeration."
- Heterogeneous (one elephant + several mice on the hot worker): the
  worker-rate/count estimate misattributes — it would pick an arbitrary
  (possibly mouse) flow, and moving a mouse off a worker dominated by an
  elephant does NOT flatten CoV. Here a *coarse per-flow magnitude rank*
  (which flow is the elephant) is needed — but only an **ordinal** signal
  ("heaviest flow on this worker"), not an accurate rate.
- **Design implication:** the eventual increment should (a) guarantee the
  reliable list, and (b) provide an *eviction-independent ordinal* per-flow
  byte signal good enough to pick the heaviest flow. See Q3.

### Q3 — is `observed_bytes` reset-on-eviction cheaply fixable?
**Answer: yes, cheaply, via carry-forward on re-insert — but it only matters
for the heterogeneous ordinal case (Q2), and even then a coarse fix suffices.**
- The reset is one line: `insert` builds the entry with
  `observed_bytes = pkt_len` (`flow_cache.rs:370`). A re-insert of an
  *already-present-then-evicted* key loses the prior accumulation.
- **CORRECTION (Codex + AGY r1): the dedup-on-insert branch is DEAD CODE in
  production.** The hot path always `lookup_counted` first
  (`poll_descriptor/flow_cache_hit.rs:94`); a hit skips `insert`, and a miss
  means the key is absent OR was just deleted inside `lookup_counted` on a
  generation/epoch/lease mismatch (`flow_cache.rs:625-652`). So when `insert`
  runs it never finds a matching key to dedup (`flow_cache.rs:686-694`) — a
  carry-forward there NEVER executes and does NOT fix the reset under LRU
  eviction churn. v1's "cheap option 1" is invalid; drop it.
- **The only correct carry-forward is a cold-path eviction side-table:** a tiny
  bounded per-binding `HashMap<SessionKey,u64>` "recent bytes" updated only when
  an entry is evicted (LRU displacement `flow_cache.rs:705-710`, or
  generation/lease delete in `lookup_counted`), read back into the new entry's
  `observed_bytes` on the next `insert` of that key. Owner-only, cold-path, no
  per-packet work. Bounded by an LRU/size cap so it cannot grow unbounded.
- **Or switch the controller to an ordinal signal** (rank candidate flows by
  `age_epochs` + the worker-rate/count estimate) and skip per-flow byte
  accounting entirely — the controller only needs "which flow is heaviest", and
  for homogeneous traffic the estimate already gives that.
- Per-flow byte accounting is therefore NOT fundamentally unreliable; the
  reset is an artifact of overwrite-on-insert, fixable on the cold path.
- **However:** if A/B/C shows the *list* itself is reliable in steady state and
  the only real failure was the rate (already fallback-patched) plus a
  cadence/first-publish skew, then Q3 is a *follow-up nicety* for heterogeneous
  traffic, not a blocker. The plan keeps it as an optional path component.

### Q4 — is the reactive-controller approach still right?
**Answer: yes.** The data-feed difficulty is a *consumer/cadence* defect, not a
flaw in reactive selection. R1 proved reactive established-flow re-pin works.
Alternatives (connect-time placement #1203, RSS-table tuning #840) are already
falsified in project memory (count-blind / cross-binding-skew dead ends). The
reactive ntuple controller remains the only mechanism that improves `Cstruct`.
No re-architecture is warranted; the increment is a feed-reliability fix.

### Q5 — honest cost/benefit
- **If D (slot/worker_id keying) is the live cause:** fix is keying the rate
  vector by the row identifier (Path 1 part 2) + a `slot != worker_id` test.
  Few lines, no hot-path cost. **Ship.** (Strong candidate even on the 6:6
  cluster — verify whether slot == worker_id there before assuming it is
  latent.)
- **If A (non-atomic dual-publish skew) is the live cause:** fix is bundling the
  count into `FlowWorkerMapSnapshot` (Path 1 part 1) + the staleness defer.
  Few lines, no hot-path cost. **Ship.**
- **If B (eviction churn / low-PPS age-out) is the live cause:** fix is the
  cold-path eviction side-table OR ordinal selection (Path 2) + the staleness
  defer; possibly a longer "seen recently" mark. Low hot-path cost. **Ship.**
- **If C (consumer filter/parse bug) is the live cause:** trivial fix in
  `rebalance.rs`. **Ship.**
- **PLAN-KILL trigger:** only if the live `REBALANCE_FLOW`/`REBALANCE_EVAL`
  trace shows the flow_cache scan *itself* (not the publish/keying/consumer)
  drops active forward flows in steady state AND no cold-path side-table
  restores them — improbable at P12. Honest stance: **this is a cheap fix, not
  a kill.**

## 5. Multiple Path Options

### Path 1 — Single-snapshot consume + worker-id keying fix + cadence hardening (RECOMMENDED)
Three parts:
1. **Bundle count into the row snapshot (fixes the non-atomic dual-publish).**
   Extend `FlowWorkerMapSnapshot` (`umem/mod.rs:250-255`) to carry the
   per-binding `active_flow_count` and publish BOTH from the one
   `active_flow_debug_entries` tuple in the SAME `ArcSwap` store
   (`debug_state.rs:216-249`). The controller then reads count and rows from one
   atomic load and never cross-references an out-of-band Prometheus count.
2. **Fix the slot-vs-worker_id keying (cause D — independent zero-install
   bug).** Key the controller's per-worker rate vector (`WorkerByteRate`) by the
   SAME identifier the rows carry. Either (a) carry `worker_id` alongside the
   `slot` key when building `per_iface_workers` in `tick_rebalance`
   (`rebalance.rs:209-228`) and filter `f.worker_id == hottest.worker_id` against
   that, or (b) carry `slot` on the published rows and key the filter by slot.
   Pick ONE and apply it through `WorkerByteRate`, `FlowSample`, and
   `select_move`'s filter (`controller.rs:507-511`). Add a unit test with
   `slot != worker_id`.
3. **Staleness/first-publish guard.** If a worker's bundled `active_flow_count`
   > 0 but its row list is empty (stale, pre-first-publish, or one-tick
   age-out), record a new `SkipReason::StaleFlowSnapshot` and DEFER one tick —
   do not record terminal `no_eligible_flow`. Keep the worker-rate fallback for
   magnitude.
- **Pros:** smallest change set that fixes BOTH the publish skew (A) AND the
  keying bug (D) — either of which alone keeps installs at 0; uses the
  proven-reliable scan; no hot-path cost.
- **Cons:** does not improve heterogeneous selection (still worker-rate
  estimate). Acceptable for the P12 homogeneous gate; heterogeneous is Path 2.

### Path 2 — Path 1 + cold-path eviction side-table OR ordinal selection
Add to Path 1 an accurate per-flow magnitude signal for heterogeneous
(elephant+mice) traffic, via EITHER:
- the bounded cold-path **eviction side-table** (Q3, corrected) that carries
  `observed_bytes` across LRU/generation eviction — the dedup-insert
  carry-forward is dead code and is NOT used; OR
- switching the controller to an **ordinal** "heaviest flow" signal
  (`age_epochs` + worker-rate/count estimate) and dropping per-flow byte
  accounting from the decision entirely.
- **Pros:** correct elephant-vs-mice selection; still no per-packet cost.
- **Cons:** the side-table is bounded but new state; only matters if
  heterogeneous fairness is in scope for the increment.

### Path 3 — New per-worker sampled flow table (REJECTED unless A/B/C forces it)
A dedicated hot-path reservoir/sketch of (5-tuple→bytes) per worker.
- **Pros:** fully decoupled from flow_cache eviction.
- **Cons:** duplicates flow_cache state, adds per-packet sampling cost, new
  memory, new correctness surface. Violates the "no per-packet cost" invariant
  unless sampled at very low rate (which reintroduces sparsity). Rejected as
  over-engineering given the scan is already authoritative.

### Path 4 — PLAN-KILL
Only if the live trace proves the scan itself is unreliable in steady state and
no cheap carry-forward fixes it. Code analysis makes this improbable.

**Recommendation: Path 1 (all three parts — snapshot-bundle + worker-id keying
fix + staleness defer) as the blocker-clearing increment. It must fix BOTH the
non-atomic dual-publish (A) AND the slot/worker_id keying (D); either alone
keeps installs at 0. Defer Path 2's heterogeneous magnitude work until the live
trace + a heterogeneous gate prove it needed. Gate the design on a pre-code
`REBALANCE_FLOW`/`REBALANCE_EVAL` debug-log trace (already on the branch) that
confirms which of A/B/C/D is the LIVE cause AND checks the worker-id match, not
just row presence.**

## 6. Concrete design (Path 1; Path 2 deferred unless live trace forces it)

### 6.1 Bundle count into the row snapshot (fix the non-atomic dual-publish)
- `FlowWorkerMapSnapshot` (`umem/mod.rs:250-255`) gains a per-binding
  `active_flow_count: u32` field, populated from the same
  `active_flow_debug_entries` tuple already computed at `debug_state.rs:220`.
  Zero new scan. Count and rows are then published in ONE `ArcSwap` store, so a
  reader loads them atomically together — the `AtomicU32`-vs-`ArcSwap` skew
  (Codex/AGY r1) is structurally gone. (The standalone `active_flow_count`
  `AtomicU32` can stay for Prometheus, but the controller reads only the bundled
  snapshot.)

### 6.2 Fix worker-identity keying + staleness defer (`rebalance.rs` / `controller.rs`)
- **Keying (cause D):** key `WorkerByteRate` by the SAME identifier the rows
  carry. `tick_rebalance` (`rebalance.rs:209-228`) currently labels the
  `workers.live` SLOT key as `worker_id`; carry the binding's real `worker_id`
  onto `WorkerByteRate` (it is available on the live state /
  identities) and filter `f.worker_id == hottest.worker_id`
  (`controller.rs:507-511`) against that. Add a unit test with
  `slot != worker_id` proving `candidate_count > 0`.
- **Staleness defer (causes A/B-age-out):** when the hottest worker has zero
  candidate rows but its bundled `active_flow_count > 0`, record a new
  `SkipReason::StaleFlowSnapshot` (additive label, matches the
  `no_eligible_flow` precedent) and DEFER one tick — not terminal
  `NoEligibleFlow`. `NoEligibleFlow` then means a genuine "no movable flow".
- Keep the worker-rate fallback for magnitude (already present).

### 6.3 (Path 2, deferred) cold-path eviction side-table for per-flow magnitude
- **NOT the dead dedup-insert branch** (Codex/AGY r1: unreachable in
  production). If a heterogeneous gate proves accurate per-flow magnitude is
  needed: a bounded per-binding `HashMap<SessionKey,u64>` updated only on
  eviction (LRU displacement `flow_cache.rs:705-710` + the
  generation/lease deletes in `lookup_counted` `flow_cache.rs:625-652`), read
  back on the next `insert` of that key. Cold-path, owner-only, LRU-capped.
- Alternative: drop per-flow byte accounting and use the ordinal
  (`age_epochs` + worker-rate/count) signal. Decide from the live trace.

### 6.4 Validation harness (the part that was missing in #1748)
The #1748 ledger is explicit: "Unit tests + miri + 9 review rounds did NOT
catch these (behavioral/runtime)." So the increment MUST land with:
- A `--features debug-log` deploy capturing `REBALANCE_FLOW`/`REBALANCE_EVAL`
  for one P12 run **before** code changes, to empirically identify A/B/C.
- A live CoV gate as the acceptance criterion (installs_total > 0, CoV ≤ 10%,
  aggregate not regressed), not just unit tests.

## 7. Public API / behavior preservation
- Default-OFF #1748 semantics unchanged: no feed work runs unless the knob is
  set. The snapshot `active_flow_count` field already exists for the harness
  (#1219/#1294); reusing it is additive.
- New `SkipReason::StaleFlowSnapshot` is an additive metric label
  (matches the `no_eligible_flow` precedent, commit `b219d1280`).
- No hot-path cost added; the optional side-table (Path 2) is cold-path only.

## 8. Hidden invariants to preserve
- **No per-packet/per-poll cost** (CLAUDE.md): the scan is already owner-cadence
  (~65 ms); the consumer change is coordinator-cadence; carry-forward is
  cold-path. No new per-packet work.
- **Control-socket contention** (CLAUDE.md): the feed is read from already-
  collected telemetry (ArcSwap snapshot), not a new >1 Hz control-socket call.
- **Count/rows atomicity**: count and rows MUST come from one snapshot; the
  fix's whole point is to stop the cross-snapshot skew.
- **`last_used_epoch == 0` sentinel** semantics unchanged; the optional
  side-table only touches `observed_bytes`.
- **Worker-identity keying** must be consistent end-to-end after the fix: the
  rate vector and the flow rows MUST be keyed by the same identifier.

## 9. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW (OFF) | #1748 is default-OFF; feed work gated |
| Hot-path perf | NONE | scan unchanged; optional side-table cold-path |
| Wrong root cause | MED | mitigated by mandatory debug-log live trace BEFORE coding (identify A/B/C/D + worker-id match) |
| Latent keying bug (D) on other configs | MED | fixed by Path 1 part 2; `slot != worker_id` unit test |
| Heterogeneous selection still weak | LOW/MED | Path 2 side-table/ordinal addresses; else documented follow-up |
| Live-gate still 0 installs | MED | acceptance = live CoV gate, not unit tests |

## 10. Test plan (for the eventual `/engineer` increment)
- **Pre-code live trace:** `--features debug-log` deploy on loss cluster, P12
  -p5210, capture `REBALANCE_FLOW`/`REBALANCE_EVAL`; record which of A/B/C/D is
  live AND verify the row `worker_id` matches the rate vector's key (cause D).
  This selects whether Path 1 alone suffices or Path 2 is needed.
- Unit: `stale_snapshot_defers_not_no_eligible_flow`;
  `slot_ne_worker_id_still_selects` (cause D regression);
  count/rows single-snapshot consistency; (if Path 2)
  `observed_bytes_survives_eviction_via_sidetable`.
- cargo build + full suite + 5× flake of controller tests; go suite (label).
- **Live CoV gate (acceptance):** enable knob, P12 -p5210, installs_total > 0,
  per-flow CoV ≤ 10%, aggregate not regressed, bounded retransmits.
- Full Pass A/B smoke matrix (v4+v6 × push+reverse × CoS-off/on).
- `make test-failover` (HA-critical placement).

## 11. Out of scope / follow-ups
- Heterogeneous-traffic accurate per-flow rate (LRU-eviction side table) — only
  if the live trace / heterogeneous gate proves it needed.
- R2 reverse-direction rules, R4 HA peer rule-mirroring (already #1748 §9
  follow-ups).
- Any new hot-path sampled flow table (Path 3) — explicitly rejected.
