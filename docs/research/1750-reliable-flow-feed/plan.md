# #1750 — reliable per-flow 5-tuple feed for the #1748 rebalance controller

- **Status**: PLAN DRAFT v1 (pre-review)
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
single scan and published *atomically together*. They cannot disagree at the
binding level for ≤256 flows.** Evidence (all on `origin/master`, identical on
the engineer branch):

- `FlowCache::active_flow_debug_entries(limit)`
  (`flow_cache.rs:465`) iterates the cache once and returns
  `(active_count, rows, cos_counts, truncated)` — `active_count` is incremented
  in the **same loop** that pushes `rows` (`flow_cache.rs:479-490`), gated by
  the identical `active_entry_age(entry).is_some()` predicate. The production
  count comes from here; `count_active_flows()` is `#[cfg(test)]`-only
  (`flow_cache.rs:441`).
- `publish_binding_debug_state` (`umem/debug_state.rs:216-249`) calls that scan
  once with `limit = FLOW_WORKER_MAP_MAX_PER_BINDING = 256`
  (`flow_cache.rs:18`), then stores `active_flow_count` and the row vector from
  the **same returned tuple**. So `xpf_userspace_binding_active_flow_count` and
  the `flow_worker_map` rows are two projections of one scan.
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

**Consequence:** the issue's literal symptom ("count says 3, rows say empty")
implies a *cross-snapshot skew* or a *consumer-side filter bug*, NOT a
fundamental flow_cache enumeration deficiency. The flow_cache scan IS the
reliable per-worker enumeration the issue's Q1 is asking for; it is the very
mechanism that makes the count reliable. The defect is in how the controller
consumes it.

### 2.1 Where the consumer-side skew/loss actually comes from

The controller does NOT read count and rows from one atomic snapshot. It reads:
- per-worker rate from `live.tx_bytes()` (`rebalance.rs:210`),
- flow rows from `self.flow_worker_map()` (`rebalance.rs:243`) — an `ArcSwap`
  load (`umem/mod.rs:826` / `coordinator/status.rs:168`),
- and the human/operator compares against the *separately scraped* Prometheus
  `binding_active_flow_count` (a third read instant).

Three candidate consumer-side causes, in descending likelihood:

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
  recurs under steady iperf. So (B) is unlikely to be the steady-state cause at
  P12, but MUST be verified live (it would dominate at high flow-count /
  hot-set workloads, which is the controller's real target regime).

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
- **Cheap carry-forward options (no per-packet cost):**
  1. On `insert`, if the set already holds the same key (the dedup-on-insert
     branch, `flow_cache.rs:686-694`), keep the existing `observed_bytes`
     instead of overwriting — covers the common "stale decision refresh"
     re-insert. Zero hot-path cost (the branch is already taken on the miss
     path, not per-packet).
  2. For LRU-evicted-then-readmitted keys, a tiny per-binding
     `HashMap<SessionKey,u64>` "recent bytes" side table updated only on
     eviction (cold path) — bounded, owner-only, no per-packet work.
  3. Switch the controller to an *ordinal* signal: rank candidate flows by the
     row's `age_epochs` + a monotonic per-flow packet counter that survives
     re-insert (carry-forward as in option 1). The controller only needs "which
     is heaviest", not a calibrated rate.
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
- **If A (cadence/first-publish skew) is the live cause:** fix is a few lines
  (atomic count+rows snapshot already exists; add an eligibility-time freshness
  check + ensure the controller never compares against an out-of-band count).
  Near-zero hot-path cost, unblocks the whole PR. **High benefit / negligible
  cost → ship.**
- **If B (eviction churn) is the live cause:** fix is carry-forward (cold-path)
  + possibly raising `ACTIVE_WINDOW_EPOCHS` or making the scan use a
  longer-lived "seen recently" mark. Low hot-path cost. **Ship.**
- **If C (consumer filter/parse bug) is the live cause:** trivial fix in
  `rebalance.rs`. **Ship.**
- **PLAN-KILL trigger:** only if the live `REBALANCE_FLOW`/`REBALANCE_EVAL`
  trace shows the flow_cache scan *itself* (not the consumer) drops active
  forward flows in steady state AND no cold-path carry-forward restores them —
  which the code analysis says is improbable at P12. Honest stance: **this is
  very likely a cheap fix, not a kill.**

## 5. Multiple Path Options

### Path 1 — Single-snapshot consume + cadence hardening (RECOMMENDED)
Make the controller read the **count and the 5-tuple rows from one atomic
`flow_worker_map` snapshot** (extend the published snapshot to carry the
per-binding `active_flow_count` alongside the rows, so the controller never
cross-references an out-of-band Prometheus count). Add a first-publish / staleness
guard: if a worker's snapshot is empty but its `active_flow_count` > 0 (stale or
pre-first-publish), defer the move one tick rather than recording
`no_eligible_flow`. Keep the existing worker-rate fallback for magnitude.
- **Pros:** smallest change; uses the proven-reliable scan; eliminates the
  cross-snapshot skew that is the most likely live cause (A); no hot-path cost.
- **Cons:** does not improve heterogeneous selection (still worker-rate
  estimate). Acceptable for the P12 homogeneous gate; heterogeneous is a
  documented follow-up.

### Path 2 — Path 1 + cold-path `observed_bytes` carry-forward
Add Path 1 plus the dedup-insert carry-forward (Q3 option 1) and optional
eviction side-table (option 2) so the per-flow rate signal survives re-insert,
restoring an accurate per-flow magnitude for heterogeneous traffic.
- **Pros:** correct elephant-vs-mice selection; still no per-packet cost.
- **Cons:** more surface; only matters if heterogeneous fairness is in scope
  for the increment. Carry-forward across an LRU eviction needs the side table
  (bounded but new state).

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

**Recommendation: Path 1 as the blocker-clearing increment, with Path 2's
dedup-insert carry-forward folded in as a low-cost ordinal improvement for
heterogeneous traffic. Gate the choice on the live `REBALANCE_FLOW` trace
(already on the branch) confirming which of A/B/C is the live cause.**

## 6. Concrete design (Path 1 + Path 2 dedup carry-forward)

### 6.1 Extend the published snapshot to carry count with rows
- `FlowWorkerMapSnapshot` (umem) gains a per-binding `active_flow_count: u32`
  field, populated from the same `active_flow_debug_entries` tuple already
  computed at `debug_state.rs:220`. Zero new scan.
- `Coordinator::flow_worker_map()` already aggregates rows; add a sibling that
  also returns the per-(ifindex,worker) count from the same snapshot, OR have
  the controller key candidates only off the rows it actually received and
  treat an "empty rows but positive published count" worker as **stale, defer**.

### 6.2 Controller consume change (`rebalance.rs` / `controller.rs`)
- Build `per_iface_flows` exactly as today, but additionally track, per worker,
  whether its snapshot was *fresh* (published within N× the publish interval).
- In `select_move`, when the hottest worker has zero candidate rows but a
  positive published `active_flow_count`, record a new
  `SkipReason::StaleFlowSnapshot` (distinct from `NoEligibleFlow`) and **defer**
  (do not count it as a terminal no-op). `NoEligibleFlow` then means a genuine
  "no movable flow" only.
- Keep the worker-rate fallback for magnitude (already present).

### 6.3 Cold-path `observed_bytes` carry-forward (Path 2 component)
- In `FlowCache::insert` dedup-on-insert branch (`flow_cache.rs:686-694`), when
  replacing an existing same-key entry, set
  `new.observed_bytes = new.observed_bytes.saturating_add(existing.observed_bytes)`
  (carry forward) instead of overwriting. Cold path (miss/refresh only), no
  per-packet cost.
- (Optional, deferred) eviction side-table for LRU-evicted-then-readmitted
  keys — only if heterogeneous live data shows it is needed.

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
- No hot-path cost added; carry-forward is cold-path only.

## 8. Hidden invariants to preserve
- **No per-packet/per-poll cost** (CLAUDE.md): the scan is already owner-cadence
  (~65 ms); the consumer change is coordinator-cadence; carry-forward is
  cold-path. No new per-packet work.
- **Control-socket contention** (CLAUDE.md): the feed is read from already-
  collected telemetry (ArcSwap snapshot), not a new >1 Hz control-socket call.
- **Count/rows atomicity**: count and rows MUST come from one snapshot; the
  fix's whole point is to stop the cross-snapshot skew.
- **`last_used_epoch == 0` sentinel** semantics unchanged; carry-forward only
  touches `observed_bytes`.

## 9. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW (OFF) | #1748 is default-OFF; feed work gated |
| Hot-path perf | NONE | scan unchanged; carry-forward cold-path |
| Wrong root cause | MED | mitigated by mandatory debug-log live trace BEFORE coding (identify A/B/C) |
| Heterogeneous selection still weak | LOW/MED | Path 2 carry-forward addresses; else documented follow-up |
| Live-gate still 0 installs | MED | acceptance = live CoV gate, not unit tests |

## 10. Test plan (for the eventual `/engineer` increment)
- **Pre-code live trace:** `--features debug-log` deploy on loss cluster, P12
  -p5210, capture `REBALANCE_FLOW`/`REBALANCE_EVAL`; record which of A/B/C is
  live. This selects whether 6.1/6.2 alone suffices or 6.3 is needed.
- Unit: `stale_snapshot_defers_not_no_eligible_flow`; carry-forward
  `observed_bytes_survives_dedup_reinsert`; count/rows single-snapshot
  consistency.
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
