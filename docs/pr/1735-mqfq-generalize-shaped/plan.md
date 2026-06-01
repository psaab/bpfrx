# Plan of Action — #1735 (#1731-d): generalize per-flow MQFQ to all shaped queues

- **Status**: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude-SMR)
- **Issue**: #1735 (sub-issue of #1731; subsumes #7)
- **Base**: master `7eaec5a2a` (includes #1732 `waterfill_honored_epoch_bits` @ PR #1737, and #1733/#1734)
- **Research plan (DESIGN-READY, fully specified)**: `docs/research/1731-cos-mqfq-generalize/plan.md` §4.1 (on branch `research/1731-cos-mqfq-generalize`, commit `34112deee`)
- **Reviewer ledger**: `docs/pr/1735-mqfq-generalize-shaped/reviewer-ids.md`

## 1. Issue framing

Today per-flow MQFQ fairness is enabled **only on exact queues**.
`promote_cos_queue_flow_fair` (`admission.rs:509`) sets
`queue.config.flow_fair = queue.config.exact` and allocates
`FlowFairState` iff `flow_fair()`. Best-effort / residual / non-exact
shaped queues therefore collapse to a single FIFO
(`queue.hot.items`), so one elephant flow dominates every mouse inside
the same shape. The operator-facing CoS contract ("per-flow fair share
inside a queue") is narrower than the code delivers.

Generalize the existing `FlowFairState`/MQFQ dequeue to **all shaped
queues** (exact AND non-exact) WITHOUT regressing the best-effort
fast path — the #1183 10x-reverse-regression class is the kill-risk.

## 2. Honest scope / value framing

The win is operator-visible fairness: on a shaped best-effort or
residual queue carrying an elephant + N mice, the mice currently
starve behind the elephant's FIFO backlog. After this change each flow
gets MQFQ virtual-finish-time ordering inside the queue, so per-flow
CoV inside the shape drops to the #1217 structural floor.

The cost risk is concrete and historical: #1183 showed that putting
CoS state on the best-effort fast path caused a 10x reverse-throughput
regression (cross-binding redirect funneled all TX to one worker; the
fix was a "useful CoS state" gate). Any per-packet hash or 232 KB
`FlowFairState` allocation on the *uncontended* best-effort path is a
merge blocker. The design (§4) answers this with a hash-free
front-key contention probe + lazy alloc: the uncontended best-effort
path stays byte-identical to today (FIFO, no hash, no allocation).

**If reviewers conclude the best-effort fast-path cost is real (not
eliminated by lazy-alloc) or the fairness gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict.** A kill here is fully
acceptable; this is the headline hot-path item.

## 3. What's already shipped / load-bearing facts (verified end-to-end)

- **FACT-A (de-risks the whole thing): every queue primitive already
  dispatches on `flow_fair()`.** `cos_queue_push_back` (`push.rs:42`),
  `cos_queue_push_front` (`push.rs:79`), `cos_queue_pop_front_inner`
  (`pop.rs:59`), `cos_queue_front` (`mod.rs:124`), `cos_queue_is_empty`
  (`mod.rs:47`), `cos_queue_len` (`mod.rs:62`) all branch FIFO-vs-MQFQ
  on `flow_fair()`. The non-exact guarantee selector
  (`queue_service/mod.rs:1149-1189`) and the surplus selector
  (`:1240-1285`) both build batches via `build_cos_batch_from_queue`
  (`:1497`), which pops with `cos_queue_pop_front` and peeks with
  `cos_queue_front` — both dispatching. **So once a non-exact queue has
  `flow_fair_state == Some`, MQFQ runs inside it with ZERO new dequeue
  code.** Only the `service_exact_*_queue_direct` direct path (exact
  queues only, `service.rs`) has dedicated `_flow_fair` drain variants;
  non-exact queues never enter that path.

- **FACT-B (the cost crux): `FlowFairState` is ~232 KB** per queue
  (7× `[u64/u32; 4096]` arrays + `[VecDeque; 4096]` headers + FlowRrRing
  8 KB). It is `Option<Box<>>` so non-flow-fair queues pay 0 bytes
  today. Naively promoting ALL shaped queues = workers × queues ×
  ifaces × 232 KB. **Lazy alloc is mandatory.**

- **FACT-C: admission runs BEFORE push.** `enqueue_cos_item`
  (`cos_classify.rs:809`) computes `flow_bucket` + ECN + share/buffer
  gates reading the *pre-push* `flow_fair()` state, then calls
  `cos_queue_push_back` (`:916`). With lazy alloc the first contended
  packet is admitted under FIFO semantics (1-flow buffer-bound), then
  `push_back` promotes; all subsequent packets see the promoted state.
  This ordering is benign (the promoting packet's admission is no
  stricter than today's best-effort admission) but MUST be stated
  explicitly so reviewers can confirm no off-by-one admission drop.

- **FACT-D: the batch-settle quiescent boundary is
  `apply_cos_send_result` / `apply_cos_prepared_result`
  (`tx_completion.rs:625` / `:725`).** After `restore_cos_local_items_inner`
  (`:829`, which push_fronts retry items back), the queue is settled for
  the batch. `cos_queue_drain_all` clears `pop_snapshot_stack` at start;
  push_front of restored items takes the empty-stack path. This is the
  only safe demotion point (no in-flight scratch).

## 4. Concrete design (follows research plan §4.1 exactly)

Four composable pieces. The work is a **promotion-gate + lazy-alloc**
change, NOT a new dequeue engine (FACT-A).

### 4.1 Piece 1 — redefine `flow_fair()` as `flow_fair_state.is_some()`

`CoSQueueRuntime::flow_fair()` (`types/cos.rs:568`) currently returns
`self.config.flow_fair`. Change it to:

```rust
#[inline]
pub(in crate::afxdp) fn flow_fair(&self) -> bool {
    self.flow_fair_state.is_some()
}
```

This makes the invariant `flow_fair() == flow_fair_state.is_some()`
**structurally unbreakable**: a queue with `None` state automatically
dispatches through the cheap FIFO branch; allocation is the only thing
that flips the gate. Every `.expect("...flow_fair queue without
flow_fair_state")` site (push.rs:54/104, pop.rs:70, accounting.rs:28/103,
mod.rs:56/70/132/157, flow_hash.rs:176, admission.rs:328,
cos_classify.rs:852/862) becomes provably unreachable — the `if
queue.flow_fair() { ... .as_mut().expect(...) }` shape now reads
`is_some()` then unwraps the same `Option`. The AGY Trap A FATAL ("set
`config.flow_fair=true` but leave state `None`") is impossible by
construction.

`config.flow_fair` is **repurposed** — renamed to
`config.flow_fair_eligible` (may this queue EVER promote) — decoupled
from the runtime `is_some()` gate. (Renaming, not adding, keeps the
struct from carrying a now-misleading field; the audit will catch every
reader.)

### 4.2 Piece 2 — `flow_fair_eligible` = shaped, not exact

In `promote_cos_queue_flow_fair` (`admission.rs:476`):

```rust
// Eligible to EVER run flow-fair = the queue is shaped (has a
// per-queue transmit rate / buffer shape). Exact OR non-exact.
// Forwarding-only / unshaped interfaces stay ineligible — exactly
// the #1183 boundary.
queue.config.flow_fair_eligible = queue_is_shaped(queue_fast, queue);
// Exact queues promote EAGERLY at build (they always carry >0
// expected flows and today's behavior must be byte-identical).
// Non-exact eligible queues stay None here and use the lazy probe.
queue.flow_fair_state = if queue.config.exact && queue.config.flow_fair_eligible {
    Some(Box::new(FlowFairState::new(cos_flow_hash_seed_from_os())))
} else {
    None
};
```

**Open question for review (Q1):** the exact eligibility predicate
`queue_is_shaped`. Candidate definitions:
(a) `queue.config.exact || queue.config.guarantee_enabled ||
queue.transmit_rate_bytes() > 0` (any queue with a shape);
(b) "non-root, on a shaped interface" — needs a per-iface shaped flag.
The research plan says "queue is on a shaped interface (exact OR
non-exact)" and explicitly excludes forwarding-only/unshaped. The
*conservative* read that preserves #1183: **a queue is eligible iff it
participates in the CoS scheduler at all** (i.e. it is a real configured
CoS queue on a shaped root), which is true for every queue in
`root.queues` on an interface that has a `CoSInterfaceRuntime`.
Forwarding-only interfaces have no `CoSInterfaceRuntime` (the #1183
"useful CoS state" gate already prevents building one), so they never
reach `promote_cos_queue_flow_fair`. **Proposed: `flow_fair_eligible =
true` for every queue that reaches this promotion path** (it only runs
for interfaces with useful CoS state, post-#1183). Reviewers must
confirm this does not re-enable CoS state on a forwarding-only
interface — the #1183 boundary lives at *interface* granularity (does
this iface get a `CoSInterfaceRuntime` at all), not at queue
granularity.

### 4.3 Piece 3 — hash-free contention probe + trivial single-flow promotion

In `cos_queue_push_back` (`push.rs:20`), BEFORE the
`account_cos_queue_flow_enqueue` + `if !queue.flow_fair()` block, when
the queue is `flow_fair_eligible` but `flow_fair_state` is `None`:

```rust
fn maybe_promote_best_effort(queue: &mut CoSQueueRuntime, incoming: &CoSPendingTxItem) {
    if !queue.config.flow_fair_eligible || queue.flow_fair_state.is_some() {
        return; // already promoted, or never eligible — zero cost
    }
    // Uncontended fast path: empty queue or single-flow → FIFO, NO hash.
    let Some(front) = queue.hot.items.front() else {
        return; // empty → first packet, single flow, stay FIFO
    };
    let front_key = cos_item_flow_key(front);
    let incoming_key = cos_item_flow_key(incoming);
    if session_keys_equal(front_key, incoming_key) {
        return; // same flow as the FIFO front → still one flow, stay FIFO
    }
    // CONTENTION: first DIFFERING flow. queue.hot.items is GUARANTEED
    // single-flow (we promote on the first divergence), so migration
    // is trivial and reorder-free.
    promote_to_flow_fair(queue);
}
```

`session_keys_equal(Option<&SessionKey>, Option<&SessionKey>)` is a
structural compare (proto, addr_family, src/dst IP, src/dst port) — a
memcmp-class compare, **NOT a hash**. So the uncontended best-effort
fast path pays ZERO hash. `None == None` (both keyless) is treated as
"same flow" → no promotion (keyless traffic stays FIFO; matches today's
bucket-0 behavior for keyless on a promoted queue, and avoids promoting
on keyless noise).

`promote_to_flow_fair`:

```rust
fn promote_to_flow_fair(queue: &mut CoSQueueRuntime) {
    let mut ff = Box::new(FlowFairState::new(cos_flow_hash_seed_from_os()));
    // queue.hot.items is single-flow (probe guarantee). Bulk-move into
    // one bucket, hash that one flow ONCE.
    let bucket = match queue.hot.items.front() {
        Some(front) => cos_flow_bucket_index(ff.flow_hash_seed, cos_item_flow_key(front)),
        None => { queue.flow_fair_state = Some(ff); return; } // defensive; probe guarantees non-empty
    };
    let mut total = 0u64;
    let mut head_finish_set = false;
    for item in queue.hot.items.drain(..) {
        let len = cos_item_len(&item);
        total = total.saturating_add(len);
        // tail advances sequentially from queue_vtime=0 base; preserves
        // FIFO order within the single flow.
        let new_tail = ff.flow_bucket_tail_finish_bytes[bucket]
            .max(ff.queue_vtime)
            .saturating_add(len);
        ff.flow_bucket_tail_finish_bytes[bucket] = new_tail;
        if !head_finish_set {
            ff.flow_bucket_head_finish_bytes[bucket] = new_tail;
            head_finish_set = true;
        }
        ff.flow_bucket_items[bucket].push_back(item);
    }
    if total > 0 {
        ff.flow_bucket_bytes[bucket] = total;
        ff.active_flow_buckets = 1;
        ff.active_flow_buckets_peak = 1;
        ff.flow_rr_buckets.push_back(bucket as u16);
        // v8 lease mirror NOT needed: non-exact queues have queue_lease_v8
        // == None (verified types/cos.rs:558 doc — "None for non-flow-fair,
        // non-exact ... queues"). Confirm at impl time.
    }
    queue.flow_fair_state = Some(ff);
    // local_item_count is unchanged — items moved, not added/removed.
    // The push_back caller proceeds: flow_fair() is now true, so the
    // incoming (differing) item enqueues via the normal MQFQ branch
    // into ITS bucket, bumping active_flow_buckets to 2.
}
```

**Ordering inside `cos_queue_push_back`:** call `maybe_promote_best_effort`
FIRST (before `account_cos_queue_flow_enqueue`). After it returns,
`flow_fair()` reflects the post-promotion state, so the existing
`account_cos_queue_flow_enqueue` + bucket-push branch handles the
incoming item correctly. The accounting for the *migrated* items is
done inline in `promote_to_flow_fair` (it sets `flow_bucket_bytes`,
`active_flow_buckets`, finish-times directly), so we must NOT
double-account them via `account_cos_queue_flow_enqueue`. The incoming
item IS accounted by the normal path. **This is the migration seam the
research plan calls "the riskiest seam, made trivial."** Property tests
(§9) pin: post-promotion `flow_bucket_bytes[bucket]` == sum of migrated
lens; `active_flow_buckets` == distinct-flow-count; pop order ==
original FIFO order for the migrated flow followed by MQFQ interleave.

### 4.4 Piece 4 — lazy demotion at quiescent settle (with hysteresis)

In `apply_cos_send_result` / `apply_cos_prepared_result`
(`tx_completion.rs`), AFTER `restore_cos_local_items_inner` and the
queued_bytes settle, for a queue that is `flow_fair_eligible &&
!config.exact`:

```rust
fn maybe_demote_drained_best_effort(queue: &mut CoSQueueRuntime) {
    let Some(ff) = queue.flow_fair_state.as_ref() else { return; };
    // Quiescent: fully drained AND no in-flight rollback snapshots.
    if ff.active_flow_buckets != 0 || !ff.pop_snapshot_stack.is_empty() {
        queue.cos_demote_empty_settles = 0; // reset hysteresis
        return;
    }
    // R6 hysteresis: demote only after K consecutive empty settles so a
    // queue oscillating 1<->2 flows doesn't thrash alloc/free of 232 KB.
    queue.cos_demote_empty_settles = queue.cos_demote_empty_settles.saturating_add(1);
    if queue.cos_demote_empty_settles >= COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS {
        queue.flow_fair_state = None; // drops the ~232 KB box
        queue.cos_demote_empty_settles = 0;
    }
}
```

Demotion is exact-queue-EXEMPT: exact queues promoted eagerly at build
stay promoted for the interface's lifetime (today's behavior — they
always carry expected flows and the V_min/lease coordination assumes a
stable `flow_fair_state`). Only non-exact lazily-promoted queues demote.

`cos_demote_empty_settles: u8` is a new `CoSQueueHotState` field
(1 byte, in the hot struct that's already touched at settle). Hysteresis
constant `COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS = 4` (configurable knob in
the const block; tuned at smoke time against the contended best-effort
cell's churn counter).

**Why safe at this point (FACT-D):** `active_flow_buckets == 0` means
every bucket is drained (no items in any `flow_bucket_items`); empty
`pop_snapshot_stack` means no batched rollback is mid-flight; the retry
restore already ran. Single-worker invariant: demote and all pops run on
the same worker thread.

### 4.5 Composition: surplus DWRR outside, MQFQ inside (FACT-A — free)

`queue_service/mod.rs:1149-1285` already does priority + per-queue
`surplus_deficit` DWRR ACROSS queues. Once a selected non-exact queue is
flow-fair, `cos_queue_front` / `cos_queue_pop_front` (via
`build_cos_batch_from_queue`) pop in MQFQ order INSIDE it. Inter-queue
DWRR + intra-queue MQFQ falls out of existing dispatch. **#7 (residual
queue-level → flow-level) closes for free** — no separate work.

### 4.6 Exact rate caps preserved

Exact queues: behavior byte-identical (eager promotion, same
`shared_exact` admission caps, same `service_exact_*_flow_fair` direct
path, same V_min/lease). Non-exact promoted queues get the rate-aware
admission cap path keyed off `flow_fair()` — but they are NOT
`shared_exact`, so `cos_queue_flow_share_limit` takes the legacy
owner-local branch (`buffer_limit.div_ceil(prospective)`), and
`apply_cos_admission_ecn_policy` takes the `flow_fair() && !shared_exact`
per-flow arm. **This is a behavior change for promoted non-exact
queues** (they gain per-flow share caps + per-flow ECN) — intended, it
is the fairness mechanism. Smoke must confirm no aggregate regression on
the best-effort multi-stream cell.

## 5. Public API preservation

No control-plane / wire / Go change. All edits are
`pub(in crate::afxdp)` internal. Preserved signatures:
`flow_fair()` (same name/return type, new body),
`promote_cos_queue_flow_fair`, `apply_cos_queue_flow_fair_promotion`,
`cos_queue_push_back/push_front/pop_front*/front/is_empty/len`,
`apply_cos_send_result/apply_cos_prepared_result`. New private helpers:
`maybe_promote_best_effort`, `promote_to_flow_fair`,
`session_keys_equal`, `maybe_demote_drained_best_effort`. New field:
`CoSQueueConfigState.flow_fair_eligible` (rename of `flow_fair`),
`CoSQueueHotState.cos_demote_empty_settles`.

## 6. Hidden invariants the change must preserve

- **Invariant `flow_fair() == flow_fair_state.is_some()`** — now
  structural (Piece 1). Every `.expect()` becomes unreachable.
- **Side-effect ordering in push_back**: promote BEFORE
  account/enqueue; migrated items accounted inline (not double-counted);
  incoming item accounted by normal path.
- **`local_item_count`**: migration moves items, never changes count.
  `promote_to_flow_fair` must not touch `local_item_count`.
- **`pop_snapshot_stack` discipline**: promotion only when state is
  None (no snapshots possible); demotion only when stack empty.
- **V_min / v8 lease**: non-exact queues have `vtime_floor == None` and
  `queue_lease_v8 == None` (verified doc); promote/demote on them must
  not touch lease/V_min. Confirm at impl.
- **HA portability**: `flow_fair_state` is per-worker per-interface
  scheduler state, NOT session-sync / HA-portable state. No
  `make test-failover` requirement (assess at impl; the v8 lease path
  is HA-adjacent but untouched here — non-exact queues don't carry it).
- **Borrow shape**: `maybe_promote_best_effort` takes `&CoSPendingTxItem`
  borrow of the incoming item BEFORE it's moved into push; the
  front-key compare drops the `&queue.hot.items` borrow before
  `promote_to_flow_fair` takes `&mut queue`. NLL-clean.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression (best-effort fast path, #1183) | **HIGH** | THE kill-risk. Mitigated by hash-free probe + lazy alloc: uncontended path byte-identical (FIFO, no hash, no 232 KB). Pass-A CoS-OFF `-P12 -R` line-rate is the merge gate. |
| Behavioral regression (exact queues) | LOW | Exact path byte-identical (eager promote, same caps/direct path). |
| Lifetime / borrow-checker | MED | Promotion seam re-borrows; front-key probe borrow must drop before `&mut` promote. NLL pattern mirrors existing push_front splits. |
| Performance (contended best-effort) | MED | Contended queue pays 1 hash/packet + 232 KB once + demote churn. Hysteresis bounds churn. Smoke measures the contended cell. |
| Architectural mismatch (#961/#946-Phase-2 / cross-worker physics) | LOW | Research plan §10: all intra-queue/within-worker. No worker touches another's XSK. FACT-A confirms existing dispatch carries it. |

## 8. Test plan

- `cargo build` clean; `cargo test --release` full suite (current pass count).
- 5/5 flake on the most-affected named tests
  (`promote`/`demote`/migration property tests + existing flow_fair tests).
- New unit/property tests (in `push.rs`/`admission_tests.rs`/`queue_service/tests.rs`):
  - **Probe zero-cost**: single-flow best-effort push_back leaves
    `flow_fair_state == None` after N packets (no promotion, no hash).
  - **Promotion on first differing flow**: 2-flow best-effort promotes
    exactly once; `flow_bucket_bytes`/`active_flow_buckets` correct;
    migrated FIFO order preserved.
  - **Migration accounting**: post-promote bucket bytes == sum of
    migrated lens; `local_item_count` unchanged.
  - **Demotion + hysteresis**: drained promoted non-exact queue demotes
    after K empty settles; 1<->2 flow oscillation does NOT thrash.
  - **Exact queues never demote**.
  - **CoV acceptance (the headline gate)**: best-effort 1-elephant +
    N-mice on a shaped non-exact queue → assert per-flow max/min bytes
    bounded (NOT just aggregate queue rate); no starved mouse. This is
    the unit-level proxy for the smoke CoV gate.
- Go suite: 30 packages pass (no Go change expected; run anyway).
- Smoke on `loss:xpf-userspace-fw0/fw1`, FULL matrix: v4 (172.16.80.200)
  + v6 (2001:559:8585:80::200) × push/`-R` × CoS-off/CoS-on × per-class
  5201-5206.
  - **Pass A CoS-OFF `-P12 -R` line rate (~23G) is the KILL-METRIC**
    (#1183 class).
  - **#1217 structural-CoV gate**: gate_1 no-starve + gate_2
    priority-low are the real gates. gate_3 retrans-floor "fail" is the
    documented pre-existing divided-ceiling simul artifact (#1614 §3.A /
    #1732 merge) — distinguish from a real regression.
- `make test-failover` ONLY if FlowFairState touches HA-portable state
  (assessment: it does not — per-interface scheduler state).

## 9. Out of scope (explicitly)

- #4 FQ-CoDel dequeue AQM (#1731-f, sequenced after this).
- #6 heavy-hitter bucket-split telemetry (#1731-g).
- #3 v8 heap-scratch 48/64-core cap removal (#1731-e).
- #5 now_ns refresh (#1731-c, measure-gated).
- Pooled FlowFairState reuse (R6 alternative) — hysteresis chosen
  instead; revisit only if smoke shows churn cost.

## 10. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Q1 — eligibility granularity.** Is "every queue reaching
   `promote_cos_queue_flow_fair` is eligible" actually the #1183
   boundary, or can a forwarding-only/transparent queue reach this path
   and re-acquire the 10x-regression cost? (Verify the interface-level
   "useful CoS state" gate is the real #1183 boundary.)
2. **Q2 — probe correctness.** Does comparing only the FIFO *front*
   key (not all items) actually guarantee single-flow at promotion? Can
   a multi-flow FIFO ever exist when `flow_fair_state == None` and
   eligible? (Claim: no — every differing flow promotes on arrival, so
   a None+eligible queue is always 0-or-1-flow. Find a counter-example:
   e.g. could `restore_cos_local_items_inner` push_front a *different*
   flow onto a None queue and leave it multi-flow before the next
   push_back probe runs?)
3. **Q3 — admission/promotion ordering (FACT-C).** The promoting packet
   is admitted under FIFO (1-flow) semantics, then promotes. Does this
   cause any off-by-one admission drop or ECN mis-mark vs. an
   always-flow-fair queue? Is the asymmetry observable/harmful?
4. **Q4 — demotion safety.** Is `active_flow_buckets == 0 &&
   pop_snapshot_stack empty` at `apply_cos_send_result` truly quiescent?
   Can a partial-commit retry leave items in `flow_bucket_items` with
   `active_flow_buckets == 0`? Can demotion drop a box while a later
   stage in the same poll tick still expects `flow_fair_state`?
5. **Q5 — best-effort cost reality (the kill question).** Is the
   uncontended best-effort path truly byte-identical? Enumerate every
   added instruction on the single-flow push_back path
   (`flow_fair_eligible` load + `is_some()` + `front()` +
   key-compare-with-None-short-circuit). Is that within noise of
   today's FIFO push_back, or does it cost measurably under `-P12 -R`?
   **If real, PLAN-KILL.**
6. **Q6 — exact-queue regression surface.** Does redefining
   `flow_fair()` as `is_some()` change ANY exact-queue behavior given
   exact queues promote eagerly (state always Some)? Audit every
   `config.flow_fair` reader (coordinator/mod.rs:1001, queue_row.rs:110,
   the `flow_fair_eligible` rename targets) for a now-divergent meaning.
