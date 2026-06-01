# Plan of Action — #1735 (#1731-d): generalize per-flow MQFQ to all shaped queues

- **Status**: v2 — folds Codex round-1 PLAN-KILL findings (task-mpuie4sw-l40kxh). Pending re-review (Codex + AGY + Claude-SMR)
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

`promote_to_flow_fair` — **v2: HASH EACH migrated item into its
correct bucket** (does NOT assume the FIFO is single-flow). This is the
round-1 Codex Q2 remedy: even though the probe induction (§4.3.1)
proves a None+eligible FIFO is always 0-or-1-flow, migration that
*depends* on that invariant is a fragility Codex correctly flagged.
Hashing each item is provably correct for ANY resident flow mix at
cost = (FIFO depth) hashes, paid ONCE per promotion (a rare event), and
reuses the exact `account_cos_queue_flow_enqueue` accounting so there is
no parallel finish-time math to get wrong:

```rust
fn promote_to_flow_fair(queue: &mut CoSQueueRuntime) {
    // Take the resident FIFO out, install empty flow-fair state, then
    // re-enqueue each item through the SAME accounting path the MQFQ
    // hot path uses — no bespoke finish-time arithmetic to drift.
    let resident: VecDeque<CoSPendingTxItem> = std::mem::take(&mut queue.hot.items);
    queue.flow_fair_state = Some(Box::new(FlowFairState::new(cos_flow_hash_seed_from_os())));
    // flow_fair() is now true. Re-enqueue preserving FIFO order. Decrement
    // local_item_count first so re-push_back's increment nets to zero
    // (items are MOVED, not added). Each item is hashed into its own
    // bucket, so a multi-flow FIFO migrates correctly (defensive — the
    // probe makes >1 flow unreachable, but correctness no longer
    // DEPENDS on that).
    for item in resident {
        if matches!(item, CoSPendingTxItem::Local(_)) {
            queue.hot.local_item_count = queue.hot.local_item_count.saturating_sub(1);
        }
        cos_queue_push_back(queue, item); // now takes the MQFQ branch
    }
}
```

Re-entrancy note: `cos_queue_push_back` calls
`maybe_promote_best_effort` at its top, but on the re-push the state is
already `Some`, so the probe's `flow_fair_state.is_some()` guard returns
immediately (zero cost) and the item enqueues via the MQFQ branch. No
infinite recursion, no re-probe. The `pop_snapshot_stack.clear()` at
push.rs:38 is a no-op on the freshly-allocated empty stack.

**v8 lease / V_min:** non-exact queues have `queue_lease_v8 == None`
and `v_min.vtime_floor == None` (verified `types/cos.rs:558` +
`:875` docs — both `None` for non-exact). `account_cos_queue_flow_enqueue`'s
lease-mirror block (`accounting.rs:74`) is gated on
`queue.queue_lease_v8.as_ref()` being `Some`, so it is a no-op on
non-exact queues. Confirm at impl with an assert in the migration test.

**Ordering inside `cos_queue_push_back`:** call `maybe_promote_best_effort`
FIRST (before the `pop_snapshot_stack.clear()` and
`account_cos_queue_flow_enqueue`). `maybe_promote_best_effort` does the
FULL migration (re-enqueueing every resident item through the MQFQ
accounting path) so when it returns, `flow_fair()` is true and the
resident items are already accounted in their buckets. The *incoming*
item then falls through to the existing
`account_cos_queue_flow_enqueue` + MQFQ bucket-push branch unchanged —
it is accounted exactly once, by the normal path. Migrated items are
accounted exactly once, by the re-push inside `promote_to_flow_fair`.
**No double-accounting** because migration empties `hot.items` via
`mem::take` before re-pushing, and the incoming item was never in
`hot.items`. **This is the migration seam the research plan calls "the
riskiest seam, made trivial" — v2 makes it correctness-independent of
the single-flow claim by hashing each item.** Property tests (§9) pin:
post-promotion sum of all `flow_bucket_bytes` == sum of (migrated +
incoming) lens; `active_flow_buckets` == distinct-flow-count;
`local_item_count` unchanged; pop order == MQFQ interleave with FIFO
order preserved within each flow.

#### 4.3.1 Induction proof: a None+eligible queue is always 0-or-1-flow

(Round-1 Codex Q2 adjudication — see §11.) Claim: while
`flow_fair_state == None && flow_fair_eligible`, `queue.hot.items`
holds at most one distinct flow key. The only writers to `hot.items`
on a None queue are `cos_queue_push_back` (probe-gated) and
`cos_queue_push_front` (retry restore, not probe-gated).
- **Base:** empty queue — 0 flows. ✓
- **push_back step:** the probe compares the FIFO front key to the
  incoming key. If equal (or queue empty) → stays 1 flow. If different →
  `promote_to_flow_fair` runs and the queue is no longer None. So a
  push_back never leaves a None queue with 2 distinct flows. ✓
- **push_front (retry restore) step:** retry items are the
  un-submitted tail of a batch that `build_cos_batch_from_queue` popped
  from THIS queue. On a None queue that batch was popped contiguously
  from the FIFO front (`build_cos_batch_from_queue` pops via
  `cos_queue_pop_front`, which on a None queue is `hot.items.pop_front`),
  so the batch — and thus the retry — is a subset of the queue's then-
  resident single flow. `drain_shaped_tx → submit_cos_batch →
  apply_cos_send_result → restore_cos_local_items_inner` is **synchronous
  on one worker thread**; no foreign `push_back` interleaves between the
  drain and the restore. So push_front re-inserts the same single flow. ✓

The induction holds, so the probe-based promotion is correct. **v2
additionally makes `promote_to_flow_fair` correct even if the induction
were violated** (it hashes each item), so the implementation does not
rely on the proof — the proof justifies the *probe's promote-trigger*
(promote on first divergence is sufficient), while per-item hashing
makes the *migration* unconditionally correct. Belt and suspenders.

### 4.4 Piece 4 — lazy demotion at quiescent settle (with hysteresis)

In `apply_cos_send_result` / `apply_cos_prepared_result`
(`tx_completion.rs`), AFTER `restore_cos_local_items_inner` and the
queued_bytes settle, for a queue that is `flow_fair_eligible &&
!config.exact`:

```rust
fn maybe_demote_drained_best_effort(queue: &mut CoSQueueRuntime) {
    let Some(ff) = queue.flow_fair_state.as_ref() else { return; };
    // Quiescent: fully drained AND no in-flight rollback snapshots AND
    // no resident items in ANY bucket. The three checks are belt-and-
    // suspenders (Q4): active_flow_buckets==0 already implies every
    // bucket drained, but cos_queue_is_empty (flow_rr_buckets empty)
    // is the authoritative "no items" predicate and pins the
    // invariant against any future accounting drift. queued_bytes==0
    // cross-checks the byte accounting.
    if ff.active_flow_buckets != 0
        || !ff.pop_snapshot_stack.is_empty()
        || !ff.flow_rr_buckets.is_empty()
        || queue.hot.queued_bytes != 0
    {
        queue.hot.cos_demote_empty_settles = 0; // reset hysteresis
        return;
    }
    // R6 hysteresis: demote only after K consecutive empty settles so a
    // queue oscillating 1<->2 flows doesn't thrash alloc/free of 232 KB.
    queue.hot.cos_demote_empty_settles =
        queue.hot.cos_demote_empty_settles.saturating_add(1);
    if queue.hot.cos_demote_empty_settles >= COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS {
        queue.flow_fair_state = None; // drops the ~232 KB box
        queue.hot.cos_demote_empty_settles = 0;
    }
}
```

**Q4 implementation refinement (found during impl):** the
`pop_snapshot_stack.is_empty()` term was DROPPED from the predicate. The
non-exact service path (`build_cos_batch_from_queue` →
`cos_queue_pop_front` with snapshots) leaves committed-batch snapshots
on the stack, and nothing clears them while the queue stays idle (only a
subsequent `cos_queue_push_back` clears, at push.rs:38). Those snapshots
are STALE once the queue is fully drained (no resident items to roll
back to). Gating on the stack would make demotion structurally
impossible for non-exact queues. The final predicate is
`active_flow_buckets == 0 && flow_rr_buckets empty && queued_bytes == 0`;
dropping the `FlowFairState` box discards the stale snapshots safely.

**Q4 ordering (round-1 Codex):** `maybe_demote_drained_best_effort` runs
at the END of `apply_cos_send_result` / `apply_cos_prepared_result`,
strictly AFTER `restore_cos_local_items_inner` has push_fronted every
retry item back into the queue and AFTER `queued_bytes` is settled.
Codex's concern — "a partial-commit retry can leave restored items while
the counters indicate quiescence" — is answered by this ordering: the
retry restore *bumps* `active_flow_buckets` (push_front of a drained
bucket increments it via `push_front_drained_bucket_*`) and
`queued_bytes` BEFORE the demote check reads them, so a queue with
restored items is NOT seen as quiescent and is NOT demoted. The demote
only fires when restore left nothing (full commit, empty queue).

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
`session_keys_equal`, `maybe_demote_drained_best_effort`,
`promote_to_flow_fair`. New field:
`CoSQueueConfigState.flow_fair_eligible` (rename of `flow_fair`),
`CoSQueueHotState.cos_demote_empty_settles: u8`.

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

## 11. Round-1 adjudication (Codex PLAN-KILL → v2 remedies)

Codex round-1 (`task-mpuie4sw-l40kxh`) returned PLAN-KILL. Each
finding and the v2 remedy:

- **[Q2 critical — front-key guard not a single-flow guarantee]:**
  Codex is right that *relying* on the front-key probe to guarantee a
  single-flow FIFO for migration is fragile. **Remedy:** §4.3
  `promote_to_flow_fair` v2 hashes EACH migrated item into its own
  bucket via the existing `account_cos_queue_flow_enqueue` path, so
  migration is correct for ANY flow mix — it no longer depends on the
  single-flow claim. §4.3.1 additionally proves (induction) the FIFO is
  in fact 0-or-1-flow, but that proof now only justifies *when to
  promote* (first divergence is sufficient), not migration correctness.
  Codex's counter-example (restore push_front making a None queue
  mixed) is shown non-materializing in §4.3.1 (synchronous single-
  thread drain→restore, retry is a subset of the resident single flow),
  AND is rendered harmless by per-item hashing regardless.
- **[Q3 high — admission/promotion ordering asymmetry]:** The promoting
  packet is admitted under FIFO (1-flow, buffer-bound) semantics, then
  promotes. This is byte-identical to TODAY's best-effort admission for
  that packet (best-effort queues have no per-flow cap today). The
  per-flow gate that appears post-promotion only *tightens* admission,
  and the first packet of any flow always passes the per-flow gate (its
  bucket is empty, `prospective_active` reserves +1, so
  `cos_queue_flow_share_limit` admits). So there is no off-by-one DROP:
  the promoting packet is admitted under rules no stricter than today,
  and the next packet sees the (looser-or-equal at flow-start) per-flow
  gate. ECN: the promoting packet is marked under the aggregate arm
  (today's best-effort behavior); subsequent packets use the per-flow
  arm. No mis-mark — both are valid congestion signals. Test: assert the
  promoting packet's admit/mark decision equals the pre-change
  best-effort decision.
- **[Q4 high — demotion quiescence not provable]:** §4.4 v2 tightens the
  predicate to `active_flow_buckets==0 && pop_snapshot_stack empty &&
  flow_rr_buckets empty && queued_bytes==0`, and pins the ORDERING:
  demote runs AFTER `restore_cos_local_items_inner`, so any restored
  retry item has already re-bumped `active_flow_buckets`/`queued_bytes`
  and blocks demotion. A partial-commit retry therefore CANNOT be seen
  as quiescent. Demotion only fires on a fully-committed empty queue.
- **[Q5 high — cost not proven byte-identical; measure first]:** Agreed
  — the plan does NOT claim byte-identical without proof. The
  uncontended single-flow push_back adds exactly: one
  `config.flow_fair_eligible` byte load + `flow_fair_state.is_some()`
  (a null-pointer test on the `Option<Box>`) + `hot.items.front()`
  (already loaded — the FIFO is touched by the existing push) + a
  `cos_item_flow_key` front read + `session_keys_equal` short-circuit
  (returns on first field mismatch; both-None returns "same"). All on
  data already in cache. **This is gated, not assumed:** Pass-A CoS-OFF
  `-P12 -R` line-rate (~23G) is a HARD merge-blocker (§8), and impl adds
  a criterion-style microbench (push_back single-flow ns) to the test
  suite. If `-P12 -R` regresses, PLAN-KILL on measurement.
- **[Q6 medium — flow_fair()=is_some() broad change; audit incomplete]:**
  Completed audit. `config.flow_fair` readers: (a) `flow_fair()`
  accessor (rewritten); (b) `promote_cos_queue_flow_fair` writer
  (rewritten to set `flow_fair_eligible` + eager exact promotion);
  (c) status snapshot `queue_row.rs:110` sets `status.flow_fair` from
  the runtime `flow_fair()` — now reports a non-exact queue as flow_fair
  iff currently promoted, which is MORE accurate, not a regression;
  (d) `coordinator/mod.rs:1001` OR-aggregates the status field across
  workers — unaffected (consumes the snapshot field, not config).
  Exact queues: `is_some()` is always true (eager promotion at build,
  never demoted), so exact behavior is byte-identical. Test:
  exact-queue flow_fair()==true at build and after drain-to-empty
  (no demotion).
- **[Migration seam / lease — under-specified]:** §4.3 v2 reuses
  `account_cos_queue_flow_enqueue` (single accounting source of truth)
  and documents the `local_item_count` net-zero handoff + the
  `queue_lease_v8 == None` / `vtime_floor == None` no-op on non-exact
  queues (asserted in the migration test).
- **[Q7 — cross-worker physics]:** Codex agrees this is broadly aligned
  (per-worker state, exact-gated lease). v2 keeps all new state
  per-worker per-queue; non-exact queues never touch a peer's XSK.

Conclusion: every Codex finding is either (a) a real fragility now
removed by per-item-hash migration + tightened demotion predicate +
completed audit, or (b) a "measure before accepting" that the smoke
kill-gate already enforces. None is an architectural dead-end. v2 is
submitted for re-review.
