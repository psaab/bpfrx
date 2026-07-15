# Refactor Audit — A1b TX Path (tx/dispatch + cos_classify + tcp_segmentation + tx/rings + transmit) — 039

- Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9
- Output path: /tmp/ps-review-039-a1b.md
- Scope: userspace-dp/src/afxdp/tx/{mod,dispatch/*,cos_classify,cos_classify_tests,tcp_segmentation,rings,drain/*,transmit/*,stats,test_support}
- Date: 2026-07-08
- Reviewer: modularity-audit agent (A1b batch)
- Dedup: #4408 (enqueue_pending_forwards god-function — ALREADY FILED, new decomposition/hot-path detail only), #4408 cos/queue_service waterfill (different file, not this batch)

---

## File-Size / Shape Inventory

| File | LOC (prod) | Responsibilities | Verdict |
|------|-----------|----------------|---------|
| `tx/dispatch/mod.rs` | 1486 | TX drain orchestrator + Phase 8 (inplace/CP/direct fallbacks) + PTB + segmentation gate + fabric/prebuilt/owned/live dispatch | **(B) god-function remnant** |
| `tx/dispatch/cos.rs` | 141 | CoS fast-path routing helpers | (D) clean, single-responsibility |
| `tx/dispatch/shared_recycle.rs` | 206 | Cross-tick shared-UMEM recycle routing | (D) clean |
| `tx/dispatch/slow_path.rs` | 399 | Exception / build-failure / slow-path reinject | (D) clean, cold-tagged |
| `tx/cos_classify.rs` | 1335 | TX-selection (cached+runtime) + BA reclassify + LP rewrite + enqueue (prepared+local) + demote + admission | **(B) multi-responsibility** |
| `tx/cos_classify_tests.rs` | 4617 | Tests (separate file, correct per style guide) | (D) correct shape |
| `tx/tcp_segmentation.rs` | 309 | TCP PMTUD segmentation into prepared TX | (D) clean, single responsibility |
| `tx/rings.rs` | 415 | Completion drain + fill submit + RX/TX wake | (C) minor — two ring disciplines |
| `tx/drain/mod.rs` | 594 | Drain orchestrator + queue-bound + CoS leftover filters | (C) minor — orchestrator + helpers |
| `tx/drain/phase_shaped.rs` | 151 | Shaped CoS drain + re-ingest budget loop | (D) clean |
| `tx/drain/phase_backup.rs` | 206 | Backup post-CoS transmit (prepared+local) | (D) clean |
| `tx/drain/phase_trivial.rs` | 63 | Reap + rekick + ingest + submit-and-wake thin wrappers | (D) clean (intentionally collapsed) |
| `tx/transmit/mod.rs` | 365 | Local TX + prepared TX orchestrator | (D) clean |
| `tx/transmit/stage.rs` | 64 | Oversized-request drop | (D) clean |
| `tx/transmit/rewrite.rs` | 63 | DSCP rewrite | (D) clean |
| `tx/transmit/verify.rs` | 58 | UMEM slice re-verify | (D) clean |
| `tx/transmit/write.rs` | 60 | Reserve+write+commit+stamp | (D) clean |
| `tx/transmit/finalise.rs` | 56 | Post-commit accounting + retry recovery | (D) clean |
| `tx/stats.rs` | 169 | TX latency histograms | (D) clean |
| `tx/mod.rs` | 55 | Re-exports | (D) clean |
| **Total (prod+test)** | **~13387** | | |

---

## Finding 1: tx/dispatch/mod.rs enqueue_pending_forwards — god-function remnant, Phase 8 + direct-TX + segmentation + fabric still fused

- **Severity:** High (modularity) / Low (correctness — function is correct, but reviewability is degraded)
- **Confidence:** High
- **Refactor class:** (B) — Small, safe refactor (new modules, pure code-motion, no behavioral change)
- **Dedup note:** #4408 already filed the 1,131-LOC god-function finding. This finding provides NEW decomposition detail + hot-path preservation analysis that #4408 lacked. #4408's fix direction was "outline cold segmentation + mirror paths from hot build path." This finding identifies the STILL-REMAINING Phase 8 body, the inline direct-TX fallback enum+match, the dual TCP-segmentation builder paths (prepared vs. local-copy), the triple fabric-redirect special-case repetition, and the three PendingForwardFrame variant dispatch arms — all still fused in one function body.

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/dispatch/mod.rs`
**Function:** `enqueue_pending_forwards` — lines 270..1318 — 1048 LOC function body (1486 LOC file)

Signature (10 params, plus 5 captured via `&mut`):

```rust
pub(in crate::afxdp) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    counters: &mut BatchCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
```

The #1443 split's own comment documents the deferred work:

```rust
// The orchestrator (`enqueue_pending_forwards`) and Phase 8
// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
// this PR — Phase 8 body extraction is deferred to a follow-up so
// reviewers can compare the in-tree control flow against current
// master without a body-shape diff. See plan.md §"Out of scope".
```

Phase 8 inline span (~650 LOC, lines ~640..1295) fuses:

1. TCP segmentation admission gate (`forwarded_tcp_may_need_segmentation`)
2. Prepared-segmentation builder (`segment_forwarded_tcp_frames_into_prepared`) + local-copy segmentation fallback (`segment_forwarded_tcp_frames_from_frame`) — dual builder paths with duplicated tuple-mismatch diagnostic + per-segment enqueue + batch-drain trigger
3. NAT64 predicate + `compute_forwarded_egress_ptb` PTB derivation
4. `request_runs_under_shared_exact_policy` / `cos_owner_live_for_request` CoS routing gate
5. In-place rewrite attempt (`rewrite_forwarded_frame_in_place` → prepared TX) — **Phase 8 proper**, the deferred extraction
6. `DirectTxFallbackReason` enum (inline, 5 variants) + direct-TX attempt (free-frame pop → prefetch → `build_forwarded_frame_into_from_frame` → tuple-mismatch check → prepared enqueue → fallback reason attribution)
7. Copy-path fallback (NAT64 + plain) with oversized-frame handling
8. Fabric-redirect no-binding/inline-prebuilt/build-failure triple special-casing (repeated 3 times: prebuilt dispatch ~line 326, live-frame dispatch ~line 452, build-failure finalizer ~line 1284)
9. Three `PendingForwardFrame` variant dispatch arms (Prebuilt at line 326, Owned at 410, Live at 412) with divergent recycling/CoS/mirror logic

Fabric-redirect pattern repeated 3x (example at line 452):

```rust
if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
    ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, Ordering::Relaxed);
    record_exception(recent_exceptions, ingress_ident, "fabric_redirect_no_binding", ...);
    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
    continue;
}
```

Prebuilt vs. live/owned dispatch:

```rust
if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
    // ~80 LOC: extract frame_len, build TxRequest, enqueue, account, recycle, continue
}
// ...
let source_frame = match &request.frame {
    PendingForwardFrame::Owned(frame) => frame.as_slice(),
    PendingForwardFrame::Live => { /* UMEM slice read */ }
    PendingForwardFrame::Prebuilt(_) => unreachable!(),
};
```

### Proposed decomposition

```
tx/dispatch/mod.rs          — orchestrator loop only (~200 LOC): iter, target lookup, variant dispatch, finalizer
tx/dispatch/forward_build.rs — Phase 8: in-place rewrite → direct-TX → copy-path cascade
                              (try_inplace_or_build, DirectTxOutcome, DirectTxFallbackReason)
tx/dispatch/tcp_seg.rs       — TCP segmentation gate + dual builder dispatch
                              (try_tcp_segmentation, TcpSegOutcome)
tx/dispatch/fabric.rs        — Fabric-redirect drop helper (single site)
                              (handle_fabric_redirect_unsendable)
tx/dispatch/frame_kind.rs    — PendingForwardFrame variant helpers (optional, or inline — already small)
```

Seam: each helper takes `&mut BindingWorker` target + `&PendingForwardRequest`-equivalent + returns a small enum (`BuildOutcome::InPlace | Direct | Copy | Failed`). The orchestrator's `recycle_ingress_frame` + `apply_shared_recycles` + PTB-finalizer stay in `mod.rs` — they are loop-level concerns, not per-frame-build concerns.

Alternative seam for Phase 8: move the entire in-place→direct→copy cascade into `forward_build.rs` as:

```rust
pub(in crate::afxdp::tx::dispatch) fn build_and_enqueue_forward(
    target_binding: &mut BindingWorker,
    source_frame: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    // ... small param bag
) -> BuildOutcome { ... }
```

Returning `BuildOutcome { kind: BuildKind, bytes: u64, max_frame: u32 }`.

### Hot-path preservation analysis

This IS the TX hot path — per-packet at line rate on every forwarded frame.

- **No new heap allocation:** Proposed helpers take `&mut` + `&[u8]` + small `Copy` enums. No `Box`, `Vec`, `String`, or `clone`. The `DirectTxFallbackReason` enum is already stack-allocated; moving it to a submodule is code motion only. `BuildOutcome` is 2×`u64`+`u32` — fits in registers.
- **No dynamic dispatch:** All helpers are `#[inline]` fns in the same crate. No `Box<dyn Trait>`. Module boundary is free for inlining in the same crate (verified: `rustc` inlines across `mod` boundaries within a crate when `#[inline]` + single caller).
- **Zero-copy / UMEM frame ownership preserved:** The in-place rewrite path produces a `PreparedTxRecycle::FillOnSlot` that recycles the ingress frame to the fill ring. This single-recycle invariant must be preserved — the new module must NOT introduce a second recycle on any path. The proposed `forward_build.rs` returns ownership of the outcome; the orchestrator retains sole recycle responsibility for the ingress frame (same as today). Pin: existing `dispatch_tests.rs` already asserts single-recycle on every path (including the `FORCE_OVERSIZED` / `FORCE_TUPLE_MISMATCH` fault-injection tests). Those tests continue to pass without modification because the split is pure code motion.
- **Inlining preserved:** `build_and_enqueue_forward` is called from one site in the loop — `#[inline]` + `pub(in crate::afxdp::tx::dispatch)` ensures LLVM inlines it. The cold paths (`handle_forward_build_failure`, `maybe_reinject_slow_path*`) are already `#[cold] #[inline(never)]` — they stay out of the hot i-cache regardless of module location.
- **Single-recycle invariant:** The existing invariant is: every `source_offset` (ingress UMEM frame) is recycled exactly once — either via `recycle_ingress_frame` (→ `pending_fill_frames`) or via `PreparedTxRecycle::FillOnSlot` (→ cross-binding fill). Moving code must NOT add or remove a recycle call. Verification: run the existing `dispatch_tests.rs` fault-injection tests (they already enumerate oversized, tuple-mismatch, enqueue-err, fabric-no-binding paths and assert `free_tx_frames.len()` / `pending_fill_frames.len()` balance).

### Tests + gate

- Existing: `dispatch_tests.rs` (1564 LOC) — covers every recycle path, NAT64 frag drop, fabric unsendable, PTB derivation, tuple-mismatch, oversized. Must pass unchanged.
- New: no new tests needed for pure code motion. If adding `forward_build.rs`, add a unit test for `DirectTxFallbackReason → counter attribution` mapping (currently inline match at line ~1062, easy to regress when adding a new variant).
- Gate: `make test` (Go + Rust), `make test-deploy` (standalone ping), `make cluster-deploy` + `./test/incus/apply-cos-config.sh` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s (same as #4408 gate — this is the TX hot path).

### Why it matters

`enqueue_pending_forwards` is the single most complex function in the TX path. Every bug fix in the forward-build cascade (NAT64 frag guard #2562, PTB inner-MTU derivation #2301/#2330/#2845, fabric fail-closed #1946, direct-TX tuple mismatch #4041, owned-frame recycling #2208) added a conditional branch inside the same function body, making the next fix harder to reason about. The next feature touching this path (e.g., encap offload, GSO) will add another 100+ LOC to a function that already exceeds the 100-line / 8-param mod-threshold by 10x. Splitting Phase 8 now — while the #1443 deferred-extraction comment is fresh — keeps the function reviewable.

### Fix direction

1. Extract `DirectTxFallbackReason` + `BuildOutcome` enum + `build_and_enqueue_forward` into `tx/dispatch/forward_build.rs` (Phase 8 cascade: inplace → direct-TX → copy-path). Pure code motion, `#[inline]` helpers, same borrow shapes. Verify with `cargo test -p userspace-dp --lib afxdp::tx::dispatch::tests` + `make test-rust`.
2. Extract fabric-redirect unsendable drop helper into `tx/dispatch/fabric.rs` (de-dup 3 repeat sites → one `handle_fabric_redirect_unsendable` call). Pure code motion.
3. Extract TCP segmentation dual-builder dispatch into `tx/dispatch/tcp_seg.rs` (gate + prepared-builder + local-copy fallback + miss recording). Pure code motion.
4. Each step is a separate commit/PR — Phase 8 extraction first (largest win), fabric helper second (mechanical), TCP-seg third (independent). No behavioral change in any step — `make test` + iperf3 smoke gate on each.

### Labels

`refactor`, `modularity`, `hot-path`, `decomposition`, `dispatch`, `follow-up-to-#4408`

---

## Finding 2: tx/cos_classify.rs — 7 fused responsibilities in one 1335-LOC file (3rd-largest TX file)

- **Severity:** Medium (modularity — the file is correct but mixes admission policy, wire-format mutation, loss-priority classification, queue routing, and per-queue state machine)
- **Confidence:** High
- **Refactor class:** (B) — Small, safe refactor (new modules, pure code-motion, shared private helpers stay in same crate)

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/cos_classify.rs` — 1335 LOC (production only, 4617 LOC tests in separate file — correct shape per style guide)

7 distinct responsibilities in one `mod cos_classify`:

| Responsibility | LOC span | Distinct concept |
|---|---|---|
| TX-selection resolve — cached path | `resolve_cached_cos_tx_selection` ~line 101..330 | Flow-cache seed: filter eval + FC→queue + BA fallback, cached descriptor shape |
| TX-selection resolve — runtime path | `resolve_cos_tx_selection_internal` ~line 404..689 | Per-packet same logic + policer metering + ingress/egress filter fold |
| BA reclassification | `reclassify_cached_ba_queue` ~line 342..360 | Flow-cache HIT re-resolve from per-packet DSCP/PCP |
| Loss-priority + rewrite | `resolve_cos_loss_priority` + `resolve_cos_queue_lp_rewrite` ~line 691..757 | Per-packet loss-priority derivation + (queue, LP)→DSCP table lookup |
| Generated-reply classification | `classify_generated_reply` ~line 51..99 | ICMP PTB / Time-Exceeded / reject-reply own-tuple CoS resolve (fail-closed) |
| Local/prepared → CoS enqueue | `enqueue_local_into_cos` + `enqueue_prepared_into_cos` + `clone_prepared_request_for_cos` + `enqueue_cos_item` ~line 759..960 + ~line 1157..1331 | Materialize → admission gate (flow-share / buffer / ECN) → push |
| Demote + queue-idx helpers | `demote_prepared_cos_queue_to_local` + `resolve_cos_queue_idx` + `cos_queue_accepts_prepared` ~line 969..1143 | Prepared→local downgrade on TX-frame exhaustion, MFQ vtime snapshot/restore, queue index resolution |

`enqueue_local_into_cos` itself is a 110-LOC function fusing: TX-frame materialization (`prepare_local_request_for_cos`), prepared-enqueue attempt, fallback-to-local clone on failure, ECN policy, per-flow buffer admission, and flow-share admission — 5+ sub-steps:

```rust
pub(in crate::afxdp) fn enqueue_local_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: TxRequest,
    now_ns: u64,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), TxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding.cos.cos_interfaces.get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        match prepare_local_request_for_cos(binding.umem.area(), &mut binding.tx_pipeline.free_tx_frames, req) {
            Ok(prepared_req) => {
                // ... prepared enqueue attempt → fallback to local clone on Err ...
            }
            Err(req) => {
                // ... demote + local enqueue ...
            }
        }
    }
    let item_len = req.bytes.len() as u64;
    match enqueue_cos_item(binding, egress_ifindex, req.cos_queue_id, item_len,
        CoSPendingTxItem::Local(req), now_ns, shared_recycles.as_deref_mut()) {
        Ok(()) => Ok(()),
        Err(CoSPendingTxItem::Local(req)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => unreachable!("local request returned prepared item"),
    }
}
```

`enqueue_cos_item` (~175 LOC) fuses 4 concerns: sojourn stamping, flow-bucket index + buffer-limit derivation, per-flow flow-share admission + aggregate buffer admission + ECN marking, and queue-push + root-nonempty/runnable bookkeeping + exact-backlog publish.

The file also carries 5 inline `resolve_cos_*_queue_id` helpers that are pure table lookups — candidates for a tiny `classifiers.rs` leaf.

### Proposed decomposition

```
tx/cos_classify/
  mod.rs              — re-exports only (~30 LOC), same pattern as tx/dispatch/mod.rs post-#1443
  tx_selection.rs     — resolve_cached_cos_tx_selection + resolve_cos_tx_selection_internal
                        + reclassify_cached_ba_queue (cached + runtime TX-selection, ~400 LOC)
  loss_priority.rs    — resolve_cos_loss_priority + resolve_cos_queue_lp_rewrite + helpers (~70 LOC)
  generated_reply.rs  — classify_generated_reply + GeneratedReplyVerdict (~50 LOC)
  enqueue.rs          — enqueue_local_into_cos + enqueue_prepared_into_cos
                        + prepare_local_request_for_cos + clone_prepared_request_for_cos (~250 LOC)
  admission.rs        — enqueue_cos_item (admission gate: flow-share / buffer / ECN / push) (~180 LOC)
  demote.rs           — demote_prepared_cos_queue_to_local + resolve_cos_queue_idx
                        + cos_queue_accepts_prepared (~160 LOC)
  classifiers.rs      — resolve_cos_dscp_classifier_queue_id + resolve_cos_ieee8021_classifier_queue_id (~25 LOC)
```

Seam: each submodule is `pub(in crate::afxdp::tx)` or `pub(in crate::afxdp)`. Shared private helpers (`resolve_cos_queue_idx`) stay `pub(super)` in the new `cos_classify` parent `mod.rs` or move to `classifiers.rs`. `enqueue_cos_item` is `pub(super)`-only (consumed by `enqueue.rs` and `demote.rs`) — its visibility does not change.

Test file (`cos_classify_tests.rs`, 4617 LOC) stays as `#[path = "cos_classify_tests.rs"] mod tests;` under the new parent `mod.rs` — no test moves needed (already separate file, correct per style guide). The `#[path]` attribute moves from `cos_classify.rs` to `cos_classify/mod.rs`.

### Hot-path preservation analysis

`enqueue_local_into_cos` / `enqueue_prepared_into_cos` / `enqueue_cos_item` ARE the CoS hot path — per-packet at line rate on every shaped flow.

- **No new heap allocation:** The split is pure code motion — same function bodies, same `VecDeque` / `MmapArea` / `BindingWorker` borrows. `CoSTxSelection` / `GeneratedReplyVerdict` are small `Copy` structs (2×Option<u8> + bool + Option<FilterLogMatch>). The one `clone_prepared_request_for_cos` `to_vec()` is already present (required to materialize a prepared frame into a local `Vec<u8>` for fallback) — not new.
- **No dynamic dispatch:** All helpers are `#[inline]` in same crate, monomorphized, single caller each. Module boundary is free for inlining.
- **Zero-copy / UMEM invariant preserved:** `prepare_local_request_for_cos` draws a free TX frame and copies into UMEM in-place — the frame is NOT double-recycled on fallback (the `recycle_prepared_immediately_with_shared` on the fallback path is the single recycle). Moving this into `enqueue.rs` does not change the borrow/ownership shape.
- **Inlining:** `resolve_cos_dscp_classifier_queue_id` / `resolve_cos_ieee8021_classifier_queue_id` are `#[inline]` table lookups (array index + `u8::MAX` sentinel check) — they MUST stay inlined (they run per-packet on every shaped flow, including the BA-reclassify hit path). The `#[inline]` attribute survives the module move (same crate, sibling submodule). `resolve_cos_loss_priority` is similarly `#[inline]` + called from two sites — same guarantee.
- **Single-recycle invariant:** `enqueue_prepared_into_cos` recycles the prepared frame on fallback-to-local success (`recycle_prepared_immediately_with_shared`), and does NOT recycle on `Err` return (caller retains ownership). This must be preserved exactly — the test `resolve_cos_queue_idx_falls_back_to_default_on_explicit_queue_miss` / demote-path tests pin the recycle accounting.

### Tests + gate

- Existing: `cos_classify_tests.rs` (4617 LOC) — covers every branch (filter FC, DSCP BA, 802.1p, BA reclassify, LP rewrite, unmaterialized-queue fallback, demote vtime snapshot/restore, `cos_queue_accepts_prepared` O(1) gate). Must pass unchanged after file move (same `mod tests` parent, no test edits).
- New: if extracting `enqueue.rs` / `admission.rs`, add a unit test for the flow-share vs. buffer drop attribution precedence (currently inline `if flow_share_exceeded` → `if buffer_exceeded` in `enqueue_cos_item` at line ~1252 — easy to swap during refactor).
- Gate: `make test` (Go+Rust), `make test-deploy`, `make cluster-deploy` + `apply-cos-config.sh` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s + `show class-of-service interface` targeted counters (`flow_share` / `buffer` / `ecn_marked`) move in predicted direction (CoS validation: `docs/cos-validation-notes.md`).

### Why it matters

`cos_classify.rs` is the 3rd-largest production file in `tx/` (after `dispatch/mod.rs` and `drain/mod.rs`). Every CoS admission or classifier change (BA reclassify #3778, LP rewrite #3995, demote MQFQ fix #926, ECN #718/#722, flow-share #707/#710) added a new helper or branch to the same file. The next change (e.g., WRED, per-flow DSCP rewrite) will add another 100+ LOC and risks conflicting with concurrent work on a different CoS sub-concern. Splitting now — while the file is at 1335 LOC (below the 2000 LOC hard limit but above the 1000 LOC smell threshold) — keeps review diffs small and conflict-free.

### Fix direction

1. Create `tx/cos_classify/mod.rs` + re-export shim, move `cos_classify.rs` → `cos_classify/tx_selection.rs` (first PR — largest win, mechanical rename). Update `tx/mod.rs` `mod cos_classify;` (no change needed if using `mod cos_classify;` — Rust resolves `cos_classify/mod.rs` automatically). Verify `make test-rust` passes with zero test edits (tests already in separate file).
2. Extract `generated_reply.rs` + `loss_priority.rs` + `classifiers.rs` (small leaves, independent, no cross-deps). Second PR.
3. Extract `enqueue.rs` + `admission.rs` + `demote.rs` (hot-path modules, need inline preservation check + recycle-invariant pin). Third PR — add the flow-share vs. buffer attribution precedence test before moving.

### Labels

`refactor`, `modularity`, `cos`, `file-size`, `safe-split`

---

## Finding 3: tx/transmit/*.rs — CLEAN SEPARATION (NEGATIVE FINDING)

- **Severity:** N/A (positive example)
- **Confidence:** High
- **Refactor class:** (D) — No action needed, do NOT touch
- **Dedup note:** Not previously filed. The prior A1_b2 review flagged the phase ordering (REWRITE before VERIFY) as a correctness concern (A1-R3 in ps-review-038.md), not a modularity concern.

### Evidence

**Files:**
- `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/transmit/mod.rs` — 365 LOC
- `stage.rs` — 64 LOC, single responsibility: pop up to TX_BATCH_SIZE, drop oversized
- `rewrite.rs` — 63 LOC, single responsibility: iterate staged, apply DSCP rewrite
- `verify.rs` — 58 LOC, single responsibility: re-validate UMEM slices
- `write.rs` — 60 LOC, single responsibility: reserve+write+commit+stamp (POST-COMMIT invariant preserved)
- `finalise.rs` — 56 LOC, single responsibility: post-commit accounting + retry recovery

Orchestrator is 20 LOC and documents the six-phase contract:

```rust
/// Orchestrator: walks the prepared TX queue through six phases —
/// stage → DSCP rewrite → UMEM slice re-verify → optional RST log →
/// reserve+write+commit+stamp → finalise (success accounting / retry
/// recovery / TX kick). See `transmit/{stage,rewrite,verify,write,
/// finalise}.rs` for each phase's invariants. Pure code motion of
/// the prior monolithic body (#1354); semantics, ordering, and drop
/// accounting are byte-identical to the pre-split function.
pub(in crate::afxdp) fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    stage::stage_batch_into_scratch(binding, pending, shared_recycles)?;
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    rewrite::apply_dscp_rewrites_to_staged(binding, shared_recycles)?;
    verify::verify_umem_slices_for_staged(binding, shared_recycles)?;
    if cfg!(feature = "debug-log") {
        log_rst_frames_prepared(binding);
    }
    let inserted = write::reserve_and_write_descriptors(binding);
    finalise::finalise_prepared(binding, pending, now_ns, inserted)
}
```

### Why this is a NEGATIVE finding

This is the textbook example of clean modular decomposition on the hot path — exactly what `docs/engineering-style.md` "Modularity discipline" asks for. Each phase is a single-responsibility module with:

- Clear ownership of one step in a linear pipeline
- Shared error semantics (orphan-recycle + `tx_submit_error_drops` accounting) factored into `recycle_prepared_immediately_with_shared` helper (not duplicated)
- `#[inline]` on each phase function (single caller, inlining guaranteed)
- Doc comments stating the invariant + drop semantics per phase
- No shared mutable state beyond the `&mut BindingWorker` + `&mut Vec<…>` scratch buffers already threaded by the orchestrator
- Zero new allocation (all phases operate on `&mut [PreparedTxRequest]` in scratch, `&mut Vec<(u32,u64)>` for recycles)
- Post-commit stamping invariant preserved by keeping reserve+write+commit+stamp inside `write.rs` (not splittable without breaking #812 HIGH #1)

**Do NOT further split this.** The 6-phase split is the right granularity. Collapsing them would re-create a monolithic function. Splitting finer (e.g., separating `stamp_submits` from `write.rs`) would break the post-commit invariant documented in `write.rs:15-20`.

### Proposed decomposition

None — this is clean. Use as template for the dispatch/mod.rs Phase 8 extraction (Finding 1).

### Hot-path preservation analysis

- No new allocation, no dynamic dispatch, zero-copy preserved, inlining preserved, single-recycle invariant preserved — all by construction (the split IS pure code motion per #1354, verified by `make test-rust` at that PR).

### Tests + gate

- Existing: `transmit_tests.rs` (186 LOC) + `dispatch_tests.rs` (1564 LOC, covers prepared TX path indirectly). Must continue to pass.
- No new tests needed for this finding (it's a negative).

### Why it matters (as a negative)

Demonstrates that the TX path CAN be cleanly decomposed without hot-path cost. Finding 1 and Finding 2 should follow this pattern.

### Labels

`modularity`, `positive-example`, `no-action`, `template`

---

## Finding 4: tx/rings.rs — mixed ring disciplines (completion drain + fill drain + RX/TX wake) — minor

- **Severity:** Low (modularity — file is 415 LOC, below the 2000 LOC hard limit, but mixes two logically distinct XSK ring disciplines)
- **Confidence:** Medium
- **Refactor class:** (C) — Trivial refactor (new modules, pure code-motion, low risk) OR (D) — Accept as-is at current size, split only when adding new logic

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/rings.rs` — 415 LOC

Two distinct XSK ring disciplines + two wake mechanisms in one file:

| Discipline | Functions | Distinct failure mode |
|---|---|---|
| TX completion ring drain | `reap_tx_completions` (72 LOC), `recycle_completed_tx_offset`, `apply_prepared_recycle`, `record_tx_completion_ring_available*` | Completion ring stall → TX frame leak → `free_tx_frames` exhaustion |
| Fill ring drain | `drain_pending_fill` (59 LOC) | Fill ring starvation → RX stall → `rx_xsk_buff_alloc_err` on mlx5 |
| RX wake (POLLIN) | `maybe_wake_rx` (49 LOC) | RX wake missed → idle interface never receives packets |
| TX wake (sendto) | `maybe_wake_tx` (98 LOC) | TX wake missed → latency-sensitive reply stalls on idle zerocopy binding |

The completion path and fill path share only:
- `BindingWorker` (different fields: `tx_pipeline.free_tx_frames` vs `pending_fill_frames`, `scratch_completed_offsets` vs `scratch_fill`)
- `shared_recycles` routing (cross-binding fill-frame return)
- `update_binding_debug_state` (debug snapshot)

They are otherwise independent: different ring types (`complete` vs `fill`), different wake mechanisms (`poll(POLLIN)` vs `sendto`), different error paths, different telemetry counters. A change to completion drain (e.g., #812 latency sidecar, #825 kick-latency) should not require reading the fill drain code, and vice versa.

The file also carries a `#[cfg(test)]` block with two small unit tests for completion/available tracking — those belong with the completion discipline.

### Proposed decomposition (if splitting)

```
tx/rings/
  mod.rs          — re-exports (~15 LOC)
  completions.rs  — reap_tx_completions + recycle_completed_tx_offset + apply_prepared_recycle
                    + record_tx_completion_ring_available* + tests (~200 LOC)
  fill.rs         — drain_pending_fill + maybe_wake_rx (~130 LOC)
  wake.rs         — maybe_wake_tx (~100 LOC)
```

Or, more conservatively (2-file split, preserves the existing `#812` latency comment threading):

```
tx/completions.rs — completion drain + recycle + stats hooks (~220 LOC)
tx/fill.rs        — fill drain + RX wake + TX wake (~195 LOC)
```

Seam: both new modules take `&mut BindingWorker` + `&mut Vec<(u32,u64)>` + `u64 now_ns` — same as today. No new types, no new traits, no ownership changes. `tx/mod.rs` re-exports update from `pub(super) mod rings; pub(super) use rings::...` to `pub(super) mod completions; pub(super) mod fill;` (or `mod rings { pub mod completions; pub mod fill; }` keeping the `rings::` prefix for callers).

### Hot-path preservation analysis

Both `reap_tx_completions` and `drain_pending_fill` are hot-path — called once per `drain_pending_tx` tick (and `reap_tx_completions` also from `transmit_batch` on free-frame exhaustion).

- **No new heap allocation:** Pure code motion — same `&mut BindingWorker` borrows, same `Vec::clear()` + `Vec::push` on reuse buffers (`scratch_completed_offsets`, `scratch_fill`) that are already pre-allocated on `BindingWorker.scratch`.
- **No dynamic dispatch:** `#[inline]` functions in same crate, single caller each (from `drain/mod.rs` and `transmit/mod.rs`), module boundary free for inlining.
- **Zero-copy / UMEM invariant preserved:** `recycle_completed_tx_offset` routes `PreparedTxRecycle::FillOnSlot` to `shared_recycles` for cross-binding return, `FreeTxFrame` to `free_tx_frames`. This routing is unchanged by module move. The single-free invariant (frame freed exactly once via completion ring) is preserved — the `in_flight_prepared_recycles` map tracks frames until completion, then `remove(&offset)` ensures exactly-once recycle.
- **Inlining:** `reap_tx_completions` is `pub(in crate::afxdp)`, called from `drain/phase_trivial.rs` as `drain_phase_reap_completions` → `reap_tx_completions`. One level of indirection, `#[inline]` on both ensures LLVM collapses. Same for `drain_pending_fill` → `drain_phase_ingest_cos` path.
- **Single-recycle invariant:** Verified by existing `apply_prepared_recycle_routes_fill_and_free_explicitly` unit test (already in `rings.rs`, moves with `completions.rs`). No new paths introduced.

### Tests + gate

- Existing: `rings::tests::apply_prepared_recycle_routes_fill_and_free_explicitly` + `record_tx_completion_ring_available_*` (3 tests). Must pass unchanged after file move.
- New: none for pure code motion. If splitting, verify the `rings::` prefix re-export still resolves from `drain/phase_trivial.rs` / `transmit/mod.rs` / `dispatch/mod.rs` callers (compile check).
- Gate: `make test-rust` (unit), `make test-deploy` (standalone), `make cluster-deploy` + iperf3 smoke (same TX hot-path gate as Finding 1).

### Why it matters

At 415 LOC, `rings.rs` is well below the 2000 LOC hard limit and is NOT a monolith today. This finding is (C) — trivial split — or (D) — accept as-is. The reason to file it is: the next change touching EITHER completion drain OR fill drain will add code to a file that already mixes two disciplines, making the diff harder to review and increasing merge conflict surface with concurrent work on the other discipline. Splitting now costs one file-rename PR with zero behavioral change and makes future changes to each discipline independent.

If the team prefers to keep `rings.rs` as one file at current size, that is reasonable — mark this (D) and re-evaluate only if the file grows past ~600 LOC or a third discipline is added.

### Fix direction

1. Create `tx/rings/completions.rs` + `tx/rings/fill.rs` + `tx/rings/mod.rs` re-export shim, move code (pure `git mv` + `mod` declaration). Update `tx/mod.rs` re-exports. Verify `cargo test -p userspace-dp --lib` passes + `make test-rust` passes.
2. OR: accept as (D) — no action, re-evaluate when file grows past 600 LOC.

### Labels

`refactor`, `modularity`, `low-priority`, `trivial-split`, `rings`

---

## Finding 5: tx/drain/mod.rs — orchestrator + helpers + leftover filters in one 594-LOC file (minor)

- **Severity:** Low (modularity)
- **Confidence:** Medium
- **Refactor class:** (D) — Accept as-is at current size, well-structured; OR (C) — extract leftover filters into dedicated module (mechanical)
- **Dedup note:** Not previously filed. The drain phase split (#1443 follow-up) already extracted `phase_shaped.rs`, `phase_backup.rs`, `phase_trivial.rs` — this finding evaluates the remaining `mod.rs` residue.

### Evidence

**File:** `/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/tx/drain/mod.rs` — 594 LOC

After the phase extraction, `drain/mod.rs` contains:

1. `DrainCtx` struct + 4 re-export `use super::*` + `mod phase_*` declarations (orchestrator header, ~30 LOC)
2. `pending_tx_capacity` — pure math helper (5 LOC)
3. `bound_pending_tx_local` + `bound_pending_tx_prepared` — backpressure bound helpers (50 LOC)
4. `drain_pending_tx` — 6-phase orchestrator (35 LOC — clean, delegates to phase helpers)
5. `drop_cos_bound_prepared_leftovers` — #760 CoS shaper bypass guard, prepared side (85 LOC)
6. `drop_cos_bound_local_leftovers` — #760 CoS shaper bypass guard, local side, with rescue attempt (80 LOC)
7. `tx_request_targets_cos_interface` — predicate (5 LOC)
8. `partition_cos_bound_local_with_rescue` — pure scan helper (30 LOC, `#784` mixed-head invariant)
9. `binding_has_pending_tx_work` + `should_enter_shaped_drain` + `has_queued_cos_work` — predicates (15 LOC)
10. `drain_pending_tx_local_owner` — thin wrapper (10 LOC)
11. `ingest_cos_pending_tx` + `ingest_cos_pending_tx_with_provenance` — full MPSC inbox drain + CoS routing (200 LOC)
12. `process_pending_queue_in_place` — generic queue drain helper (15 LOC)
13. `take_pending_tx_requests` + `restore_pending_tx_requests` — inbox helpers (20 LOC)

Items 5-8 (CoS leftover filters, ~200 LOC) are logically "CoS shaper bypass guards" — they protect the #760 cap bypass invariant and have their own test file (`drain/tests.rs`, 201 LOC). They could live in `drain/cos_leftover.rs`.

Items 11-13 (CoS ingest, ~235 LOC) are the MPSC inbox drain + CoS routing logic — they could be `drain/cos_ingest.rs`.

The orchestrator itself (item 4) is clean at 35 LOC and correctly delegates to phases — that is NOT the problem.

### Proposed decomposition (if splitting)

```
tx/drain/
  mod.rs              — DrainCtx + drain_pending_tx orchestrator + pending_tx_capacity (~70 LOC)
  phase_trivial.rs    — reap + rekick + ingest + submit-and-wake (existing, unchanged)
  phase_shaped.rs     — shaped drain + re-ingest budget (existing, unchanged)
  phase_backup.rs     — backup post-CoS transmit (existing, unchanged)
  cos_ingest.rs       — ingest_cos_pending_tx + ingest_cos_pending_tx_with_provenance
                        + process_pending_queue_in_place + take/restore helpers (~250 LOC)
  cos_leftover.rs     — drop_cos_bound_prepared_leftovers + drop_cos_bound_local_leftovers
                        + partition_cos_bound_local_with_rescue + tx_request_targets_cos_interface (~130 LOC)
  bounds.rs           — bound_pending_tx_local + bound_pending_tx_prepared (~50 LOC)
  predicates.rs       — binding_has_pending_tx_work + should_enter_shaped_drain + has_queued_cos_work
                        + drain_pending_tx_local_owner (~25 LOC, or fold into mod.rs — tiny)
```

Seam: `cos_ingest.rs` and `cos_leftover.rs` take `&mut BindingWorker` + `&ForwardingState` + `&mut Vec<(u32,u64)>` — same as today. No new types beyond `DrainCtx` (already in `mod.rs`). `bounds.rs` is `pub(super)` helpers used by `cos_ingest.rs` + `cos_classify.rs` + `dispatch/mod.rs` — its visibility does not change.

### Hot-path preservation analysis

`ingest_cos_pending_tx` / `drop_cos_bound_*_leftovers` are hot-path — called once per `drain_pending_tx` tick.

- **No new heap allocation:** Pure code motion. `process_pending_queue_in_place` is generic over `T` and operates on `&mut VecDeque<T>` in-place (pop_front/push_back, no alloc). `take_pending_tx_requests` reuses `binding.tx_pipeline.pending_tx_local` as the drain target (allocation-free per file comment at line 577).
- **No dynamic dispatch:** All helpers are `#[inline]` or `pub(super)` in same crate.
- **Inlining:** `partition_cos_bound_local_with_rescue` is a pure function with two closures — `#[inline]` + monomorphized per closure type, no dynamic dispatch. Moving to `cos_leftover.rs` preserves inlining (same crate, sibling module).
- **Single-recycle / correctness:** The `drop_cos_bound_prepared_leftovers` `O(n)` full-deque scan (not head-peek — #784 correctness fix) + `drop_cos_bound_local_leftovers` rescue attempt are both load-bearing for the #760 CoS cap bypass invariant. Moving them must preserve the full-scan semantics + rescue attempt. The existing `drain/tests.rs` pins `partition_cos_bound_local_scans_mixed_head_deque` — that test moves with `cos_leftover.rs` and continues to pass.

### Tests + gate

- Existing: `drain/tests.rs` (201 LOC) — `partition_cos_bound_local_scans_mixed_head_deque`, `drop_cos_bound_*` integration tests. Must pass unchanged.
- Gate: `make test-rust`, `make cluster-deploy` + iperf3 + `show class-of-service interface` (same as Finding 2 — CoS path).

### Why it matters

At 594 LOC, `drain/mod.rs` is below the 2000 LOC hard limit and its orchestrator is clean. The phase extraction (#1443 follow-up) already did the heavy lifting. This finding is (D) — accept at current size — or (C) — trivial split if the team anticipates more CoS ingest/leftover changes. The 200 LOC `ingest_cos_pending_tx_with_provenance` function (with its #780 memoization, #760 provenance tracking, and #784 mixed-head handling) is the single largest function in `drain/` and mixes MPSC inbox management with CoS routing — a future change to either concern touches a file with the other.

### Fix direction

1. If splitting: create `drain/cos_ingest.rs` + `drain/cos_leftover.rs` + `drain/bounds.rs`, move code (pure `git mv` + `mod` declaration), update `tx/mod.rs` re-exports. Verify `cargo test -p userspace-dp --lib afxdp::tx::drain::tests` passes.
2. OR: accept as (D) — no action, re-evaluate when `drain/mod.rs` grows past ~800 LOC or a new ingest/leftover concern is added.

### Labels

`refactor`, `modularity`, `low-priority`, `drain`, `future-split`

---

## Summary — Findings by Refactor Class

| # | Title | Class | Severity | LOC | New vs. Dedup |
|---|-------|-------|----------|-----|---------------|
| 1 | `dispatch/mod.rs` enqueue_pending_forwards remnant (Phase 8 + direct-TX + segmentation + fabric still fused) | (B) safe split | High (modularity) | 1048 LOC function, ~650 LOC Phase 8 still inline | NEW detail on #4408 (hot-path preservation + Phase 8 + direct-TX + fabric dedup) |
| 2 | `cos_classify.rs` 7 fused responsibilities | (B) safe split | Medium (modularity) | 1335 LOC file, 7 responsibilities | NEW (not in #4408 — #4408 covered `cos/queue_service`, not `tx/cos_classify`) |
| 3 | `transmit/*.rs` 6-phase split — CLEAN (negative) | (D) no action | N/A | 5×~60 LOC + 365 LOC orchestrator | NEW negative (prior A1_b2 review flagged phase ordering as correctness bug, not modularity) |
| 4 | `rings.rs` mixed disciplines (completion + fill + wake) | (C) trivial / (D) accept | Low | 415 LOC file | NEW |
| 5 | `drain/mod.rs` orchestrator + leftover filters + ingest | (D) accept / (C) trivial | Low | 594 LOC file, ~200 LOC leftover + ~235 LOC ingest | NEW (phase extraction already done, this evaluates residue) |

---

## Cross-Cutting Notes

### Hot-path preservation — common to all (B) findings

All proposed splits are pure code motion within the same Rust crate (`userspace-dp`). The guarantees:

- **Module boundary is free for inlining in Rust.** Same-crate `mod` boundaries do not inhibit inlining — `rustc` inlines across `mod` boundaries when `#[inline]` + single caller. The proposed new modules (`dispatch/forward_build.rs`, `dispatch/tcp_seg.rs`, `dispatch/fabric.rs`, `cos_classify/tx_selection.rs`, etc.) are siblings of the current module — same crate, same compilation unit. Verifiable by checking `cargo rustc -- --emit=llvm-ir` for `#[inline]` functions after the split — the IR should be identical (modulo symbol names) to pre-split.

- **No new heap allocation on any hot path.** Every proposed helper takes `&mut BindingWorker` + `&[u8]` + small `Copy` enums/structs. The `Vec`-returning `clone_prepared_request_for_cos` already exists and is not changed. No new `Box`, `Vec::new`, `String`, or `clone` on any hot path.

- **Zero-copy / UMEM frame ownership preserved.** The `PreparedTxRecycle` / `FillOnSlot` / `FreeTxFrame` single-recycle invariant is the most critical TX-path invariant. Every proposed split preserves the exact `push_back` / `remove` / `recycle_prepared_immediately_with_shared` call sites — no new recycle, no removed recycle, no moved recycle across error paths. Verification: run `dispatch_tests.rs` fault-injection tests (they already enumerate every recycle path and assert `free_tx_frames.len()` / `pending_fill_frames.len()` balance) + `rings::tests`.

- **Single-recycle verification method:** The existing `dispatch_tests.rs` `FORCE_OVERSIZED` / `FORCE_TUPLE_MISMATCH` / `FORCE_ENQUEUE_ERR` thread-locals drive every error path and assert single-recycle. After each split PR, run `cargo test -p userspace-dp --lib afxdp::tx::dispatch::tests` + `cargo test -p userspace-dp --lib afxdp::tx::drain::tests` + `cargo test -p userspace-dp --lib afxdp::tx::transmit::tests` — all must pass with zero test edits (pure code motion).

### Behavioral gates (applicable to all findings)

Per `docs/engineering-style.md` "Deploy + feature validation":

- `make test` (Go suite + Rust `cargo test`) — every PR, no exceptions. Rust leg needs `cargo` (~minutes). If `make test` fails on Rust side, the PR is NOT mergeable.
- `make test-deploy` (standalone VM, ping between zones) — every PR touching TX path (this IS TX path — always required).
- `make cluster-deploy` (loss userspace cluster) + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥ 23 Gbit/s — every TX-path PR (this batch IS TX path — always required). Deploy wipes CoS — re-apply before iperf3.
- `show class-of-service interface` — for Finding 2 / Finding 5 (CoS admission path) — `flow_share` / `buffer` / `ecn_marked` counters must move in predicted direction per `docs/cos-validation-notes.md`.
- `make test-failover` — if touching `fabric.rs` or `rings.rs` shared-recycle path (Finding 1 fabric helper, Finding 4 fill/completion split).
- Fairness gates: `docs/fairness-regimes.md` — per-flow CoV floor check for CoS changes.

### Dedup — full cross-reference

- **#4408** `tx/dispatch enqueue_pending_forwards (1,131 LOC) god-function` — ALREADY FILED. Finding 1 provides NEW decomposition detail (Phase 8 body, direct-TX fallback enum, dual TCP-seg builder paths, fabric-redirect triple repetition, PendingForwardFrame variant dispatch) + hot-path preservation analysis (inlining, zero-copy, single-recycle verification method) that #4408 lacked. Finding 1 does NOT re-report the god-function — it assumes #4408's filing and adds the next-level breakdown.
- **#4408** `cos/queue_service waterfill` — different file (`userspace-dp/src/afxdp/cos/queue_service/mod.rs`, not `tx/cos_classify.rs`). Finding 2 covers `tx/cos_classify.rs` — different file, different responsibility set (TX-selection + enqueue + admission + demote vs. drain-side waterfill selection). No overlap.
- **Prior A1 batch reviews** (`ps-review-038-A1_rust_dataplane_packet-b2.md`, `ps-review-038.md` A1-R1/R2/R3) — filed correctness bugs (MTU→u16 truncation, completion-ring OOB, REWRITE-before-VERIFY ordering), not modularity findings. No overlap with this audit's modularity focus.
- **#1354** `transmit` 6-phase split — already complete, verified, merged. Finding 3 is a NEGATIVE (no action) that confirms the split is exemplary. Not a duplicate.
- **#1443** `dispatch` 3-submodule split (cos, shared_recycle, slow_path) — already complete, verified, merged. Finding 1 identifies the STILL-REMAINING Phase 8 + direct-TX + fabric + frame-kind fusion that #1443 explicitly deferred ("Phase 8 body extraction is deferred to a follow-up"). Not a duplicate — it's the follow-up #1443 anticipated.

