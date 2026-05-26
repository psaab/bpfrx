# #1331 Step 1: extract 221-LOC `submit_cos_batch()` into per-variant handlers

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/afxdp/cos/queue_service/mod.rs` is 1536 prod LOC and
contains a 221-LOC `fn submit_cos_batch` (L1184-L1404). That fn is a
single `match` on the `CoSBatch` enum with two arms (`Local`,
`Prepared`). Each arm is independent:

- assigns a per-variant DSCP rewrite to its items,
- builds a stack-allocated `[(u16,u64); TX_BATCH_SIZE]` sidecar from
  the per-queue `flow_fair_state.flow_hash_seed` (if active),
- calls the variant-specific transmit fn (`transmit_batch` for Local,
  `transmit_prepared_queue` for Prepared),
- on Ok: applies the variant-specific `apply_cos_*_result`, drains the
  sidecar prefix into `account_flow_bucket_tx`, bumps tx counters,
- on Err: restores items to the queue head via the variant-specific
  `restore_cos_*_items` helper, bumps error counters, returns a
  progress flag via `cos_batch_tx_made_progress`.

The arms share no mutable state with each other. The two `Some(CoSBatch::*
{ ... })` constructors that feed this fn already live in
`drain_exact_local_to_scratch_with_*` / `drain_exact_prepared_to_scratch_*`
sites (mod.rs L1131, L1172) — the arms have already been independent at
the call site for some time. The match-dispatch is the only thing keeping
the two bodies in one fn.

This plan extracts each arm into a sibling file under
`queue_service/submit/`, leaving `mod.rs` with a thin `match` shim that
delegates to `submit::local` / `submit::prepared`. Pure code motion,
no behavioral change.

## Honest scope / value framing

- **Win at absolute scale:** one fn shrinks from 221 LOC to ~15 LOC
  (the match shim). The two new sibling files are ~110 LOC each. Total
  LOC across mod.rs + new files goes up by ~30 LOC (signature
  duplication + module wiring), but mod.rs drops to ~1320 prod LOC and
  the largest fn drops from 221 to ~110.
- **Reviewability win:** the two arms read independently; future
  flow-fair / lease-telemetry changes touch one file rather than
  threading a diff through a 221-LOC match.
- **Perf:** zero. Per-variant handlers are `#[inline]`, called from one
  callsite each; LLVM's inliner sees through trivially. No per-tick
  allocations introduced — sidecar stays as a stack array inside each
  handler (was already on the stack inside each match arm).

**If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.** This is a Tier-1 modularity-rule
finding (221 LOC, threshold 200), not a hot-path optimization. The
issue's stated value is reviewability + per-arm perf-top symbol
granularity, not throughput.

## What's already shipped / partially batched

- The `CoSBatch` enum is **two** variants today: `Local` (L73-L78) and
  `Prepared` (L79-L84). The issue body anticipated more (`Forwarded`,
  `Recycled`, etc.) — those do **not** exist on master. Plan must match
  current code, not the issue's speculative variant list.
- `drain.rs` already houses the `drain_exact_*_to_scratch*` helpers
  that **construct** the `CoSBatch` variants. The new `submit/` module
  is the natural symmetric partner.
- `service.rs` exists at the same level and houses
  `service_exact_local_queue_direct` / `service_exact_prepared_queue_direct`.
  Those two callers are the **only** callsites of `submit_cos_batch`
  (verified by grep — 2 hits in service.rs, 1 hit in `select` path via
  `drain_into_cos_batch` returning `Option<CoSBatch>`).
- The Prepared arm's flow-fair sidecar (#1229 v7) was added in the same
  diff as the Local arm's — the structure is intentionally mirrored.
  Extraction preserves that symmetry by giving each variant its own
  file with the sidecar literal copied verbatim.

## Concrete design

### New file layout

```
userspace-dp/src/afxdp/cos/queue_service/
  mod.rs                  (existing)  — match shim only after extract
  drain.rs                (existing)
  service.rs              (existing)
  tests.rs                (existing)
  submit/
    mod.rs                NEW — `pub(super) use` re-exports of the
                          two per-variant handlers; no other code.
    local.rs              NEW — `submit_local()` extracted verbatim
                          from `submit_cos_batch`'s `CoSBatch::Local`
                          arm.
    prepared.rs           NEW — `submit_prepared()` extracted verbatim
                          from `submit_cos_batch`'s `CoSBatch::Prepared`
                          arm.
```

### Signatures

```rust
// queue_service/submit/local.rs
#[inline]
pub(super) fn submit_local(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool { /* body verbatim from L1198-L1296 */ }

// queue_service/submit/prepared.rs
#[inline]
pub(super) fn submit_prepared(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool { /* body verbatim from L1304-L1402 */ }
```

The destructuring-by-value `mut items: VecDeque<...>` parameter
preserves the ownership shape — the match arm moved `items` out of the
batch, so the extracted fn owns it equivalently. `phase`, `batch_bytes`,
`queue_idx` are `Copy`.

### mod.rs shim after extract

```rust
fn submit_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    batch: CoSBatch,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    match batch {
        CoSBatch::Local { queue_idx, phase, batch_bytes, items } =>
            submit::local::submit_local(
                binding, root_ifindex, queue_idx, phase,
                batch_bytes, items, now_ns, shared_recycles,
            ),
        CoSBatch::Prepared { queue_idx, phase, batch_bytes, items } =>
            submit::prepared::submit_prepared(
                binding, root_ifindex, queue_idx, phase,
                batch_bytes, items, now_ns, shared_recycles,
            ),
    }
}
```

### Imports in the new files

Each submodule needs:
- `BindingWorker` from `crate::afxdp::worker`
- `TxRequest` / `PreparedTxRequest` / `CoSPendingTxItem` from `crate::afxdp::types`
- `TX_BATCH_SIZE` from `crate::afxdp`
- `Ordering` from `std::sync::atomic`
- `VecDeque` from `std::collections`
- Hot-path helpers from `super::super`:
  - `CoSServicePhase`, `apply_cos_send_result` / `apply_cos_prepared_result`,
    `refresh_cos_interface_activity`, `restore_cos_local_items_inner` /
    `restore_cos_prepared_items_inner`
  - `cos_queue_dscp_rewrite`, `transmit_batch` / `transmit_prepared_queue`,
    `TxError`
  - `assign_local_dscp_rewrite` (already `pub(in crate::afxdp)`) /
    `assign_prepared_dscp_rewrite` (currently `fn` — needs to become
    `pub(super) fn`, otherwise visibility-shadowed by the move)
  - `cos_flow_bucket_index`, `account_flow_bucket_tx`,
    `cos_batch_tx_made_progress`
  - `restore_cos_local_items`, `restore_cos_prepared_items` — currently
    private `fn` at mod.rs L1488/L1511. Either:
    (a) bump both to `pub(super) fn` so the new submodules can call them, OR
    (b) move both helpers into the matching `submit/{local,prepared}.rs`
        since each is only called from inside one extracted arm.
    **Plan picks (b)** — restore helpers are tightly coupled to the
    restore-on-error path and have no other caller. Moving them keeps the
    submit module self-contained.

### Visibility adjustments required

- `assign_prepared_dscp_rewrite`: `fn` → `pub(super) fn` (kept in mod.rs
  because it's narrow and used only by `submit::prepared`).
- `restore_cos_local_items`, `restore_cos_prepared_items`: **moved** into
  `submit/local.rs` and `submit/prepared.rs` respectively as private
  `fn`s within their owning submodule.
- `cos_batch_tx_made_progress`: already `pub(in crate::afxdp)`, no change.
- `account_flow_bucket_tx`: already imported via `super::fairness`,
  re-imported in each submodule via `crate::afxdp::cos::fairness::...`.
- `cos_flow_bucket_index`: already imported via `super::flow_hash`,
  re-imported per submodule.

## Public API preservation

- `submit_cos_batch` itself stays a module-private `fn` in mod.rs.
  Its signature, return type, and side effects are unchanged.
- Per-variant handlers are `pub(super)` — visible only inside the
  `queue_service` module tree. No new crate-level API surface.
- No changes to `CoSBatch`, `CoSServicePhase`, `TxRequest`,
  `PreparedTxRequest`, `transmit_batch`, `transmit_prepared_queue`,
  `apply_cos_*_result`, `restore_cos_*_items_inner`.
- No changes to `mod tests` in `queue_service/tests.rs` — they call
  `submit_cos_batch` (via service-level callers), which preserves its
  signature.

## Hidden invariants the change must preserve

1. **Side-effect ordering inside each arm.** The exact sequence is:
   `assign_*_dscp_rewrite` → sidecar build → transmit → match Ok/Err →
   apply / account / counter-bump (Ok) or set_error / restore / error-counter
   (Err). Verbatim copy preserves this.

2. **No new per-batch heap allocation.** The sidecar is
   `[(u16,u64); TX_BATCH_SIZE]` on the stack; that allocation must stay
   on the stack inside each extracted fn. No `Vec` or `Box` introduced.

3. **`#1229 v7` flow-fair sidecar semantics.** The `local_seed_opt` /
   `prepared_seed_opt` lookup chains through `cos_interfaces.get(...)`
   → `queues.get(...)` → `flow_fair_state.as_ref()` →
   `flow_hash_seed`. The Drop-borrow shape (immutable borrow released
   before the mutable borrow in the Ok arm) must be preserved or the
   borrow checker rejects the extracted fn. The verbatim move preserves
   this since the local scope shape is unchanged.

4. **`#760` instrumentation order:** `tx_packets` bump → `tx_bytes`
   bump → `owner_profile_owner.drain_sent_bytes_shaped_unconditional`
   bump, all under `if packets > 0`. Per-variant comment about
   "non-exact / shared-exact Local path" vs "Prepared path (in-place
   rewrite hot path)" is preserved.

5. **`#710` `tx_submit_error_drops` accounting** on `Drop` error path.

6. **`#1561` (open race) compatibility:** the open race is in
   *first-snapshot publish*, before `CoSBatch` is ever drained — i.e.
   in coordinator snapshot-install / ArcSwap ordering, not in
   `submit_cos_batch`. This refactor:
   - Does NOT change the `CoSBatch` enum shape, layout, or `Drop`
     implementation. (`CoSBatch` has no custom `Drop`; its fields
     `VecDeque<TxRequest>` and `VecDeque<PreparedTxRequest>` each have
     their own `Drop`.)
   - Does NOT change the lifetime of a `CoSBatch` between construction
     (in `drain.rs`) and consumption (in `submit_cos_batch`). The
     enum is still passed by value into the dispatch fn and moved into
     the matching arm's destructuring binding.
   - Does NOT introduce any new `Arc` / `ArcSwap` publish along the
     CoSBatch path.
   - **Must NOT** add any new place where a `CoSBatch` field is read
     before the constructing thread's stores are visible. Since the
     refactor changes nothing about who constructs the `CoSBatch` or
     who consumes it, the race window's surface is identical.
   - Plan is hostile-validated against this in the open-questions
     section below.

7. **`stamp_submits` / `transmit_batch` interior contract.** The
   transmit fns may mutate `items` in place (consume the successful
   prefix). The sidecar slice `&sidecar[..packets as usize]` indexes
   into the **original** order. Since `transmit_batch` returns
   `packets` as the count of items consumed from the head, and
   `items.iter().take(TX_BATCH_SIZE)` walks in the same head-first
   order at sidecar build time, the slice indexing is correct. Move is
   verbatim so this holds.

## Risk assessment

| Risk class | Level | Rationale |
|---|---|---|
| Behavioral regression | **LOW** | Pure code motion. Bodies copied verbatim. No control-flow change. |
| Lifetime / borrow-checker | **LOW** | Each arm already destructured by value and owned `items` locally; extraction preserves ownership exactly. Risk: re-importing types where the original used `super::` paths — verifiable at compile time. |
| Performance regression | **NEGLIGIBLE** | `#[inline]` on `pub(super) fn` called from one site; LLVM inlines through cgu boundary trivially. No new alloc. |
| Architectural mismatch (#961/#946-Phase-2 style) | **LOW** | Sibling-file extraction is the established pattern for this directory (`drain.rs`, `service.rs`). Not introducing a new abstraction. |
| #1561 race compatibility | **LOW** | Refactor doesn't touch construction / publish / Drop of `CoSBatch`. See invariant #6. |

## Test plan

1. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` — clean.
2. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release` —
   952+ tests pass.
3. 5/5 named-test flake check on `cos::queue_service::tests::*` (the
   tests file calls into `submit_cos_batch` via the service helpers).
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — 30 Go
   packages pass.
5. **No per-PR smoke** (per standing rule for #1331 batch — AWAITING-BATCH-MERGE
   after 4-of-4 attestation).

## Out of scope (explicitly deferred)

- `select_exact_cos_guarantee_queue_with_lease_telemetry` (126 LOC,
  Tier-2 warning) — issue body mentions it as a future sibling but
  this PR is scoped to `submit_cos_batch` only.
- Any change to `CoSBatch` enum (variants, fields, layout, Drop).
- Any change to `transmit_batch` / `transmit_prepared_queue` /
  `apply_cos_*_result`.
- Any change to flow-fair sidecar semantics or per-bucket accounting.
- #1207 (`service.rs` consolidation) — separate issue.
- #1206 (CoSQueueRuntime split) — orthogonal.
- #1561 first-snapshot race — separate open issue; this refactor must
  not change behavior on that race path.

## Open questions for adversarial review

1. **Is the perf/reviewability gain worth the file fan-out?** Two new
   files for ~220 LOC of body extracted. Modularity rule says yes
   (Tier-1 threshold crossed); reviewer may disagree. **PLAN-KILL is
   acceptable** if the reviewer's verdict is that mod.rs at 1536 LOC
   is fine and the 221-LOC fn body reads well enough as a single
   match.

2. **Does moving `restore_cos_local_items` / `restore_cos_prepared_items`
   into the submit submodules violate the existing layering** (those
   helpers are below `apply_cos_*_result` and `refresh_cos_interface_activity`
   in the call chain comment at the top of mod.rs, line 1-13)? Should
   they instead stay in mod.rs as `pub(super) fn`? If the reviewer
   prefers visibility-bump-only, the move can be reverted with no
   behavioral impact.

3. **Is `pub(super)` the right visibility?** The handlers are called
   from inside the same module tree as their dispatcher. Any reason
   to prefer `pub(in crate::afxdp)` for consistency with sibling
   modules? `drain` re-exports via `pub(in crate::afxdp) use`; this
   plan picks `pub(super)` because the handlers are dispatched only
   from `submit_cos_batch` in the same file, not from arbitrary
   `afxdp/*` callers. Reviewer may prefer the broader visibility for
   consistency.

4. **Does this introduce any new failure mode vs the current
   monolith?** Plan asserts no — same control flow, same error paths,
   same restore behavior. Reviewer should attempt to construct a
   counter-example (a code path that would behave differently because
   of cross-arm interaction within the original match).

5. **Race compatibility with open #1561:** the open race is in
   first-snapshot publish (coordinator → worker), upstream of
   `submit_cos_batch`. Plan asserts this refactor cannot widen, narrow,
   or relocate that race because it doesn't touch any of the publish
   path, the `CoSBatch` enum layout, or the `Drop` ordering. Reviewer
   should hostile-verify this — is there any way an extracted
   per-variant handler could observe a half-published inner `VecDeque`
   that the monolithic match arm could not?

6. **Stack-array sidecar duplication:** the `[(u16,u64); TX_BATCH_SIZE]`
   literal appears twice (once per arm). Plan keeps both copies
   verbatim — extracting a shared helper would either need
   `flow_key.as_ref()` (Local) / `flow_key.as_ref()` (Prepared) to
   share a trait, or generics over `TxRequest`/`PreparedTxRequest`.
   That's out-of-scope generification and a future cleanup. Reviewer
   may flag this as "duplication you should fix now" — plan defends
   "verbatim move first, dedup later" as the safer order.

7. **`assign_prepared_dscp_rewrite` visibility:** plan bumps it to
   `pub(super) fn` so `submit::prepared` can import it. Reviewer should
   confirm this is acceptable (vs moving the helper into
   `submit/prepared.rs`, since it's only called from there now). Plan
   picks visibility bump because `assign_*_dscp_rewrite` is a "fix-up
   helper" the file groups together at the bottom — moving one without
   the other splits the pair across files. Reviewer may prefer the
   move for stronger locality.
