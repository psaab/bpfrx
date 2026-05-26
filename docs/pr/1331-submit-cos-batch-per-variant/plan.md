# #1331 Step 1: extract 221-LOC `submit_cos_batch()` into per-variant handlers

**Status:** DRAFT v2 — flat-sibling layout per round-1 reviewer findings (AGY PLAN-NEEDS-MAJOR, Codex PLAN-NEEDS-MAJOR, Gemini PLAN-NEEDS-MINOR, Claude SMR PLAN-READY-pending-revision). Round-1 task IDs in `reviewer-ids.md`.

## Round-1 review findings folded into v2

1. **AGY PLAN-NEEDS-MAJOR / Gemini PLAN-NEEDS-MINOR — drop the `submit/`
   subdirectory.** Both reviewers (independently) flagged that fanning out
   into a nested `submit/` directory with three files is overkill for a
   1536-LOC parent module that's well below the 2000-LOC smell threshold.
   The user's standing rule for this issue mandates flat sibling files
   inside `queue_service/`, NOT a `submit/` subdir. v2 picks
   `queue_service/submit_local.rs` and `queue_service/submit_prepared.rs`
   as flat siblings of the existing `drain.rs` / `service.rs` /
   `tests.rs`.

2. **Codex PLAN-NEEDS-MAJOR — Local sidecar prefix invariant is false.**
   `transmit_batch` (userspace-dp/src/afxdp/tx/transmit.rs:96-109) pops
   from `pending`, can skip `mirror_clone` items under
   `MIRROR_TX_FRAME_RESERVE` and `continue`. The successful sent prefix
   is therefore a prefix of `scratch_local_tx`, **not** a prefix of the
   original `items`. The existing sidecar at mod.rs:1256
   `&sidecar[..packets as usize]` was built from
   `items.iter().take(TX_BATCH_SIZE)` — so if a mirror_clone is dropped
   ahead of a sent packet, the sidecar accounts the wrong original
   item's bucket. This is an **existing accounting defect**, not
   introduced by this refactor. v2 documents it as an explicit
   carry-over hazard with a deferred-fix follow-up note, and the
   extraction preserves the buggy-but-stable behavior verbatim.

3. **Codex MINOR — shim path/visibility & assign_prepared_dscp_rewrite
   visibility.** With flat-sibling layout the module path becomes
   `submit_local::submit_local(...)` / `submit_prepared::submit_prepared(...)`,
   no submodule re-export needed. Child modules can reach private
   helpers in the parent via `super::`, so
   `assign_prepared_dscp_rewrite` stays `fn` (private) — the visibility
   bump in v1 was unnecessary. `restore_cos_{local,prepared}_items`
   still move into their owning child since they have one caller each.

4. **Claude SMR (in-conversation, hostile) — #1561 race surface
   unchanged.** The null-deref crash is at the outer `CoSBatch` Self
   pointer (`%rbx == NULL`), which can only happen when `CoSBatch` is
   held behind an Arc whose inner pointer was published torn. The
   `submit_cos_batch` consumer takes `CoSBatch` by value (the upstream
   Arc has already been resolved). The refactor adds at most one extra
   memcpy of the destructured `items: VecDeque<...>` header bytes when
   moving caller→callee; that memcpy reads the same bytes the inline
   match arm reads, so the race observability is identical.

**Status of v1:** DRAFT v1 — superseded by v2.

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

This plan extracts each arm into a flat sibling file under
`queue_service/` (alongside the existing `drain.rs`, `service.rs`,
`tests.rs`), leaving `mod.rs` with a thin `match` shim that delegates
to `submit_local::submit_local` / `submit_prepared::submit_prepared`.
Pure code motion, no behavioral change.

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
  that **construct** the `CoSBatch` variants. The new `submit_local.rs`
  / `submit_prepared.rs` flat siblings are the natural symmetric
  partners.
- `service.rs` exists at the same level and houses
  `service_exact_local_queue_direct` / `service_exact_prepared_queue_direct`.
  Those two callers are the **only** callsites of `submit_cos_batch`
  (verified by grep — 2 hits in service.rs, 1 hit in `select` path via
  `drain_into_cos_batch` returning `Option<CoSBatch>`).
- The Prepared arm's flow-fair sidecar (#1229 v7) was added in the same
  diff as the Local arm's — the structure is intentionally mirrored.
  Extraction preserves that symmetry by giving each variant its own
  file with the sidecar literal copied verbatim.

## Concrete design (v2 — flat siblings)

### New file layout

```
userspace-dp/src/afxdp/cos/queue_service/
  mod.rs              (existing)  — submit_cos_batch becomes a thin
                                    match shim only.
  drain.rs            (existing)
  service.rs          (existing)
  tests.rs            (existing)
  submit_local.rs     NEW — pub(super) #[inline] fn submit_local(...),
                            extracted verbatim from the
                            CoSBatch::Local arm. Owns
                            restore_cos_local_items (moved from mod.rs)
                            as a private fn.
  submit_prepared.rs  NEW — pub(super) #[inline] fn submit_prepared(...),
                            extracted verbatim from the
                            CoSBatch::Prepared arm. Owns
                            restore_cos_prepared_items (moved from
                            mod.rs) as a private fn.
```

Same fan-out level as `drain.rs` / `service.rs`. No new directory. No
`submit/mod.rs` re-export layer.

### Signatures

```rust
// queue_service/submit_local.rs
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
) -> bool { /* body verbatim from mod.rs L1198-L1296 */ }

// queue_service/submit_prepared.rs
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
) -> bool { /* body verbatim from mod.rs L1304-L1402 */ }
```

The destructuring-by-value `mut items: VecDeque<...>` parameter
preserves the ownership shape — the match arm moved `items` out of the
batch, so the extracted fn owns it equivalently. `phase`, `batch_bytes`,
`queue_idx` are `Copy`.

### mod.rs additions (flat-sibling mod decls)

```rust
mod submit_local;
mod submit_prepared;
use submit_local::submit_local;
use submit_prepared::submit_prepared;
```

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
            submit_local(
                binding, root_ifindex, queue_idx, phase,
                batch_bytes, items, now_ns, shared_recycles,
            ),
        CoSBatch::Prepared { queue_idx, phase, batch_bytes, items } =>
            submit_prepared(
                binding, root_ifindex, queue_idx, phase,
                batch_bytes, items, now_ns, shared_recycles,
            ),
    }
}
```

### Imports in the new files

Each submodule needs:
- `BindingWorker` from `crate::afxdp::worker`
- `TxRequest` / `PreparedTxRequest` from `crate::afxdp::types`
- `TX_BATCH_SIZE` from `crate::afxdp`
- `Ordering` from `std::sync::atomic`
- `VecDeque` from `std::collections`
- Hot-path helpers reached via `super::` (private parent access from
  a child module is allowed in Rust; no visibility bumps needed):
  - `super::CoSServicePhase`, `super::apply_cos_send_result` /
    `super::apply_cos_prepared_result`,
    `super::refresh_cos_interface_activity`,
    `super::restore_cos_local_items_inner` /
    `super::restore_cos_prepared_items_inner`
  - `super::cos_queue_dscp_rewrite`, `super::transmit_batch` /
    `super::transmit_prepared_queue`, `super::TxError`
  - `super::assign_local_dscp_rewrite` (already
    `pub(in crate::afxdp)`) — used by `submit_local`.
  - `super::assign_prepared_dscp_rewrite` (stays private `fn` in mod.rs;
    reachable from the child via `super::` per Rust's parent-access
    rule). v1's `pub(super)` bump dropped per Codex finding #3.
  - `super::cos_batch_tx_made_progress` (already
    `pub(in crate::afxdp)`).
  - `super::fairness::account_flow_bucket_tx`,
    `super::flow_hash::cos_flow_bucket_index`.

`restore_cos_local_items` / `restore_cos_prepared_items` **move**
into their owning submodule as private `fn`s (each had exactly one
caller — both call sites inside its own variant arm). The
`*_inner` companions stay in `super` (they're used by other call
chains).

### Visibility adjustments required (v2)

- **None.** All extracted-fn callees stay at their current visibility.
  Children read private parent items via `super::`.
- `submit_local` / `submit_prepared` themselves are `pub(super) fn`
  so the parent mod.rs can name them in the shim's `use` decls.
- `restore_cos_local_items` / `restore_cos_prepared_items` move
  into their owning child as private `fn`s (no visibility change since
  the file boundary moves with the helper).

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

7. **`transmit_batch` / `transmit_prepared_queue` interior contract
   (v2 correction per Codex MAJOR finding).**

   - **Prepared path:** `transmit_prepared_queue` is prefix-preserving
     on success — sent packets are a head-prefix of `items`. The
     sidecar `&sidecar[..packets as usize]` indexes correctly into the
     original order. ✓
   - **Local path:** `transmit_batch` (transmit.rs:96-109) pops from
     `pending` and can drop `mirror_clone` items under
     `MIRROR_TX_FRAME_RESERVE` via `continue;`. The successful sent
     count `packets` is a count of `scratch_local_tx` entries, **not**
     a head-prefix of the original `items`. If a mirror_clone is
     dropped ahead of a sent packet, the sidecar at mod.rs:1256
     attributes that packet's bytes to the wrong original item's flow
     bucket. **This is an existing accounting defect that pre-dates
     this refactor** (added when the mirror-clone reserve was wired
     in). The verbatim move preserves the defect — it does not
     introduce it.

   v2 explicitly does NOT fix this defect in scope. Follow-up issue
   to be filed separately (the fix requires either (a) keeping a
   mirror-clone-aware skip count alongside the sidecar build, or
   (b) building the sidecar in `transmit_batch` itself from the
   post-skip order rather than `items.iter()`). For Step 1 pure code
   motion, the extracted `submit_local` must preserve the existing
   sidecar build and indexing verbatim so it remains
   bit-for-bit equivalent to the inline arm.

   **Invariant for this PR:** the per-bucket TX bytes attribution on
   the Local path is identical before and after the refactor under
   all input sequences — including those that exercise mirror_clone
   reserve drops.

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
- **Mirror-clone sidecar misalignment defect on the Local path**
  (Codex round-1 MAJOR finding, see invariant #7). Existing bug.
  Follow-up issue to be filed separately. Refactor preserves the
  current buggy-but-stable behavior verbatim.
- #1207 (`service.rs` consolidation) — separate issue.
- #1206 (CoSQueueRuntime split) — orthogonal.
- #1561 first-snapshot race — separate open issue; this refactor must
  not change behavior on that race path.

## Open questions for adversarial review (round-2)

Round-1 reviewer findings are folded into v2 above. The following
questions remain open for round-2 hostile-verify.

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

7. **`assign_prepared_dscp_rewrite` visibility (v2 resolution):** v2
   keeps it as `fn` (private). Child modules
   (`submit_local.rs` / `submit_prepared.rs`) reach private parent
   items via `super::` per Rust's visibility rules. The v1 bump to
   `pub(super)` was unnecessary and is dropped (Codex round-1 minor
   finding). `assign_*_dscp_rewrite` is a "fix-up helper" pair that
   stays grouped together at the bottom of `mod.rs`.
