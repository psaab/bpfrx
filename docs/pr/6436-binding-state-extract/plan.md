# #6436 — extract `afxdp::binding_state` out of `afxdp::umem`

## Problem

`afxdp/umem/mod.rs` is nominally the UMEM memory-region module but
~85% of it is binding runtime state: the 153-field `BindingLiveState`
god-struct (:292-882), the `PendingTxAdmission` RAII single-release
token (:883-909), the hot per-packet TX enqueue paths (:1252-1420),
and the HA session-delta loss-latch buffer (:1422-1495). The sibling
files `snapshot.rs` / `debug_state.rs` / `profile.rs` are also
binding-state concerns (they exist solely to render/flush
`BindingLiveState`), leaving only `mmap.rs` + `WorkerUmem{,Inner,Pool}`
as actual UMEM memory-region code.

## Approach

Pure code-motion, same crate. No field reordering, no visibility
widening beyond what the split requires, `#[inline]`/`#[cold]` and
atomic orderings move byte-identical, `const _: () = assert!` guards
travel verbatim.

New layout:

```
afxdp/binding_state/
  mod.rs            BindingLiveState struct + new() + setter/counter
                    impl block; SharedUmemLiveStatus;
                    FlowWorkerMapSnapshot; pub(in crate::afxdp)
                    re-exports (debug_state precedent, E0364 note)
  tx_inbox.rs       PENDING_TX_INBOX_HARD_CAP, PendingTxAdmission +
                    Drop, impl BindingLiveState { enqueue_tx,
                    enqueue_tx_owned, try_enqueue_tx_owned,
                    try_reserve_mirror_tx_owned, push_redirect_inbox,
                    try_push_redirect_inbox, pending_tx_admission_cap,
                    try_acquire_pending_tx_admission,
                    release_pending_tx_admission,
                    record_redirect_inbox_overflow,
                    take_pending_tx_into, pending_tx_empty }
  latency.rs        DRAIN_HIST_BUCKETS + const asserts,
                    REDIRECT_SAMPLE_MASK + assert, REDIRECT_SAMPLE_SEQ
                    TLS + next_redirect_sample, TX_SUBMIT_LAT_BUCKETS +
                    paired asserts, TX_SIDECAR_UNSTAMPED,
                    bucket_index_for_ns
  session_delta.rs  impl BindingLiveState { push_session_delta,
                    has_pending_session_deltas, set_delta_loss,
                    take_delta_loss, drain_session_deltas }
  snapshot.rs       verbatim move from umem/snapshot.rs
  debug_state.rs    verbatim move from umem/debug_state.rs
  profile.rs        verbatim move from umem/profile.rs
  tests/            the six binding-state concern files from
                    umem/tests/ (#4667 layout maps 1:1):
                    tx_inbox, latency_buckets, snapshot_propagation,
                    tx_submit_latency, tx_kick_latency, debug_state,
                    plus mod.rs (shared header + fixture, verbatim)

afxdp/umem/
  mod.rs            WorkerUmemInner / WorkerUmem / WorkerUmemPool +
                    MmapArea re-export only (~150 lines)
  mmap.rs, mmap_tests.rs   unchanged
  tests/            mod.rs shrunk to the mmap_area concern only
```

`pub(super)` on `BindingLiveState` fields is preserved verbatim: from
`afxdp::binding_state` it resolves to `pub(in crate::afxdp)`, exactly
what it resolved to from `afxdp::umem` — field visibility is
unchanged. The two `pub(in crate::afxdp)` fields
(`tunnel_encap_unresolved_drops`, `fabric_redirect_unsendable_drops`)
travel as-is.

Path updates at explicit-path consumers (glob consumers via
`use self::binding_state::*;` in `afxdp/mod.rs` are untouched):

- `coordinator/status.rs:697` `crate::afxdp::umem::BindingLiveState`
- `coordinator/tests.rs` (4x) `super::super::umem::DRAIN_HIST_BUCKETS`
- `cos/cross_binding.rs:17` `use crate::afxdp::umem::BindingLiveState`
- `neighbor_dispatch.rs:1323` `use crate::afxdp::umem::BindingLiveState`
- `tx/stats.rs:6` `use crate::afxdp::umem::{bucket_index_for_ns,
  OwnerProfileOwnerWrites, TX_SIDECAR_UNSTAMPED, TX_SUBMIT_LAT_BUCKETS}`
- `types/cos.rs:1640` `super::umem::DRAIN_HIST_BUCKETS`

`MmapArea` consumers (`cos/admission.rs`, `cos/ecn.rs`,
`cos/queue_service`, `cos/queue_ops/*`) are untouched — `MmapArea`
stays in `umem`.

Stale file-path citations in moved comments (`umem.rs:...`,
`umem/mod.rs`) are updated to the new paths in the same diff; no
comment semantics change.

## Guardrails (all mandatory, from the issue)

1. Same-crate move — inlining free. Evidence: `objdump -Cd
   --no-show-raw-insn` slices of the canonical
   `target/release/xpf-userspace-dp` binary, baseline vs PR, for the
   out-of-line copies of the hot TX enqueue fns
   (`BindingLiveState::enqueue_tx_owned`,
   `BindingLiveState::push_redirect_inbox`,
   `BindingLiveState::take_pending_tx_into`) plus the
   `drop_in_place<PendingTxAdmission>` RAII glue. Baseline captured at
   `/tmp/6436-asm/baseline-*.asm` (worktree @ 023f17a60). Instruction
   bodies must be identical modulo symbol-name / address noise.
2. `const _: () = assert!` size/align guards travel verbatim
   (DRAIN_HIST_BUCKETS, REDIRECT_SAMPLE_MASK mask-shape,
   TX_SUBMIT_LAT_BUCKETS pairing, profile.rs align(64)/size ceilings).
3. Atomic orderings + RAII disarm-on-push move byte-identical.
4. No field reordering (drop order is load-bearing where documented).
5. `umem/tests/` per-concern files (#4667) map 1:1 onto the new
   layout — same filenames under `binding_state/tests/`; `umem/tests/`
   keeps `mmap_area` only.
6. `umem/README.md` + `afxdp/README.md` updated in the same PR; a new
   short `binding_state/README.md` carries the moved invariants.

## Test strategy

- `cargo build` + full `cargo test` on userspace-dp (the moved tests
  are the behavior pin — they must pass unchanged at the new paths).
- asm-diff per guardrail 1.
- No cluster smoke: pure code-motion refactor, no behavior change
  (stated in PR body per engineering-style "when a validation lane
  can't be run... say so" — here: not applicable, nothing to
  validate at the feature level).

## Alternatives rejected

- **Re-export shims at `umem::`** to avoid touching consumer paths:
  keeps the fused-module coupling the issue is removing; rejected.
- **Splitting `BindingLiveState` itself into sub-structs:** out of
  scope — the issue is module extraction, not struct decomposition;
  field reordering is explicitly forbidden by the guardrails.
