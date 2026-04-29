# #956 Phase 2: extract cos/flow_hash.rs from tx.rs

Plan v3 — 2026-04-29. Addresses Codex round-2 (task-mokeuga7-ksgioj):
five factual drift fixes.

A. `exact_cos_flow_bucket` is NOT test-referenced. Tests use
   `cos_flow_bucket_index` (which calls it internally), not the
   raw function. v2 over-engineered a `pub(in crate::afxdp)` +
   cfg-gated test-visibility scheme — none of it is needed.
   `exact_cos_flow_bucket` stays file-private. Removed the
   visibility-trick branch from the plan.

B. Files-touched bullet still claimed `worker.rs` might need an
   import-path update. Removed — Codex round-1 already
   established the only call site is `tx.rs:5830`.

C. Production-call-site list missed `tx.rs:4305, 4326` for
   `cos_flow_bucket_index` and the nested call at `tx.rs:5987`
   for `cos_item_flow_key`. Added.

D. Files-touched bullet for `flow_hash.rs` still said "6
   functions + the mask constants if moved with". Mask
   constants stay in `types.rs` (round-1 #1); the bullet now
   says 6 functions only.

E. `cos/mod.rs` has a stale module-level comment referencing
   the Phase 1 phase-order; updated to call out current Phase 2
   = flow_hash; admission Phase 3.

v2 — Addresses Codex round-1 (task-mokelx3b-mo5av4):
five factual corrections.

1. COS_FLOW_FAIR_BUCKETS / COS_FLOW_FAIR_BUCKET_MASK already live
   in `types.rs:623,642` (not `tx.rs`). Don't move them — leave
   in types and import from there; moving would invert ownership
   and risk a `types -> cos::flow_hash -> types` cycle.

2. `cos_flow_hash_seed_from_os` is called from `tx.rs:5830`
   (promotion path), NOT `worker.rs`. Plan v1 falsely claimed a
   worker.rs import-path update is needed — it isn't.

3. Don't re-export `mix_cos_flow_bucket` and don't expose it.
   It's an internal hash-mix only used by `exact_cos_flow_bucket`
   and `cos_flow_hash_seed_from_os` (both moving). Keep it
   file-private. `exact_cos_flow_bucket` is exposed only because
   tests reference it directly.

4. `SessionKey` import path: `crate::session::SessionKey`, not
   `crate::afxdp::session::SessionKey`. Plus `std::net::IpAddr`
   for the v4/v6 match arms.

5. Production-vs-test gating: 3 of the moved fns are PRODUCTION
   paths (verified at the listed tx.rs lines); do NOT gate them
   behind `#[cfg(test)]`. Only `exact_cos_flow_bucket` is test-
   only-referenced in tx::tests.

Continues the phased decomposition started by #956 Phase 1
(cos/ecn.rs at PR #976). Phase 2 extracts the flow-hashing
helpers next per the plan committed in Phase 1 (see
docs/pr/956-tx-decomposition/plan.md "Out of scope" section).

## Investigation findings (Claude, on commit d719decb)

The flow-hash subsystem in tx.rs comprises 6 functions at
`userspace-dp/src/afxdp/tx.rs:3833-3981`:

| Item | Line | Visibility | Callers |
|---|---|---|---|
| `mix_cos_flow_bucket` | 3833 | private (file) | `exact_cos_flow_bucket`, `cos_flow_hash_seed_from_os` (only) |
| `cos_flow_hash_seed_from_os` | 3857 | `pub(super)` | tx.rs:5830 (promotion) |
| `exact_cos_flow_bucket` | 3927 | private | `cos_flow_bucket_index` (only) |
| `cos_item_flow_key` | 3954 | private | `apply_cos_admission_ecn_policy`, `account_cos_queue_flow_*` |
| `cos_flow_bucket_index` | 3962 | private | admission + promotion paths |
| `cos_queue_prospective_active_flows` | 3976 | private | admission per-flow gate |

Phase 1's lesson: items used outside the moved module need to be
declared `pub(in crate::afxdp)` so re-exports from `cos/mod.rs`
work.

`cos_flow_hash_seed_from_os` is already `pub(super)` because it
is called from `tx.rs:5830` (the promotion path that
re-randomizes the per-queue hash seed). After the move its
source declaration becomes `pub(in crate::afxdp)` and the
re-export from `cos/mod.rs` keeps the call site import path
short via `super::cos::{...}`.

8 existing tests at `tx.rs:13455-13750` exercise the moved
functions (5× `exact_cos_flow_bucket_*`, 2× distribution tests,
1× `cos_flow_hash_seed_from_os_draws_nonzero_entropy`).

### Phase 1 lesson applied: keep tests in place

Phase 1 originally planned to move tests + fixtures with the
production code; the implementation walked that back to avoid a
same-PR fixture relocation. Phase 2 takes the lesson up front:
**leave the 8 tests in `tx::tests`** for this PR. They reach the
moved items via `use super::cos::{...}` — the re-exports from
`cos/mod.rs` deliver `cos_flow_bucket_index` and
`cos_flow_hash_seed_from_os` at the short path, matching the
production import shape. Test relocation is deferred to a later
cleanup PR (or to whichever phase finally consolidates
`tx::tests`).

The flow-hash tests are simpler than ECN's — they don't share
fixtures with admission tests. So they're easier to move later
than ECN's were.

## Approach

Create `userspace-dp/src/afxdp/cos/flow_hash.rs` with the 6
moved functions. Each item that needs cross-module visibility
gets `pub(in crate::afxdp)`. `cos/mod.rs` adds a `pub(super) mod
flow_hash;` line plus re-exports for the items called from
`tx.rs` (the only consumer; `worker.rs` does not call any of these).

Move list (production code only, ~150 LOC, 6 functions):

```rust
// cos/flow_hash.rs
use crate::session::SessionKey;            // exact_cos_flow_bucket reads
                                            // (Codex round-1 #4: NOT
                                            // crate::afxdp::session)
use std::net::IpAddr;
use crate::afxdp::types::{CoSPendingTxItem, CoSQueueRuntime,
    COS_FLOW_FAIR_BUCKET_MASK};            // mask import per Codex r1 #1

// File-private (no callers outside flow_hash). Codex round-2 #1
// confirmed neither has a direct external caller — `tests` use
// `cos_flow_bucket_index`, not `exact_cos_flow_bucket` directly.
fn mix_cos_flow_bucket(seed: &mut u64, value: u64) { ... }
fn exact_cos_flow_bucket(
    queue_seed: u64, flow_key: Option<&SessionKey>) -> u16 { ... }

// Production callers exist in tx.rs — pub(in crate::afxdp).
pub(in crate::afxdp) fn cos_flow_hash_seed_from_os() -> u64 { ... }
pub(in crate::afxdp) fn cos_item_flow_key(
    item: &CoSPendingTxItem) -> Option<&SessionKey> { ... }
pub(in crate::afxdp) fn cos_flow_bucket_index(
    queue_seed: u64, flow_key: Option<&SessionKey>) -> usize { ... }
pub(in crate::afxdp) fn cos_queue_prospective_active_flows(
    queue: &CoSQueueRuntime, flow_bucket: usize) -> u64 { ... }
```

**Note on test reach** (Codex round-2 #1): the 8 tests staying
in `tx::tests` reference `cos_flow_bucket_index` and
`cos_flow_hash_seed_from_os` (production-exposed) directly, NOT
`exact_cos_flow_bucket`. So no visibility widening is needed
for the file-private helpers. If a future PR wants to test
`exact_cos_flow_bucket` directly, those tests should land in
`cos::flow_hash::tests` (where the file-private item is
in-scope) rather than going through cross-module visibility
tricks.

`cos_flow_bucket_index` references `COS_FLOW_FAIR_BUCKET_MASK`.
Investigation (Codex round-1 #1): the constants
`COS_FLOW_FAIR_BUCKETS` (`types.rs:623`) and
`COS_FLOW_FAIR_BUCKET_MASK` (`types.rs:642`) ALREADY live in
`types.rs`, NOT in `tx.rs`. They size `FlowRrRing`,
`CoSQueueRuntime` arrays, and worker / test queue construction.
Moving them to `flow_hash.rs` would invert ownership and risk a
bad `types -> cos::flow_hash -> types` dependency cycle.

**Decision**: leave constants in `types.rs`. `flow_hash.rs`
imports `COS_FLOW_FAIR_BUCKET_MASK` from `crate::afxdp::types`
when it needs it.

### Visibility model (Phase 1 R1+R2 pattern)

Items in `cos/flow_hash.rs` that need cross-module visibility are
declared `pub(in crate::afxdp)`. `cos/mod.rs` re-exports the
externally-called ones via `pub(super) use`. Per Codex round-1
#3, do NOT re-export the internal helpers (`mix_cos_flow_bucket`,
`exact_cos_flow_bucket` itself is exposed only because tests need
it):

```rust
// cos/mod.rs (extended)
pub(super) mod ecn;
pub(super) mod flow_hash;

pub(super) use ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared,
    ECN_MASK, ECN_NOT_ECT, ECN_ECT_0, ECN_ECT_1, ECN_CE};
pub(super) use flow_hash::{cos_flow_bucket_index,
    cos_flow_hash_seed_from_os, cos_item_flow_key,
    cos_queue_prospective_active_flows};
```

`tx.rs` imports via `super::cos::{...}`. Per Codex round-1 #2,
**`worker.rs` does NOT need updating** — `cos_flow_hash_seed_from_os`
is called from `tx.rs:5830` (the promotion path), not from
`worker.rs`. The earlier plan claim was wrong.

### Test-only imports (Phase 1 Copilot lesson)

Phase 1 caught that `EthernetL3` / `mark_ecn_ce_*` / codepoint
masks were referenced only by `tx::tests` and would trigger
`unused_imports` in non-test builds. Codex round-1 #5 verified
the actual situation for flow_hash:

- **Production paths** (do NOT gate; Codex round-2 #4 added the
  missed call sites):
  - `cos_queue_prospective_active_flows` at `tx.rs:4060, 4074, 4119`
  - `cos_flow_bucket_index` at `tx.rs:4138, 4188, 4305, 4326, 5987`
  - `cos_item_flow_key` at `tx.rs:4283, 4317, 4624` (plus a
    nested call inside `cos_flow_bucket_index` at `tx.rs:5987`)
  - `cos_flow_hash_seed_from_os` at `tx.rs:5830` (promotion)
- **No test-only imports** (Codex round-2 #1): tests reference
  `cos_flow_bucket_index` (production) and
  `cos_flow_hash_seed_from_os` (production) directly. They do
  NOT call `exact_cos_flow_bucket` or `mix_cos_flow_bucket` —
  both stay file-private inside `cos/flow_hash.rs` and need no
  cross-module exposure.

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/flow_hash.rs`: ~150 LOC
  of moved production code (6 functions only — constants stay
  in `types.rs`, see Codex round-1 #1).
- `userspace-dp/src/afxdp/cos/mod.rs`: append `pub(super) mod
  flow_hash;` + extend the `pub(super) use` block. Also update
  the existing module-level comment (Codex round-2 unrelated
  note) to reflect the current phase order: Phase 2 = flow_hash;
  admission is Phase 3.
- `userspace-dp/src/afxdp/tx.rs`: removes ~150 LOC; adds `use
  super::cos::{...}`. Net ~150 LOC smaller. Also update the
  Phase 1 comment at `tx.rs:3546` that says admission moves
  "in Phase 2" — admission is Phase 3 now (Codex round-1
  unrelated note).
- `userspace-dp/src/afxdp/cos/ecn.rs`: update the Phase 1
  comment at `ecn.rs:5` that says admission moves "in Phase 2"
  — admission is Phase 3 now.
- `userspace-dp/src/afxdp/worker.rs`: NO change. Codex round-1
  #2 verified that `cos_flow_hash_seed_from_os` is called from
  `tx.rs:5830`, not from worker.rs.
- The 8 existing tests stay in `tx::tests`; reach moved items
  (`cos_flow_bucket_index`, `cos_flow_hash_seed_from_os`) via
  the new use statements. None of them reference the file-
  private helpers `mix_cos_flow_bucket` or
  `exact_cos_flow_bucket` directly (Codex round-2 #1).

## Tests

8 existing tests must continue to pass:
- `exact_cos_flow_bucket_is_stable_for_same_seed_and_flow`
- `exact_cos_flow_bucket_diverges_across_seeds_for_same_flow`
- `exact_cos_flow_bucket_preserves_legacy_behavior_at_zero_seed`
- `exact_cos_flow_bucket_handles_missing_flow_key`
- `exact_cos_flow_bucket_distribution_at_1024_keeps_collisions_below_budget`
- `exact_cos_flow_bucket_distribution_narrow_inputs_all_v4`
- `exact_cos_flow_bucket_distribution_narrow_inputs_scattered_ports`
- `cos_flow_hash_seed_from_os_draws_nonzero_entropy`

No new tests required — pure structural refactor.

## Acceptance gates

1. `cargo build --release --manifest-path userspace-dp/Cargo.toml`
   clean (no new warnings beyond baseline).
2. `cargo test --release --manifest-path userspace-dp/Cargo.toml`
   ≥ baseline (865 post-#976), 0 failed.
3. Cluster smoke (HARD): no regression. Run on
   `loss:xpf-userspace-fw0/fw1` AND with CoS configured via
   `test/incus/cos-iperf-config.set`.

   | Class       | Port  | Shape | P=12 gate     |
   |-------------|-------|-------|---------------|
   | iperf-c     | 5203  | 25 g  | ≥ 22 Gb/s     |
   | iperf-f     | 5206  | 19 g  | ≥ 17.1 Gb/s   |
   | iperf-e     | 5205  | 16 g  | ≥ 14.4 Gb/s   |
   | iperf-d     | 5204  | 13 g  | ≥ 11.7 Gb/s   |
   | iperf-b     | 5202  | 10 g  | ≥ 9.0 Gb/s    |
   | iperf-a     | 5201  | 1 g   | ≥ 0.9 Gb/s    |
   | best-effort | 5207  | 100 m | ≥ 90 Mb/s     |

   Every P=12 row blocking. iperf-c also keeps P=1 ≥ 6 Gb/s.

   Per-CoS-class smoke specifically validates the flow-hash path
   for the SHARED_EXACT iperf-c queue (multiple TCP flows hashed
   into per-flow buckets for fairness).

4. Failover smoke: 90-s iperf3 -P 12 through fw0, force-reboot
   fw0 at +20s, fw1 takes over <10s, iperf3 ≥ 1 Gb/s avg / ≥ 5 GB.
5. Codex hostile review (plan + impl): AGREE-TO-MERGE.
6. Gemini adversarial review (plan + impl): AGREE-TO-MERGE.
7. Copilot review on PR: all valid findings addressed.

## Risk

**Low.** Pure structural refactor. The 6 moved functions are
leaf-level pure functions (no internal state, no side effects
except the syscalls in `cos_flow_hash_seed_from_os`). Existing
tests have dense coverage — including 3 distribution tests that
verify hash quality at scale.

The only realistic risk is a missed import or visibility tweak,
caught at compile time.

## Out of scope

This PR is Phase 2 of the multi-phase #956 plan. Subsequent
phases (preserved from Phase 1's plan):
- **Phase 3**: `cos/admission.rs`
- **Phase 4**: `cos/token_bucket.rs`
- **Phase 5**: `cos/queue_ops.rs`
- **Phase 6**: `cos/builders.rs`
- **Phase 7**: `cos/queue_service.rs`
- **Phase 8**: `cos/cross_binding.rs`

## Stale-comment cleanup (Codex round-1 unrelated note)

Phase 1 left comments in `tx.rs` and `cos/ecn.rs` saying
admission policy "moves with admission to cos/admission.rs in
Phase 2" — accurate at the time but now wrong (Phase 2 is
flow_hash; admission is Phase 3). This PR's implementation
fixes those comments to reference Phase 3 and adds the
flow-hash equivalent at the relevant locations.
