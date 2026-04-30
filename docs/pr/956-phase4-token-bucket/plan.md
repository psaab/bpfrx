# #956 Phase 4: extract cos/token_bucket.rs from tx.rs

Plan v4 — 2026-04-29. Continues #956 (cos/ submodule decomposition).
Phase 1 (cos/ecn.rs) shipped at PR #976; Phase 2 (cos/flow_hash.rs)
at PR #977; Phase 3 (cos/admission.rs) at PR #978. Phase 4 = the
token-bucket lease/refill subsystem.

Round-3 changelog (v3 → v4): Codex round-3 returned PLAN-NEEDS-MAJOR
with 1 substantive issue + 5 minor + 2 nits. All 8 are fixed in v4:

- #1 (MAJOR): tx.rs is NOT a caller of `release_all_cos_root_leases`
  or `release_all_cos_queue_leases` — those callers all live in
  worker.rs. Plan v3 told tx.rs to import all 7 helpers, which
  would trip a Phase-4-introduced unused-import warning. v4 narrows
  the tx.rs import block to the 5 fns it actually calls plus
  `COS_MIN_BURST_BYTES`, and moves the 2 release helpers into the
  worker.rs explicit-import line.
- #2 (minor): existing definitions at tx.rs:3511, 3533, 3582 have
  no `#[inline]` attribute — the previous claim that the move
  must "preserve `#[inline]`" was wrong. v4 calls the move
  byte-identical and notes that any post-merge regression is a
  follow-up rather than a Phase-4 blocker.
- #3 (minor): stale-text cleanup must include `tx.rs:3479-3491`
  (the cos/ submodule import-header still says "Phase 3 (this PR)"
  and lists Phase-1+2+3 imports without token-bucket helpers).
- #4 (minor): cos/mod.rs cleanup is lines 1-7, not 1-5 (line 6 also
  references `docs/pr/956-phase3-admission/plan.md` as "the current
  phase").
- #5 (minor): test-invariant wording — root-lease floor is
  `lease_bytes().max(tx_frame_capacity())`, not
  `tx_frame_capacity().max(COS_MIN_BURST_BYTES)`. Updated.
- #6 (nit): COS_MIN_BURST_BYTES non-test list extended to include
  tx.rs:5237, 5264, 5269 (added in R1-3 follow-up; v3 list was
  consistent with the table but the Round-1 changelog sentence
  had only `1832, 5237, plus 7 inside top-up helpers`).
- #7 (nit): worker.rs caller-line wording in the Round-2 changelog
  updated to match the table — root at 746/1613/1911, queue at
  747/755/1614/1912.
- #8 (nit): "tests call 2 of them" is misleading — direct
  tx::tests call sites are 2 fns, but #[cfg(test)]-gated call
  sites cover 3 fns. Tests section corrected.

Round-2 changelog (v2 → v3): addresses 5 Codex round-2 wording /
line-number fixes (move set + visibility unchanged):
- R1-1 follow-up (still wrong in v2): the Risk-section claim
  that `refill_cos_tokens` is called "3 times per enqueue cycle
  in production" was still naming tx.rs:1651 as a production
  site. tx.rs:1651 is inside the `#[cfg(test)]` legacy selector
  starting at tx.rs:1625 — corrected.
- R1-3 follow-up (still wrong in v2): non-test
  `COS_MIN_BURST_BYTES` consumer set was missing tx.rs:5264 and
  tx.rs:5269 (`build_cos_interface_runtime` queue construction).
  Added.
- N1 (new): `maybe_top_up_cos_root_lease` test caller is
  tx.rs:6824, but tx.rs:6380 is `mod tests {`, so 6824 is a
  test-module call. Re-labelled.
- N2 (new): `release_all_cos_queue_leases` caller line numbers
  in worker.rs were off by one — root calls at 746/1613, queue
  calls at 747/1614/1912. Corrected to 747/755/1614/1912.
- N3 (new): admission.rs header-note text in the Phase-1+2+3
  cleanup section had to be aligned with R1-5 (use the
  cos/mod.rs re-export, not a direct token_bucket path).

Round-1 changelog (v1 → v2): addresses 4 Codex round-1 findings,
all wording-level (move list and visibility unchanged):
- R1-1: corrected production-vs-test caller counts (some cited
  call sites are inside `#[cfg(test)]` blocks at tx.rs:1626+).
- R1-2: `tx_frame_capacity()` lives in parent `afxdp.rs:273`,
  not tx.rs. Dependency direction is `cos/token_bucket -> afxdp`,
  not `cos/token_bucket -> tx`.
- R1-3: clarified COS_MIN_BURST_BYTES non-test consumer set
  inside tx.rs (mostly tests after line 6380; production sites
  at 1832, 5237, plus 7 inside the moving top-up helpers).
- R1-4: worker.rs gets the release helpers via a module-level
  `use super::*` glob at worker.rs:1, with `afxdp.rs:149`
  glob-importing tx — not via `super::tx::*`. The plan's fix
  (explicit `use super::cos::{...}` import in worker.rs) is
  still right; rationale wording corrected.
- R1-5 (new preference): admission.rs should import
  COS_MIN_BURST_BYTES via `use super::COS_MIN_BURST_BYTES`
  (cos/mod.rs re-export) rather than reaching directly into
  `super::token_bucket::COS_MIN_BURST_BYTES`. Avoids leaking
  the cos/* internal file layout.

## Goal

Move 7 token-bucket helpers + 1 named constant (~250-300 LOC of
production code) into `userspace-dp/src/afxdp/cos/token_bucket.rs`.
Resolve the Phase 3 forward-debt where admission.rs imports
`COS_MIN_BURST_BYTES` from tx.rs (admission → tx edge); after Phase 4
both admission.rs and tx.rs import the constant from cos/, so the
back-reference is gone.

## Investigation findings (Claude, on commit 1cb07118)

**Functions** (all currently file-private or `pub(super)` in tx.rs):

| Item | Line | Visibility | Production callers | Test callers |
|---|---|---|---|---|
| `maybe_top_up_cos_root_lease` | 3511 | private | tx.rs:1515 | tx.rs:6824 (inside `mod tests {` at tx.rs:6380) |
| `maybe_top_up_cos_queue_lease` | 3533 | private | tx.rs:1733 | tx.rs:1643 (inside `#[cfg(test)] fn` at tx.rs:1625-1626), tx.rs:6873 (inside test module) |
| `refill_cos_tokens` | 3582 | private | tx.rs:1829 (`select_nonexact_cos_guarantee_batch` at tx.rs:1814 — non-test) + internal call from `maybe_top_up_cos_queue_lease` body at tx.rs:3558 | tx.rs:1651 (inside `#[cfg(test)] fn` at tx.rs:1625-1626) |
| `cos_refill_ns_until` | 3625 | private | tx.rs:4257, 4259 | none |
| `release_cos_root_lease` | 5524 | private | tx.rs:5509 (refresh_cos_interface_activity), tx.rs:5545 (release_all_cos_root_leases) | none |
| `release_all_cos_root_leases` | 5542 | `pub(super)` | worker.rs:746, 1613, 1911 | none |
| `release_all_cos_queue_leases` | 5549 | `pub(super)` | worker.rs:747, 755, 1614, 1912 | none |

Production-vs-test note (Codex round-1 R1-1): tx.rs:1626 starts a
`#[cfg(test)]` legacy-selector block, so call sites at tx.rs:1643,
1651 are test-only. The move set is unchanged — every fn still has
at least one production caller — but the visibility justification
relies on the production sites listed above, not the test ones.

**Constant**:

| Item | Line | Visibility | Use count |
|---|---|---|---|
| `COS_MIN_BURST_BYTES` | 3472 | `pub(in crate::afxdp)` | tx.rs: 91 total (most are tests below tx.rs:6380); non-test consumers: tx.rs:1832 (`refill_cos_tokens` body in `select_nonexact_cos_guarantee_batch`), 7 sites at tx.rs:3522/3530/3545/3553/3561/3570/3578 inside the moving top-up helpers, tx.rs:5237/5264/5269 (runtime construction in `build_cos_interface_runtime`). cos/admission.rs: 3 (admission gates). |

`COS_MIN_BURST_BYTES` is the burst-cap argument applied uniformly across
every `maybe_top_up_*` and `refill_cos_tokens` call. It logically belongs
with the token-bucket module that consumes it.

`tx_frame_capacity()` is referenced by `maybe_top_up_*` to floor lease
size — Codex round-1 R1-2 caught that this helper lives in the parent
module at `afxdp.rs:273`, not `tx.rs`. So the dependency direction
after the move is `cos/token_bucket -> afxdp::tx_frame_capacity`,
which is a parent-module reference (not a sibling `tx` import). The
moved file should `use crate::afxdp::tx_frame_capacity;` directly.

## Approach

Create `userspace-dp/src/afxdp/cos/token_bucket.rs` with all 7 functions
+ the `COS_MIN_BURST_BYTES` constant.

Visibility:
- `pub(in crate::afxdp)`:
  - All 7 functions (each has at least one cross-module caller in
    tx.rs or worker.rs; tests call 2 of them).
  - `COS_MIN_BURST_BYTES` (91 tx.rs sites + 3 admission.rs sites).
- File-private: nothing (token-bucket is a thin layer with no
  internal-only state helpers).

`cos/mod.rs` adds:
```rust
pub(super) mod token_bucket;
pub(super) use token_bucket::{
    cos_refill_ns_until,
    maybe_top_up_cos_queue_lease,
    maybe_top_up_cos_root_lease,
    refill_cos_tokens,
    release_all_cos_queue_leases,
    release_all_cos_root_leases,
    release_cos_root_lease,
    COS_MIN_BURST_BYTES,
};
```

No `#[cfg(test)]` re-export split needed: every item has at least one
production caller across tx.rs / worker.rs / cos/admission.rs, so the
non-test build will use them all.

tx.rs:
- Remove the 7 fn definitions and the `COS_MIN_BURST_BYTES` const.
- Update the existing `use super::cos::{...}` block to add ONLY the 5
  helpers tx.rs actually calls in non-test code plus the constant
  (Codex round-3 #1 — tx.rs is NOT a caller of either
  `release_all_cos_*_leases`; those callers all live in worker.rs):
  ```rust
  use super::cos::{
      cos_refill_ns_until, maybe_top_up_cos_queue_lease,
      maybe_top_up_cos_root_lease, refill_cos_tokens,
      release_cos_root_lease, COS_MIN_BURST_BYTES,
  };
  ```
  Adding the two `release_all_*` helpers to tx.rs's import block
  would trip a Phase-4-introduced unused-import warning, just like
  Phase 3 commit 4276eac0 had to clean up.

worker.rs:
- `release_all_cos_*_leases` are called from worker.rs:746, 747, 755,
  1613, 1614, 1911, 1912. Today they're picked up via worker.rs:1's
  `use super::*` glob (Codex round-1 R1-4). After the move worker.rs
  needs an explicit `use super::cos::{release_all_cos_root_leases,
  release_all_cos_queue_leases};` so the symbol resolution is
  unambiguous.

cos/admission.rs:
- Replace `use crate::afxdp::tx::COS_MIN_BURST_BYTES` with
  `use super::COS_MIN_BURST_BYTES` (resolves to the cos/mod.rs
  re-export rather than the file-internal token_bucket path).
  Codex round-1 R1-5 prefers this form so admission.rs doesn't
  encode the cos/* internal file layout. Eliminates the
  admission → tx back-reference noted as forward-debt in Phase 3.

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/token_bucket.rs`: ~280 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: add module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -280 LOC; widen the `use
  super::cos::{...}` block.
- `userspace-dp/src/afxdp/worker.rs`: add cos:: import for the 2
  release helpers.
- `userspace-dp/src/afxdp/cos/admission.rs`: re-route
  COS_MIN_BURST_BYTES import path; update header note.

## Tests

No new tests required — pure structural refactor. Existing tests in
`tx::tests` exercise:
- `maybe_top_up_cos_root_lease` at tx.rs:6824 (root-lease behaviour
  pinned by the `lease_bytes().max(tx_frame_capacity())` floor — the
  invariant that lease size never falls below a max-sized frame; the
  test comment at tx.rs:6794 names this exact form). Codex round-3 #5
  caught the previous wording that wrote it as
  `tx_frame_capacity().max(COS_MIN_BURST_BYTES)` — wrong direction.
- `maybe_top_up_cos_queue_lease` at tx.rs:6873 (queue-lease grant
  vs queue.tokens prerequisite)
- Three additional fns have test-only call sites that the refactor
  must keep reachable: `refill_cos_tokens` at tx.rs:1651,
  `maybe_top_up_cos_queue_lease` at tx.rs:1643, and
  `maybe_top_up_cos_root_lease` at tx.rs:6824. (Codex round-3 #8
  flagged the earlier "tests call 2" wording — direct
  `tx::tests` calls happen to two helpers but #[cfg(test)] -gated
  call sites cover three.)

Both tests will continue to compile after the move because both fns
become `pub(in crate::afxdp)` and are reachable via
`super::cos::{maybe_top_up_*}` re-exports — same Phase 1+2+3 pattern.

## Phase-1+2+3 stale-text cleanup

- `tx.rs:3466-3472` — the `COS_MIN_BURST_BYTES` Phase-3 forward-debt
  comment block becomes false once the constant moves to
  cos/token_bucket.rs. Remove the comment block (the constant is gone
  from tx.rs).
- `tx.rs:3479-3491` — the cos/ submodule import-header (Codex round-3
  #3). Currently says "Phase 3 (this PR)" and the `use super::cos::{...}`
  block lists only Phase-1+2+3 items. Update header text to
  "Phase 4 (this PR)" plus drop the now-stale Phase-3-tense wording,
  and refresh the imported-items list.
- `cos/admission.rs:24-27` — header note about COS_MIN_BURST_BYTES
  staying in tx.rs needs to switch to past-tense (Codex round-2 N3:
  the wording must align with R1-5's chosen import path). Replace
  with: "Phase 4 moved `COS_MIN_BURST_BYTES` into cos/token_bucket.rs.
  This module imports it via `super::COS_MIN_BURST_BYTES` (resolves
  to the cos/mod.rs re-export), not via direct
  `super::token_bucket::COS_MIN_BURST_BYTES` — that keeps admission
  agnostic to the cos/* internal file layout."
- `cos/mod.rs:1-7` — phase-order header (Codex round-3 #4: line 6
  also references `docs/pr/956-phase3-admission/plan.md` as "the
  current phase"). Update lines 1-7 to call out Phase 4 as the
  current state.

## Risk

**Low-medium.** Smaller move than Phases 2+3 (~280 vs ~600 LOC) but
touches the hot-path enqueue/refill loop — every TX byte goes through
`maybe_top_up_cos_*` and `refill_cos_tokens`. Risks:

- **Hot-path inline cost.** `refill_cos_tokens` non-test call sites are
  tx.rs:1829 (in `select_nonexact_cos_guarantee_batch`) and the
  internal call from `maybe_top_up_cos_queue_lease`'s body at
  tx.rs:3558 (which itself moves to token_bucket.rs and stays
  intra-file). The third syntactic site at tx.rs:1651 is inside a
  `#[cfg(test)]` legacy-selector fn, so it's not part of the
  production hot path. **Implementation note** (Codex round-3 #2):
  the source definitions at tx.rs:3511, 3533, 3582 do NOT currently
  carry an `#[inline]` attribute — they rely on the compiler's
  cross-module inlining via `pub(in crate::afxdp)` visibility, the
  same pattern Phases 2+3 validated. The implementation should
  reproduce them unchanged (no `#[inline]` added or removed). If a
  post-merge perf regression points at a missing inline, that's a
  follow-up rather than a Phase-4-blocking decision.
- **worker.rs import migration.** worker.rs picks up the release
  helpers via a module-level `use super::*` glob at worker.rs:1
  (with afxdp.rs:149 glob-importing tx — Codex round-1 R1-4
  correction). After the move worker.rs needs an explicit
  `use super::cos::{release_all_cos_root_leases,
  release_all_cos_queue_leases};`.
- **Stale-comment churn.** Phase 3 added a comment block flagging
  the forward-debt; that comment becomes false in this PR.

The core design is the same successful pattern Phases 1-3 validated:
`pub(in crate::afxdp)` source items + `pub(super) use` re-exports +
tests stay in `tx::tests`.

## Acceptance criteria

- `cargo build --bins` clean (no Phase-4 unused-import warnings).
- `cargo test --bins` passes the same 865/0/2 baseline as Phase 3
  (the 2 ignored micro-benchmarks are pre-existing).
- `make loss-cluster-deploy` rolls successfully; `apply-cos-config.sh`
  applies the per-class iperf3 config.
- Per-CoS-class iperf3 smoke (memory: refactor PRs must validate every
  configured class):
  - port 5201 / iperf-a / 1G shaper: ≥ 0.85 Gbps, 0 retrans
  - port 5202 / iperf-b / 10G shaper: ≥ 8 Gbps, 0 retrans
  - port 5203 / iperf-c / 25G shaper: ≥ 10 Gbps, ≤ 1k retrans
  - port 5204 / iperf-d / 13G shaper: ≥ 10 Gbps
  - port 5205 / iperf-e / 16G shaper: ≥ 12 Gbps
  - port 5206 / iperf-f / 19G shaper: ≥ 12 Gbps
  - port 5207 / best-effort / 100M shaper: ≥ 0.07 Gbps
- Failover smoke (RG1 cycled twice): zero 0-bps SUM intervals;
  ≥ 95% of intervals at ≥ 3 Gbps.
- Plan + impl signed off by both Codex (`gpt-5.5` xhigh) and Gemini.
