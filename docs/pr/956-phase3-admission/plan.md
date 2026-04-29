# #956 Phase 3: extract cos/admission.rs from tx.rs

Plan v4 — 2026-04-29. Addresses Codex round-3 (gpt-5.5
local exec), three MINOR findings on top of v3.

Round-3 changelog (v3 → v4):

R3-1. Stale Round-2 wording at the (former) line 180 still
said `tx -> admission` and "9 callers", contradicting the
canonical section. Note rewritten to `admission -> tx` with
the verified 91-occurrence count and a pointer to the
canonical block below.

R3-2. Inconsistency between two re-export wordings: one place
said test-only items get `#[cfg(test)] pub(super) use` while
the canonical section said the plan picks always-on. Picked
always-on uniformly.

R3-3. V-min vacate line reference was sloppy: dequeue resets
MQFQ state at `tx.rs:4058` and vacates the shared V-min slot
at `tx.rs:4069-4077`. Updated the precise line span.

Round-2 changelog (v2 → v3):

Round-2 changelog (v2 → v3):

R2-1. **Visibility model contradiction (round-2 finding 1).**
v2 still carried prose listing `bdp_floor_bytes` and the four
test-referenced constants as "file-private" while the round-1
corrections elsewhere upgraded them to `pub(in crate::afxdp)`.
Visibility model section rewritten as the canonical
classification (4 buckets: file-private / pub-for-prod /
pub-for-tests / stays-in-tx) and earlier prose marked as
superseded.

R2-2. **`account_*` rationale was false (round-2 finding 3).**
v2 said the account_* helpers "exist solely to maintain
flow_bucket_bytes/active_flow_buckets". They actually update
MQFQ head/tail finish-time state (enqueue at tx.rs:4016) and
vacate the V-min slot (dequeue at tx.rs:4058). Rationale
rewritten to acknowledge the three-way coupling
(admission lifecycle + MQFQ ordering + V-min) and justify
keeping them in admission.rs by lockstep-landing cost rather
than asserting they are admission-only.

R2-3. **COS_MIN_BURST_BYTES wording (round-2 finding 2).** v2's
Approach paragraph still implied "all 5 (+2)" constants would
move and described the dependency edge as "tx → admission"
(it's actually admission → tx, since admission imports the
constant from tx). The 9-callers claim was off — actual count
is 91 (`grep -nE COS_MIN_BURST_BYTES` in tx.rs). Approach
paragraph updated, dependency direction corrected, count fixed.

R2-4. **Stale-text site missed (round-2 finding 4).**
`cos/flow_hash.rs:15` still says "Phase 3 will import the
public-to-afxdp helpers". Added to the Stale-text cleanup
list alongside the three sites already noted in v2
(`tx.rs:3543`, `cos/ecn.rs:2`, `cos/mod.rs:1`).

Round-1 changelog (v1 → v2) preserved below for context:

1. `bdp_floor_bytes` is called by tests at `tx.rs:10917, 10998`,
   so it MUST be `pub(in crate::afxdp)`. v1 wrongly classified it
   as file-private.

2. Test-referenced constants (verified by grep): tests use
   `COS_FLOW_FAIR_MIN_SHARE_BYTES` (17×), `COS_ECN_MARK_THRESHOLD_NUM/_DEN`
   (11× each), `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS` (2×). All four
   need `pub(in crate::afxdp)`. `RTT_TARGET_NS` and
   `SHARED_EXACT_BURST_HEADROOM` are not test-referenced and stay
   private.

3. **Big finding**: `COS_MIN_BURST_BYTES` (currently in tx.rs
   private) is referenced inside `cos_flow_aware_buffer_limit`
   (which moves to admission.rs). It has 91 total uses across
   tx.rs (only 1 inside the moving admission code) — moving
   it would force tx.rs to import back from admission for the
   other 90. Decision: leave in tx.rs but bump visibility to
   `pub(in crate::afxdp)`; admission.rs imports via
   `use crate::afxdp::tx::COS_MIN_BURST_BYTES`. Phase 4+ may
   consolidate to a shared location.

4. Stale-text cleanup IS needed in this PR (`tx.rs:3543`,
   `cos/ecn.rs:2`, `cos/mod.rs:1`) — those comments correctly say
   admission moves "in Phase 3" but Phase 3 lands in this PR, so
   they should switch to past tense.

5. The promotion doc block at `tx.rs:5401-5467` is separated from
   `promote_cos_queue_flow_fair` by V-min code. Implementation
   must keep the doc attached to its function during the move.

Plus minor notes: import `crate::session::SessionKey` for
accounting fns, do NOT import `ECN_MASK`/`ECN_NOT_ECT` (not used
by admission code), `account_*` accounting fns stay in admission
(treated as admission-state lifecycle, not Phase 5 queue_ops).

Continues #956 Phase 1 (cos/ecn.rs at PR #976) and Phase 2
(cos/flow_hash.rs at PR #977). Phase 3 extracts the admission /
flow-fair-promotion subsystem.

## Investigation findings (Claude, on commit e08710a9)

The admission subsystem in tx.rs comprises 8 functions and 5+
named constants spread across two regions:

**Constants (lines 3481-3539)**:
| Item | Line | Visibility | Notes |
|---|---|---|---|
| `COS_FLOW_FAIR_MIN_SHARE_BYTES` | 3481 | private | + const_assert at 3488 |
| `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS` | 3497 | private | + const_assert at 3501 |
| `COS_ECN_MARK_THRESHOLD_NUM` | 3532 | private | Phase 1 left here for Phase 3 |
| `COS_ECN_MARK_THRESHOLD_DEN` | 3533 | private | + 2 const_asserts at 3538-9 |

**Functions (lines 3606-5698)**:
| Item | Line | Visibility | Callers |
|---|---|---|---|
| `apply_cos_admission_ecn_policy` | 3606 | private | tx.rs admission entry (~6 sites) |
| `bdp_floor_bytes` | 3881 | private | `cos_queue_flow_share_limit` only |
| `cos_queue_flow_share_limit` | 3887 | private | admission + ECN policy + tests |
| `cos_flow_aware_buffer_limit` | 3980 | private | admission + tests |
| `account_cos_queue_flow_enqueue` | 3996 | private | enqueue path |
| `account_cos_queue_flow_dequeue` | 4046 | private | dequeue path |
| `apply_cos_queue_flow_fair_promotion` | 5391 | private | tx.rs queue-build entry |
| `promote_cos_queue_flow_fair` | 5661 | private | called only by `apply_*_promotion` |

Plus two SHARED_EXACT-specific constants near the share-limit fn:
- `RTT_TARGET_NS` at 3857
- `SHARED_EXACT_BURST_HEADROOM` at 3865

Total move: ~700 LOC of production code (functions + constants +
their dense doc comments).

## Approach

Create `userspace-dp/src/afxdp/cos/admission.rs` with the 8
moved functions and the named constants/asserts that admission
owns. `COS_MIN_BURST_BYTES` STAYS in `tx.rs` with bumped
visibility (it has 91 uses across tx.rs and only 1 in moving
admission code). Items needing cross-module visibility from
admission.rs get `pub(in crate::afxdp)`; `cos/mod.rs` extends
the re-export block.

### Move list (~700 LOC)

Codex round-1 verified call sites and corrected several
visibility decisions:

```rust
// cos/admission.rs
use crate::afxdp::ethernet::*; // if needed by admission policy parse
use crate::afxdp::types::{CoSInterfaceRuntime, CoSPendingTxItem,
    CoSQueueRuntime, WorkerCoSQueueFastPath};
use crate::afxdp::umem::MmapArea;
use crate::session::SessionKey;     // accounting fns reach SessionKey
                                     // (Codex round-1 noted missing
                                     // import)
use super::flow_hash::{cos_flow_bucket_index, cos_flow_hash_seed_from_os};
use super::ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared};
                                     // do NOT import ECN_MASK / ECN_NOT_ECT —
                                     // not used by admission code (Codex r1)
use crate::afxdp::tx::COS_MIN_BURST_BYTES;
                                     // (Codex round-1 #3) — referenced by
                                     // cos_flow_aware_buffer_limit. Leave
                                     // the const in tx.rs because multiple
                                     // tx.rs sites consume it; bump
                                     // visibility to pub(in crate::afxdp)
                                     // so admission can reach. Phase 4+
                                     // may consolidate to types.rs or
                                     // cos/mod.rs.

// Constants used by tests in tx::tests are pub(in crate::afxdp);
// purely-internal ones stay private (Codex round-1 #2).
pub(in crate::afxdp) const COS_FLOW_FAIR_MIN_SHARE_BYTES: u64 = 16 * 1500;
const _: () = assert!(COS_FLOW_FAIR_MIN_SHARE_BYTES >= 16 * 1500);
pub(in crate::afxdp) const COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS: u64 = 5_000_000;
const _: () = assert!(COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS >= 1_000_000);
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_NUM: u64 = 1;
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_DEN: u64 = 3;
const _: () = assert!(COS_ECN_MARK_THRESHOLD_NUM < COS_ECN_MARK_THRESHOLD_DEN);
const _: () = assert!(COS_ECN_MARK_THRESHOLD_DEN > 0);
const RTT_TARGET_NS: u64 = 10_000_000;
const SHARED_EXACT_BURST_HEADROOM: u64 = 2;

// Functions — pub(in crate::afxdp) where production callers OR
// tests reach them directly. bdp_floor_bytes is test-called at
// tx.rs:10917, 10998 (Codex round-1 #1) so it MUST be visible.
pub(in crate::afxdp) fn bdp_floor_bytes(...) -> u64 { ... }
pub(in crate::afxdp) fn cos_queue_flow_share_limit(...) -> u64 { ... }
pub(in crate::afxdp) fn cos_flow_aware_buffer_limit(...) -> u64 { ... }
pub(in crate::afxdp) fn account_cos_queue_flow_enqueue(...) { ... }
pub(in crate::afxdp) fn account_cos_queue_flow_dequeue(...) { ... }
pub(in crate::afxdp) fn apply_cos_admission_ecn_policy(...) -> bool { ... }
pub(in crate::afxdp) fn apply_cos_queue_flow_fair_promotion(...) { ... }
fn promote_cos_queue_flow_fair(...) { ... }
```

**Notes**:
- `tx.rs` declares `pub(in crate::afxdp) const COS_MIN_BURST_BYTES`
  (was private). admission.rs imports it via
  `use crate::afxdp::tx::COS_MIN_BURST_BYTES`, so the dependency
  edge is `admission -> tx`. The const has 91 occurrences in
  `tx.rs` itself (only 1 in moving admission code), so leaving it
  there until a later cleanup is the smaller risk. See the
  canonical block under "STAYS in `tx.rs`" below for the full
  rationale.

- The promotion-rationale doc block currently at `tx.rs:5401-5467`
  (Codex round-1 unrelated note) is separated from
  `promote_cos_queue_flow_fair` by intervening V-min code. The
  implementation must ensure it moves with `promote_cos_queue_flow_fair`
  to admission.rs so the documentation stays attached to the function
  it documents.

- `account_cos_queue_flow_enqueue`/`_dequeue` are queue-state
  lifecycle helpers; Codex round-1 flagged them as arguably
  belonging to Phase 5 (`cos/queue_ops.rs`), and round-2 #2
  corrected my v2 rationale (they don't ONLY maintain
  `flow_bucket_bytes`/`active_flow_buckets`):
  - `enqueue` updates MQFQ head/tail finish-time state
    at `tx.rs:4016`.
  - `dequeue` resets that state at `tx.rs:4058` and vacates the
    shared V-min slot at `tx.rs:4069-4077`.

  **Decision**: keep in admission.rs in Phase 3, with explicit
  acknowledgment that `cos/admission.rs` ends up coupling three
  responsibilities: admission lifecycle, MQFQ ordering bookkeeping,
  and V-min slot participation. The alternative (defer to Phase 5)
  has higher coordination cost — Phase 3's admission gates
  (`cos_queue_flow_share_limit`, `apply_cos_admission_ecn_policy`)
  consume the same `flow_bucket_bytes` / `active_flow_buckets`
  fields these helpers maintain, so splitting them across two
  PRs forces both to land in lockstep or temporarily import
  back. Phase 5 can revisit when queue_ops has a cleaner
  boundary; the helpers will likely move to wherever MQFQ /
  V-min state ends up living.

`cos/mod.rs` re-exports the production-callable items via
`pub(super) use`. Test-referenced items (`bdp_floor_bytes` and
the four test-touched constants) are simply
`pub(in crate::afxdp)` and re-exported always-on — see the
canonical Visibility model section below for the rationale
for picking always-on over `#[cfg(test)]`-gated re-exports.
Tests stay in `tx::tests` — same Phase 1+2 pattern.

### Visibility model (corrected per Codex round-2 #1)

This is the canonical visibility classification. Earlier prose
in this plan got the picture wrong; treat this section as the
source of truth.

- **File-private inside `cos/admission.rs`** (no callers outside
  the module after the move):
  - `promote_cos_queue_flow_fair` (only called by
    `apply_cos_queue_flow_fair_promotion`)
  - `RTT_TARGET_NS`, `SHARED_EXACT_BURST_HEADROOM` (zero test
    references; verified by grep)

- **`pub(in crate::afxdp)` (re-exported from `cos/mod.rs` for
  production callers)**:
  - `cos_queue_flow_share_limit`
  - `cos_flow_aware_buffer_limit`
  - `account_cos_queue_flow_enqueue`
  - `account_cos_queue_flow_dequeue`
  - `apply_cos_admission_ecn_policy`
  - `apply_cos_queue_flow_fair_promotion`

- **`pub(in crate::afxdp)` (test-referenced; either always-on or
  cfg-gated re-exports are both acceptable, plan implementation
  picks always-on for simplicity)**:
  - `bdp_floor_bytes` (called by tests at `tx.rs:10917, 10998`)
  - `COS_FLOW_FAIR_MIN_SHARE_BYTES` (17 test references)
  - `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS` (2 test references)
  - `COS_ECN_MARK_THRESHOLD_NUM`, `COS_ECN_MARK_THRESHOLD_DEN`
    (11 test references each)

- **STAYS in `tx.rs` with bumped `pub(in crate::afxdp)` visibility**:
  - `COS_MIN_BURST_BYTES` — 91 uses across tx.rs make moving it
    impractical. admission.rs imports via
    `use crate::afxdp::tx::COS_MIN_BURST_BYTES`. The Rust
    dependency edge is `admission -> tx` (admission imports from
    tx); Phase 4+ may consolidate to a shared location to remove
    even that one back-reference.

Tests in `tx::tests` reach the moved items via the re-exports.
Investigation phase 1 of implementation will verify each
production call site and grep for any test-only references that
may need additional cfg-gated imports (Phase 1 lesson).

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/admission.rs`: ~700 LOC of
  moved production code.
- `userspace-dp/src/afxdp/cos/mod.rs`: append `pub(super) mod
  admission;` + extend `pub(super) use admission::{...}` block.
- `userspace-dp/src/afxdp/tx.rs`: removes ~700 LOC; adds `use
  super::cos::{...}` for the 6 cross-module items. Net ~700
  LOC smaller.
- 0 new tests required — pure structural refactor. ~30 admission-
  related tests stay in `tx::tests`.

### Phase-1+2 stale-text cleanup

Codex round-1 #4 caught that prior phases' comments will be
factually stale once Phase 3 ships. As of PR #977 those comments
correctly say admission moves "in Phase 3" — but in this PR
admission has already moved, so the comments need to be updated
again to past tense (or removed).

Items to fix in this PR's implementation:
- `tx.rs:3543` — the `use super::cos::{...}` block comment
  currently says "they move with admission to cos/admission.rs in
  **Phase 3**". After Phase 3 ships, this should read:
  "Admission policy was extracted to cos/admission.rs in Phase 3
  (PR #...)." Fix the wording in this PR's tx.rs edit.
- `cos/ecn.rs:2` — Phase 1 docstring's reference to admission moving
  in Phase 3. Same past-tense fix.
- `cos/mod.rs:1` — phase-order header. Update to call out the
  current state (Phase 3 = admission; Phase 4+ are still future).
- `cos/flow_hash.rs:15` — Phase 2 docstring still says "Phase 3
  will import the public-to-afxdp helpers". Update to past tense
  once Phase 3 lands (Codex round-2 #4).

## Tests

~30 admission-related tests at `tx.rs:10664+` must continue to pass:
- `flow_fair_exact_queue_limits_dominant_flow_share`
- `cos_flow_aware_buffer_limit_respects_non_flow_fair_queues`
- `flow_share_limit_shared_exact_*` (5 tests)
- `cos_queue_flow_share_limit_never_drops_below_fast_retransmit_floor`
- `cos_flow_aware_buffer_limit_preserves_non_flow_fair_path_after_clamp`
- `flow_fair_queue_pops_in_virtual_finish_order_local`
- ~15 `admission_ecn_*` tests
- promotion / share-cap / accounting tests

No new tests required — pure structural refactor.

## Acceptance gates

The repo has no root `Cargo.toml`; cargo commands must run with
`--manifest-path userspace-dp/Cargo.toml`.

1. `cargo build --release --manifest-path userspace-dp/Cargo.toml`
   clean (no new warnings beyond baseline).
2. `cargo test --release --manifest-path userspace-dp/Cargo.toml`
   ≥ baseline (865 post-#977), 0 failed.
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

   Per-CoS-class smoke EXERCISES the moved code (admission
   policy + flow-share gates fire on every iperf3 packet that
   hits a flow-fair queue).

4. Failover smoke: 90-s iperf3 -P 12 through fw0, force-reboot
   fw0 at +20s, fw1 takes over <10s, iperf3 ≥ 1 Gb/s avg / ≥ 5 GB.
5. Codex hostile review (plan + impl): AGREE-TO-MERGE.
6. Gemini adversarial (plan + impl): AGREE-TO-MERGE (or skip if
   daemon unavailable, per Phase 2 precedent).
7. Copilot review on PR: all valid findings addressed.

## Risk

**Medium.** Larger move than Phases 1+2 (~700 LOC vs ~210/~150)
and admission is the hottest CoS path — every iperf3 packet on a
flow-fair queue routes through it. Risks:

- Hidden visibility leak (a function pulled into admission.rs
  references a tx.rs-private item that needs widening).
- Stale-comment / phase-numbering churn (Phase 1+2 each generated
  Copilot findings here; mitigated by Phase 2's already-fixed
  references).

The core design is the same successful pattern Phases 1+2
validated: pub(in crate::afxdp) source items + pub(super) use
re-exports + tests stay in place. Existing test coverage on
admission paths is dense (~30 tests).

## Out of scope

- Phase 4: `cos/token_bucket.rs`
- Phase 5: `cos/queue_ops.rs`
- Phase 6: `cos/builders.rs`
- Phase 7: `cos/queue_service.rs`
- Phase 8: `cos/cross_binding.rs`
