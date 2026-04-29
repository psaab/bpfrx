# #956 Phase 1: extract cos/ecn.rs from tx.rs (establish the cos/ submodule)

Plan v6 — 2026-04-29. Addresses Codex round-5 (task-mokc6mah-pcctmc):
three minor inventory cleanups.

α. Files-touched section duplicated the `cos/mod.rs` entry — kept
   only the fuller one with the `pub(super) use` re-export list.

β. Files-touched section's `afxdp.rs` bullet still said `pub(super)
   mod cos;` — contradicted the corrected actionable section.
   Updated to `#[path = "afxdp/cos/mod.rs"] mod cos;`.

γ. v4 estimated test_fixtures.rs at ~860 LOC; actual at this commit
   is 663 LOC. Corrected.

v5 — Addresses Codex round-4 (task-mokc037q-sjefmd):
three stale-text findings.

A. Module declaration style: v4 said `pub(super) mod cos;` and
   claimed to match `pub(super) mod tx;` — but the existing local
   style is `#[path = "afxdp/tx.rs"] mod tx;` (private, explicit
   path). Now matches: `#[path = "afxdp/cos/mod.rs"] mod cos;`.

B. Stale fixture-history at the round-1 changelog still said the
   plan "keeps fixtures in `tx::tests`" — superseded by v2+. Now
   says fixtures move to the existing `afxdp::test_fixtures`
   module (with a back-reference to the corrected actionable
   section).

C. v3-changelog summary said "8-phase plan ends at builders" —
   wrong, builders is Phase 6, queue_service Phase 7, cross_binding
   Phase 8. Corrected.

v4 — Addresses Codex round-3 (task-mokbrce8-p76zar):
three findings.

i. ECN codepoint masks (`ECN_MASK`, `ECN_NOT_ECT`, `ECN_ECT_0`,
   `ECN_ECT_1`, `ECN_CE`) cannot stay file-private to `cos::ecn`
   because 15 admission tests in `tx::tests` use them directly.
   Now `pub(in crate::afxdp)` and re-exported from `cos/mod.rs`.

ii. Stale text in the Tests section still said fixtures "stay in
    `tx::tests`" — contradicted the corrected Test-fixtures
    section. Now consistent: fixtures move to the existing
    `afxdp::test_fixtures` module.

iii. `test_fixtures.rs` already EXISTS in the repo (declared at
    `afxdp.rs:93-94` via `#[path = ...]` form). v3 said NEW;
    v4 says EXTEND, and notes not to add a duplicate `mod`
    declaration.

v3 — Addresses Codex round-2 (task-mokbj8l7-x8capj):
four blocking findings + one stale-text fix.

a. Visibility re-export model corrected. `pub(super) use ecn::{...}`
   in `cos/mod.rs` does NOT widen visibility past what the source
   items permit. Items must be `pub(in crate::afxdp)` in `ecn.rs`
   AND re-exported with `pub(super) use` in `cos/mod.rs`. Plan now
   shows both halves.

b. Test-fixture sharing via `tx::tests` was broken: `pub(super) fn`
   inside `tx::tests` makes it visible to `tx`, not to a sibling
   `cos::ecn::tests`. And `mod tests` is private. v3 introduces a
   new `#[cfg(test)] mod test_fixtures;` at `afxdp/` (sibling of
   `tx.rs`/`cos/`) with `pub(in crate::afxdp)` helpers. Both
   `tx::tests` and `cos::ecn::tests` import via
   `crate::afxdp::test_fixtures::*`.

c. Stale Risk-section prose said the const_assert invariants "must
   move with the constants" — flipped from v1, but the surrounding
   plan now says they STAY in tx.rs for Phase 1 and only move with
   admission later. Risk text now consistent.

d. Phase order: queue_service depends on builders
   (`prime_cos_root_for_service`, `build_cos_batch_from_queue`,
   `apply_cos_send_result`, `apply_cos_prepared_result`). v2 had
   builders in Phase 8 — would leave queue_service depending back
   on `tx.rs`. Swapped: Phase 6 = builders, Phase 7 = queue_service.

e. Stale "+ 13 tests" residue in Files-touched section — replaced
   with 15.

v2 — Addresses Codex round-1 (task-mokb9f8h-mwlbl8):
five blocking findings, all fixed.

1. Visibility: `pub(super)` from `afxdp::cos::ecn` only exposes to
   `afxdp::cos`, not back up to `afxdp::tx`. Plan now uses
   `pub(super) use ecn::{...}` re-export from `cos/mod.rs` so the
   parent `afxdp` module can reach the symbols.

2. Constants belong with policy, not the marker. Threshold
   `COS_ECN_MARK_THRESHOLD_*` constants STAY in tx.rs alongside
   `apply_cos_admission_ecn_policy` (which also stays in Phase 1).
   They move with admission to `cos/admission.rs` in Phase 2 — the
   correct dependency direction.

3. Test count was 13; actual is 15 — corrected (added
   `maybe_mark_ecn_ce_dispatches_by_addr_family`,
   `_handles_single_vlan_tagged_frame`,
   `_rejects_unknown_ethertype`).

4. Test fixtures (`build_ipv4_test_packet` etc.) are shared between
   moving marker tests AND staying admission tests. v2 superseded
   the v1 plan and now moves the shared fixtures out of `tx::tests`
   into the existing `afxdp::test_fixtures` module (see the
   actionable Test fixtures section in v3+ for the corrected
   approach).

5. Path import: `super::ethernet` is wrong from inside `cos::ecn`.
   Use `crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN}` (or
   the equivalent `super::super::ethernet::{...}`). Plan picks the
   fully-qualified form for stability.

Plus future-phase ordering corrected:
- `flow_hash` now precedes admission (admission's flow-fair
  promotion calls `cos_flow_hash_seed_from_os`).
- Added explicit `queue_ops` phase before `queue_service` — queue
  service depends on `cos_queue_push/pop` and the `CoSBatch` enum
  having a clear home.

Now an 8-phase plan (Phase 1 = ECN; Phase 6 = builders; Phase 7 =
queue_service; Phase 8 = cross_binding).

## Investigation findings (Claude, on commit 76384e9a)

`userspace-dp/src/afxdp/tx.rs` is 18,008 lines with 153 functions.
The issue ("#956: Deconstruct tx.rs God File into CoS Subsystems")
asks for it to be broken into a dedicated `cos/` module. That is too
large for one PR — moving 5K–10K LOC at once is high coordination
risk and review fatigue. This PR is **Phase 1 of a multi-PR plan**.

The major subsystems currently colocated in tx.rs:

1. **XSK ring management** (descriptor pop/push, completion reap,
   kick threshold) — pure XDP socket plumbing.
2. **CoS pending-tx draining** (`drain_pending_tx`,
   `drain_pending_tx_local_owner`, ingestion paths).
3. **Cross-binding redirect** (`redirect_local_cos_request_to_owner`,
   `redirect_prepared_cos_request_to_owner`, MPSC inbox handling).
4. **CoS queue service** (`select_cos_guarantee_batch`,
   `select_cos_surplus_batch`, `service_exact_*`, MQFQ virtual-time
   selection).
5. **ECN marking + parsing** (`maybe_mark_ecn_ce`,
   `maybe_mark_ecn_ce_prepared`, `mark_ecn_ce_ipv4`,
   `mark_ecn_ce_ipv6`, `ethernet_l3` + `EthernetL3` enum).
6. **CoS admission policy** (`apply_cos_admission_ecn_policy`,
   `apply_cos_queue_flow_fair_promotion`).
7. **Token-bucket / timer wheel** (`refill_cos_tokens`,
   `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
   `maybe_top_up_cos_root_lease`, etc.).
8. **Flow-bucket hashing + share limits** (`mix_cos_flow_bucket`,
   `exact_cos_flow_bucket`, `cos_queue_flow_share_limit`,
   `cos_flow_aware_buffer_limit`, account_*).
9. **CoS queue ops** (`cos_queue_push_*`, `cos_queue_pop_*`,
   `cos_queue_len`, `cos_queue_min_finish_bucket`).
10. **Builders + appliers** (`build_cos_interface_runtime`,
    `apply_cos_send_result`, `apply_cos_prepared_result`).

### Phase 1 scope (this PR): extract `cos/ecn.rs`

ECN marking is the most self-contained byte-mutation subsystem in
the file. It has:
- A small bounded surface: 4 mutating functions
  (`maybe_mark_ecn_ce`, `maybe_mark_ecn_ce_prepared`,
  `mark_ecn_ce_ipv4`, `mark_ecn_ce_ipv6`) plus the `ethernet_l3`
  parser + `EthernetL3` enum.
- 5 ECN codepoint masks (`ECN_MASK`, `ECN_NOT_ECT`,
  `ECN_ECT_0`, `ECN_ECT_1`, `ECN_CE`) — these belong with the
  byte mutator since they describe IP TOS / IPv6 tclass low bits.
- **15 existing unit tests** (Codex round-1 #3 corrected my count
  of 13): `mark_ecn_ce_ipv4_*` (5), `mark_ecn_ce_ipv6_*` (5),
  `maybe_mark_ecn_ce_dispatches_by_addr_family`,
  `maybe_mark_ecn_ce_handles_single_vlan_tagged_frame`,
  `maybe_mark_ecn_ce_rejects_unknown_ethertype`, plus 2
  `ethernet_l3_*` tests (QinQ rejection + tagged-non-IP rejection).
- Two main call sites in tx.rs: the in-tx-request marker path and
  the prepared-UMEM marker path (both inside or near
  `apply_cos_admission_ecn_policy`).

It does NOT depend on other CoS subsystems (token bucket, queue ops,
builders) — only on `crate::afxdp::ethernet::{ETH_HDR_LEN,
VLAN_TAG_LEN}`, `TxRequest`, `PreparedTxRequest`, and `MmapArea`.
Self-contained for the byte-mutation surface.

**What stays in tx.rs (Codex round-1 #2)**:

The threshold constants `COS_ECN_MARK_THRESHOLD_NUM` and
`COS_ECN_MARK_THRESHOLD_DEN` (plus their two `const _: () = assert!`
compile-time invariants) belong with `apply_cos_admission_ecn_policy`,
not with the byte mutator. They are admission-policy tuning knobs,
not ECN codepoint definitions. Moving them into `cos::ecn` and
having admission reach back creates exactly the wrong dependency
direction (a byte-mutation module owning admission tuning). Phase 2
will extract them when admission policy moves to `cos/admission.rs`.

Phase 1 establishes the `cos/` submodule pattern that Phase 2+ PRs
will extend.

## Approach

Create the new module:

```
userspace-dp/src/afxdp/cos/
├── mod.rs       — module declaration + re-exports
└── ecn.rs       — moved code (constants, EthernetL3, helpers, tests)
```

Move from `tx.rs`:
- 5 ECN codepoint masks (`ECN_MASK`, `ECN_NOT_ECT`, `ECN_ECT_0`,
  `ECN_ECT_1`, `ECN_CE`).
- `EthernetL3` enum.
- `ethernet_l3` parser.
- `mark_ecn_ce_ipv4` and `mark_ecn_ce_ipv6` helpers.
- `maybe_mark_ecn_ce` and `maybe_mark_ecn_ce_prepared`.
- All **15** unit tests for the above (Codex round-1 #3).

**Stays in tx.rs**:
- `COS_ECN_MARK_THRESHOLD_NUM` / `_DEN` (admission tuning, used by
  `apply_cos_admission_ecn_policy` which also stays).
- The two `const _: () = assert!` compile-time invariants for the
  threshold (move only when admission moves in Phase 2).

### Visibility model (Codex round-1 #1, refined per round-2 #1)

`pub(super)` from inside `afxdp::cos::ecn` only exposes to
`afxdp::cos` — NOT back up to `afxdp::tx`. And `pub(super) use ...`
in `cos/mod.rs` does NOT widen visibility past what the source
items already permit; it can only re-export at a visibility ≤ the
source. So the round-1 fix needs both halves:

```rust
// userspace-dp/src/afxdp/cos/ecn.rs
pub(in crate::afxdp) fn maybe_mark_ecn_ce(req: &mut TxRequest) -> bool { ... }
pub(in crate::afxdp) fn maybe_mark_ecn_ce_prepared(...) -> bool { ... }

// userspace-dp/src/afxdp/cos/mod.rs
pub(super) use ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared};
```

Items declared `pub(in crate::afxdp)` are visible to anything in the
`afxdp` module tree (including `afxdp::tx`). The `pub(super) use`
re-export is a convenience so call sites can write
`use super::cos::{maybe_mark_ecn_ce, ...}` instead of the longer
`use super::cos::ecn::{...}` path.

The internal `EthernetL3` enum, `ethernet_l3` parser, and the
`mark_ecn_ce_ipv4`/`_ipv6` helpers stay file-private (no `pub`)
since they have no callers outside `cos::ecn` after the move.

**ECN codepoint masks (Codex round-3 #1)**: the 5 codepoint masks
(`ECN_MASK`, `ECN_NOT_ECT`, `ECN_ECT_0`, `ECN_ECT_1`, `ECN_CE`)
ARE used by 15 admission tests that stay in `tx::tests` (at
`tx.rs:15612` and `tx.rs:16462`). They cannot stay file-private to
`cos::ecn`. Make them `pub(in crate::afxdp)` so internal tests and
admission code can still import them via
`use crate::afxdp::cos::ecn::{ECN_MASK, ...};` (or via a
`pub(super) use ecn::{ECN_MASK, ...};` re-export from `cos/mod.rs`).

### Path imports (Codex round-1 #5)

From inside `afxdp::cos::ecn`, the existing `use super::ethernet::{...}`
in tx.rs becomes `use crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN};`
(or equivalently `use super::super::ethernet::{...}`). The fully-
qualified `crate::afxdp::ethernet::...` form is preferred for
readability and stability across future module reshuffles.

### Test fixtures (Codex round-1 #4, refined per round-2 #2)

`tx::tests` contains shared fixtures used by BOTH the marker tests
(moving) AND admission/V_min tests (staying):
`build_ipv4_test_packet`, `build_ipv6_test_packet`,
`compute_ipv4_header_checksum`, `insert_single_vlan_tag`,
`test_prepared_item_in_umem`. A naive helper move would break the
remaining `tx::tests`. Round-1 #4 noted the problem; round-2 #2
flagged that my proposed fix (`pub(super) fn` inside
`tx::tests`) doesn't actually compile — `mod tests` is private and
cross-importing from another module's `mod tests` is brittle even
with `pub(super)` on the helpers.

**Decision (Codex round-2 #2 preferred fix, refined per round-3 #3)**:
extend the EXISTING `userspace-dp/src/afxdp/test_fixtures.rs`
module (already declared at `afxdp.rs:93-94` via
`#[cfg(test)] #[path = "afxdp/test_fixtures.rs"] mod test_fixtures;`).
Move the shared fixtures out of `tx::tests` into
`test_fixtures.rs`, matching the existing `pub(super)` visibility
pattern used by `forwarding_snapshot`, `nat_snapshot`, etc.:

```rust
// userspace-dp/src/afxdp/test_fixtures.rs (extended)
pub(super) fn build_ipv4_test_packet(...) -> Vec<u8> { ... }
pub(super) fn build_ipv6_test_packet(...) -> Vec<u8> { ... }
pub(super) fn compute_ipv4_header_checksum(hdr: &[u8]) -> u16 { ... }
pub(super) fn insert_single_vlan_tag(...) -> Vec<u8> { ... }
pub(super) fn test_prepared_item_in_umem(...) -> ... { ... }
```

`pub(super)` here exposes the items to `afxdp` (the parent of
`afxdp::test_fixtures`); `afxdp::tx::tests` and
`afxdp::cos::ecn::tests` reach them via
`use crate::afxdp::test_fixtures::*;` (descendants of `afxdp` can
access items visible to `afxdp` itself).

DO NOT add a duplicate `#[cfg(test)] mod test_fixtures;` declaration
in `afxdp.rs` — the existing `#[cfg(test)] #[path = ...] mod
test_fixtures;` line at `afxdp.rs:93-94` is already in place.

### Module declaration (Codex round-4 #1)

Match the existing local style at `afxdp.rs:97`:
```rust
#[path = "afxdp/tx.rs"]
mod tx;
```

So the new `cos` module declaration is:
```rust
#[path = "afxdp/cos/mod.rs"]
mod cos;
```

Private (no `pub`), explicit path. The `#[cfg(test)] #[path = ...]
mod test_fixtures;` declaration at `afxdp.rs:93-94` already exists
and is reused; do not add a duplicate.

### What this is NOT

- Not a behavior change. Every moved item is dropped into
  `cos/ecn.rs` with identical signature and body.
- Not a rename. Function names and constant names stay the same.
- Not the full `cos/` submodule decomposition. Phase 2+ extends
  with admission, queue service, builders, etc.
- Not a perf claim. Moving code between files does not change
  generated code if visibilities and `#[inline]` attributes are
  preserved.

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/ecn.rs`: ~250 LOC (moved
  code + 15 tests).
- **NEW** `userspace-dp/src/afxdp/cos/mod.rs`: ~5 LOC — `mod ecn;`
  plus `pub(super) use ecn::{maybe_mark_ecn_ce,
  maybe_mark_ecn_ce_prepared, ECN_MASK, ECN_NOT_ECT, ECN_ECT_0,
  ECN_ECT_1, ECN_CE};`. (Codex round-5 #2 caught a duplicate entry
  in v5.)
- `userspace-dp/src/afxdp/test_fixtures.rs` (EXISTS, currently
  ~663 LOC at this commit; round-5 #3 corrected the v4 ~860 LOC
  estimate): EXTENDED with the ~80 LOC of shared fixtures moved
  out of `tx::tests` (`build_ipv4_test_packet`,
  `build_ipv6_test_packet`, `compute_ipv4_header_checksum`,
  `insert_single_vlan_tag`, `test_prepared_item_in_umem`). Existing
  `pub(super)` visibility pattern preserved.
- `userspace-dp/src/afxdp/tx.rs`: removes ~250 LOC (moved code +
  marker tests), removes ~80 LOC (fixtures moved to `test_fixtures.rs`),
  adds `use` statements pointing at `cos::{...}` and
  `test_fixtures::*`. Net: ~330 LOC smaller.
- `userspace-dp/src/afxdp.rs`: adds `#[path = "afxdp/cos/mod.rs"]
  mod cos;` (private, explicit path, matching the existing
  `#[path = "afxdp/tx.rs"] mod tx;` pattern at line 97 — Codex
  round-5 #1 caught a stale `pub(super) mod cos;` residue in v4).
  The existing `#[cfg(test)] #[path = "afxdp/test_fixtures.rs"]
  mod test_fixtures;` line at `afxdp.rs:93-94` already declares the
  test_fixtures module — DO NOT add a duplicate (Codex round-3 #3).

## Tests

All **15 existing tests** for the moved code must continue to pass
(Codex round-1 #3):
- `mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum`
- `mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum`
- `mark_ecn_ce_ipv4_leaves_not_ect_untouched`
- `mark_ecn_ce_ipv4_leaves_ce_untouched`
- `mark_ecn_ce_ipv4_rejects_short_buffer`
- `mark_ecn_ce_ipv6_converts_ect0_to_ce`
- `mark_ecn_ce_ipv6_converts_ect1_to_ce`
- `mark_ecn_ce_ipv6_leaves_not_ect_untouched`
- `mark_ecn_ce_ipv6_leaves_ce_untouched`
- `mark_ecn_ce_ipv6_rejects_short_buffer`
- `maybe_mark_ecn_ce_dispatches_by_addr_family`
- `maybe_mark_ecn_ce_handles_single_vlan_tagged_frame`
- `maybe_mark_ecn_ce_rejects_unknown_ethertype`
- `ethernet_l3_rejects_qinq_until_explicitly_supported`
- `ethernet_l3_rejects_vlan_tagged_non_ip_payload`

The **15 admission-path tests** that exercise the marker indirectly
through `apply_cos_admission_ecn_policy` (including the Prepared
UMEM path and VLAN Prepared path) STAY in `tx::tests` because the
admission policy stays in `tx.rs` (see Phase 1 scope). They depend
on shared fixtures that this PR moves out of `tx::tests` into the
existing `afxdp::test_fixtures` module (per the Test fixtures
section above), so both staying admission tests and moving marker
tests can `use crate::afxdp::test_fixtures::*;`.

No new tests required — the refactor is structure-only and the
existing test suite has dense branch coverage.

## Acceptance gates

The repo has no root `Cargo.toml`; cargo commands must run with
`--manifest-path userspace-dp/Cargo.toml`.

1. `cargo build --release --manifest-path userspace-dp/Cargo.toml`
   clean (no new warnings beyond baseline).
2. `cargo test --release --manifest-path userspace-dp/Cargo.toml`
   ≥ baseline (865 post-#963), 0 failed.
3. Cluster smoke (HARD): no regression on the warmed-flow-cache
   path. Run on `loss:xpf-userspace-fw0/fw1` AND with CoS configured
   via `test/incus/cos-iperf-config.set`. CoS state is wiped by
   `cluster-deploy`, so the smoke runner must re-apply the fixture
   before measurement. The ECN marking path is exercised when
   queues fill — iperf-c at ≥ 22 Gb/s through the 25 g shape will
   hit it.

   | Class       | Port  | Shape | P=12 gate     |
   |-------------|-------|-------|---------------|
   | iperf-c     | 5203  | 25 g  | ≥ 22 Gb/s     |
   | iperf-f     | 5206  | 19 g  | ≥ 17.1 Gb/s   |
   | iperf-e     | 5205  | 16 g  | ≥ 14.4 Gb/s   |
   | iperf-d     | 5204  | 13 g  | ≥ 11.7 Gb/s   |
   | iperf-b     | 5202  | 10 g  | ≥ 9.0 Gb/s    |
   | iperf-a     | 5201  | 1 g   | ≥ 0.9 Gb/s    |
   | best-effort | 5207  | 100 m | ≥ 90 Mb/s     |

   Every P=12 row is a blocking gate. iperf-c also keeps the P=1
   ≥ 6 Gb/s historical gate.

4. Failover smoke: 90-s iperf3 -P 12 through fw0, force-reboot fw0
   at +20s, fw1 takes over within 10s, iperf3 average ≥ 1 Gb/s and
   ≥ 5 GB received.
5. Codex hostile review (plan + impl): AGREE-TO-MERGE.
6. Gemini adversarial review (plan + impl): AGREE-TO-MERGE.
7. Copilot review on PR: all valid findings addressed.

## Risk

**Low.** Pure structural refactor — no algorithm changes, no
behavior change. The moved code is ~250 LOC of leaf functions and
constants with dense test coverage. The only realistic risk is a
visibility / `use`-statement mistake during the cut, caught at
compile time.

The compile-time invariants
`const _: () = assert!(COS_ECN_MARK_THRESHOLD_NUM < COS_ECN_MARK_THRESHOLD_DEN);`
and
`const _: () = assert!(COS_ECN_MARK_THRESHOLD_DEN > 0);`
**stay with the constants in `tx.rs` for Phase 1** (round-2 #3
caught a stale prose flip from v1 that said they "must move"). They
move with admission and the threshold constants in Phase 2 to
`cos/admission.rs`. The build asserts continue to fire either way.

## Out of scope (future Phase 2+ PRs)

This PR is the first in a chain. Subsequent PRs (one issue, one PR
each, tracked under the #956 umbrella) extract additional
subsystems. Order revised per Codex round-1 #6 — `flow_hash` must
precede admission because `apply_cos_queue_flow_fair_promotion`
calls `cos_flow_hash_seed_from_os`, and a `queue_ops` phase is
broken out explicitly so queue service has somewhere to land its
container helpers:

- **Phase 2**: `cos/flow_hash.rs` — `mix_cos_flow_bucket`,
  `exact_cos_flow_bucket`, `cos_item_flow_key`,
  `cos_flow_bucket_index`, `cos_flow_hash_seed_from_os`,
  `cos_queue_prospective_active_flows`. Pure functions; few callers
  outside admission/promotion.
- **Phase 3**: `cos/admission.rs` — `apply_cos_admission_ecn_policy`
  (and the `COS_ECN_MARK_THRESHOLD_*` constants currently kept in
  `tx.rs` move with it), `apply_cos_queue_flow_fair_promotion`, the
  per-flow share-cap helpers (`cos_queue_flow_share_limit`,
  `cos_flow_aware_buffer_limit`, `account_cos_queue_flow_enqueue`,
  `account_cos_queue_flow_dequeue`, `bdp_floor_bytes`).
- **Phase 4**: `cos/token_bucket.rs` — `refill_cos_tokens`,
  `maybe_top_up_cos_root_lease`, `maybe_top_up_cos_queue_lease`,
  `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
  `cos_refill_ns_until`, `cos_surplus_quantum_bytes`,
  `cos_guarantee_quantum_bytes`.
- **Phase 5**: `cos/queue_ops.rs` — `cos_queue_push_back`,
  `cos_queue_push_front`, `cos_queue_pop_front`,
  `cos_queue_pop_front_no_snapshot`, `cos_queue_front`,
  `cos_queue_len`, `cos_queue_is_empty`,
  `cos_queue_min_finish_bucket`, plus the `CoSBatch` /
  `CoSServicePhase` / `ExactCoSQueueKind` enums and
  `CoSPendingTxItem` accessors. Required before queue service can
  cleanly extract.
- **Phase 6**: `cos/builders.rs` — `build_cos_interface_runtime`,
  `build_cos_batch_from_queue`, `apply_cos_send_result`,
  `apply_cos_prepared_result`, `prime_cos_root_for_service`.
  Codex round-2 #4 caught that `queue_service` calls all of these,
  so builders must extract BEFORE queue_service or queue_service
  will be left dependent on `tx.rs`. Phase 6 in v3 (was Phase 8 in
  v2).
- **Phase 7**: `cos/queue_service.rs` — `select_cos_guarantee_batch`,
  `select_cos_surplus_batch`, `service_exact_*`, `drain_shaped_tx`,
  MQFQ virtual-time logic, `select_exact_cos_guarantee_queue_*`.
  Pulls in builders/appliers from Phase 6.
- **Phase 8**: `cos/cross_binding.rs` —
  `redirect_local_cos_request_to_owner`,
  `redirect_prepared_cos_request_to_owner`,
  `prepared_cos_request_stays_on_current_tx_binding`, the MPSC
  inbox handling. Was Phase 7 in v2.

After Phase 8 the `tx.rs` left in place is just XSK ring management
(descriptor pop/push, kick threshold, completion reap) +
orchestration glue (`drain_pending_tx`, `bound_pending_tx_*`)
(~3-5K LOC). Each phase is independently reviewable, smokeable,
and mergeable.

If during Phase 1 review a smaller or different first cut emerges,
the plan can swap order — Phase 1 must just be the smallest
defensible cohesive piece.
