# #956 Phase 1: extract cos/ecn.rs from tx.rs (establish the cos/ submodule)

Plan v2 — 2026-04-29. Addresses Codex round-1 (task-mokb9f8h-mwlbl8):
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
   moving marker tests AND staying admission tests. Plan now keeps
   fixtures in `tx::tests` (made `pub(super)`) so `cos::ecn::tests`
   can import them. Fixtures re-evaluate their home in Phase 2.

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

Now an 8-phase plan (Phase 1 = ECN; ends at builders).

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

### Visibility model (Codex round-1 #1)

`pub(super)` from inside `afxdp::cos::ecn` only exposes to
`afxdp::cos`, NOT back up to `afxdp::tx`. To make the moved
functions callable from `tx.rs`, the cleanest options are:

(a) Declare each exported item as `pub(in crate::afxdp)` —
    visible to anything inside the `afxdp` module tree.
(b) Re-export from `cos/mod.rs`:
    ```rust
    pub(super) use ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared};
    ```
    where `pub(super)` here means "visible to `afxdp`" because
    `cos/mod.rs` lives at `afxdp::cos`.

**Decision**: use option (b). Re-exporting from `cos/mod.rs` keeps
the per-file visibility within `cos/ecn.rs` as `pub(super)` (i.e.
"visible to siblings within `cos/`") and lets `cos/mod.rs` decide
the surface area exposed to `afxdp`. This is the pattern the codebase
already follows for `afxdp` itself (see `afxdp.rs`).

### Path imports (Codex round-1 #5)

From inside `afxdp::cos::ecn`, the existing `use super::ethernet::{...}`
in tx.rs becomes `use crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN};`
(or equivalently `use super::super::ethernet::{...}`). The fully-
qualified `crate::afxdp::ethernet::...` form is preferred for
readability and stability across future module reshuffles.

### Test fixtures (Codex round-1 #4)

`tx::tests` contains shared fixtures used by BOTH the marker tests
(moving) AND admission/V_min tests (staying):
`build_ipv4_test_packet`, `build_ipv6_test_packet`,
`compute_ipv4_header_checksum`, `insert_single_vlan_tag`,
`test_prepared_item_in_umem`. A naive helper move would break the
remaining `tx::tests`.

**Decision**: keep the fixtures in `tx::tests` and make them
`pub(super)` (or `pub(in crate::afxdp)`) so `cos::ecn::tests` can
import them via
`use crate::afxdp::tx::tests::{build_ipv4_test_packet, ...};`.
Fixtures don't move in Phase 1; they get re-evaluated when admission
extracts in Phase 2 (likely the right place for them is
`cos/test_helpers.rs` once both admission and ecn live in `cos/`).

### Module declaration

Update `userspace-dp/src/afxdp.rs` to declare the new submodule:
```rust
pub(super) mod cos;
```

(or whatever visibility matches the existing `pub(super) mod tx;`
pattern — investigation will pin the exact form.)

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

- **NEW** `userspace-dp/src/afxdp/cos/mod.rs`: ~5 LOC declaring
  `pub(super) mod ecn;`.
- **NEW** `userspace-dp/src/afxdp/cos/ecn.rs`: ~250 LOC (moved
  code + 13 tests).
- `userspace-dp/src/afxdp/tx.rs`: removes ~250 LOC (moved code +
  tests), adds 1 `use` statement + visibility tweak. Net: ~250 LOC
  smaller.
- `userspace-dp/src/afxdp.rs`: adds `mod cos;` declaration (1 LOC).

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
on shared fixtures that also stay in `tx::tests` and are made
`pub(super)` so `cos::ecn::tests` can import them.

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
must move with the constants and continue to fire — verified by
the build still succeeding.

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
- **Phase 6**: `cos/queue_service.rs` — `select_cos_guarantee_batch`,
  `select_cos_surplus_batch`, `service_exact_*`, `drain_shaped_tx`,
  MQFQ virtual-time logic, `select_exact_cos_guarantee_queue_*`.
- **Phase 7**: `cos/cross_binding.rs` —
  `redirect_local_cos_request_to_owner`,
  `redirect_prepared_cos_request_to_owner`,
  `prepared_cos_request_stays_on_current_tx_binding`, the MPSC
  inbox handling.
- **Phase 8**: `cos/builders.rs` — `build_cos_interface_runtime`,
  `build_cos_batch_from_queue`, `apply_cos_send_result`,
  `apply_cos_prepared_result`, `prime_cos_root_for_service`.

After Phase 8 the `tx.rs` left in place is just XSK ring management
(descriptor pop/push, kick threshold, completion reap) +
orchestration glue (`drain_pending_tx`, `bound_pending_tx_*`)
(~3-5K LOC). Each phase is independently reviewable, smokeable,
and mergeable.

If during Phase 1 review a smaller or different first cut emerges,
the plan can swap order — Phase 1 must just be the smallest
defensible cohesive piece.
