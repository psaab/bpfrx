# #956 Phase 1: extract cos/ecn.rs from tx.rs (establish the cos/ submodule)

Plan v1 — 2026-04-29.

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

ECN marking is the most self-contained subsystem in the file. It
has:
- A small bounded surface: 4 mutating functions
  (`maybe_mark_ecn_ce`, `maybe_mark_ecn_ce_prepared`,
  `mark_ecn_ce_ipv4`, `mark_ecn_ce_ipv6`) plus the `ethernet_l3`
  parser + `EthernetL3` enum.
- 8 named ECN constants (`COS_ECN_MARK_THRESHOLD_NUM`,
  `COS_ECN_MARK_THRESHOLD_DEN`, `ECN_MASK`, `ECN_NOT_ECT`,
  `ECN_ECT_0`, `ECN_ECT_1`, `ECN_CE`) with two compile-time
  invariants (`const _: () = assert!`).
- 13 existing unit tests dense across all branches (ECT-0/ECT-1/
  not-ECT/CE-untouched/short-buffer × v4/v6, plus QinQ rejection
  and tagged-non-IP rejection).
- Three call sites in tx.rs: `apply_cos_admission_ecn_policy`
  (lines ~3700-3796 within tx.rs) and elsewhere.

It does NOT depend on other CoS subsystems (token bucket, queue ops,
builders) — only on `super::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN}`,
`TxRequest`, `PreparedTxRequest`, and `MmapArea`. Self-contained.

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
- All 8 ECN constants + the two compile-time invariants.
- `EthernetL3` enum.
- `ethernet_l3` parser.
- `mark_ecn_ce_ipv4` and `mark_ecn_ce_ipv6` helpers.
- `maybe_mark_ecn_ce` and `maybe_mark_ecn_ce_prepared`.
- All 13 unit tests for the above.

Update `tx.rs`:
- Remove the moved items.
- `use super::cos::ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared};`
  for the call sites that survive in tx.rs.
- Make `COS_ECN_MARK_THRESHOLD_NUM` / `_DEN` `pub(super) const` in
  `cos::ecn` so `apply_cos_admission_ecn_policy` (which stays in
  tx.rs in this phase) can still reach them.

Update `userspace-dp/src/afxdp.rs` to declare the new submodule:
```rust
mod cos;
```

(Or the appropriate spot in the existing `mod` declarations —
investigation will pin the exact location.)

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

All 13 existing ECN/ethernet_l3 tests must continue to pass:
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
- `ethernet_l3_rejects_qinq_until_explicitly_supported`
- `ethernet_l3_rejects_vlan_tagged_non_ip_payload`
- (one more `ethernet_l3` test — verified during investigation)

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
each, but tracked under #956 umbrella) will extract:

- **Phase 2**: `cos/admission.rs` — `apply_cos_admission_ecn_policy`,
  `apply_cos_queue_flow_fair_promotion`, the per-flow share-cap
  helpers (`cos_queue_flow_share_limit`,
  `cos_flow_aware_buffer_limit`, account_*).
- **Phase 3**: `cos/token_bucket.rs` — `refill_cos_tokens`,
  `maybe_top_up_*`, `cos_tick_for_ns`, `cos_timer_wheel_*`.
- **Phase 4**: `cos/flow_hash.rs` — flow-bucket hashing helpers.
- **Phase 5**: `cos/queue_service.rs` — `select_cos_*`,
  `service_exact_*`, `drain_shaped_tx`, MQFQ virtual-time logic.
- **Phase 6**: `cos/cross_binding.rs` — redirect logic + MPSC.
- **Phase 7**: `cos/builders.rs` — `build_cos_interface_runtime`,
  `apply_cos_send_result`, etc.

After Phase 7 the `tx.rs` left in place is just XSK ring management
+ orchestration glue (~3-5K LOC). Each phase is independently
reviewable, smokeable, and mergeable.

If during Phase 1 review a smaller or different first cut emerges
(e.g., extract token-bucket first because it has even fewer call
sites), the plan can swap order — Phase 1 must just be the
smallest defensible cohesive piece.
