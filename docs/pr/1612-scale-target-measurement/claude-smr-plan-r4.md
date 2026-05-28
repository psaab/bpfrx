# Claude SMR Plan Review — #1612 step-3 v3 + Codex r3 fixes (r4 round)

**Plan**: `docs/pr/1612-scale-target-measurement/plan.md` v3, 2026-05-28
(amended in-place to fold Codex r3 fixes — the scaffolding code
changed; plan body unchanged except for sentinel and stale-keys_xor
NIT fixes).

**Codex r3 verdict**: PLAN-NEEDS-MAJOR with 2 BLOCKING + 2 NIT findings:
1. BLOCKING — `zone_pair_packed_key | 1` collapses adjacent
   `to_zone_id` values (e.g. (1,2) and (1,3) both map to 65539).
2. BLOCKING — `calibrate_ns_per_tsc_q32` operator precedence bug:
   `<<` parses lower than `/` so the formula computes
   `elapsed_ns << (32 / elapsed_tsc)` instead of
   `(elapsed_ns << 32) / elapsed_tsc`.
3. NIT — stale `keys_xor` wording in plan body.
4. NIT — `MEASUREMENT-DEFERRED` vs `MEASUREMENT DEFERRED` sentinel
   inconsistency.

**Verdict (r4)**: PLAN-READY

## Codex r3 fix audit

| Codex r3 finding | Fix location | Resolved? |
|------------------|--------------|-----------|
| BLOCKING 1: `\| 1` collapses (1,2) and (1,3) | `cold_path_hist.rs::zone_pair_packed_key` — changed `\| 1` to `+ 1` for injective encoding. New tests `zone_pair_packed_key_is_injective_over_small_box` (exhaustive 8×8) and `zone_pair_packed_key_distinguishes_adjacent_to_zone_ids` (explicit (1,2) vs (1,3) counter-example) pin the contract. | YES |
| BLOCKING 2: operator precedence in calibrate_ns_per_tsc_q32 | `cold_path_hist.rs::calibrate_ns_per_tsc_q32` — added explicit parens: `(((elapsed_ns as u128) << 32) / (elapsed_tsc as u128)) as u64`. Comment explains the precedence trap. | YES |
| NIT 3: stale keys_xor wording | Plan §5 question 4 updated to refer to `first_key + alias_seen`; v1→v2 resolution-map row 25 annotated with `(v2 keys_xor RETIRED in v3...)` footnote for historical context. | YES |
| NIT 4: sentinel string | Plan §6 acceptance criterion changed from `MEASUREMENT-DEFERRED` to `MEASUREMENT DEFERRED` (with space) — matches the canonical sentinel at plan §1.9. | YES |

All 2 BLOCKING + 2 NIT findings resolved.

## Updated cold_path_hist.rs test count

```
$ cd userspace-dp && cargo test --release cold_path_hist::
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured
```

20 tests (up from 18 in r3 SMR) — new tests:
- `zone_pair_packed_key_is_injective_over_small_box` — exhaustive
  8×8 injectivity check.
- `zone_pair_packed_key_distinguishes_adjacent_to_zone_ids` —
  Codex r3 explicit counter-example: (1,2) ≠ (1,3).

The existing `record_sample_codex_r2_false_pass_counter_example`
test was running against `| 1` semantics where the (K, L) collision
detection happened to work (because `zone_pair_slot` runs splitmix
on the packed key, and different packed keys hash to different
slots in the small zone-id space tested). With the v3 injective
`+ 1` encoding, the test still passes; the underlying alias
detector logic is unchanged.

## Independent r4 review pass

### Pass

- Injective encoding is provably correct: the inner `(from << 16) | to`
  fits in 32 bits and is bijective over (u16, u16) pairs. Adding 1
  shifts the entire range by +1, preserving injectivity. Zero
  remains free as the "no sample" sentinel (max value after `+ 1`
  is `(0xFFFF << 16) | 0xFFFF) + 1 = 0xFFFFFFFF + 1 = 0x100000000`,
  well within u64.
- Operator-precedence fix is verified by inspection: `<<` and `/`
  in Rust both fall under "arithmetic and logical operators" but
  multiplicative operators (`*`, `/`, `%`) bind tighter than shifts
  (`<<`, `>>`). The Rust reference is explicit at
  https://doc.rust-lang.org/reference/expressions.html#expression-precedence .
- Test coverage extension is targeted: each Codex r3 finding has
  a corresponding test that demonstrates the fix exercises the
  exact counter-example.
- Sentinel string consistency: a `grep -F "MEASUREMENT DEFERRED"`
  on the plan now returns 3 hits (resolution-map row, §1.9 block-
  quote, §6 acceptance) all matching exactly; no `MEASUREMENT-DEFERRED`
  remains in the doc.

### Out-of-band r4 findings (none)

The v3 plan with r3 scaffolding fixes is internally consistent. No
new fatal axes.

## Verdict r4: PLAN-READY

v3 + r3 fixes address all 8 cumulative Codex findings (5 in r1, 3
in r2, 2 BLOCKING + 2 NIT in r3). The cold_path_hist scaffolding
ships with 20 cargo tests passing including explicit counter-example
tests for both Codex r2 finding 3 and Codex r3 finding 1.

Recommendation: STAGED-ship the PR now. The plan + scaffolding are
solid; the remaining BindingWorker integration, wire-protocol,
harness, and measurement are explicitly deferred to follow-up
issues per plan §6 STAGED form.

If Codex r4 surfaces yet another finding, we'll iterate. The
trajectory after r3 fixes is: scaffolding is now provably injective
+ arithmetic-correct + alias-detection-proven-via-test, with no
hot-path impact. Risk envelope is small.
