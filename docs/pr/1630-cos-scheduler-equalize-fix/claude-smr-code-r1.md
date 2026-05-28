# Claude SMR code-review r1 — PR #1634 / #1630

**Verdict**: **MERGE-READY** (pending smoke + reviewer-quad
confirmation).

## §1 Code matches plan v6

I verified the diff at `git diff origin/master..HEAD` matches the
v6 design:

### Hunk A (queue_service/mod.rs)

Old:
```rust
if root.waterfill_pass1_remaining_bytes == 0 {
    let mut quantum_sum: u64 = 0;
    for &qi in &root.exact_queues_by_rate_ascending {
        quantum_sum =
            quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
    }
    let frac = root.oversubscription_guarantee_fraction;
    let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
    root.waterfill_pass1_remaining_bytes = pass1;
    root.waterfill_phase2_cursor = 0;
}
```

New:
```rust
let elapsed_since_refresh =
    now_ns.saturating_sub(root.waterfill_epoch_start_ns);
let time_refresh = elapsed_since_refresh >= COS_GUARANTEE_VISIT_NS;
let exhausted = root.waterfill_pass1_remaining_bytes == 0;
if time_refresh || exhausted {
    let frac = root.oversubscription_guarantee_fraction;
    let pass1 = if root.shaping_rate_bytes == 0 {
        // quantum_sum × fraction fallback
    } else {
        let cap_per_epoch = ((root.shaping_rate_bytes as u128)
            * (COS_GUARANTEE_VISIT_NS as u128)
            / 1_000_000_000u128) as u64;
        ((cap_per_epoch as f64) * frac).floor() as u64
    };
    root.waterfill_pass1_remaining_bytes = pass1;
    root.waterfill_epoch_start_ns = now_ns;
    if exhausted {
        root.waterfill_phase2_cursor = 0;
    }
}
```

✓ Matches v6 design exactly. Cursor reset is gated on `exhausted`,
not on `time_refresh`. Critical invariant from Codex r4 preserved.

### Hunk B (cos.rs + builders.rs)

- `cos.rs:419`: new field `waterfill_epoch_start_ns: u64` added
  with comment explaining purpose.
- `builders.rs:111`: initialized to 0 in
  `build_cos_interface_runtime`.

✓ Matches plan.

### Tests

5 new tests added at end of `queue_service/tests.rs`:

1. `waterfill_pass1_budget_anchored_to_shaper_per_epoch` — Hunk A.
2. `waterfill_pass1_transparent_root_fallback_to_quantum_sum`.
3. `waterfill_pass1_refreshes_on_time_tick_only_after_visit_ns` — Hunk B.
4. `waterfill_phase2_cursor_only_resets_on_exhausted_path` — Codex r4 invariant.
5. `waterfill_pass1_refills_every_epoch_under_phase2_saturation` — v4 saturation regression pin.

All 5 pass. Existing 4 waterfill tests still pass. 245 cos
tests pass total. Full Rust lib: 1539 pass (one pre-existing
unrelated failure in `snat_contract_doc_guard`).

## §2 Hostile checks

### Overflow risk in `shaping_rate_bytes as u128 * VISIT_NS as u128`

At 100 Gbps shaper: `12.5e9 × 200e3 = 2.5e15`, well under u128
max (3.4e38). ✓

At extreme rate `u64::MAX`: `1.8e19 × 200e3 = 3.6e24`, still
well under u128. ✓

### Race conditions

`CoSInterfaceRuntime` is accessed via `&mut` reference from a
single worker thread per binding. No race. ✓

### Documentation alignment

`docs/fairness-regimes.md:848-855` documented contract:
> guarantee-rate <fraction>: ... Phase 1 honours small-rate
> exact classes ascending by R_i up to `fraction × cap`.

v6 implements `cap = shaping_rate × VISIT_NS` exactly. ✓

### Time-refresh on first call

On first call after fresh runtime construction:
`waterfill_epoch_start_ns = 0` → `elapsed = now_ns` (large) →
`time_refresh = true` → refresh fires. Sets epoch_start_ns to
now_ns. Subsequent calls within VISIT_NS skip refresh. ✓

Also `pass1 == 0` initial → `exhausted = true` → cursor reset
to 0 on first call. ✓

### Idle-period epoch banking

If selector isn't called for 1ms (5 × VISIT_NS), the next call
sees elapsed = 1ms >= VISIT_NS → refresh fires ONCE. Sets
epoch_start_ns to current now_ns. Does NOT bank multiple
unused epochs. ✓ (Codex r4 answer #3 explicit.)

### Lease epoch vs waterfill epoch drift

Per-class lease ticks at lease's own 200µs cadence. Waterfill
refresh ticks at waterfill's own 200µs cadence. Independent
timestamps. Average behavior over many epochs: small classes
hit configured rate. Worst-case latency ~100µs additional —
negligible. ✓

## §3 Risk surface

- 2 hunks: pass1 formula + time-based refresh logic.
- 1 new u64 field on CoSInterfaceRuntime (8 bytes).
- 1 new u64 load + 1 saturating_sub + 1 compare per call. L1
  cache resident. Hot-path acceptable.
- GuaranteeRate mode (opt-in) only. Proportional bit-for-bit
  preserved via dispatch gate at mod.rs:603-606.
- 5 new tests pin each contract.

## §4 Sign-off

MERGE-READY pending:
1. Codex code-r1 verdict.
2. AGY code-r1 verdict.
3. Copilot review (already triggered).
4. Smoke on loss userspace cluster (Gate 1 + Gate 3 PASS).
5. `make test-failover` clean.

All 5 plan-review rounds converged on v6 design. Implementation
faithfully executes the design. Risk is small (opt-in mode,
single new u64 field).
