# Codex code-r1 — task-mppr9yzg-9kbwt7 (verbatim)

## Verdict: NEEDS-MAJOR (subsequently addressed in f14f11e43)

### Findings

1. **userspace-dp/src/afxdp/cos/queue_service/tests.rs:2547** does not implement the plan v6 saturation regression test it claims to. Plan §11 test 5 requires a 5-epoch saturated fixture with `[100M, 1G, 3G, 6G] + [24G]` and per-epoch tallies proving the small classes are honored every epoch. The committed test uses only two queues, manually sets `waterfill_pass1_remaining_bytes = 100`, and checks that timed refresh restores pass1. That validates the timer gate in isolation, but it does not exercise the v4-killing Phase-2 saturation interaction.

2. **userspace-dp/src/afxdp/cos/queue_service/tests.rs:2528** weakens the exhausted-path cursor contract. After forcing `pass1 == 0`, this path should leave `waterfill_phase2_cursor` exactly `0`; instead the assertion is self-referential and effectively accepts both `0` and `1`, so it would not reliably catch a bad exhausted-path reset.

### Checks (implementation matches plan v6 §7)

- Hunk A present at queue_service/mod.rs:813
- Hunk B present via cos.rs:420, builders.rs:111, refresh block at mod.rs:809
- Cursor-preservation invariant correctly implemented: timed refresh does not write the cursor; only the exhausted branch resets it at mod.rs:830, and the legacy Phase-2-no-selection fallthrough still resets it at mod.rs:1038
- Docs contract matches docs/fairness-regimes.md:848-855
- Overflow risk fine (u128 multiply, 100 Gbps × VISIT_NS = 2.5e15 far below u128 max)
- waterfill_epoch_start_ns only accessed under &mut CoSInterfaceRuntime borrow contract

### Resolution

Both findings addressed in subsequent commit f14f11e43:
1. Added `waterfill_multi_epoch_small_classes_honored_via_lease_throttle_simulation` test that exercises 5 epochs × 15 selections × 4-small + 1-large fixture with lease-throttle simulation. Assertions verify each small class honored at least once per epoch.
2. Replaced self-referential assertion with strict equality: `assert_eq!(waterfill_phase2_cursor, 0)` with the explanation that Phase-1 walk does NOT advance Phase-2 cursor — only successful Phase-2 selections do.

Re-dispatch as code-r2 for confirmation.
