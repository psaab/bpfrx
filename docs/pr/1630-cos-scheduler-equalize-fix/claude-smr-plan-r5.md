# Claude SMR plan-review r5 — #1630 (v5 design)

**Verdict**: **PLAN-READY**.

## §1 v5 design summary

After my own r4 self-correction identified that v4 (Hunk-A-only)
was insufficient under saturation, v5 adds a time-based pass1
refresh:

- **Hunk A**: pass1 formula = `shaping_rate × VISIT_NS × fraction`.
- **Hunk B (v5)**: time-based pass1 refresh. Add
  `waterfill_epoch_start_ns: u64` field. Refresh pass1 when
  `now_ns - waterfill_epoch_start_ns >= COS_GUARANTEE_VISIT_NS`,
  OR when `pass1 == 0` (preserved legacy).

No bitmask. No Phase-1 walk change. No starvation paths.

## §2 Why v5 is correct (under saturation)

Each 200µs lease epoch:
1. Refresh pass1 to 437.5K (full budget).
2. Walk ascending. Honor small classes one at a time as their
   per-class-lease tokens permit:
   - 100m sends 1 packet (1500B), pass1 -= 2500, tokens drained.
   - 1g sends ~16 packets (24K), pass1 -= 25K, tokens drained.
   - 3g sends ~50 packets (75K), pass1 -= 75K, tokens drained.
   - 6g sends 64 packets (96K, TX_BATCH_SIZE), pass1 -= 150K.
     Tokens 54K remaining.
   - 6g again: candidate 54K. pass1 (185K) ≥ 54K → honor.
     pass1 -= 54K → 131K. 6g drained.
   - 9g: quantum 225K > 131K → break Phase 2.
3. Phase 2 picks 24g, 21g, etc, descending RR for the rest of
   the 200µs epoch.
4. Next 200µs tick: time-refresh fires, pass1 = 437.5K, Phase-2
   cursor reset. Cycle repeats.

Per second (5000 epochs × 200µs):
- 100m: 1 packet × 5000 = 5000 packets = 7.5 MB = 60 Mbps?
  Wait, that's lower than 100 Mbps. Let me recompute.

Actually per-class lease grants 100M × 200µs / 1e9 = 2.5 KB per
lease epoch (rate is in bytes/sec). Per second: 100M / 8 = 12.5
MB. So 12.5 MB/s = 100 Mbps. That's 5000 epochs × 2.5 KB grant.

Per epoch, 100m emits ~1.67 packets (2500/1500). Per second: 8330
packets = 12.5 MB = 100 Mbps. ✓

Same logic for 1g, 3g, 6g — each drains at exactly its
configured rate. Per-class lease throttles independently of
the selector.

Large classes share residual via Phase 2 + per-class lease.

## §3 Hostile checks

### Does `waterfill_epoch_start_ns = 0` first-call refresh correctly?

`elapsed = now_ns - 0 = now_ns` (likely large). `elapsed >=
VISIT_NS` → refresh. Set `waterfill_epoch_start_ns = now_ns`.
Subsequent calls within VISIT_NS skip refresh. ✓

### Can the new time-based refresh be defeated by sparse callers?

The waterfill selector is called from `drain_shaped_tx` per
worker. Under saturation, called many times per ms. Under idle,
called once per ms (drain tick). Time-refresh fires either way
when elapsed exceeds 200µs. ✓

### Does it interact correctly with the per-class lease rotate_epoch_v8?

Per-class lease has its own 200µs epoch (EPOCH_DURATION_NS =
200_000). The waterfill's pass1 refresh ALSO ticks at 200µs.
They're independent timestamps but the granularity matches.
This is correct — pass1 represents Phase-1 ASCENDING ALLOCATION
budget across all classes; per-class lease represents PER-CLASS
RATE cap. Both refresh together (approximately) maintaining
their respective contracts. ✓

### Edge case: clock wraparound

`now_ns` is u64. Wraparound is 584 years. ✓

### Edge case: first call at very small now_ns

If `now_ns < VISIT_NS` (1ms after boot), `elapsed = now_ns -
0 = now_ns < VISIT_NS` → refresh skipped? No — initial
`waterfill_epoch_start_ns = 0` means elapsed = now_ns; if
now_ns < VISIT_NS (=200_000ns = 200µs), `elapsed < VISIT_NS` →
no refresh. But pass1 IS 0 (initial state) → `pass1 == 0`
triggers refresh via OR condition. ✓

## §4 Risk surface

- New field `waterfill_epoch_start_ns: u64` adds 8 bytes to
  CoSInterfaceRuntime. Negligible.
- Per-call cost: 1 u64 load + 1 saturating_sub + 1 compare.
  All in L1 cache. Hot-path-acceptable.
- Behavior change: only in GuaranteeRate mode (opt-in).
  Proportional bit-for-bit preserved.

## §5 Sign-off

**PLAN-READY**. v5 design is the right semantics for the
documented contract. All Codex r1+r2+r3 findings addressed
without regressions. SMR r4 self-correction validated against
v5 design.

Recommend dispatching Codex r4 + AGY r4 for confirmation.
