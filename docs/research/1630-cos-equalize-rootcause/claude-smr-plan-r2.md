# Claude SMR hostile plan-review — #1630 r2

Reviewer role: CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP
multi-worker-shaper domain expert. Hostile by mandate.

**VERDICT: PLAN-NEEDS-MAJOR**

v2's measurement-corrected root cause (per-class quantum-MTU waste, NOT
root competition or multi-worker visibility) is CORRECT and now
empirically grounded — `park_root=0` everywhere + the small-four-alone
A/B (69/79/87/86%) settle it. That is a real advance over v1 and #1634.
But v2's FIX (Path A: DRR deficit on the scheduler `secondary_budget`)
is **insufficient for exact queues**, and I reach this independently of
Codex r2 by working the watermark arithmetic.

## The decisive defect (independently verified)

v2 assumes the per-queue token bucket accumulates across epochs (it cites
token_bucket.rs:197-201) and that only the selector's `.min(quantum)`
clamp discards budget. **That is false for EXACT queues.** The exact
branch of `maybe_top_up_cos_queue_lease` (token_bucket.rs:180-203)
WATERMARKS the bucket:

```
lease_bytes = shared_queue_lease.lease_bytes()
                .max(tx_frame_capacity())          // = max(rate×200µs, 4096)
                .min(buffer...);
if queue.hot.tokens >= lease_bytes { return; }     // early-return: no top-up
... acquire(lease_bytes - tokens) ...              // only refill UP TO the watermark
```

`lease_bytes()` = `config.lease_bytes` = `target_lease_bytes = rate ×
COS_ROOT_LEASE_TARGET_US(200µs)` clamped (shared_cos_lease/mod.rs:703-711).
For 100m: target = 2500 B; `.max(tx_frame_capacity()=4096)` ⇒ **watermark
= 4096 B**. So the bucket NEVER accumulates above ~4096 B (≈ 2 frames),
no matter how many epochs pass. After sending, the top-up only refills
back to 4096. The accumulation v2 relies on does not happen for exact
queues. This is exactly the 69% (not 90%) the A/B measured — 4096 B
watermark ÷ ~2 frames spendable explains the ~60-70% band, and confirms
the contradiction I flagged in v2-Q1.

Consequence: **Path A (deficit on `secondary_budget`) cannot help**,
because `secondary_budget` is itself bounded by `queue.hot.tokens` which
is bounded by the 4096 B watermark. Even a perfect DRR deficit clamps to
`tokens` and `tokens ≤ 4096`. The fix MUST raise the per-queue
bucket watermark (lease top-up target) and/or carry the lease grant
deficit, so exact queues can bank several frames and average to their
configured rate. v2's §6 recommendation is targeting the wrong layer.

## Confirming the other open questions

- **Q1 (mine, now answered)**: the lease epoch reset is NOT the
  irreducible floor by itself; the irreducible floor is the
  TOP-UP WATERMARK (lease_bytes ≈ rate×200µs, floored at 4096). Raise it
  (e.g. to N×MTU, or carry a deficit) and the v8 lease's per-epoch
  `acquire_v8` grant (rate×elapsed) will still meter the long-run RATE
  correctly — the lease grants exactly rate×elapsed each epoch, so a
  higher watermark only changes BURST/accumulation, not the steady-state
  rate cap. So the rate cap (Gate 4) is preserved even with a much
  larger watermark, AS LONG AS the lease `consume(sent_bytes)` debits
  actual bytes (tx_completion.rs). Good — the fix is rate-safe.

- **Q2 (Path A vs B)**: BOTH as written fail for exact queues for the
  same reason (the watermark). The correct fix is a THIRD framing:
  raise the per-queue lease top-up watermark to a small N×MTU multiple
  (so the bucket can bank ≥ a few frames) AND drive `acquire_v8` to
  request up to a full epoch's grant, while debiting actual sent bytes.
  The DRR deficit then lives in the lease top-up target, not the
  selector secondary_budget. v3 must say this.

- **Q3 (RR fairness)**: agree with Codex — large classes are already
  bounded per drain by TX_BATCH_SIZE=64 (drain.rs:56) and RR cursor
  advancement. A rate-scaled idle-accumulation cap (not a flat N×MTU) is
  the right burst bound; a flat "small multiple of MTU" would under-
  deliver the 24g class.

- **Q5 (non-exact)**: non-exact guarantee queues use `refill_cos_tokens`
  (accumulates to buffer_bytes) so their bucket is NOT watermarked the
  same way, but they ARE still clamped by `.min(quantum)` at selection
  (queue_service/mod.rs:1064). So non-exact has the selector-clamp half
  of the bug but not the watermark half. v3's fix should cover both, but
  the EXACT path (the smoke fixture) is the watermark-dominated case.

## What v3 must contain for PLAN-READY

1. Re-state the root cause to include BOTH discard points: (a) selector
   `.min(quantum)` clamp, AND (b) the exact-queue lease TOP-UP WATERMARK
   (`lease_bytes ≈ rate×200µs` floored at tx_frame_capacity) that prevents
   the per-queue bucket from banking more than ~1-2 frames. (b) is the
   dominant one for the smoke fixture.
2. Re-target the fix: raise/relax the exact-queue top-up watermark to a
   bounded N×MTU (DRR-style burst allowance), carry the unspent grant,
   and keep `acquire_v8`/`consume` debiting actual sent bytes so the
   long-run rate cap (Gate 4) is preserved. Keep a per-visit frame cap
   for RR fairness.
3. Prove rate-safety: show the configured rate is still enforced by the
   per-epoch `acquire_v8` grant (rate×elapsed) regardless of watermark
   size, since the lease only ever grants rate×elapsed.
4. Sweep the watermark / burst cap in the small-four-alone A/B (Gate 1):
   find the smallest N that lifts 100m to ≥95% without over-delivering
   (Gate 4) or hurting RR latency (Gate 3).
5. Keep the honest Path D fallback if a watermark that hits ≥95% for
   100m proves to over-deliver or burst unacceptably.

The research is converging on the RIGHT layer now; v2 just stopped one
level too high in the stack. NEEDS-MAJOR for the re-target; the
measurement and the corrected root-cause direction are sound.
