# #1630 Path A — engineer measurement log (BLOCKED: Gate 1 unreachable)

Branch: `fix/1630-cos-lease-watermark` (off origin/master @ `dbfbf680c`).
Cluster: `loss:xpf-userspace-fw0/fw1`, reth0.80, `cos-iperf-config.set`
applied (`oversubscription-policy guarantee-rate 0.7`).

## Implementation (Path A as planned)

- **P1**: exact-queue lease top-up watermark raised from `lease_bytes`
  to `lease_bytes.max(COS_EXACT_QUEUE_LEASE_BANK_BYTES = N×MTU)`
  (`token_bucket.rs`); `max_total_leased` raised in lock-step for QUEUE
  leases only (`compute_shared_cos_lease_config_with_bank`, bank_floor;
  root lease unchanged).
- **P2**: guarantee per-visit budget converted from the rate-scaled
  quantum (`cos_guarantee_quantum_bytes`) to a per-visit FRAME-count cap
  (`cos_guarantee_visit_cap_bytes` = TX_BATCH_SIZE×frame) at the
  legacy/exact/non-exact selectors + the waterfill Phase-1 (send) and
  Phase-2 sites. Waterfill Phase-1 *budget unit* kept rate-scaled
  (decoupled `phase1_cost` vs `send_budget`).

Build clean; full cargo test (1583 pass, 1 pre-existing unrelated doc
guard fail `snat_contract_documents_current_fail_closed_runtime`); cos
tests 5/5 flake-clean.

## Gate 1 — small-four-alone (12 streams/class, push, v4)

| Class | Shape | Baseline | N=8 | N=64 |
|-------|------:|---------:|----:|-----:|
| iperf-100m | 0.1 G | 69 % | 72.3 % | 76.2 % |
| iperf-1g   | 1.0 G | 79 % | 78.4 % | 73.1 % |
| iperf-3g   | 3.0 G | 87 % | 86.3 % | 86.9 % |
| iperf-6g   | 6.0 G | 86 % | 85.5 % | 86.5 % |

**The watermark sweep is empirically inert.** N=8 → N=64 (32 KB → the
96 KB buffer cap) does not move any class. The watermark only sets a
ceiling the per-queue bucket never reaches under saturation.

## Why P1 cannot work (mechanism, verified)

The plan's P1 hypothesis assumes a low-rate class can *bank* N frames of
unspent lease across epochs. Under saturation there is no unspent grant
to bank: the v8 `acquire_v8` grant is bounded by the per-epoch class cap
`cap = rate × elapsed` (`rotate_epoch_v8.rs:220-221`), and a saturated
class drains its bucket to < 1 frame every visit (`park_queue=285382`
vs `drain_invocations=82238`, `park_root=0`). Raising the bucket
watermark (P1) or the outstanding-credit cap therefore changes nothing —
the binding limiter is the rate-metered per-epoch grant, not the bucket
ceiling.

## The actual root cause (in the v8 seqlock — OUT of Path A scope)

Solo (single class, single port, zero competition) the per-class ceiling
is still sub-95%: 100m=81.4 %, 1g=83.7 %, 3g=89.9 % — efficiency rises
with rate. This is a pure per-class rate-metering floor.

Diagnostic probe: relaxing the rotation-time clamp
`elapsed_ns = (now_ns - start).min(EPOCH_DURATION_NS)`
(`rotate_epoch_v8.rs:218`) to `.min(EPOCH_DURATION_NS * 8)` lifted the
solo ceilings to 100m=94.5 %, 1g=95.3 %, 6g=94.4 % (3g=84.9 %, noisy).

⇒ The dominant loss is the v8 rotation **clamping elapsed to one epoch**:
when a rotation lags past 200 µs (which it does for a low-rate class
that is only visited intermittently), the rate credit for the overshoot
`rate × (lag − EPOCH_DURATION)` is discarded at the linearization point.
This is the **Path B** mechanism (carry/un-clamp across rotation) that
the converged plan explicitly REJECTED as out-of-scope and seqlock-risky
(plan §5 row B, §9). The probe is NOT a safe fix — an uncapped elapsed
lets an idle-then-bursting class exceed its configured rate over a window
(Gate 4 violation); a real fix needs a seqlock-safe bounded carry, which
is a separate, higher-blast-radius change.

## Disposition

Per the `/engineer` STOP-and-report instruction ("if the implementation
reveals the fix needs to touch the v8 seqlock or HA path, STOP and
report"), Path A is BLOCKED: it cannot reach Gate 1 at any N, and the
real lever is the v8 rotation clamp. Recommend either:
- a new issue for a seqlock-safe rotation-carry fix (Path B, with a
  Gate-4-preserving bounded-carry design + fresh adversarial round), or
- Path D: reframe Gate 1 to "≥95 % of the achievable per-rate ceiling"
  and document the rotation-clamp floor.

The branch retains the Path A code (P1 watermark + P2 visit-cap) because
P2 is a genuine, correct improvement (removes the sub-frame-remainder
discard) and the watermark is harmless (rate-safe; Gate 4 holds), but
neither closes #1630 on its own.
