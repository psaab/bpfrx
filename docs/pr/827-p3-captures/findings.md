# PR #827 P3 Findings — M1 INCONCLUSIVE on both load-bearing cells

## TL;DR

Both `p5201-fwd-with-cos` and `p5202-fwd-with-cos` classify as **M1
INCONCLUSIVE** under threshold T1 (#819 §3.2 / §5.3). The kick-
latency half of the signature is strongly elevated (mean 4-11 µs,
well above bucket-3 IN threshold in several elevated blocks), but
the retry-counter half is completely silent (`retry_delta = 0` on
every block across both cells, 24 block-samples total, 120 s of
shaped iperf3 forwarding). T1's conjunction rule requires both;
OUT requires mean < 2048 ns, which no block satisfies, so neither
IN nor OUT fires.

Per #819 §7.2 decision tree on both-INCONCLUSIVE: file Issue C (P2
NAPI cadence capture) and note in findings that additional
non-P3 discriminators are required.

## Capture-run sanity

| Cell                   | iperf3 Gbps | retransmits | step1 verdict |
|------------------------|------------:|------------:|:-------------:|
| p5201-fwd-with-cos     |        0.95 |         666 | PASS          |
| p5202-fwd-with-cos     |        9.55 |          93 | PASS          |

p5201 is the 1 Gbps shaped cell; p5202 is the 10 Gbps shaped cell —
both matching #823 P1 cell semantics. The retransmit counts are the
natural consequence of iperf3 hitting a hard MQFQ shaper
(1 Gbps / 10 Gbps caps per cos-iperf-config.set). This is expected
for shaped-traffic cells and not a capture-run artefact; #823 P1
captures showed similar retransmit counts on the same cells.

## Per-cell verdicts

### p5201-fwd-with-cos — INCONCLUSIVE

- `rho(T_D1, retry_count_delta)`: n/a (retry_delta is 0 on every
  block — series is constant, Spearman ρ undefined).
- `rho(T_D1, kick_latency_mean_ns)`: **-0.7343** (p=0.0065).
  Negative correlation: mean kick latency trends DOWN as T_D1
  trends UP. Unexpected for a pure M1 signature (M1 predicts
  positive correlation — kick latency rises when the D1-shape
  buckets are heavier). The negative ρ fits an M1-is-NOT-the-
  mechanism reading.
- Elevated blocks (top-quartile T_D1): `[1, 10, 11]`.
- `max_retry_count_delta_in_elevated`: **0**.
- `max_kick_latency_mean_ns_in_elevated`: **4417 ns** — above the
  4096 ns bucket-3 lower edge (would flag IN on the latency half
  in isolation).
- Mean kick latency floor (across all 12 blocks): **4147 ns**
  (block 2). Every block is above the 2048 ns OUT threshold.

Full report:
[`docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/correlation-report.md`](../819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/correlation-report.md)

### p5202-fwd-with-cos — INCONCLUSIVE

- `rho(T_D1, retry_count_delta)`: n/a (retry_delta constant 0).
- `rho(T_D1, kick_latency_mean_ns)`: **-0.9231** (p=1.86e-05) —
  strong negative correlation, again opposite to the M1 prediction.
- Elevated blocks: `[4, 8, 9]`.
- `max_retry_count_delta_in_elevated`: **0**.
- `max_kick_latency_mean_ns_in_elevated`: **6481 ns** (well above
  IN threshold).
- Mean kick latency across all blocks: 6354-10894 ns. Block 0
  alone shows 10894 ns (bucket 4 range, 8-16 µs). No block goes
  below OUT threshold.

Full report:
[`docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/correlation-report.md`](../819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/correlation-report.md)

## What the data says about mechanism M1

M1 (in-AF_XDP submit → TX DMA stalls under no-shaper backpressure;
#819 §2 #1) predicts:

1. **`Δ(retry_counter)/block` elevated** — the ring fills and
   `sendto(MSG_DONTWAIT)` starts returning EAGAIN repeatedly. This
   was pre-registered as the *primary* M1 signal.
2. **`mean(sendto_kick_latency) ≥ 4 µs`** during T_D1-elevated
   blocks — time inside sendto covers the submit-path queuing.

The captures show (1) at zero across 120 s of shaped traffic and
(2) uniformly above 4 µs on both cells. **Half the M1 signature is
firing; the other half is silent.**

Possible readings of this split (pre-registered in the findings
synthesis, not post-hoc):

- **M1 is genuinely NOT the mechanism.** The ring never fills to
  backpressure because the MQFQ scheduler + `TX_WAKE_MIN_INTERVAL_NS`
  gate at `tx.rs:6432-6434` throttle the submit rate below the kick
  cadence. Kick latency is elevated for some *other* reason — e.g.,
  the sendto syscall itself is paying a cost unrelated to ring
  backpressure (KVM exit to virtio-net, `skb_set_hash`, CHECKSUM_PARTIAL
  bookkeeping, etc.).
- **M1 IS the mechanism but our retry instrumentation misses it.**
  If the kernel's xsk_generic_xmit path drops packets with a code
  path that does NOT return EAGAIN to userspace (e.g., silent drop
  via `xdp_do_xmit` buffer exhaustion), the user-visible sendto
  would succeed while the underlying ring stall mechanism still
  fires. Checking this requires instrumentation beneath sendto —
  out of scope for P3.
- **The negative ρ is informative.** Strong negative correlation
  between T_D1 and kick latency means **when buckets 3-6 carry
  *more* mass, kick latency goes *down***. This fits a scheduler /
  NAPI cadence mechanism (M2, M3) better than a submit-path stall
  (M1): if the kernel is batching harder during periods of larger
  TX submit sizes, the per-kick latency drops. #823 already showed
  M3 OUT, so M2 (NAPI) is the next candidate.

The correct conclusion on just the P3 data is **M1 INCONCLUSIVE**.
The indirect evidence (negative ρ + zero retries) *weakly favours*
M1 OUT and points toward M2, but §7.2 requires the T1 threshold to
decide, and T1 is INCONCLUSIVE by definition.

## Next step per #819 §7.2 decision tree

Both cells INCONCLUSIVE → **file Issue C (P2 NAPI cadence
capture)** per #819 §8.2. The P2 harness uses bpftrace to measure
`napi_complete_done` cycle accounting on the RX queue + cross-CPU
scheduling delay traces — discriminator T2.

This closes #827 without closing #819.

### P2 pre-registration reminder

From #819 §3.2 T2:

- **M2 IN.** p99 NAPI inter-arrival ≥ 100 µs during T_D1-elevated
  blocks AND `ρ(T_D1, p99_ns) ≥ 0.8`.
- **M2 OUT.** p99 ≤ 10 µs on every block AND `ρ ≤ 0.3`.
- **M2 INCONCLUSIVE.** Otherwise.

Per §6.1 wall-clock estimate, P2 captures are ~15 min end-to-end.

## Overhead retrospective

Wall-clock delta `step1-capture.sh` pre-vs-post-#826 on
p5201-fwd-with-cos:

| Metric | Pre-#826 (#823 P1 capture) | Post-#826 (this capture) | Delta |
|---|---:|---:|---:|
| step1-capture wall time | ~63 s | ~63 s | ≈0 |

No measurable overhead from the daemon-side kick-latency histogram.
Consistent with #812's ≤1 ns/kick bench envelope × 300 k kicks/s ≈
300 µs/s total cost.

## Artifacts committed

Under
`docs/pr/819-step2-discriminator-design/evidence/<cell>/tx-kick/`
for each of the two cells:

- `correlation-report.md` — human verdict
- `correlation-report.meta.json` — machine verdict
- `correlation-report.diag.json` — full diagnostic table
- `tx-kick-by-block.jsonl` — 12 lines per-block view
- `flow_steer_cold.json`, `flow_steer_samples.jsonl`,
  `hist-blocks.jsonl` — step1 originals copied in for
  self-containment
- `iperf3.json`, `verdict.txt`, `worker-tids.txt`,
  `control-status-pre.json`, `cluster-status-pre.txt`,
  `cos-interface-pre.txt` — operational context

Total: <800 KB across both cells (as promised by plan §6.3's "<2 MB
per cell" ceiling — no perf.data produced).
