# #900 — 100E100M empirical finding (early outcome)

## TL;DR

The xpf-userspace-dp SFQ + DRR scheduler **scales well to high
concurrent flow counts** in the iperf-a CoS class (1 Gb/s
shaped). Tested up to 128 concurrent TCP streams — the iperf3
client process limit:

- **0 / 128 streams collapsed** (all > 5 Mbps)
- 119 / 128 streams (93 %) within ±25 % of fair share
- CoV across 128 streams = **16.6 %**, *tighter* than the
  16-stream baseline (18.5 %, see `docs/pr/840-slice-d-v2/findings.md`)

The user's original symptom — *"many streams collapse to 0
bps"* — does **not** manifest at 128 concurrent flows. Existing
SFQ infrastructure handles this workload.

## What was actually tested

The originally-planned 100E100M harness (100 elephants + 100
latency-sensitive mice concurrent) **was not completed**. The
infrastructure to drive 100 mice concurrent failed in two
ways:

1. **hping3 raw-SYN at 100 concurrency drops 99 % of replies.**
   Tested 1 → 5 → 25 → 100 mice; replies degrade rapidly above
   ~5 concurrent processes. Likely raw-socket-recv bottleneck
   in the container or rate-limiting somewhere in the firewall.
2. **Python TCP-connect at 100 concurrency drops 63 % to
   `ConnectionRefusedError`.** Likely the firewall's SYN-cookie
   flood defense (per `CLAUDE.md` "SYN cookie flood protection")
   engaging on bursty mouse-connect SYN trains, plus iperf3
   server's single-client accept limit.

Additional bug: iperf3 backgrounded via `incus exec` dies at
~5 s of its own clock despite `setsid` detachment. Single-mouse
isolated tests do not reproduce. Root cause not isolated within
the time budget.

## Pivot: simpler test that answers the actual question

Rather than chase the 100E100M harness infrastructure, ran the
single-process `iperf3 -c <target> -p 5201 -P 128 -t 60` test.
Headline numbers above. Raw JSON committed to
`docs/pr/900-100e100m-harness/128stream.json`.

### 128-stream result

| Metric | Value |
|---|---|
| Aggregate Gbps | 0.954 (matches 1 Gb/s shaper) |
| Streams collapsed (< 1 Mbps) | 0 / 128 |
| Streams within ±25 % of fair | 119 / 128 (93 %) |
| Streams > 2 × fair share | 0 / 128 |
| Mean per-stream Mbps | 7.45 |
| CoV | 16.6 % |
| Min / Max stream Mbps | 5.40 / 12.55 |
| Stream rate distribution (p10/p50/p90 Mbps) | 6.10 / 7.11 / 9.12 |
| Total retransmits | 7,729 |

### Comparison to 16-stream baseline (#840 reverted-attempt run)

| Metric | 16 streams | 128 streams |
|---|---|---|
| Aggregate Gbps | 0.954 | 0.954 |
| CoV | 18.5 % | 16.6 % |
| Min Mbps | 48.06 | 5.40 |
| Max Mbps | 79.02 | 12.55 |
| Min / Mean ratio | 0.81 | 0.72 |

CoV got *tighter* at 128 streams (more streams → law-of-large-
numbers averaging of TCP cwnd noise). The
absolute min-stream rate dropped only modestly relative to fair
share (0.81 → 0.72 of mean), so worst-case performance
preserves well.

## What this finding tells us

1. **For the throughput-fairness aspect of 100E100M, the
   existing scheduler is sufficient.** No new algorithm or
   table-tuning is needed (which closes the loop on
   `#897/#898/#899` from #840 — those were RSS-rebalance
   approaches that the empirical data doesn't justify).

2. **For the mouse-latency-tail aspect of 100E100M, we have no
   data.** The hping3 + Python TCP-connect approaches both hit
   infrastructure walls. Any future attempt would need:
   - A managed TCP echo server (not iperf3 listener; iperf3 is
     single-tenant and rejects concurrent clients)
   - Disabled SYN-cookie defense during the test, OR a
     non-bursty mouse driver that ramps up gradually below the
     defense threshold
   - A non-raw-socket probe approach (Python TCP-connect is
     OK but needs pacing + a real echo target)

## Recommendation

- Close `#897`, `#898`, `#899` with reference to this finding —
  the SFQ/DRR scheduler already delivers acceptable per-stream
  fairness at 128-flow scale; no algorithm work is justified.
- Do NOT merge `test/incus/test-100e100m.sh` (the partial
  harness) — preserve as `docs/pr/900-100e100m-harness/` for
  any future revisit.
- Keep `#900` open with this finding; defer the
  mouse-latency-tail measurement until/unless a real workload
  shows mouse latency degradation in production.

## Files

- `docs/pr/900-100e100m-harness/plan.md` — original 100E100M
  plan (5 review rounds; preserved as design reference)
- `docs/pr/900-100e100m-harness/128stream.json` — raw iperf3
  output with all 128 per-stream rates
- `docs/pr/900-100e100m-harness/findings.md` — this document
