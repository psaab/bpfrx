---
status: DRAFT v1 — pending adversarial plan review
issues: #774, #775, #776, #777, #779, #781
phase: Triage — close-or-keep decision per issue
---

## 1. Why one triage doc for 6 Tier S issues

Tier S is the "active perf bugs with measured cost" stack on the
loss userspace cluster. Several of the umbrella/gate issues
(#774 ceiling, #775 campaign gate) were filed before the perf
work that has since landed (PRs #780/#782/#783 + #1191 + ring/
hugepage activation + V_min stack from #913/#917/#940/#941/#942/
#943). The author of these issues left **detailed scope-
correction comments** on several of them — some of which already
say "close" or "target met" but the close action was never taken.

This triage:

1. Validates each issue against the author's own most-recent
   scope correction comment.
2. Validates each issue against current master perf data.
3. Routes to close-or-keep with refined scope.

Same pattern that worked for Tier B (#786, #793, #794, #917
closed as overtaken / shipped; #837, #936, #937 kept open with
gating notes).

## 2. Recent perf evidence

### Throughput (P=12 -R sustained, master HEAD `b029e91c`)

| Source | iperf-c P=12 | Stddev | Retrans/30s |
|---|---:|---:|---:|
| Pre-campaign (ring=8192, no hugepages) | 16.9 Gb/s | 1.7 | 92K-170K |
| + #780 cache ingest decision | ~18.9 Gb/s | — | — |
| + #782 ring=16384 | 20.4 Gb/s | 1.7 | 0-1910 |
| + #783 hugepages reserved (600) | **21.8 Gb/s** | 0.8 | **0-2** |
| + V_min sync (#917, PR #939) | **23.47 Gb/s** | — | 3 |

Source: #775 own "Campaign target met" comment (2026-04-19) +
`docs/pr/917-mqfq-phase4/findings-post-917.md`.

### CPU profile (current master, P=12 -R sustained)

| % CPU | Symbol | Tracker |
|---:|---|---|
| 13.43 | `__memmove_evex_unaligned_erms` | #776 cross-UMEM body memcpy |
| 9.45 | `poll_binding_process_descriptor` | #777 RX hot path |
| 5.94 | bpf_prog (XDP) | XDP redirect |
| 4.50 | `worker_loop` | userspace-dp main loop |
| 4.20 | `enqueue_pending_forwards` | #779 TX dispatch |
| 1.52 | `htab_map_hash` | #761 KILLED |
| 0.95 | `mlx5e_xsk_skb_from_cqe_linear` | #778 closed — SKB fallback |

#776 / #777 / #779 are all still on the profile. Neither has been
"silently fixed" by adjacent landings.

## 3. Per-issue assessment

### #774 — userspace DP ceiling at 18 Gbps vs 25+ Gbps target

**Author's own scope correction (2026-04-19):**
> "Leaving this issue open for the shared-UMEM activation as the
> real fix."

Lists four fix paths: NIC RSS tuning (tried via #840, reverted),
cross-worker memcpy (#776, scope-corrected as not single-PR-
tractable), MPSC batching (medium), SFQ (irrelevant; queue never
backs up).

**Reality on master:**
- 18 Gb/s ceiling has been **beaten**: 23.47 Gb/s per
  `findings-post-917.md` (2026-04-27), well above the 18 Gb/s
  ceiling this issue documents.
- The remaining gap to the 25 Gb/s shaper rate is the 12-13%
  cross-UMEM memcpy (#776), which is architecturally blocked on
  this lab per its own scope correction.

**Recommendation:** **Close.** The 18 Gb/s ceiling premise is
overtaken. The remaining 12-13% memcpy gap is tracked as #776
which has its own scope correction. Pointing at the wrong number
in #774 wastes triage cycles on future readers. If a new ceiling
is measured at some future point, file a fresh issue with the
new number.

### #775 — campaign to land consistent 22+ Gbps on iperf3 -P 12 -t 600 -p 5203

**Author's own comment (2026-04-19) literally says:**
> "Closing campaign issue as target met; leaving remaining child
> issues open for future work."

But the close action was never taken. The 22 Gb/s gate was met
at 21.8 Gb/s median + 0.8 stddev, with two 5-run benchmark sets
showing 22+ Gb/s. Subsequent #917 V_min landing pushed it to
23.47 Gb/s, well clear.

**Recommendation:** **Close** per the author's own intent stated
in the comment. The follow-up child issues (#776, #777, #779,
#781) stay open or get their own triage decisions.

### #776 — 12% CPU memcpy in build_forwarded_frame_into_from_frame

**Author's own scope correction (2026-05-03):**
> "This issue should split into:
> - #776a (this issue, repurposed): document the cross-NIC
>   constraint as the fundamental blocker for the 12% on this
>   topology; close as 'wontfix on current lab' with the memory
>   note as evidence.
> - #776b (new): hugepage UMEM activation. Single-PR-tractable
>   per the existing plan.
> - #776c (new): activate same-device shared-UMEM (FQ/CQ ownership
>   fix). Multi-PR; tracked via docs/shared-umem-plan.md.
> Without one of these new issues being filed and the topology
> constraint accepted, #776 as written cannot be resolved by a
> single PR."

The constraint analysis is verified against `docs/shared-umem-plan.md`
+ `feedback_cross_binding_impossible.md`. Cross-NIC shared UMEM is
blocked at the mlx5 driver layer (EINVAL on second bind);
same-device prototype exists but FQ/CQ ownership bug blocks it.

**Recommendation:** **Close as wontfix-on-current-lab.** Follow
the author's own #776a directive. Note in close comment that #776b
(hugepage UMEM) and #776c (same-device shared-UMEM activation)
are the tractable follow-ups but neither is currently filed —
recommend filing them only when someone's about to take them up.
Don't pre-file work that won't get touched.

### #777 — 7.8% CPU in poll_binding_process_descriptor (RX hot path)

**Status:** zero comments since the issue was filed. Still 9.45%
on the current master profile (slightly worse than the 7.8%
the issue body cites — likely because #913/#917 landed atop the
same hot path).

**Reality:** the issue body itself says:
> "Without instrumentation on the sub-steps we can't say. First
> action: inline perf annotate on this function to find the 2-3
> dominant basic blocks, then file per-block issues."

So #777 is a "scope-me" issue; it can't ship without first running
`perf annotate` to find the 2-3 dominant basic blocks. That's
~20 min of work but it has not been done.

**Recommendation:** **Keep open.** Add a comment that the next
action is `perf annotate` to break out sub-hot-spots into per-block
issues. Single-PR-tractable once scoped, but cannot triple-review
a plan against an unscoped target.

### #779 — 3.28% CPU in enqueue_pending_forwards (TX dispatch)

**Status:** zero comments. Still 4.20% on current master.

**Reality:** the issue body lists three concrete fix hypotheses:
1. `flow_key.clone()` per request — measurable at 1.3M pps
2. Branch-heavy dispatch (segmentation / in-place / copy)
3. `PreparedTxRequest` field copy

Concrete fix hypotheses (1) is the easiest to attack:
`Arc<SessionKey>` instead of `Option<SessionKey>` clone. One
refcount bump vs full struct copy.

**Recommendation:** **Keep open.** Single-PR-tractable. Could
be the next concrete attack target after this triage if user
wants to start actual perf work. Note: #1016 was filed to decouple
the mutation in this function from TX dispatch — that's a
prerequisite for batched-pipeline work but not for the smaller
flow_key clone fix.

### #781 — 9.67M rx_xsk_buff_alloc_err + 506M tx_xsk_full

**Author's own note in #775 (2026-04-19):**
> "Largely mitigated by ring=16384 + hugepages; needs re-measurement
> of the kernel counters."

The cumulative ethtool numbers in the issue body (9.67M, 506M)
were captured at a single point in time and are NOT reset by
ring/hugepage activation — they're cumulative since NIC up. So
the issue body's headline numbers are stale; the rate of new
errors per unit time may have fallen substantially.

**Reality:** the structural-pipeline-stall hypothesis was
"largely mitigated" by ring=16384 + hugepages per the author's
own note. The retrans-storm symptom (92-170K retrans/30s) has
fallen to 0-2 retrans/30s per #775's progression table.

**Recommendation:** **Keep open** but explicitly note: requires
fresh re-measurement before any code work. If fresh ethtool
counters (rate over a 30-60s window, not cumulative) show
near-zero `tx_xsk_full` or `rx_xsk_buff_alloc_err`, close as
mitigated. If they're still substantial, scope a fix.

## 4. Recommendation summary

| # | Recommendation | Justification |
|---|---|---|
| #774 | **Close** | 18 Gb/s ceiling beaten (23.47 Gb/s); remaining gap is #776 |
| #775 | **Close** | Author's own comment says "Closing campaign issue as target met"; never closed |
| #776 | **Close as wontfix-on-current-lab** | Author's own scope correction recommends close; cross-NIC blocked, follow-ups tracked separately |
| #777 | **Keep** | Needs perf annotate to scope before plan |
| #779 | **Keep** | Single-PR-tractable; concrete fix hypotheses |
| #781 | **Keep** | Largely mitigated by ring/hugepage; needs fresh re-measurement before action |

**Net effect:** 3 closures, 3 stay open with refined gating notes.

Pattern matches the prior triage outcomes today:
- SIMD batch: 4 close (4/4 unanimous KILL)
- Tier D batch: 4 close, 13 stay open with NEEDS-MAJOR
- #946: 1 close (wontfix-with-rationale)
- Tier B: 4 close, 3 stay open
- Tier S: 3 close, 3 stay open

Aggregate today: **16 close, 19 stay open with refined gating** if Tier S
executes as planned.

## 5. Out of scope

- Implementing fixes for #777 / #779 / #781. This triage is
  close-or-keep only.
- Filing #776b (hugepage UMEM) or #776c (same-device shared-UMEM)
  as new issues. The author explicitly recommends NOT pre-filing
  them; only file when someone's about to take them up.

## 6. Open questions for adversarial review

1. Is "close #774" defensible given the issue's title still
   names a 25 Gb/s target that hasn't been hit (we're at 23.47)?
   Or is the 23.47 figure good enough that the ceiling-tracking
   value is gone?
2. Is "close #776 as wontfix" actually consistent with the author's
   #776a directive, or should the issue stay open as the
   "topology-constraint tracker" with the cross-NIC blocker
   noted in the body?
3. For #781: is the author's "largely mitigated" assertion strong
   enough to close, or is the recommended path (keep open + need
   fresh measurement) appropriately cautious?

## 7. Verdict request

PLAN-READY → execute close-or-keep recommendations.
PLAN-NEEDS-MINOR → tweak rationale, then execute.
PLAN-NEEDS-MAJOR → revise close vs keep per finding.
PLAN-KILL → don't execute; rationale wrong.
