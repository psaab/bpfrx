---
status: REVISED v3 — Codex round-2 PLAN-NEEDS-MINOR citation/wording tweaks applied; ready to execute
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

### Throughput (P=12 -R sustained, latest measured master `b029e91c`; current master is `dab78ef6` and may have moved)

| Source | iperf-c P=12 | Stddev | Retrans/30s |
|---|---:|---:|---:|
| Pre-campaign (ring=8192, no hugepages) | 16.9 Gb/s | 1.7 | 92K-170K |
| + #780 cache ingest decision | ~18.9 Gb/s | — | — |
| + #782 ring=16384 | 20.4 Gb/s | 1.7 | 0-1910 |
| + #783 hugepages reserved (600) | **21.8 Gb/s** | 0.8 | **0-2** |
| + V_min sync (#917, PR #939) | **23.47 Gb/s** | — | 3 |

Source: #775 own "Campaign target met" comment (2026-04-19) +
`docs/pr/917-mqfq-phase4/findings-post-917.md`.

### CPU profile (latest measured master `b029e91c`, P=12 -R sustained)

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
- 18 Gb/s ceiling has been beaten: 23.47 Gb/s per
  `findings-post-917.md` (2026-04-27).
- BUT the issue's title target is **25 Gb/s** (the iperf-c shaper
  rate), not 22 Gb/s (#775's campaign gate). 23.47 still doesn't
  hit 25.
- The remaining ~6% gap (23.47 → 25) is the cross-UMEM body
  memcpy (#776), which is architecturally blocked on this lab
  per its own scope correction (cross-NIC shared UMEM is blocked,
  same-device shared-UMEM exists but FQ/CQ ownership bug blocks
  activation).

**Recommendation (revised v2 per Codex round-1):** **Close as
"umbrella not actionable on this lab".** The 18 Gb/s ceiling
premise is overtaken (now 23.47), but the 25 Gb/s shaper target
is not hit, and the remaining gap is the cross-NIC body memcpy
that #776 already tracks as a topology constraint. Closing #774
removes the stale ceiling-tracker; keeping #776 open preserves
the structural-copy / topology trail. Avoid framing as "25 Gb/s
impossible forever" — `docs/shared-umem-plan.md:237` notes
cross-NIC memcpy is unavoidable on this hardware **but leaves
"make the existing memcpy cheaper" as an optimization path**
(e.g., hugepage UMEM via `/home/ps/.claude/plans/elegant-meandering-lamport.md`).

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

**Recommendation (revised v2 per Codex round-1):** **Keep open
as topology-constraint tracker.** Codex round-1 caught the
inconsistency: if both #774 and #776 close, the cross-NIC
shared-UMEM constraint trail is lost, and #774's "remaining gap
tracked as #776" rationale points at a closed issue. Keep #776
open as the active constraint tracker; it's the canonical place
to land #776b (hugepage UMEM) or #776c (same-device shared-UMEM
activation) when someone's ready to take them up. Add a comment
documenting this role explicitly.

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

**Reality:** the issue body lists three concrete fix hypotheses
(`flow_key.clone()`, branch-heavy dispatch, PreparedTxRequest
field copy). Per Codex round-1 review, **the `flow_key.clone()`
hypothesis is stale**: the current common direct path mostly
moves the key via `take()`; clones remain in request construction,
segmentation, and prepared-to-local fallback paths. So `Arc<SessionKey>`
is no longer the obvious lead fix.

**Recommendation (revised v2 per Codex round-1):** **Keep open.**
Next action: fresh `perf annotate` on `enqueue_pending_forwards`
on current master to find the actual dominant basic blocks — do
NOT prescribe `Arc<SessionKey>` until annotate confirms it's still
the right target. Scope the fix off measurement, not the stale
hypothesis. #1016 (decouple mutation from dispatch) remains a
prerequisite for any batched-pipeline angle.

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

Codex round-1 cited fresh evidence from `#778 diagnostic`:
`rx_xsk_buff_alloc_err=899`, `tx_xsk_full=0`. If those numbers
are accurate as a 30-60s rate (not cumulative), the structural
pipeline stall is effectively gone — fresh-measurement-before-
close is the cautious path, but close-as-mitigated is the likely
outcome.

**Recommendation:** **Keep open with explicit fresh-measurement
gate.** Add a comment requesting a 30-60s window measurement of
`tx_xsk_full` and `rx_xsk_buff_alloc_err` rates on current master.
If both are near-zero (Codex's data suggests they are), close as
mitigated. If still substantial, scope a fix.

## 4. Recommendation summary (revised v2 per Codex round-1)

| # | Recommendation | Justification |
|---|---|---|
| #774 | **Close as wontfix-on-current-lab** | 25 Gb/s target unachievable on dual-NIC mlx5 lab without shared-UMEM unblock; preserved trail in #776 |
| #775 | **Close** | Author's own comment says "Closing campaign issue as target met"; quote author, don't overclaim 600s campaign |
| #776 | **Keep open as topology-constraint tracker** | Closing #774 + #776 erases the constraint trail; keep one as active tracker |
| #777 | **Keep** | Needs fresh perf annotate to scope before plan |
| #779 | **Keep** | `flow_key.clone()` hypothesis stale; needs fresh annotate before fix prescription |
| #781 | **Keep with measurement gate** | Codex cites fresh data showing rx_xsk_buff_alloc_err=899, tx_xsk_full=0; likely close-as-mitigated after rate measurement |

**Net effect:** 2 closures (#774, #775), 4 stay open with refined
gating notes. Down from v1's 3 closures — Codex correctly caught
that closing both #774 AND #776 erases the cross-NIC shared-UMEM
constraint trail.

**Codex round-1 corrections applied:**
1. #774 reframed: not "ceiling beaten" but "current-lab target
   wontfix" (25 ≠ 23.47).
2. #776 changed from close to keep — preserve the topology-
   constraint trail.
3. #779 fix hypothesis flagged as stale — annotate before
   prescribing.
4. #781 gets measurement-gate framing with Codex's fresh data
   noted.

Pattern matches the prior triage outcomes today:
- SIMD batch: 4 close (4/4 unanimous KILL)
- Tier D batch: 4 close, 13 stay open with NEEDS-MAJOR
- #946: 1 close (wontfix-with-rationale)
- Tier B: 4 close, 3 stay open
- Tier S: **2 close, 4 stay open** (after Codex round-1 corrections)

Aggregate today: **15 close, 20 stay open with refined gating**
if Tier S executes as planned.

## 5. Out of scope

- Implementing fixes for #777 / #779 / #781. This triage is
  close-or-keep only.
- Filing #776b (hugepage UMEM) or #776c (same-device shared-UMEM)
  as new issues. The author explicitly recommends NOT pre-filing
  them; only file when someone's about to take them up.

## 6. Open questions for adversarial review v2

1. Is keeping #776 alone sufficient as the topology-constraint
   tracker, or should successor issues #776b (hugepage UMEM) /
   #776c (same-device shared-UMEM activation) be filed
   simultaneously to make the trail explicit?
2. For #781: is the measurement-gate framing tight enough, or
   should the close-as-mitigated already be the recommendation
   given Codex's cited fresh data (rx_xsk_buff_alloc_err=899,
   tx_xsk_full=0)?

## 7. Verdict request

PLAN-READY → execute close-or-keep recommendations.
PLAN-NEEDS-MINOR → tweak rationale, then execute.
PLAN-NEEDS-MAJOR → revise close vs keep per finding.
PLAN-KILL → don't execute; rationale wrong.
