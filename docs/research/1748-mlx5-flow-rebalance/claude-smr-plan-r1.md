# Claude SMR hostile plan-review — #1748 r1

Role: domain SMR (AF_XDP/XDP dataplane) + CPU-arch/cache + SW-design. Hostile by
default. The plan proposes PLAN-KILL; my job is to try to *falsify* the kill
(find a reason #1748 is actually feasible on mlx5), and if I can't, to attack
the kill's rigor so it doesn't hide a soft pass.

## Attempt 1 to falsify Wall A (XDP_REDIRECT could work on mlx5 now)

I tried to find a current-kernel path where XSKMAP delivers across RX queues.
`xsk_rcv_check()` in upstream `net/xdp/xsk.c` checks `xs->dev` and
`xs->queue_id == xdp->rxq->queue_index`. This is structural to zero-copy: the
UMEM fill/completion rings are bound to one (dev,queue) at `XDP_BIND`. mlx5
native XDP and `ndo_xdp_xmit` are about *redirecting to another netdev's TX*,
not about delivering RX to a non-matching XSK. The 2026 leased-queue work
(cited by #937 Codex) is queue-leasing, not arbitrary cross-queue RX. **I could
not falsify Wall A.** The plan's RQ2 conclusion stands. CONCEDE.

## Attempt 2 to falsify Wall B (maybe re-pin IS safe because session sync exists)

The most aggressive pro-#1748 argument: the dataplane already moves session
state across *nodes* in HA (owner-RG export/import in `ha.rs`). Could we reuse
that to move a session across *workers* on the same node when we re-pin a flow?

I checked: HA owner-RG export/import operates on whole RGs (resource groups)
at failover boundaries, is slow-path, and re-homes ALL sessions of an RG to the
peer's workers via RSS placement on the peer — it does NOT do per-flow,
mid-stream, intra-node worker handoff. Repurposing it for per-flow rebalance
would mean a full conntrack lock + flow-cache transfer + MQFQ re-accounting on
the hot path, plus draining in-flight TX on the old worker to avoid reorder.
That is the "cross-worker session-migration subsystem" the plan says does not
exist — confirmed it does not, and the HA path is not a shortcut to it.
**Wall B holds. CONCEDE.**

## Attack on the kill's rigor (where the plan is soft)

1. **The plan asserts the ntuple re-pin "plausibly YES" moves a live flow but
   did NOT measure it this session** (correctly — cluster is serialized for
   smoke). This is fine for a KILL because the kill does not *depend* on the
   re-pin working — it depends on Wall B blocking it *even if* it works. The
   plan should make explicit that it grants RQ1 in #1748's favor (re-pin
   works) and kills on the downstream wall, so a reader can't say "you didn't
   prove re-pin works." → The plan does state this in §5 ("Plausibly YES") and
   §8 Path 2. Acceptable. MINOR: §0 TL;DR could state the grant more crisply.

2. **§6 leans on the #1203/#789 "49–55% CoV" number as a realized measurement
   of "the reactive rebalance form."** I want to be careful this isn't a
   bait-and-switch: was #1203/#789 actually a *cross-worker re-steer*, or a
   *within-queue* scheme? Per fairness-regimes.md §"Even placement..." and the
   #1649 closing comment, #1203/#789 "built and measured that reactive
   closed-loop form on this exact cluster" and closed with "per-flow CoV is
   bounded by within-queue scheduling, not placement." That phrasing suggests
   #1203 was a *placement* controller, which is the right comparand. But the
   plan should not overclaim it as *identical* to #1748's intra-node worker
   migration — it's the closest realized analogue, not the same code. → Plan
   §6 says "closest realizable form" — that hedge is correct. Keep it; do not
   strengthen to "identical."

3. **The plan's Wall B argument should name the alternative the architecture
   DOES permit, so the kill isn't read as "fairness is hopeless."** It does
   (§7, §10: PR #1230 fair-share lease coordinates the scheduler without moving
   packets; #1746 cap). Good — this is the constructive landing. Keep it
   prominent.

4. **HA constraint (RQ3) is correctly demoted to a *consequence* of Wall B,
   not an independent reason.** If Wall B fell, HA would be the next wall; but
   stacking it as "independent" would be overcounting. Plan handles this
   correctly (§5 RQ3: "consequence of Wall B, not an independent reason").

## Verdict

**PLAN-READY (kill correct).** I could not falsify Wall A or Wall B, and the
§6 floor theorem (inherited from #1649's 3-way-converged Monte-Carlo) means
even a Wall-B-free reactive rebalance has one realized data point *below* the
gate. The mlx5 capability delta is genuine and correctly conceded (the hardware
CAN steer) — it simply was never the blocker. The kill is grounded on the right
two walls, both with verbatim/structural evidence, and lands constructively on
the already-shipped permitted mechanism.

One non-blocking nit for r2 if the doc is revised: tighten §0 to state up front
that the plan *grants* RQ1 (re-pin works) and kills on Wall B downstream, so
Codex/AGY don't spend a round on "you didn't prove re-pin."
