# Research plan — #1748 Cross-worker per-flow REBALANCE (re-steer of established flows) on mlx5 VFs

- **Revision**: r1 (DRAFT — pre-review)
- **Status**: PLAN-KILL (proposed) — see §10. Reviewers must falsify the kill or ratify it.
- **Skill**: `/research` (research-only; stop at PLAN-READY or PLAN-KILL; no code; docs only)
- **Issue**: #1748 (label `perf`)
- **Worktree**: `.claude/worktrees/1748-research-mlx5-flow-rebalance`, branch `research/1748-mlx5-flow-rebalance`
- **Base**: origin/master @ `ecdc16f2e`

---

## 0. TL;DR for the reviewer

#1748 asks whether the mlx5 VF capability surface (native XDP, exact/masked
ntuple steering, 6 RX queues → 6 workers) finally makes **cross-worker
per-flow REBALANCE** — moving an *already-established* long-lived flow off an
overloaded worker onto an idle one — tractable, after four prior kills
(#840 RSS table, #899 per-flow XDP_REDIRECT, #936 cross-worker MQFQ, #937
ingress XDP_REDIRECT) and one direct predecessor (#1649 initial-placement).

The honest distinction #1748 raises is real: **#1649 forbade re-steer by fiat
("programmed once, NEVER re-steered"). #1748 explicitly asks to evaluate the
re-steer itself.** This plan does NOT lean on #1649's by-fiat exclusion. It
evaluates re-steer of an established flow on its merits, on the two physically
distinct mechanisms #1748 names (ntuple HW re-pin vs XDP_REDIRECT), against
the **two independent walls** that both prior chains hit.

**Proposed verdict: PLAN-KILL.** The mlx5 capability delta (which is genuine
and verified) changes the *delivery primitive availability* but does NOT
change either wall:

- **Wall A — AF_XDP queue-binding (kills XDP_REDIRECT path):** permanent
  zero-copy physics. `xsk_rcv_check()` enforces
  `xs->queue_id == xdp->rxq->queue_index`. Verbatim-cited in #937 by both
  Codex and Gemini against current 7.x source. mlx5 native XDP does not touch
  this; CPUMAP does not bypass it.

- **Wall B — per-worker session/UMEM ownership (kills the ntuple HW re-pin
  path even though the primitive exists):** moving an established flow's RX
  queue with an ntuple rule succeeds at the HW/`xsk_rcv_check` layer (packets
  legitimately arrive on the new queue's socket), but **strands the flow's
  session, conntrack, flow-cache, and MQFQ state on the old worker.** There is
  no cross-worker session-migration mechanism, and the flow cache is
  explicitly per-worker with "no cross-worker cache-line traffic"
  (`userspace-dp/src/afxdp/flow_cache.rs:146`). This is the structural reason
  #1649 forbade re-steer; #1748 forces us to confront it head-on rather than
  assume it, and the confrontation confirms it.

The mlx5 ntuple primitive #1748 hoped would change the verdict is the *same*
primitive #1649 already found, measured (cap 1024, ~1 ms/rule), and showed
cannot beat the multinomial floor without a re-steer — and the re-steer it
would enable is blocked by Wall B, not by #1649's fiat. So the newer hardware
does not revive the line. PLAN-KILL is the proposed outcome; reviewers are
asked to falsify Wall A or Wall B with a quoted-line/measured counter-example
or ratify the kill.

---

## 1. Problem statement (verbatim from #1748 + live evidence)

Live A/B (#1746): per-flow CoV swings 14–29% on `-P12` shaped ports, driven by
RSS flow-count imbalance across the 6 VF workers (1-flow worker → ~1.8 G/flow,
4-flow worker → ~0.87 G/flow). A per-flow rate **cap** (the #1746 equal-flow
knob) provably cannot fix this: it only clips fast flows down, never lifts slow
flows up, because the spare capacity is on a *different worker's* queue. The
only mechanism that lifts slow flows (fairness WITHOUT aggregate loss) is
moving flows off overloaded workers onto idle ones — i.e. **cross-worker
rebalance of established flows.** #1748 is that mechanism.

This is a per-flow *distribution* effect, not an aggregate-throughput defect
(`docs/fairness-regimes.md`, "What this means operationally"). The structural
ceiling `Cstruct` for a given `{aᵢ}` is the best any scheduler can do; the only
way to beat `Cstruct` is to change `{aᵢ}` itself — which requires moving an
established flow to a different worker.

## 2. Hardware capability findings (mlx5 VF — re-verified live 2026-06-01)

Re-probed `loss:xpf-userspace-fw0:ge-0-0-2` (the iperf path, reth0.80) read-only
this session. Verbatim:

```
$ ethtool -i ge-0-0-2
driver: mlx5_core
version: 7.0.0-rc7+
firmware-version: 26.48.1000 (MT_0000000531)
bus-info: 0000:09:00.0

$ ethtool -l ge-0-0-2
Combined: 6   (pre-set max 6, current 6)        # 6 RX queues = 6 workers

$ ethtool -k ge-0-0-2 | grep -iE 'ntuple|hashing'
ntuple-filters: off                              # togglable on (per #1649)
receive-hashing: on

$ ethtool -n ge-0-0-2
6 RX rings available
Total 0 rules                                    # clean; no leftover rules

$ uname -r (in VM)
7.0.0-rc7+
```

This matches #1649's findings (commit `36fcd1b8`) exactly. Capabilities
established by #1649 and not re-probed disruptively this session (cluster is
shared/serialized for smoke — no rule inserts performed):

- **Exact 5-tuple → RX-queue ntuple steering works**: `ethtool -N ... action N`
  → `Added rule with ID 1023`. (#1649 verbatim)
- **Masked src-port-residue steering works**: `src-port 0 m 0xfff8` etc. (#1649)
- **Rule-table capacity = 1024** (probed to exhaustion; = mlx5
  `MLX5E_ETHTOOL_FLOW_SPEC_NUM`). (#1649)
- **Per-rule cost ~1 ms-class** firmware-synchronous command. (#1649)
- **Native XDP + `ndo_xdp_xmit`** present on mlx5 VF (CLAUDE.md "XDP on
  SR-IOV Interfaces"; #1649).

**The #1748 premise is correct: the primitive #840/#937 named as missing
EXISTS on this NIC.** The question is whether it changes the verdict. It does
not — see §4–§6.

## 3. Prior-art kill ledger (what each kill actually turned on)

| Issue | Mechanism | Hardware at kill | Load-bearing kill reason |
|---|---|---|---|
| #840 | RSS *indirection table* tuning | mlx5 VF | Global hash buckets; can't move a *long-lived* flow (table change only affects future hashes). Empirically net-negative (CoV 37.7% vs 18.5% baseline). |
| #899 | per-flow XDP_REDIRECT | i40e/iavf era; closed on #900 empirical (scheduler scaled fine) | Re-opened as #937. |
| #936 | cross-worker MQFQ shared vtime | mlx5 VF | Throttle-only (stall fast workers); ~43% aggregate hit. Later subsumed by PR #1230 fair-share lease (iperf-e CoV 60→13.3%). |
| #937 | ingress XDP_REDIRECT (before UMEM bind) | mlx5 VF, kernel 7.0-rc | **Wall A**: `xsk_rcv_check()` device+queue validation; CPUMAP doesn't bypass; verbatim Codex+Gemini against 7.x source. |
| #1649 | HW ntuple **initial** placement (no re-steer) | mlx5 VF, 7.0-rc7+ | Static `f(tuple)→queue` = i.i.d. multinomial draw = RSS floor (CoV ≈0.87 at N=6); reactive exact-rule placement IS a re-steer (SYN RSS-placed before ephemeral port knowable). 3-way converged kill. |

**Key observation:** every kill on the *current* mlx5 hardware (#840, #936,
#937, #1649) already had the mlx5 capabilities #1748 cites. The kills did not
turn on "the hardware lacks ntuple steering" — they turned on Wall A (XSKMAP)
or the multinomial theorem (#1649) or the throttle trade-off (#936). #1748's
hardware-delta premise is therefore *already incorporated* in the most recent
kills. The genuinely-new question #1748 adds is the re-steer of an established
flow via ntuple — which #1649 forbade by fiat and this plan evaluates on
merits (§5, Wall B).

## 4. RQ2 — per-flow XDP_REDIRECT between VFs/queues (Wall A)

**Verdict: blocked, permanently, by AF_XDP zero-copy physics. mlx5 native XDP
+ `ndo_xdp_xmit` does not change this.**

The XDP shim's `select_userspace_queue()` (`userspace-xdp/src/lib.rs:1364`)
returns `rx_queue_index % queue_count` and carries the load-bearing comment
(`:1378-1385`):

> AF_XDP delivery is queue-bound. XDP may only redirect to a socket bound to
> the packet's actual RX queue. Hashing to a different userspace queue here
> silently strands packets between redirect intent and ring delivery.

Kernel mechanism (verbatim from #937 Codex review, current 7.x):
`xsk_rcv_check()` enforces `xs->dev == xdp->rxq->dev` AND
`xs->queue_id == xdp->rxq->queue_index` before delivery. A
`bpf_redirect_map(XSKMAP, slot)` to a socket bound to a *different* queue is
silently dropped (no error counter). `ndo_xdp_xmit` is the TX-side hook for
redirecting to *another netdev*; it is irrelevant to cross-RX-queue delivery
on the same netdev. CPUMAP moves an `xdp_frame` to another CPU/kthread but does
NOT change RX-queue provenance (Codex: "CPU != RX queue"; cpumap.c has a TODO
for `queue_index` propagation) — a subsequent XSKMAP redirect still hits
`xsk_rcv_check()`.

The 2026 "leased/peered queue" patches Codex cited extend validation for
leased queues; they do **not** add arbitrary cross-queue delivery. No reviewer
across #937 found a primitive that falsifies this.

**Conclusion RQ2: XDP_REDIRECT cross-worker rebalance is impossible on AF_XDP
zero-copy regardless of mlx5 capabilities. Unchanged from #937.**

## 5. RQ1 + RQ3 — ntuple HW re-pin of an established flow (Wall B)

This is the genuinely-new evaluation #1748 demands (#1649 forbade it by fiat).

**RQ1 sub-question (does ntuple re-pin a live flow's RX queue?):** Plausibly
YES at the HW layer. An `ethtool -N flow-type tcp4 ... action 5` rule with the
exact 5-tuple of an *established* flow directs that flow's future packets to RX
queue 5. Unlike #840's indirection-table (which only changes the hash for
*future* flows), an exact-tuple rule is a HW override that takes effect for the
matching live flow. After the rule lands, packets arrive on RX queue 5, whose
XSK socket belongs to worker 5 → `xsk_rcv_check()` *passes* (queue now matches).
So unlike Wall A, the delivery primitive does not block this.

**Wall B (why it still fails):** the flow's *session state* does not move with
it. On this dataplane, a flow's conntrack/session entry, its flow-cache entry,
and its MQFQ bucket all live on the **worker that first ingressed it** (the old
worker, queue 2). The flow cache is per-worker by construction:

> `userspace-dp/src/afxdp/flow_cache.rs:146`: "...atomics and no cross-worker
> cache-line traffic."

There is **no cross-worker session-migration mechanism** in the dataplane
(grep of `userspace-dp/src/afxdp/*.rs` for migrate/steal/work-shar finds only
mirror-clone TX paths and HA owner-RG export — neither migrates a live
forwarding session between local workers). After an ntuple re-pin:

1. Worker 5 receives packets for a flow it has no flow-cache/session entry for
   → forced full session-table lookup miss path, or (worse) a *second* session
   gets created on worker 5 while worker 2 still holds the original. Conntrack
   correctness (NAT mappings, TCP state, seq tracking) is now split across two
   workers with no synchronization.
2. The old worker (2) keeps any half-open TX/retransmit state and its MQFQ
   accounting; the new worker (5) starts cold. Mid-stream reordering and
   likely TCP reset.

This is *exactly* the forbidden re-steer pattern the entire chain was killed
on, and #1649's verbatim general statement covers it:

> #1649: "any later correction MOVES an established flow ... the forbidden
> re-steer pattern."

The mlx5 ntuple primitive makes the re-steer *physically expressible* (it was
always expressible — #840 used the indirection table; #1649 used exact rules),
but the re-steer was never blocked by *expressibility*. It is blocked by the
**lack of cross-worker session migration** — Wall B — which is independent of
the NIC and unchanged by mlx5.

**RQ3 (rebalance policy — which flows, hysteresis, HA consistency):** moot if
Wall B holds, but worth recording the HA constraint as an *additional*
independent blocker: a moved flow must land on the matching worker on BOTH
cluster nodes or session-sync breaks. The HA session-sync owner derivation
(`pkg/cluster` + `userspace-dp/src/afxdp/ha.rs` owner-RG export) keys session
ownership to the ingress worker derived from the *local* RSS placement. An
ntuple re-pin on node 0 would have to be mirrored on node 1's NIC with an
identical rule AND the synced session would have to be re-homed on node 1's
worker 5 — but node 1's worker 5 has no migration intake either (Wall B
applies per-node). So even granting Wall B were solvable on one node, HA
doubles the requirement. This is a *consequence* of Wall B, not an independent
reason to revive.

## 6. RQ — does ntuple re-pin beat the multinomial floor at all? (#1649 theorem)

Even setting Wall B aside (hypothetically): would moving flows even help? Only
a *reactive, occupancy-aware* controller could, and #1649 proved (3-way
converged, Codex+AGY Monte-Carlo, 200k trials) that:

- Any **static** `f(5-tuple) → queue` produces i.i.d. multinomial draws =
  the RSS floor (CoV ≈ 0.87 at N=6, M=6) for ephemeral ports; worse if
  imbalanced. No static scheme creates the negative dependence needed for
  N≤M flows to avoid occupied queues.
- A **reactive** controller (observe occupancy, move the offending flow) IS
  the re-steer — and #1203/#789 already *built and measured* that reactive
  closed-loop form on this exact cluster: **49–55% CoV at P=12** (gate ≤20%
  not met), closed with "per-flow CoV is bounded by within-queue scheduling,
  not placement."

So the reactive rebalance #1748 proposes is not novel-unmeasured: its closest
realizable form was measured at 49–55% CoV and did not clear the gate, *and*
that measurement was taken without even paying Wall B's session-migration
cost (it re-steered by other means and still failed).

## 7. RQ4 — interaction with #1746 equal-flow cap + waterfill

#1746 (equal-flow cap, default-OFF) clips fast flows to lift fairness CoV
22%→8.6% by *capping*, accepting aggregate loss on the capped flows. #1748's
premise is that rebalance would lift slow flows *without* aggregate loss,
making the cap unnecessary. Since #1748 is PLAN-KILL (Walls A+B), the
interaction is: **the #1746 cap remains the only shipped lever** for the
shaped-port CoV symptom. Rebalance does not replace it because rebalance is not
feasible. No code interaction to design.

Note: PR #1230's per-worker fair-share lease (which closed #936) already
provides cross-worker *coordination* of the per-flow share via
`epoch_total_granted` — it equalizes the *rate each worker grants per active
flow* without moving flows. That is the architecturally-permitted form of
cross-worker fairness (coordinate the scheduler, don't move the packets), and
it is already shipped. #1748's "move the packets" form is the blocked one.

## 8. Multiple Path Options (as required by /research)

Three mechanisms are physically distinct; all are evaluated and all fail:

- **Path 1 — XDP_REDIRECT rebalance (the #899/#937 form).** KILLED by Wall A
  (`xsk_rcv_check` queue binding). Not revived by mlx5 native XDP / `ndo_xdp_xmit`.
- **Path 2 — ntuple exact-5-tuple HW re-pin of established flows (the new
  #1748 angle).** Delivery primitive EXISTS and survives `xsk_rcv_check`
  (packets legitimately arrive on the new queue), but KILLED by Wall B
  (no cross-worker session migration; flow cache per-worker; conntrack/MQFQ
  stranded). HA doubles the requirement. And per #1649/§6 it wouldn't beat
  the floor even if Wall B were solved (reactive form measured 49–55% CoV).
- **Path 3 — hybrid (XDP_REDIRECT for delivery + ntuple for HW assist).**
  Inherits Wall A from Path 1; no combination removes both walls.

There is no fourth viable mechanism. The only architecturally-permitted
cross-worker fairness form — coordinate the scheduler rather than move
packets — is *already shipped* (PR #1230 fair-share lease; #1746 equal-flow
cap). #1748 specifically asks for the move-packets form, which is what is
blocked.

## 9. Cost/benefit at absolute scale (RQ5)

Even under the most optimistic hypothetical (Wall B magically solved, single
node only):

- **Benefit:** lift the worst-case `-P12` shaped-port CoV from 14–29% toward
  `Cstruct` for a balanced `{aᵢ}`. The *realized* benefit ceiling is bounded
  by the #1203/#789 measurement (49–55% CoV achieved by the reactive form) —
  i.e. it did not even reach the ≤20% gate. So the benefit is speculative and
  the one realized data point is below-gate.
- **Cost:** a cross-worker session-migration subsystem (does not exist; would
  need locked conntrack handoff, flow-cache transfer, MQFQ re-accounting,
  in-flight TX drain to avoid reorder), HA double-programming, ntuple rule
  churn at ~1 ms/rule against a 1024-rule cap (production flow counts vastly
  exceed 1024 → fall back to RSS floor for the overflow), and a reactive
  controller polling per-worker occupancy at >1 Hz on the contended control
  socket (CLAUDE.md control-socket contention rule). This is multi-month
  architecture work to chase a benefit whose one realized measurement is
  below the gate.

**Cost/benefit: strongly negative.** This is the same conclusion the chain
reached; mlx5 does not move it.

## 10. Recommendation — PLAN-KILL

Proposed outcome: **PLAN-KILL**, label `plan-kill`, close per
`feedback_plan_kill_label_required`. The mlx5 capability delta is real and was
the right thing to re-check, but it changes only the *delivery-primitive
availability* for Path 2, which was never the blocker. The two walls stand:

- **Wall A** kills XDP_REDIRECT (Path 1/3) — permanent zero-copy physics,
  verbatim 7.x source, re-confirmed by #937.
- **Wall B** kills ntuple HW re-pin (Path 2) — no cross-worker session
  migration; mlx5 makes the move expressible but not *safe*. This is the wall
  #1649 named by fiat and #1748 forced us to confront on merits — it holds.

And independently, per #1649's converged multinomial theorem and the
#1203/#789 realized 49–55% CoV measurement, even a hypothetical Wall-B-free
reactive rebalance does not beat the floor for production ephemeral-port
traffic.

**The shipped, architecturally-permitted answer to the #1746 symptom is:**
(1) PR #1230 fair-share lease (cross-worker scheduler coordination, no packet
moves), and (2) the #1746 equal-flow cap (operator opt-in, accepts aggregate
loss). #1748's "move the packets" form adds no reachable benefit over these.

**Documentation deliverable on kill:** `docs/fairness-regimes.md` already has
the "Why hardware steering does NOT beat the floor" subsection (from #1649).
Add a one-paragraph note there explicitly distinguishing *initial placement*
(killed #1649) from *re-steer/rebalance of established flows* (killed #1748,
Wall B), so the next person who notices "but #1649 only forbade re-steer by
fiat" finds the on-merits Wall-B analysis instead of re-opening. This is a
docs-only follow-up at `/engineer` time, NOT part of this research.

## 11. Reviewer falsification targets (be hostile — quote lines / measure)

To overturn PLAN-KILL, a reviewer must produce ONE of:

1. **Falsify Wall A:** a current-kernel (≥7.0) mechanism + citation showing
   XSKMAP (or any AF_XDP) delivery to a socket bound to a *different* RX queue
   than the packet's `xdp->rxq->queue_index` succeeds. (CPUMAP staging does not
   count — show the subsequent XSK delivery passing `xsk_rcv_check`.)
2. **Falsify Wall B:** point to an existing cross-worker session-migration path
   in `userspace-dp/src/afxdp/` (conntrack + flow-cache + MQFQ) that a moved
   flow could use, OR a credible bounded design for one that does not
   re-introduce cross-worker cache-line contention (the explicit
   `flow_cache.rs:146` non-goal) and survives HA double-homing.
3. **Falsify §6:** a static-or-reactive placement scheme + Monte-Carlo or
   measurement showing it beats CoV ≈ 0.87 at N=6 M=6 for *ephemeral* ports
   without coordinating source ports (the #1649 harness artifact).

Absent at least one, ratify PLAN-KILL. Do not KILL the *kill* on stale grounds
(e.g. "the hardware can't steer") — the hardware CAN steer; that is conceded
and is not the blocker.
