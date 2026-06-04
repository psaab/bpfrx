# #1767 — Induce TCP re-convergence on oversubscribed workers WITHOUT re-steering (per-worker AQM / ECN / pacing)

**Type:** DESIGN / FEASIBILITY research (deep `/research`). Stops at
PLAN-READY or PLAN-KILL. No implementation, no PR, no production source
edits.

**Sub-issue of #1765.** The architecture-legal alternative to the
forbidden re-steering chain (#840 / #1203 / #937 / #1215 / #1748).

---

## 1. Problem statement and premise

At low parallelism (`-P 12` over `M = 6` RSS queues), TCP flows land as
a multinomial draw and lock into a bimodal per-flow split that never
re-converges. The umbrella (#1765) three-way analysis established:

- **Root cause:** RSS multinomial skew (a flow is pinned to its
  RSS-queue's worker for life — AF_XDP ZC physics,
  `xsk_rcv_check()` `queue_id` match).
- **Why it persists:** SUM is *under* the shaper and there are
  **0 retransmits**, so TCP AIMD never sees a multiplicative-decrease
  event. Each flow stalls at its per-worker share equilibrium.
- **Moving flows is forbidden** (the SYN is RSS-placed before any exact
  rule can exist; cross-queue ZC redirect needs a copy).

The research question for #1767: **can a per-worker congestion signal
make the flows on an oversubscribed worker back off so the system
re-converges to a fairer cross-worker split, WITHOUT re-steering any
flow?** Three candidate levers, each evaluated code-grounded below:

1. Per-worker AQM / ECN CE-marking driven by the worker's local
   oversubscription signal.
2. Per-worker / per-flow pacing to a *cross-worker fair share* (vs the
   local share that `drain.rs` already paces to).
3. Selective AQM drop (RED / CoDel) on the oversubscribed worker to
   force AIMD, at the cost of the prized 0-retransmit property.

---

## 2. What the dataplane already has (code-grounded inventory)

This issue is NOT greenfield. The relevant machinery is already in tree;
the feasibility verdict turns on whether *re-aiming* it at cross-worker
fairness is sound, not on whether the primitives exist.

### 2.1 Egress ECN CE-marking — EXISTS and is proven on the ZC path

`userspace-dp/src/afxdp/cos/ecn.rs` implements RFC-3168-correct CE
marking:

- `mark_ecn_ce_ipv4()` (RFC 1624 incremental IP checksum update),
  `mark_ecn_ce_ipv6()` (no checksum), VLAN-transparent L3 parse
  (`ethernet_l3()`), dispatch on parsed wire bytes not the
  `expected_addr_family` sideband.
- `maybe_mark_ecn_ce_prepared(req, umem)` marks **in place inside the
  UMEM** on the zero-copy XSK-RX→XSK-TX hot path (the iperf3 / NAT'd
  fast path). #718/#722/#727 history.
- **This directly answers one of the issue's open questions:** *"Is
  egress ECN rewrite feasible on the zero-copy TX path?"* — **YES, it
  ships today.** Only ECT(0)/ECT(1) packets cross to CE; NOT-ECT is
  never touched (RFC 3168 §6.1.1.1).

### 2.2 ECN marking is already per-worker and driven by a local signal

`apply_cos_admission_ecn_policy()`
(`cos/admission.rs:276`) fires at the egress admission gate
(`tx/cos_classify.rs:878`), keyed off **this worker's local queue
state**:

- **shared_exact** (the iperf-18g class in the repro): marks on the
  **aggregate** arm — `queue.hot.queued_bytes > buffer_limit × 1/3`.
- **owner-local-exact**: marks on the **per-flow** arm —
  `flow_bucket_bytes[bucket] > share_cap × 1/3`.

Each worker owns its own `CoSQueueRuntime` for its slice of the shared
queue. So a "per-worker AQM" hook is not just feasible — it is the
*current* shape. The mark threshold is a local-backlog proxy.

### 2.3 Cross-worker signals that ALREADY exist

The dataplane already computes everything a cross-worker controller
would need (this is the surprising part):

- **`worker_active_flow_buckets`** (shared lease v8,
  `types/shared_cos_lease/`): per-worker active-flow count, published
  cross-worker via atomics, read at epoch rotation.
- **`SharedCoSQueueVtimeFloor` / V_min** (`cos/queue_ops/v_min.rs`):
  per-worker committed virtual-time floor, published Release / read
  Acquire. `cos_queue_v_min_continue()` *throttles* a worker whose
  `queue_vtime` runs ahead of the peer-min by more than a lag
  threshold. This is an existing **cross-worker, per-queue,
  work-conserving-ish brake** — but it equalizes per-worker *virtual
  time*, not per-flow *rate*.
- **`flow_bucket_observed_bps`** (`cos/fairness.rs`): per-bucket EWMA
  TX rate, owner-local, threshold-gated (100 µs min dt) to kill
  microspikes. The MQFQ cap-aware selector (`drain.rs:165`,
  `compute_drain_target_bps`) paces each bucket to
  `queue_bw / active_flow_buckets` — **the local per-flow share**.
- **Equal-flow-enforcement v8** (`publish_equal_flow_epoch_v8.rs`):
  the *already-shipped, opt-in, default-OFF* cross-worker fairness
  mechanism. It computes
  `candidate_target = min over workers of (prev_grants[w]/active_flows[w])`
  — i.e. it **picks the slowest worker's per-flow rate** as the class
  target and hard-caps every worker to `target × its_flow_count`.
  Prior testing: CoV ~22% → ~8.6%, at an aggregate-throughput cost
  (it is explicitly non-work-conserving — premise-4 break). This is
  the dataplane-hard-cap analogue of what ECN would try to do via TCP.

**Implication:** the #1767 mechanisms are not blocked on missing
primitives. They are a *policy* question — whether to drive a
congestion signal off the existing cross-worker oversubscription state.
The feasibility verdict is therefore about *whether the control loop
converges to cross-worker fairness*, not about plumbing.

---

## 3. The crux: does per-worker ECN marking converge to CROSS-worker
fairness, or just throttle the hot worker?

This is the load-bearing question. Worked through with the AIMD
steady-state model.

### 3.1 The TCP response model

A long-lived loss/marking-based congestion-controlled flow (Reno
square-root law; CUBIC behaves similarly in the marking regime under
DCTCP-style or classic ECN) settles at an equilibrium rate

```
rate ≈ (MSS / RTT) · (k / sqrt(p))
```

where `p` is the **per-flow CE-mark probability** and `k` is a
constant. Classic RFC-3168 ECN treats a CE mark like a single loss per
RTT: the sender halves cwnd (CUBIC: ×0.7). Standard (non-DCTCP)
receivers set ECE for *at least one* CE per RTT, so the sender reacts
**at most once per RTT regardless of how many packets in that RTT were
marked** — classic ECN is a binary per-RTT signal, NOT proportional.

Two consequences pin the analysis:

1. **A worker marking ALL its flows at the same probability `p` drives
   all of its flows to the same per-flow equilibrium rate.** That is
   *within-worker* equalization — which MQFQ + the per-bucket cap
   (`drain.rs`) already provide for free, losslessly. Per-worker ECN
   adds nothing to within-worker fairness.

2. **The cross-worker asymmetry is structural, not a cwnd artifact.**
   The hot worker has `a_hot` flows sharing one worker's egress
   capacity `C`; the cold worker has `a_cold < a_hot` flows sharing the
   same `C`. Even at `p = 0` everywhere (today), the hot worker's
   per-flow rate is `C/a_hot` and the cold worker's is `C/a_cold`. The
   ratio `a_hot / a_cold` IS the per-flow CoV. This is `Cstruct`.

### 3.2 Why marking the hot worker cannot raise the floor

To equalize cross-worker, you must bring the hot worker's per-flow rate
`C/a_hot` *up* to the cold worker's `C/a_cold`, OR bring the cold
worker's *down* to the hot worker's. ECN can only ever **reduce** a
flow's rate (a CE mark is a decrease signal; there is no "speed-up"
codepoint). So:

- **Marking the hot worker's flows** lowers them *below* `C/a_hot`,
  moving them *further* from the (higher) cold-worker rate. CoV gets
  **worse**, and aggregate drops, until the hot worker's flows hit
  some floor. The only way this *reduces* CoV is if the cold worker's
  flows then expand to absorb the freed bandwidth — **but they cannot,
  because they are on a different worker / different RSS queue.** The
  freed bandwidth on the hot worker's egress slice cannot be consumed
  by a flow pinned to a different RX queue's worker (that is precisely
  the re-steer that is forbidden). The freed capacity goes **idle**.
  Net: lower aggregate, CoV unchanged or worse. This is the worst
  outcome.

- **Marking the cold worker's flows** (to drag them DOWN to the hot
  worker's rate) DOES reduce CoV — but this is **clip-to-slowest /
  Harrison-Bergeron**. It is *exactly* what equal-flow-enforcement v8
  already does deterministically and losslessly via a hard cap. Doing
  it via ECN instead is strictly worse: it relies on the sender
  honoring ECE, it injects RTT-scale convergence lag and oscillation,
  and classic ECN's once-per-RTT binary response is a far coarser
  actuator than a byte-rate token cap. You would re-derive
  equal-flow-enforcement with a noisier, sender-dependent actuator.

### 3.3 The decisive conclusion on the core claim

> **Per-worker ECN/AQM marking does NOT converge to cross-worker
> fairness. It can only (a) throttle the hot worker and strand its
> freed capacity as idle — lowering aggregate while leaving or worsening
> CoV — or (b) be re-aimed at the COLD worker, in which case it is a
> strictly-worse, sender-dependent re-implementation of the already
> shipped equal-flow-enforcement clip-to-slowest hard cap.**

The reason is fundamental and survives any marking-policy refinement:
**the bandwidth that ECN frees on the oversubscribed worker is
physically unconsumable by the flows on the underloaded worker** — they
are pinned to a different RX queue. ECN moves a flow's *demand*, but it
cannot move *where that demand is served*. Cross-worker re-convergence
requires moving served bytes across workers, which is the forbidden
re-steer. **A congestion signal changes how much each flow asks for; it
cannot change which worker answers.**

This is the same wall every mechanism in the `state.md` "Killed
designs" table hit, restated in the AQM frame: ECN attacks premise 4
(work conservation) but cannot attack premise 2/3 (the per-worker
capacity partition), and the per-flow CoV floor is set by the
partition, not by within-worker scheduling.

---

## 4. Mechanism-by-mechanism feasibility verdicts

### 4.1 Per-worker AQM / ECN CE-marking off the oversubscription signal

**Verdict: PLAN-KILL (does not converge to cross-worker fairness).**

- Plumbing is trivial and already exists (§2.1, §2.2). Egress ZC ECN
  rewrite is shipped; a per-worker oversubscription threshold
  (`worker_active_flow_buckets[self] > mean`, or V_min lag) is a few
  lines.
- But by §3, marking the hot worker strands freed bandwidth as idle
  (CoV unchanged/worse, aggregate down); marking the cold worker is a
  worse equal-flow-enforcement. Neither raises the per-flow floor.
- Additional disqualifiers (independent of the convergence argument):
  - **ECN-responsiveness gate (the #1211/#1233 kill reason).** The
    smoke senders are Linux iperf3; ECN is *not negotiated by default*
    (`net.ipv4.tcp_ecn=2` = passive). With `0 retransmits` and no
    ECT bits, `maybe_mark_ecn_ce` returns false on the first byte —
    the mechanism is **inert on the actual repro traffic**. The
    revisit criteria in `tcp-head-start-floor.md` require
    "endpoints known to be responsive to the signal"; the repro does
    not meet it.
  - **Classic ECN is binary-per-RTT, not proportional** (§3.1) — a
    coarse actuator for a fairness target that needs fine rate
    control. DCTCP-style proportional marking needs DCTCP senders,
    which the deployment does not control.
  - This is a near-exact re-tread of **#1211 Path 2 AFD overlay**
    (PLAN-KILL, 8 Codex + 3 Gemini rounds) and #1233
    (DOC-RESOLVED). The narrow novelty here — drive marking off the
    *per-worker* signal instead of a *per-flow lead/lag estimator* —
    does not escape the convergence wall; it makes it worse (per-flow
    AFD at least tries to mark only the *leader*, which is closer to
    correct than marking a whole worker).

### 4.2 Per-worker / per-flow pacing to a cross-worker fair share

**Verdict: PLAN-KILL as "fairness improvement", REDUNDANT with shipped
v8 as "equal split".**

- `drain.rs:165` / `compute_drain_target_bps` already paces each bucket
  to `queue_bw / active_flow_buckets` — the **local** per-flow share.
- The issue asks: pace to the **cross-worker** fair share instead.
  The cross-worker fair per-flow share is `total_class_bw / total_flows`.
  Pacing the hot worker's flows to that target means **capping them
  below** `C/a_hot` would require... no — `total_bw/total_flows` for
  a skewed draw is *higher* than `C/a_hot` (the hot worker has more
  than its proportional share of flows). To deliver
  `total_bw/total_flows` to each of the hot worker's `a_hot` flows, the
  hot worker would need `a_hot × total_bw/total_flows > C` egress
  capacity — **which it does not have.** Pacing UP is impossible (you
  cannot pace a flow faster than its worker's capacity / its TCP cwnd).
- So "pace to cross-worker fair share" degenerates to: pace the **cold**
  worker's flows DOWN to `total_bw/total_flows`. That is again
  clip-to-slowest = **exactly equal-flow-enforcement v8**, which ships.
  No new mechanism; the issue's pacing lever is the v8 lease re-described.
- Net: nothing to build that is not already built. If the operator
  wants the equal-split tradeoff, `set ... equal-flow-enforcement`
  already delivers it (default-OFF by design, per the documented
  throughput tradeoff).

### 4.3 Selective AQM drop (RED / CoDel) on the oversubscribed worker

**Verdict: PLAN-KILL (forces AIMD but converges to the same idle-or-clip
outcome, and destroys the 0-retrans property the contract values).**

- A drop *does* force AIMD on non-ECN senders (unlike ECN, it works on
  the actual repro traffic). So it clears the "no signal" precondition.
- But the convergence analysis (§3.2) is identical: dropping the hot
  worker's packets lowers its flows' rates; the freed capacity is
  unconsumable by cold-worker flows (wrong RX queue) → idle. Dropping
  the cold worker's packets = clip-to-slowest with retransmits.
- It trades away the explicitly-prized **0-retransmit** property
  (#1765 highlights it; the fairness fixtures in `fairness-regimes.md`
  deliberately *deepen buffers* — `scheduler-100m` 500k,
  `scheduler-1g` 4m — specifically to *suppress* retransmits). A
  selective-drop fairness lever runs directly counter to a tuned,
  shipped, validated design decision.
- RED/CoDel on a per-worker queue also re-introduces exactly the
  tail-drop oscillation that the 24 KB `COS_FLOW_FAIR_MIN_SHARE_BYTES`
  fast-retransmit floor (#704/#707) and the #717 5 ms delay envelope
  were built to avoid.

---

## 5. The one structurally-honest framing (why all three fail together)

All three levers are **demand-side actuators** (they change how fast a
sender offers load). Cross-worker per-flow fairness is a **supply-side
partition problem** (the per-worker capacity slices are fixed and a
flow cannot cross slices). A demand-side actuator can:

- equalize *within* a supply slice (MQFQ already does, losslessly), or
- *shrink* the demand on the over-subscribed slice (ECN/drop/pace-down),
  which only strands that slice's freed capacity as idle because no
  flow on another slice can grow into it.

The only way a demand-side actuator reduces cross-worker CoV is by
shrinking the **fast** flows (on cold workers) down to the **slow**
flows' rate — clip-to-slowest, non-work-conserving, premise-4 break —
which the dataplane **already implements deterministically** as
equal-flow-enforcement v8 (and far better than a sender-dependent ECN
loop ever could). There is no demand-side actuator that raises the
slow flows.

**The floor is the floor.** `Cstruct` is set by the RSS partition
`{a_i}`; no congestion signal moves it work-conservingly. This matches
the #1765 umbrella's own consensus item 1 + 2 and the entire
`state.md` kill table.

---

## 6. What WOULD change the verdict (honest revisit criteria)

Stated so a future session does not re-litigate:

1. **DCTCP / L4S deployment with proportional ECN** AND a measured
   workload where the hot worker has genuine *idle headroom under its
   own shaper* that ECN backoff could redistribute *to other flows on
   the same worker* (not cross-worker). That is a within-worker
   bufferbloat fix, not the #1765 cross-worker problem.
2. **A supply-side change** (more RSS queues with proportional CPU,
   asymmetric `p_w` RSS weighting per `state.md` lever 4, or a
   genuinely new cross-worker byte-moving primitive that survives
   AF_XDP ZC physics). None of these is an AQM/ECN/pacing lever — they
   are out of scope for #1767.
3. **The operator explicitly wants clip-to-slowest** — already served
   by `equal-flow-enforcement` today. No new code.

None of these is "per-worker AQM/ECN/pacing induces cross-worker
re-convergence", which is the #1767 hypothesis. The hypothesis is
**false** under AF_XDP ZC physics.

---

## 7. Hot-path cost note (moot given the kill, recorded for completeness)

Even if convergence worked, the #1757 box is 6/6 CPU-bound. The ECN
marker itself is cheap (one TOS byte + RFC-1624 fold, already paid on
the existing path). A *cross-worker* oversubscription read would add a
shared-cache-line Acquire load per admission decision (the V_min /
worker_active_flow_buckets read), which is the exact cache-line-bounce
class flagged as a deal-breaker in the #1211 Gemini rounds and the
`tcp-head-start-floor.md` revisit criterion 5 ("no contended shared
per-packet writes"). The V_min path amortizes this with a 1-in-K=8
cadence; a per-packet ECN-threshold read would not have that
amortization unless it also batched — adding design surface for a
mechanism that cannot converge anyway.

---

## 8. Composition with shared-lease v8 / V_min / equal-flow (moot, recorded)

The mechanisms either duplicate v8 (4.2) or fight it: per-worker ECN
(4.1) marking the hot worker while V_min is *also* throttling the
fast worker would double-throttle and could deadlock progress against
the hard-cap suspension logic (`cos_queue_v_min_consume_suspension`).
The admission.rs comment block at :340 already documents that
shared_exact deliberately uses the **aggregate** ECN arm and NOT the
per-flow arm precisely because per-flow ECN on top of MQFQ
"double-signals on the same flow" and "collapses cwnd twice" — the
codebase has already learned this lesson once.

---

## 9. Recommendation

**PLAN-KILL all three candidate mechanisms.** No per-worker
AQM/ECN/pacing/drop mechanism induces cross-worker per-flow
re-convergence on the AF_XDP zero-copy dataplane, because the freed
bandwidth on the oversubscribed worker is physically unconsumable by
flows pinned to other workers' RX queues. The only CoV reduction a
demand-side signal can produce is clip-to-slowest, which the dataplane
already ships as `equal-flow-enforcement` (default-OFF, documented
throughput tradeoff). ECN/drop variants are strictly worse actuators
for that same clip (sender-dependent, RTT-lagged, retrans-inducing) and
re-tread the closed #1211/#1233 design space.

The honest product answer is the one `fairness-regimes.md` already
encodes: **the per-flow CoV floor is `Cstruct`, a function of the RSS
partition `{a_i}`; it is not movable work-conservingly by any
congestion signal.** Operators who want stricter equality enable
equal-flow-enforcement and accept the throughput cost.

Do **not** open `/engineer 1767`. File nothing new; close #1767 with
this rationale and the `plan-kill` label (topic label `perf` already
set). Cross-reference #1211 archive + `state.md` kill table.

---

## 10. Reviewer instructions (TCP-CC / AQM / AF_XDP / queueing experts)

The reviewers must stress-test the **core claim in §3** — specifically
attack:

1. Is there ANY marking policy (per-worker, proportional/DCTCP,
   time-varying) that makes the hot worker's freed bandwidth consumable
   by another worker's flows WITHOUT moving the flow? (We claim no — ZC
   queue pinning.) Find a counterexample or confirm.
2. Is the "marking the cold worker = equal-flow-enforcement" reduction
   exact, or is there a regime where ECN-on-cold beats the v8 hard cap?
3. Does the once-per-RTT classic-ECN binary response model hold, or is
   there an Accurate-ECN / AccECN path that changes the actuator
   analysis enough to matter?
4. Pacing (4.2): is the "pace-up is impossible" argument airtight, or
   is there a pace-to-fair-share formulation we missed?

A reviewer who can exhibit a concrete, AF_XDP-ZC-legal,
sender-realistic mechanism that raises the slow flows (not just lowers
the fast ones) flips this to PLAN-READY. We assert none exists.

---

## 11. Verdict summary table

| Mechanism | Plumbing exists? | Converges cross-worker? | Verdict |
|---|---|---|---|
| Per-worker ECN CE-mark off oversubscription signal (4.1) | Yes (ecn.rs, ZC-proven) | **No** — strands idle (hot) or = worse equal-flow (cold); inert on non-ECN repro | **PLAN-KILL** |
| Per-worker/per-flow pace to cross-worker fair share (4.2) | Yes (drain.rs MQFQ) | **No** — pace-up impossible; pace-down = equal-flow v8 (already shipped) | **PLAN-KILL / redundant** |
| Selective AQM drop RED/CoDel on hot worker (4.3) | Partial (drop paths exist) | **No** — same idle/clip; destroys 0-retrans; re-tread #704/#707 | **PLAN-KILL** |

**Overall: PLAN-KILL. The floor is the floor.**
