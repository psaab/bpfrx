# #1630 — CoS scheduler equalizes ~20%/class under `guarantee-rate 0.7`: verified root cause + plan-of-action

- Issue: #1630
- Branch: `research/1630-cos-equalize-rootcause`
- Mode: `/research` (plan only; no production code touched; STOP at PLAN-READY)
- Rev: **v1**
- Author: Claude SMR (CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP multi-worker-shaper domain)

> This plan SUPERSEDES the #1634 plan
> (`docs/pr/1630-cos-scheduler-equalize-fix/plan.md`). The #1634 plan's
> "Bug 1 = pass1 over-provisioning / Bug 2 = pass1 never refreshes"
> diagnosis is **mechanically incapable of fixing the measured
> behavior**, because the waterfill selector it patches operates in
> worker-local scope and the bytes-per-class are gated by mechanisms
> the selector does not touch. #1634's own post-mortem
> (`SMOKE-DECLINED-DIAGNOSIS.md`) reached the correct architectural
> root cause AFTER the smoke decline; this plan formalizes and verifies
> that root cause and lays out the path forward.

---

## 1. Problem statement

Smoke fixture `cos-iperf-config.set` on `loss:xpf-userspace-fw0/1`
applies, on `reth0.80`:

- `shaping-rate 25g`
- `oversubscription-policy guarantee-rate 0.7` → Phase-1 budget 17.5 G
- 11 exact classes (`transmit-rate {100m..24g} exact`), best-effort q0

Documented contract (`docs/fairness-regimes.md` guarantee-rate section,
referenced by #1634): under `guarantee-rate`, small-rate exact classes
whose aggregate fits under the Phase-1 budget should each reach ~100% of
their configured rate FIRST; only the residual goes to the larger
classes.

Measured (parent agent, #1634 binary deployed):

- **5-class simul** (100m+1g+3g+6g+9g, demand 19.1 G, small-four sum
  10.1 G ≤ 17.5 G Phase-1 budget): achievement **72 / 65 / 80 / 76 /
  76 %**. Proportional fair-share, NOT small-class-first.
- **Solo iperf-1g**: 0.842 G / 1.0 G = **84 %**.
- **11-class simul** (109 G demand): ~22-23 % per class ≈
  ceiling/demand.
- Generator 70%+ idle; not the bottleneck.
- `show class-of-service interface`: each queue has a **distinct owner
  worker** (round-robin), workers 0-5 each own ~2 queues.

The 5-class case is the decisive one: demand (19.1 G) is below both the
shaping rate (25 G) and the Phase-1 budget (17.5 G), and below the
cluster push ceiling (~18 G). Under a correct guarantee-rate scheduler
the four small classes (10.1 G total) should each be ≥95% of shape and
iperf-9g should take the residual. Instead every class lands at ~74%.

---

## 2. Verified code path (file:line, master @ `dbfbf680c`)

The CoS exact-guarantee data path on the loss userspace cluster:

1. **Queue → owner-worker assignment is round-robin per queue.**
   `coordinator/mod.rs:935-938`
   (`build_cos_owner_worker_by_queue_with_fallback_ifindexes`):
   ```rust
   for queue in &iface.queues {
       let owner_worker_id = eligible_workers[*next_slot % eligible_workers.len()];
       *next_slot += 1;
       owner_by_queue.insert((egress_ifindex, queue.queue_id), owner_worker_id);
   }
   ```
   With 6 workers and 12 queues, each worker owns ~2 queues. iperf-100m
   → worker 1, iperf-1g → worker 2, etc.

2. **Packets for queue X are cross-binding-redirected to X's owner.**
   After redirect, queue X's backlog lives ONLY on its owner worker's
   `CoSInterfaceRuntime.queues[X]`. A non-owner worker sees
   `cos_queue_is_empty(queues[X]) == true`.

3. **The `guarantee-rate` knob feeds ONLY the worker-local waterfill
   selector.** `forwarding_build/cos.rs:426-444` copies
   `oversubscription_policy` + `oversubscription_guarantee_fraction`
   onto `CoSInterfaceConfig`; `queue_service/mod.rs:603-614` dispatches
   to `select_exact_cos_guarantee_queue_waterfill` when policy ==
   GuaranteeRate ∧ fraction > 0. The selector
   (`queue_service/mod.rs:771-1007`) walks
   `root.exact_queues_by_rate_ascending` (ALL queue indices), but skips
   every queue with `cos_queue_is_empty` (line 811). On any given owner
   worker, **only that worker's ~2 owned queues are non-empty** — the
   ascending "small-class-first" walk only ever sees its own queues.
   Phase-1 budget gating, `honored_mask`, Phase-2 descending walk: all
   compute over a 1-2-element effective set. The selector cannot honor
   "small classes interface-wide first" because no single worker
   observes the interface-wide backlog.

4. **Actual bytes-per-class are gated by two token buckets the selector
   does not control:**
   - **Per-class v8 queue lease** (`coordinator/mod.rs:1118-1127`):
     `SharedCoSQueueLease::new_v8_with_rate_mode(queue.transmit_rate_bytes, ...)`.
     The lease's `epoch_total_grant_cap = rate_bytes × elapsed`
     (`rotate_epoch_v8.rs:220-222`), so the cap equals the class's OWN
     configured rate. `acquire_v8`
     (`shared_cos_lease/mod.rs:1018-1245`) hands out up to
     `my_fair_share = cap × my_active_flows / total_active_flows`. Since
     only the owner worker has flows on this queue, `total_active_flows
     == owner's flows` and `my_fair_share == cap` → the lease can grant
     the full per-class rate. The lease is NOT the limiter for the small
     classes.
   - **Shared root shaper lease** (`coordinator/mod.rs:1035-1042`):
     ONE `SharedCoSRootLease` per ifindex, rate = full
     `iface.shaping_rate_bytes` (25 G), shared across all workers via a
     single greedy `compare_exchange` token pool
     (`shared_cos_lease_acquire`, `shared_cos_lease/mod.rs:738-771`).
     Each worker tops up its local `root.tokens` toward `lease_bytes`
     (512 KB; `maybe_top_up_cos_root_lease`, `token_bucket.rs:54-87`)
     from this shared pool, and every per-queue send is gated by
     `root.tokens >= head_len` (`queue_service/mod.rs:830, 973`).
     **The guarantee fraction never reduces the root rate.** The root
     pool is acquired FCFS/greedy with no per-class reservation.

### Verified correction to the prior #1634 diagnosis

The parent's verified read of the token bucket
(`token_bucket.rs:153-236`) is correct: per-queue tokens **accumulate**
(`saturating_add(grant)`, no per-epoch reset), `lease_bytes` is floored
at one frame, and the "parks after 1 packet" claim in #1634's earliest
diagnosis is false. The real per-class rate gate is the SHARED v8
queue-lease `acquire_v8` cap (= configured rate) and the shared root
shaper — confirmed above. The #1634 "anchor pass1 to shaper × fraction"
fix touched only the selector's budget math (`queue_service/mod.rs:787-800`),
which controls service ORDER within a worker, not bytes-per-class —
hence the smoke decline.

---

## 3. Verified root cause

> **Multi-worker queue-ownership fragmentation makes interface-wide
> small-class-first impossible for the worker-local waterfill selector,
> and the only interface-wide arbiter (the shared root shaper) allocates
> root tokens greedily/proportionally to per-worker demand, not by
> guarantee priority.**

Two independent facts combine:

- **(A) The guarantee-rate selector has no interface-wide visibility.**
  Each owner worker runs the waterfill selector over only its own ~2
  backlogged queues. "Honor 100m before 9g" is meaningless when 100m and
  9g live on different worker threads. This is the Axis-B2 gap called out
  in `docs/pr/1614-multi-rss-cos/plan.md:526-528`.

- **(B) The only cross-worker arbiter ignores guarantee priority.**
  The shared root shaper (`SharedCoSRootLease`) is the single point where
  all classes' traffic competes interface-wide. It is a flat FCFS token
  pool refilling at the full shaping rate. When aggregate offered load
  approaches the delivery ceiling, the root pool drains faster than it
  refills and every worker hits `root.tokens < head_len` and parks. Win
  probability for a root-token top-up scales with how often a worker
  asks, which scales with its class rate → proportional starvation.
  Neither `guarantee-rate` nor `guarantee_fraction` is consulted in
  `shared_cos_lease_acquire` or `maybe_top_up_cos_root_lease`.

### Worked numeric trace — 5-class case (demand 19.1 G, shaper 25 G, Phase-1 budget 17.5 G)

Per 200 µs epoch (`EPOCH_DURATION_NS = COS_GUARANTEE_VISIT_NS = 200 µs`):

| Class | Rate | Owner | Per-class lease cap/epoch | Demand/epoch |
|-------|-----:|------:|--------------------------:|-------------:|
| 100m  | 12.5 MB/s | w1 | 2 500 B | full (12 streams) |
| 1g    | 125 MB/s  | w2 | 25 000 B | full |
| 3g    | 375 MB/s  | w3 | 75 000 B | full |
| 6g    | 750 MB/s  | w4 | 150 000 B | full |
| 9g    | 1 125 MB/s | w5 | 225 000 B | full |

- Root shaper delivers 625 000 B/epoch (25 G). Sum of small-class lease
  caps = 2 500+25 000+75 000+150 000+225 000 = **477 500 B/epoch** = 19.1 G.
  Per-class leases alone do NOT cap the small classes below their rates
  (each ≤ its own cap), and 477.5 KB < 625 KB root budget. **So in
  isolation, root + per-class leases would let all five classes reach
  ~100%.**
- The shortfall to ~74% is NOT the per-class lease and NOT the root rate
  in the steady-state token sense. It is the interaction of: (i) the
  ~18 G cluster TX-delivery ceiling sitting just under the 19.1 G offered
  load, so the system is mildly oversubscribed at the wire; (ii) the flat
  root pool distributing the deliverable ~14-18 G greedily/proportionally
  rather than guarantee-first; (iii) per-visit quantum vs MTU
  carry-forward losses (the same mechanism that caps solo iperf-1g at
  84% even with ZERO competition — `cos_guarantee_quantum_bytes` grants
  `R×VISIT_NS` per visit and the drain rounds down to whole frames,
  leaving a systematic per-class under-delivery of ~15-35% before any
  competition).
- Net: every class lands at ≈ (deliverable share) × (per-class
  quantum-efficiency) ≈ 74%, proportional to rate — exactly the
  measured signature.

**Falsifiable prediction** (to confirm at /engineer time, or now via a
throwaway debug build): with the small-four classes ALONE (no 9g, demand
10.1 G, well under both 17.5 G budget and 18 G ceiling), if the root
shaper / quantum theory is right they should each reach ~84% (the solo
quantum-efficiency ceiling), NOT ~95%+. If instead they reach ~95%+,
then the 9g class's root-pool competition is the dominant term and the
fix must arbitrate the root pool by guarantee priority. This single A/B
measurement discriminates between "quantum-efficiency confound" and
"root-pool proportional-starvation" as the dominant cause and MUST be
run before committing to a fix path. (Open question Q1.)

---

## 4. Is small-class-first achievable in the current architecture?

**Honest assessment: NOT with a worker-local selector change alone.** The
selector is structurally blind to peer-worker backlog. Two routes can
make it achievable:

1. **Collapse the scope** — assign all of an interface's CoS queues to a
   single owner worker, so that one worker's waterfill selector regains
   interface-wide visibility. Correct, simple, but sacrifices the
   per-worker drain parallelism the system was built for (one core
   pinned at up-to-shaper-rate with all backlog queues).

2. **Add cross-worker coordination (Axis B2)** — a shared per-interface
   structure where each worker publishes its per-class demand and the
   root-token arbiter (or each worker's admission) consults
   guarantee-priority before consuming root tokens. This is the only path
   that delivers small-class-first AND preserves multi-worker
   parallelism, but it is a substantial new mechanism (analogous to the
   #917 V_min cross-worker floor, generalized to root-budget
   reservation).

There is no purely-local fix. Anyone proposing one must explain how a
worker honors a smaller class living on a different thread.

---

## 5. Multiple path options

| # | Path | Delivers small-class-first? | Keeps parallelism? | Scope | Risk |
|---|------|:---:|:---:|------|------|
| 1 | **Single-owner per interface (forced)**: change `build_cos_owner_worker_by_queue_*` so all queues of an interface share one owner. | Yes (selector regains visibility) | No (1 core/interface) | Small (1 fn + tests) | Perf regression on multi-queue interfaces; collides with #1183 single-owner-funnel regression history |
| 2 | **Single-owner opt-in knob** (`single-owner` / reuse `guarantee-rate` as the trigger): operators who set `guarantee-rate` accept single-owner for that interface; default stays proportional multi-worker. | Yes, when opted in | Yes for non-opted interfaces | Small-medium (Go knob + wire field + owner-build branch + selector already works) | Doc + operator-expectation surface; per-interface, so blast radius bounded |
| 3 | **Axis B2 cross-worker shaper-budget atomic**: per-interface shared per-class demand + guarantee-priority root-token reservation; generalize #917 V_min. | Yes, fully | Yes | Large (multi-week; new shared atomics, per-worker throttle, rotation) | High; matches #1614 §5.B2 explicitly deferred follow-up; prior dataplane-only fairness mechanisms PLAN-KILLED repeatedly (memory: #1236/#1237/#1239/#1243) |
| 4 | **Document limitation + close**: state that guarantee-rate requires single-owner (future) or B2 (future); keep proportional as the multi-worker behavior; close #1630 with a B2 tracker. | No | Yes | Doc-only | Leaves contract unmet; but honest |

Note Path 2 ⊃ Path 1: Path 2 is Path 1 gated behind opt-in. Path 1
unconditionally is rejected because it regresses the default multi-worker
deployment (the #1183 funnel-collapse precedent: any forced single-owner
CoS funnel collapsed reverse throughput to ~2 G).

---

## 6. Recommendation

**Path 2 (single-owner opt-in), with Path 4's documentation as a
mandatory companion, contingent on the Q1 A/B measurement.**

Rationale grounded in the verified root cause:

- The selector (#1634) is already correct WITHIN single-worker scope.
  Path 2 makes its scope match its assumptions for opted-in interfaces by
  collapsing the interface's queues onto one owner — the smallest change
  that lets the existing waterfill selector actually see all classes.
- Operators who configure `guarantee-rate` are explicitly choosing
  guarantee semantics over raw throughput; coupling that knob to
  single-owner ownership is a defensible, Junos-plausible trade (vSRX
  scheduler hierarchies are per-interface, single-context).
- Keeps the high-throughput default (proportional, multi-worker)
  untouched — no regression for the common case.
- B2 (Path 3) remains the "proper" long-term answer but is out of scope
  for #1630; file as the #1614 §5.B2 follow-up tracker.

**However**, the recommendation is gated on Q1: if the A/B measurement
shows the small-four-alone classes reach ~95%+ (not ~84%), then the
dominant cause is root-pool proportional-starvation under the 9g
competitor, and Path 2's single-owner collapse will ALSO be limited by
the same flat root shaper UNLESS the single owner's local root bucket is
the only consumer (which it would be, since one owner = one root-token
consumer for that interface). Path 2 still wins in that sub-case because
a single owner serializes all classes through one `root.tokens` bucket
and the waterfill selector then arbitrates that bucket guarantee-first.
The A/B simply tells us how much of the 26% gap is recoverable vs.
quantum-efficiency floor.

---

## 7. Implementation sketch (for /engineer, NOT executed here)

Path 2:

1. **Go control plane**: add `single-owner` boolean (or derive from
   `oversubscription-policy guarantee-rate`) on the CoS interface unit;
   plumb through `pkg/config/types.go`,
   `pkg/config/compiler_class_of_service.go`,
   `pkg/dataplane/userspace/protocol.go`,
   `pkg/dataplane/userspace/interfaces.go`.
2. **Wire + Rust config**: new field on `CoSInterfaceConfig`
   (`forwarding_build/cos.rs`), serde in `protocol/cos.rs`.
3. **Owner build**: branch in
   `build_cos_owner_worker_by_queue_with_fallback_ifindexes`
   (`coordinator/mod.rs:935-938`): if the interface is single-owner,
   assign ALL its queues to `eligible_workers[0]` (stable choice).
4. **No selector change** — `select_exact_cos_guarantee_queue_waterfill`
   already does the right thing once it sees all queues. Keep #1634's
   waterfill correction as the foundation (it is correct in-scope).
5. **Root shaper**: with single owner, the interface's `root.tokens` has
   exactly one consumer, so the waterfill selector's small-class-first
   ordering directly governs root-token allocation. Verify the per-class
   v8 lease still caps each class at its rate (it does).
6. **Docs**: `docs/fairness-regimes.md` guarantee-rate section — state
   single-owner requirement + parallelism trade-off; add B2 follow-up
   tracker reference.

---

## 8. Acceptance gate

Canonical reduced-load gate (rules out the cluster-ceiling confound):

- **Gate 1 (primary)**: 5-class simul, demand 19.1 G ≤ 17.5 G Phase-1
  budget on the OPTED-IN interface → each of the four small classes
  (100m/1g/3g/6g) ≥ **95% of configured shape**; iperf-9g takes the
  residual. Run v4 (172.16.80.200) AND v6 (2001:559:8585:80::200).
- **Gate 1b (Q1 A/B)**: small-four-alone (no 9g, demand 10.1 G) → each
  ≥ 95% (establishes the recoverable ceiling and validates the
  quantum-efficiency vs root-starvation split).
- **Gate 2**: priority-low / smallest class ≥ 5% of cluster ceiling (no
  starvation).
- **Gate 3**: per-class retransmits ≤ 100 / 30 s OR explicitly
  rationalized.
- **Gate 4 (no-regression)**: default (proportional, NOT opted-in)
  multi-worker interface aggregate throughput does not regress below
  ~22 G on the standard reverse-path smoke.
- **Gate 5 (CoS matrix)**: full smoke matrix per
  `feedback_cos_iperf3_per_class` / `feedback_smoke_push_and_reverse`
  (v4/v6 × push/-R × CoS-off/CoS-on).

---

## 9. Risk / rollback

- Single-owner collapse on an interface re-introduces the #1183
  funnel-collapse failure mode FOR THAT INTERFACE. Bounded because it is
  opt-in and per-interface; default deployments untouched. Rollback =
  remove the knob / revert the owner-build branch.
- The v8 per-class lease and shared root lease are NOT modified in Path
  2 → no change to the cross-worker atomic protocol, no HA/failover
  surface (memory: any cluster/VRRP/session-sync change needs
  `make test-failover`; Path 2 touches none).

---

## 10. Documentation contract

Per CLAUDE.md module-doc rule: `docs/fairness-regimes.md` guarantee-rate
section MUST be updated to state the single-owner requirement and the
parallelism trade-off; the #1614 umbrella plan's §5.B2 follow-up must be
filed as a real tracker. No code ships without these.

---

## 11. Open questions for hostile reviewers (≥5)

- **Q1 (load-bearing)**: Is the ~26% small-class shortfall dominated by
  (a) root-pool proportional-starvation under the 9g competitor, or (b)
  the quantum-efficiency floor (solo iperf-1g = 84%)? The
  small-four-alone A/B (Gate 1b) discriminates. If (b) dominates, even
  Path 2 cannot reach 95% and the gate itself is unachievable — does the
  gate need to be "≥ 95% of the solo-achievable ceiling" rather than
  "≥ 95% of configured shape"? Quote the solo-84% mechanism
  (`cos_guarantee_quantum_bytes` + drain frame-rounding) and decide.

- **Q2**: With a single owner draining ALL 11 classes through one
  `root.tokens` bucket at up to 25 G, is one core actually capable of
  ~18-25 G of CoS-shaped TX, or does the single-owner path itself become
  CPU-bound below the small-class guarantee sum (10.1 G)? If the owner
  core caps at, say, 12 G, the small-four guarantee (10.1 G) barely fits
  and 9g gets ~2 G — is that acceptable? Need a single-owner CPU-ceiling
  measurement.

- **Q3**: Does the per-class v8 lease's `my_fair_share = cap ×
  my_active_flows / total_active_flows` behave correctly when a single
  owner has flows for MANY queues but each queue lease is independent? Is
  there any cross-queue interaction in `acquire_v8` /
  `worker_active_flow_buckets` that breaks when one worker owns all
  queues (vs the ~2-per-worker the code was tuned against)?

- **Q4**: Is reusing the `guarantee-rate` knob as the single-owner
  trigger (vs a separate `single-owner` knob) safe? Existing configs may
  set `guarantee-rate` on multi-queue interfaces expecting current
  (proportional, multi-worker) behavior; silently collapsing them to
  single-owner is a behavior change on COMMIT. Must single-owner be a
  distinct explicit knob to avoid surprising existing operators?

- **Q5**: The #1634 waterfill selector clones
  `root.exact_queues_by_rate_ascending` into a `Vec` every call
  (`queue_service/mod.rs:807`) and the `honored_mask` is a dead local
  reset per call (lines 806, 913-921). With single-owner (all 11+ queues
  on one worker, hot path), is the per-call `Vec` allocation +
  full-ascending-walk acceptable on the hot drain path, or does Path 2
  surface a hot-path allocation that violates the engineering-style
  no-alloc rule and needs the selector reworked first?

- **Q6**: Path 4 (document + close) — is the guarantee-rate contract
  genuinely worth the single-owner perf cost, or should the project
  accept proportional-under-multi-worker as the documented behavior and
  reserve true guarantee-rate for B2? I.e. is Path 2 solving a problem
  operators actually have, or satisfying a self-imposed contract?
