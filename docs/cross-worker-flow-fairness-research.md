# Cross-Worker Per-Flow Fair Queueing at 100G+ — Research & Design Survey

Status: research / design note (follow-up to PR #785)
Audience: xpf userspace-dp maintainers
Goal: pick the next 2-3 algorithms to prototype for per-flow fairness on
`shared_exact` CoS queues, scaling to 100G / 200G / 400G NICs.

## 1. Problem Statement

xpf's userspace dataplane is an AF_XDP, multi-worker packet forwarder. Each
worker owns one NIC RX queue (fed by RSS), one TX ring, one UMEM slice, and
a local Rust `Arc`-shared view of CoS runtime state. On a CoS queue whose
rate is high enough (≥ 2.5 Gbps on our current 25 Gbps cap) we classify it
as `shared_exact`: the queue can be serviced by *multiple* workers
concurrently, with a shared rate lease that all contending workers draw
from.

With 12 long-lived iperf3 TCP flows through a 25 Gbps `shared_exact` queue,
we observe severely tiered per-flow throughput (1 flow at ~4 Gbps, 2 at
~2.8 Gbps, 7 at ~1.2 Gbps, etc.) rather than the ~2 Gbps/flow even share
the cap permits. Root cause analysis (task #98, issue tracker) shows this
is *not* fundamentally a scheduler problem but an ingress-distribution
problem compounded by a scheduling problem:

1. **RSS toeplitz hash distributes flows unevenly across N RX queues.**
   With 6 RX queues and 12 flows the expected pigeonhole skew is large; a
   worker servicing 3 flows vs a worker servicing 1 flow cannot be made
   per-flow fair by a *per-worker* scheduler alone, because each worker is
   locally work-conserving and will push its own flows through at their
   natural TCP rate.
2. **A per-worker SFQ DRR cannot equalise flows distributed unevenly
   across workers** — SFQ's O(1) fairness guarantee holds only within its
   own queue set.
3. **Naïve global schedulers serialise traffic** and collapse throughput
   (PR #785 slice 1: 22.3 → 16.3 Gbps, +25k retrans when SFQ was flipped
   on shared_exact blindly).
4. **Per-worker rate gate** (`queue_rate × local / total_rate`) achieved
   CoV 4.5% at 1 ms burst but throughput collapsed to 7.7 Gbps
   (#785 slice 2); at 10 ms burst throughput recovered but CoV degraded
   to 63%.

Both gradient directions — "cheap, shared-nothing, per-worker" and "global,
coordinated, serialising" — have clean failure modes. The interesting
regime is the middle: *approximate* global fairness with minimal cross-core
coordination on the data path. Target evaluation axes:

- **Scalability**: linear in worker count. Atomic contention hotspots must
  be bounded (ideally O(1) CAS per batch, not per packet).
- **Implementation cost in Rust/AF_XDP**: zero-copy preserved, shared state
  reuses existing multi-`Arc` pattern, no extra indirection per packet.
- **Fairness quality**: per-flow CoV target ≤ 10% with 10-100 flows; ≤ 20%
  with 1000+ flows.
- **Dynamic flow churn**: handles short-lived TCP (sub-RTT flows) without
  per-flow allocation on the hot path.
- **Hardware assistance needed**: ideally none; willing to use Mellanox
  ConnectX-6 programmable flow steering where it cleanly amortises work.

Scope: this doc surveys candidate algorithms, ranks them against xpf's
constraints, and names the 2-3 to prototype next.

---

## 2. Survey of Candidate Approaches

Ranked best-fit → worst-fit for xpf's constraints.

### 2.1 Multi-Queue Fair Queueing (MQFQ) — Hedayati & Shen, USENIX ATC '19

*Best theoretical fit for the "per-worker queue + global fairness"
shape we already have.*

MQFQ is the most directly relevant published result. It was designed for
NVMe-over-RDMA fabrics where each CPU core has its own submission queue
(like each xpf worker has its own TX ring + local CoS queue view) but a
fair share of device throughput must be maintained across queues.

**Core idea:**
- Each local queue maintains start/finish virtual-time tags per dispatched
  request, in the classic WFQ/DRR sense.
- A single 64-bit global minimum virtual-time `V_min` is tracked (or
  approximated via a token tree).
- A local queue is allowed to dispatch as long as its local virtual time
  satisfies `S_local ≤ V_min + T`, where **T is the throttle threshold**
  that bounds unfairness.
- If `S_local > V_min + T` the queue self-throttles until `V_min` catches
  up.

**Fairness bound:** MQFQ proves unfairness is bounded by O(T) — tunable by
the operator. Larger T = more work conservation and less coordination, but
wider fairness bound. Smaller T = tighter fairness at the cost of more
cross-core sync.

**Cross-core contention:** `V_min` is the only global state; it is updated
cheaply (either with one atomic-min CAS per dispatch batch, or via a token
tree where each leaf holds a per-core virtual time and parents hold the
local minimum — O(log N) reads/writes, cache-aligned).

**Work conservation:** retained unless *all* local queues are throttled
*and* have work pending. The paper shows near-ideal work conservation in
practice at practical T values.

**Mapping onto xpf:**
- Each worker's local view of a `shared_exact` CoS queue gets a virtual
  finish-time field per flow (replace existing per-worker SFQ round robin
  with DRR + virtual time).
- One atomic `V_min` per `shared_exact` queue (cache-line-aligned), updated
  on each drain batch.
- Throttle check: before a worker dequeues its *N*th byte from the queue
  in a poll iteration, if `local_virt_time − V_min > T_bytes` it yields.
- T is set to a few packet times at line rate (e.g., 64 KB at 25 Gbps ≈
  21 µs; at 100 Gbps ≈ 5 µs). Burst budget remains large enough that
  small flows don't starve.

**Strengths:** matches our architecture point-for-point (per-core queue,
device with shared throughput, fairness required across queues).
Published fairness bounds, real-world 3.1 Mops/s at 20× the prior art.
Trivially generalises to N workers.

**Weaknesses:** requires O(1) atomic read of `V_min` per batch, but this
is a *read* of a single hot cache line; contention is bounded. Virtual
time arithmetic is O(1) per flow. Requires revisiting the SFQ DRR machinery
we already have in place.

**xpf prototype sketch:** 2-3 weeks. Replace `WorkerCoSQueueFastPath`'s
SFQ promotion gate with a DRR-over-flow-hash that also advances a local
virt time. Add `Arc<AtomicU64>` for `V_min` on `CoSQueueRuntime` for every
`shared_exact` queue. Throttle path: spin/yield, same as current per-worker
rate gate but with a correct invariant.

Sources: [Hedayati & Shen, Multi-Queue Fair Queueing (ATC '19)](https://www.usenix.org/system/files/atc19-hedayati-fair-queuing.pdf), [slides/abstract](https://www.usenix.org/conference/atc19/presentation/hedayati-queue)

---

### 2.2 RSS++ — Barbette et al., CoNEXT '19

*Attack the root cause: fix NIC flow→worker distribution.*

RSS++ is not a scheduler; it is a runtime that modifies the NIC RSS
indirection table ~10× per second to rebalance RSS buckets across cores.
It monitors per-bucket packet rate, solves a load-balancing optimisation,
and reassigns buckets — with a lockless flow-state migration technique
that avoids dropped packets during reassignment.

**Mapping onto xpf:**
- We already have a multi-worker XSK bind set; RSS buckets map to those.
- Mellanox ConnectX-6 supports indirection-table updates via ethtool and
  via `rte_flow` / `devlink` (rate-limited but fast enough — the paper
  targets 10 Hz rebalance).
- Requires symmetric Toeplitz key so both halves of a flow land on the
  same bucket (we should verify the current RSS key).
- Requires flow-state migration: any per-worker session cache or NAT slot
  may need to be drained/moved when the bucket it owns is reassigned.

**Strengths:** attacks the actual root cause. Upstream results show 14×
lower p95 tail latency and "orders of magnitude fewer drops" under
imbalanced RSS. Complementary to every other scheduler approach — RSS++
reduces the imbalance the scheduler has to correct.

**Weaknesses:**
- Not a fairness primitive on its own. It equalises *core utilisation*;
  it does not equalise *per-flow rate* among flows in the same bucket.
  Two flows on the same RSS bucket still share one worker's share of a
  `shared_exact` lease.
- Flow-state migration is not free in Rust; our session tables are
  multi-Arc and not trivially re-hosted between workers. Would need to
  either (a) keep sessions sharded by RSS bucket and migrate buckets +
  sessions together, or (b) fall back to lookup-by-key across all workers
  after migration.
- NIC-specific. We're on ConnectX-6 today, but we want a strategy that
  also works on a next-gen Broadcom or Intel 800-class NIC without a
  driver-specific adapter.
- Indirection-table update rate has implementation-specific limits
  (ConnectX has reported ≥ 1M cycles for some `rte_flow_async_create`
  paths — adequate for 10 Hz rebalance, marginal for sub-ms).

**xpf prototype sketch:** 3-5 weeks. Needs a periodic RSS rebalancer task
on the control plane, symmetric hash key verification, and a flow-state
migration protocol for the per-worker session cache. Most of the work is
wiring rather than algorithm.

Sources: [RSS++: load and state-aware receive side scaling (CoNEXT '19)](https://dl.acm.org/doi/10.1145/3359989.3365412), [APNIC summary](https://blog.apnic.net/2020/01/28/rss-a-new-model-for-elastic-high-speed-networking/)

---

### 2.3 Core-Stateless Fair Queueing (CSFQ) + Approximate Fair Dropping (AFD)

*Push per-flow state out of the hot path; keep workers stateless.*

CSFQ (Stoica, Shenker, Zhang, SIGCOMM '98) was designed for internet core
routers that cannot afford per-flow state. The edge estimates each flow's
rate and writes a label into the packet; the core drops probabilistically
based on the label vs a running estimate of the fair rate.

AFD (Pan et al., SIGCOMM CCR '03) is the "no-edge" version: a single
shared FIFO keeps a bounded history, estimates per-flow rate from the
history, and drops probabilistically proportional to each flow's excess
over the fair share.

**Mapping onto xpf:**
- A `shared_exact` queue is conceptually one "router" with multiple
  parallel service stations (workers).
- Each worker can independently run the AFD drop test against a shared,
  lock-free per-flow rate estimator (e.g., a sharded Count-Min sketch with
  exponential decay).
- No hard per-flow queueing state: workers dequeue FIFO from their own TX
  ring, drop on ingress before enqueue into the CoS queue.

**Strengths:**
- Extremely cheap hot path: hash flow, look up estimated rate, compute
  drop probability, drop or forward. O(1) per packet, one shared read.
- Flow-churn-friendly: a Count-Min sketch has constant memory regardless
  of active flow count.
- Maps cleanly to Rust atomics — the rate estimator is a shared `Arc<[...]>`
  of decaying counters; writes are atomic-add; reads are relaxed.
- Proven fairness results going back 25 years; actively revisited in
  modern data-plane papers ("Twenty Years After: Hierarchical CSFQ", NSDI
  '21).

**Weaknesses:**
- AFD is a *drop* scheme, not a *queueing* scheme. It trades throughput
  for fairness under excess offered load — which is exactly the
  `shared_exact` case. TCP CWND will react to drops and back off, which is
  what we want, but it relies on TCP's congestion control being well-behaved.
  UDP (or badly-behaved TCP) will see real drops.
- The fair-rate estimator has a convergence time (typically a few RTTs);
  during that window fairness is approximate.
- Our `_Log.md` / bugs.md history shows we already tried admission-based
  dropping (#705, #718) and hit TCP CWND collapse when dropping was too
  aggressive. An AFD-style prototype must validate that the drop rate is
  proportional (not greedy) to excess.

**xpf prototype sketch:** 2 weeks. Implement a sharded Count-Min sketch
per `shared_exact` queue; add an AFD drop test in front of the CoS
enqueue; preserve ECN-marking mode (if DCTCP/CUBIC are in use, marking
is preferable to dropping). Telemetry: per-flow drop/mark rate.

Sources: [Stoica, Shenker, Zhang, CSFQ (SIGCOMM '98)](https://people.eecs.berkeley.edu/~istoica/classes/cs268/10/papers/afd.pdf), [Pan et al., Approximate Fair Dropping (SIGCOMM CCR '03)](https://dl.acm.org/doi/10.1145/956981.956985), [Yu et al., Twenty Years After: Hierarchical CSFQ (NSDI '21)](https://www.usenix.org/conference/nsdi21/presentation/yu)

---

### 2.4 Symmetric-Toeplitz RSS + Tuned Indirection Table (no runtime rebalance)

*The "before RSS++" baseline: just ensure RSS is evenly configured.*

Before we commit to dynamic rebalancing, verify that the NIC is in the
best static configuration. Intel 800-series and Mellanox ConnectX-5/6 both
support:
- **Symmetric Toeplitz** (or symmetric-XOR) hash keys — same hash for both
  halves of a 4-tuple flow. xpf is stateful, so we want both directions on
  the same worker anyway. mTCP and Cloudflare use this pattern widely.
- **Indirection table weighting** via ethtool. A 128- or 512-entry
  indirection table with flat weights gives the best *expected* spread;
  non-flat weighting is only useful if you're deliberately quarantining a
  bad queue.

**Strengths:** zero implementation cost. One ethtool call.

**Weaknesses:** pure hashing at small flow counts has high variance
(pigeonhole at 12 flows / 6 queues ≈ 2× skew in worst case is
unavoidable). Does not self-correct. A necessary but not sufficient step.

**xpf prototype sketch:** 1 day. Audit `ethtool -x` on the test NICs;
verify symmetric key; flatten indirection table.

Sources: [Linux kernel scaling.rst](https://docs.kernel.org/networking/scaling.html), [Intel symmetric RSS patch series](https://lore.kernel.org/netdev/20231016154937.41224-1-ahmed.zaki@intel.com/T/), [Cloudflare "symmetric RSS"](https://blog.cloudflare.com/)

---

### 2.5 Carousel / Eiffel — Timing-Wheel Single-Queue Shapers

*Conceptually elegant; not a great fit for xpf's shape.*

Carousel (Saeed et al., SIGCOMM '17) is a per-core timing-wheel shaper
where packets are indexed by their intended send time. Eiffel (Saeed et
al., NSDI '19) generalises this with a Find-First-Set-based integer
priority queue and claims 3-14× speedup over FQ/Carousel.

**Architectural match:**
- Carousel explicitly uses *one timing wheel per core*, with per-core
  allocation of aggregate bandwidth via a "water-filling" algorithm —
  i.e., the multi-core fairness mechanism is *outside* the data-plane
  timing wheel. This is approximately what we already tried in slice 2
  (per-worker rate gate from `queue_rate × local / total`).
- Eiffel's FFS priority queue is excellent for per-core scheduling
  throughput but does not address cross-core fairness.
- Both systems' strength is *rate conformance* for many independent
  tokenised flows; our problem is *equalisation among a small number of
  uncoordinated flows*.

**Strengths:** excellent per-core raw performance; well-understood.
Single-queue timing-wheel avoids priority-queue log-n cost.

**Weaknesses:** the multi-core fairness question is left to the
surrounding system. Carousel's NBA (NIC Bandwidth Allocation) is
"periodic, approximate" and is explicitly called out in the paper as not
providing exact cross-core fairness. Our slice 2 experiment effectively
validated this: allocating bandwidth quotas across workers produces either
collapse (tight burst) or unfairness (loose burst), depending on burst
parameter.

Useful as a *building block inside* an MQFQ or CSFQ implementation (e.g.,
Eiffel-style integer priority queue for the per-worker DRR), but not as a
cross-worker fairness mechanism on its own.

Sources: [Saeed et al., Carousel (SIGCOMM '17)](https://saeed.github.io/files/carousel-sigcomm17.pdf), [Saeed et al., Eiffel (NSDI '19)](https://www.usenix.org/system/files/nsdi19-saeed.pdf)

---

### 2.6 Approximate Fair Queueing (AFQ) on Reconfigurable Switches

*Promising in switch ASICs; moderate fit in software.*

AFQ (Sharma et al., NSDI '18, and follow-ups) approximates PIFO with a
rotating set of priority FIFOs. Each FIFO represents a "time bucket" in
virtual time. A packet's bucket is determined by its flow's virtual
finish time. As virtual time advances, buckets rotate.

**Mapping onto xpf:**
- Small number of FIFOs (typically 8-32) per `shared_exact` queue.
- Each worker hashes the flow, computes virtual finish time, picks a FIFO
  index. Enqueue/dequeue is lock-free if each FIFO is a per-shard MPMC
  ring (or an MPSC ring per worker per bucket).
- The service order is strict priority on bucket index; this naturally
  gives WFQ-equivalent fairness.

**Strengths:** much simpler than full PIFO; composes with our existing
per-worker TX ring architecture. Well-studied fairness properties.

**Weaknesses:** 8-32 FIFOs × N workers × M queues is a lot of queues.
Rotating the priority base requires coordination (all workers must agree
on current virtual-time base). In hardware this is trivial (single
counter); in software it's another shared atomic — similar cost to MQFQ's
`V_min`, but with more data structures.

AFQ is strictly simpler *conceptually* than MQFQ but has more moving
parts in a multi-worker Rust/AF_XDP implementation. It is also strictly
*less work-conserving* at the boundaries between virtual-time buckets.

**xpf prototype sketch:** 3-4 weeks. More infrastructure than MQFQ; same
theoretical fairness bound.

Sources: [Approximating Fair Queueing on Reconfigurable Switches (NSDI '18)](https://homes.cs.washington.edu/~arvind/papers/afq.pdf)

---

### 2.7 PIFO / SP-PIFO / AIFO — Programmable Packet Schedulers

*Designed for switch ASICs. Software analogs are stretched.*

- **PIFO** (Sivaraman et al., SIGCOMM '16): arbitrary-priority push, FIFO
  pop. The theoretical basis for programmable scheduling; real hardware
  implementations exist only in recent P4 switches.
- **SP-PIFO** (Alcoz et al., NSDI '20): approximates PIFO with 8 strict-
  priority queues, adaptive rank→priority mapping.
- **AIFO** (Yu et al., SIGCOMM '21): PIFO approximation with a *single*
  FIFO and a sliding-window rank admission test.

**Software relevance:**
- The "rank" abstraction is clean: compute a virtual time per packet at
  enqueue, use it to gate admission.
- AIFO maps particularly well to the AFD / CSFQ family — it is effectively
  a more principled admission-control drop scheme.
- SP-PIFO doesn't buy much in software: 8 priority queues per CoS queue is
  fine, but so is a Tree-based DRR. The "adaptive mapping" is the
  interesting bit.

Treat these as *design inspiration* — the rank+admission-window pattern
(AIFO) is worth borrowing inside an MQFQ or AFD prototype, but neither is
a ready-to-implement multi-core scheduler.

Sources: [Sivaraman et al., PIFO (SIGCOMM '16)](https://anirudhsk.github.io/papers/pifo-sigcomm.pdf), [Alcoz et al., SP-PIFO (NSDI '20)](https://www.usenix.org/conference/nsdi20/presentation/alcoz), [Yu et al., AIFO (SIGCOMM '21)](https://www.cs.jhu.edu/~zhuolong/papers/sigcomm21aifo.pdf)

---

### 2.8 DPDK QoS Hierarchical Scheduler

*Existing battle-tested implementation; wrong threading model for us.*

DPDK's `rte_sched` library implements a 5-level hierarchical token-bucket
scheduler (port → subport → pipe → traffic class → queue) with thousands
of leaf queues, rate limiting, and weighted DRR. Used in Cisco VPP and many
downstream NFV stacks.

**Architectural fit:** the DPDK QoS scheduler is explicitly **single-thread
per port**: "scheduler enqueue and dequeue operations have to be run from
the same thread, which allows the queues and the bitmap operations to be
non-thread-safe." Per-core workers feed the scheduler thread via lock-free
software rings.

This is the PSPAT pattern (single arbiter thread, lock-free mailboxes from
workers) at the library level. It is explicitly *not* what we have — our
workers both classify *and* transmit. Retrofitting a dedicated arbiter
thread means:
- One more context switch on the hot path.
- Lock-free MPMC rings per worker → arbiter (similar to our current
  `mpsc_inbox` but on every packet instead of just HA events).
- The arbiter becomes the throughput ceiling — 25 Gbps out of one core
  is feasible, 200 Gbps is not.

**Strengths:** proven at scale in production NFV. Deep hierarchy support
(we'd get multi-tenant pipe/TC/queue for free).

**Weaknesses:** wrong threading model. Would require a substantial
refactor of the xpf worker pipeline. The single-thread arbiter is a fixed
cost ceiling we don't want at 100G+.

Sources: [DPDK QoS Framework docs](https://doc.dpdk.org/guides/prog_guide/qos_framework.html), [PSPAT (Computer Communications '18)](https://docenti.ing.unipi.it/l.rizzo/papers/20160921-pspat.pdf)

---

### 2.9 DCTCP / ECN Marking at the Scheduler Layer

*Complementary, not a replacement.*

DCTCP and related ECN-based congestion controls give the *endpoint*
precise signal about queue depth, so the endpoint can reduce its window.
In a multi-tenant, multi-flow, single-queue world, ECN on a shared queue
gives *aggregate* signal — every flow in the queue sees the same mark
probability. This is fair *to well-behaved ECN-aware flows* but does
nothing to police misbehaving flows, and our test matrix (iperf3 -P 12)
will not trigger DCTCP-style fairness improvements on a non-ECN path.

We already mark on CoS queues (issue #747 for the per-flow ECN signal
extension). ECN is a supporting actor: combined with AFD-style per-flow
rate tracking, ECN marking becomes a precise per-flow signal (mark the
flows exceeding fair share, leave the rest). That's the essence of
modern approximate-fair-queueing papers like CodelAF.

Sources: [DCTCP RFC 8257](https://datatracker.ietf.org/doc/html/rfc8257), [CodelAF draft](https://datatracker.ietf.org/doc/id/draft-morton-tsvwg-codel-approx-fair-01.html)

---

### 2.10 Work Stealing / Shenango / Caladan

*Scheduler for cores, not for packets.*

Work-stealing schedulers (Cilk, Tokio, Go runtime) and Shenango/Caladan's
core-allocation runtime solve a different problem: how to allocate *CPU
cores* fairly across *applications*. They do not solve per-flow fairness
within a single application's packet stream.

A work-stealing-style rebalancer is orthogonally useful (rebalance
workers that are lightly loaded to pick up packets from heavily-loaded
workers' queues — similar to RSS++ but in software only). But our primary
problem is per-flow, not per-worker utilisation.

Sources: [Ousterhout et al., Shenango (NSDI '19)](https://amyousterhout.com/papers/shenango_nsdi19.pdf), [Fried et al., Caladan (OSDI '20)](https://amyousterhout.com/papers/caladan_osdi20.pdf)

---

### 2.11 Google Snap / Pony Express / Aquila

*Public details limited; mostly hardware-assisted fairness.*

Snap uses a "MicroQuanta" kernel scheduling class for CPU fair-share
between Snap engine tasks and other processes; its multi-tenancy story
is "if you overrun a one-sided engine, packets get dropped and congestion
control takes care of it". Pony Express relies on congestion control for
fairness, not on a scheduler-layer mechanism.

Aquila (NSDI '22) is a cell-switched datacenter fabric with fairness
enforced at L2 via solicit/grant — not applicable to a general-purpose
firewall.

None of these are directly implementable in our constraints, but they
confirm a general principle: at very high rates, the design point that
scales is *admission control* (drop/mark on excess) rather than
*reservation* (per-flow scheduler state). That reinforces the CSFQ/AFD
recommendation.

Sources: [Marty et al., Snap (SOSP '19)](https://courses.grainger.illinois.edu/CS598HPN/fa2020/papers/snap.pdf), [Gibson et al., Aquila (NSDI '22)](https://www.usenix.org/system/files/nsdi22-paper-gibson.pdf)

---

## 3. Comparative Table

| Approach | Scalability | Rust/AF_XDP cost | Per-flow fairness (CoV) | Churn friendly | HW assist | xpf prototype effort |
|---|---|---|---|---|---|---|
| **MQFQ** (2.1) | O(log N) V_min + O(1)/batch CAS; linear | Low — reuses existing per-worker queue; 1 `Arc<AtomicU64>` per shared_exact queue | Bounded by T, tunable; ~10% at sensible T | Yes — per-flow state is small & reused | None | 2-3 weeks |
| **RSS++** (2.2) | Control-plane O(workers) every ~100 ms; data-plane free | Medium — NIC config + flow-state migration | Indirect — equalises *utilisation*, not per-flow | Partial — migration needed for long-lived flows | ConnectX-6 flow steering | 3-5 weeks |
| **CSFQ / AFD** (2.3) | O(1) per packet; single hot cache line (Count-Min) | Low — no per-flow queues; sharded atomic counters | Approximate, depends on estimator; 10-20% steady state | Excellent — CM sketch is fixed memory | None (optional ECN marking) | 2 weeks |
| **Symmetric RSS + flat indirection** (2.4) | Trivial | ~0 | Floor-setter: eliminates obvious RSS bugs, does not solve pigeonhole | Yes | ethtool only | 1 day |
| **Carousel/Eiffel** (2.5) | Per-core excellent; cross-core fairness unsolved | High — integrate into our dispatcher | Not directly applicable | Yes | None | 4-6 weeks (for limited benefit) |
| **AFQ** (2.6) | O(1) per packet; shared rotation counter | Medium — N × M × 8-32 rings | Bucketed, ≈ WFQ ± 1 bucket | Yes | None | 3-4 weeks |
| **PIFO / SP-PIFO / AIFO** (2.7) | HW-first; software stretches | High | Best in HW; as software inspiration only | Yes | P4 switch helpful | 4-8 weeks as lift |
| **DPDK QoS / PSPAT** (2.8) | Single-arbiter ceiling (~25 Gbps/core) | High — architectural refactor | Excellent per-port | Yes | None | 6-10 weeks |
| **DCTCP / ECN marking** (2.9) | O(1) | ~0 (already have mark path) | Complementary only | Yes | None | Already largely present |
| **Work stealing** (2.10) | Orthogonal | Medium | Does not solve per-flow | Yes | None | Not applicable directly |

---

## 4. Recommendation

Prototype, in order:

### Rec. 1 — Baseline check: symmetric RSS + flat indirection (§2.4), ~1 day

Before any algorithmic work, verify that the `shared_exact` RSS imbalance
we're chasing is not partly caused by non-symmetric Toeplitz keys or a
weighted indirection table from the vendor default. This is cheap and
either (a) closes part of the problem or (b) rules out a confounder
before we design the real fix. Mechanic:

- `ethtool -x <iface>` — dump current RSS key and indirection table.
- `ethtool -X <iface> equal N hkey <symmetric-key>` — flatten and install
  a verified symmetric key (mTCP, DPDK, and Mellanox docs all publish the
  standard one).
- Re-run the iperf3 -P 12 fairness test; record deltas.

### Rec. 2 — MQFQ-style cross-worker virtual time gate (§2.1), 2-3 weeks

This is the primary recommendation. It exactly matches the architectural
shape we already have (per-worker local queues + one virtualised resource)
and gives provable fairness bounds at minimal hot-path cost.

Prototype slice:
- Add `Arc<AtomicU64>` `v_min` to `CoSQueueRuntime` for every `shared_exact`
  queue.
- Maintain per-worker `v_local` = DRR virtual finish time of the last
  packet dispatched from this `shared_exact` queue.
- On each drain batch: read `v_min` once (relaxed). If `v_local − v_min >
  T_bytes`, yield this queue for the batch (do not block the worker — do
  other queues). Periodically update `v_min = min(v_local across workers)`
  via a sweep task (cheap; same cadence as current rate-lease refresh).
- Tune T. Start at `T_bytes = 2 × per_flow_BDP_at_queue_rate`; we expect
  this to give CoV ≤ 10% on iperf3 -P 12 at 25 Gbps without throughput
  regression.
- Anti-regression: keep slice 2's per-worker rate gate as a fallback behind
  a feature flag; benchmark both on `test-failover` and `make cluster-deploy`.

Success criteria: CoV ≤ 15% at 25 Gbps, 0 retrans increase over baseline,
scaling curve shows ≤ 5% throughput drop vs work-conserving baseline at
100 Gbps (modelled).

### Rec. 3 — AFD-style approximate fair dropping with ECN marking (§2.3), 2 weeks

Run this **in parallel** to MQFQ as an orthogonal hedge:

- Per `shared_exact` queue, maintain a sharded Count-Min sketch of bytes
  per 5-tuple over a sliding 10 ms window (4 rows × 1024 columns, atomic
  u32 counters, per-worker write shards to avoid contention, summed on
  read).
- On ingress into the CoS enqueue: estimate flow rate; if above fair share
  (queue_rate / active_flow_estimate) then drop (or ECN-mark if ECT set)
  with probability proportional to excess.
- Telemetry: per-flow mark/drop counts.

Why in parallel: AFD may work better *with* MQFQ (the estimator drives ECN
marks, MQFQ drives scheduling) than either alone. Also, AFD protects
against UDP / non-ECN-aware misbehaving flows, which MQFQ alone does not.

If both land, the final system is: RSS++-style rebalancing (optional
Phase 3) → MQFQ for scheduling → AFD for ingress-side fairness of
misbehaving flows.

### Rec. 4 (deferred to Phase 3) — RSS++ dynamic indirection rebalance (§2.2)

Defer until Phase 2 is proven out. RSS++ is high-value but high-complexity
(flow-state migration in Rust is nontrivial with the current Arc-based
session sharing). If MQFQ + AFD together get us CoV ≤ 15% at 100G+ on
synthetic workloads, RSS++ is unnecessary. If we still see imbalance past
that, RSS++ is the cleanest next step.

---

## 5. Open Questions

1. **What is the current ConnectX-6 RSS key?** We must verify before
   investing in RSS++ or accepting any fairness measurement as
   representative. One ethtool dump answers this.

2. **Is the existing per-worker SFQ DRR the right building block for
   MQFQ?** MQFQ operates on a single "flow queue" model with virtual-time
   tags. Our SFQ has bucket hashing. Prototype: adapt
   `WorkerCoSQueueFastPath` promotion path to produce virtual-time tags
   per flow; don't collapse into buckets on `shared_exact`.

3. **Can we get per-flow telemetry cheaply enough to *measure* fairness
   CoV in production, not just in test?** A production-safe p99 CoV
   monitor would let us tune T online without re-running iperf3. This is
   the same tooling question #747 raises for ECN.

4. **What is the cross-worker `V_min` update cadence for MQFQ?** The
   paper uses a sweep; we may be able to piggyback on the existing 1-Hz
   rate-lease refresh. If that's too coarse, a lock-free atomic-min CAS
   per drain batch is the fallback. Need to measure the cache-line traffic.

5. **Does Mellanox ConnectX-6 support symmetric-XOR hash or only
   symmetric-Toeplitz?** Relevant for Rec. 1. The mlx5 DPDK docs claim
   symmetric Toeplitz is supported; the kernel driver patchset for
   symmetric XOR is landed in 6.8+. We are on 6.18+, so both should work.

6. **How does MQFQ interact with HA session sync and failback?** Virtual
   time state is per-worker per-queue; on failover it must be re-initialised
   (fine — the lease refresh already resets). Cross-check that the sync
   protocol does not need to carry any MQFQ state.

7. **Is there a simpler "minimal MQFQ" shape we can ship first?** A
   degenerate variant: one shared atomic "bytes dispatched this second"
   counter per queue, and each worker's dispatch rate is capped at
   `(queue_rate × local_active_flows / global_active_flows)` — i.e., a
   self-adjusting version of slice 2's per-worker rate gate where
   `total_rate` is replaced with a live count. This may give 80% of
   MQFQ's benefit with 20% of the implementation; worth evaluating as
   slice 1.

8. **Do we need hierarchical scheduling or is flat-per-queue enough?**
   Today's `shared_exact` is flat. If we ever add sub-classes (guaranteed
   vs best-effort, or DSCP-hierarchical rewrite already wired into
   firewall filters), we'll want an AFQ- or DPDK-QoS-style hierarchy. For
   now, MQFQ-flat is sufficient.

---

## 6. References

**Papers:**
- Hedayati & Shen, "Multi-Queue Fair Queueing", USENIX ATC 2019 — https://www.usenix.org/system/files/atc19-hedayati-fair-queuing.pdf
- Barbette et al., "RSS++: load and state-aware receive side scaling", CoNEXT 2019 — https://dl.acm.org/doi/10.1145/3359989.3365412
- Stoica, Shenker, Zhang, "Core-Stateless Fair Queueing", SIGCOMM 1998 — https://people.eecs.berkeley.edu/~istoica/classes/cs268/10/papers/afd.pdf
- Pan et al., "Approximate Fairness through Differential Dropping", SIGCOMM CCR 2003 — https://dl.acm.org/doi/10.1145/956981.956985
- Yu et al., "Twenty Years After: Hierarchical Core-Stateless Fair Queueing", NSDI 2021 — https://www.usenix.org/conference/nsdi21/presentation/yu
- Saeed et al., "Carousel: Scalable Traffic Shaping at End Hosts", SIGCOMM 2017 — https://saeed.github.io/files/carousel-sigcomm17.pdf
- Saeed et al., "Eiffel: Efficient and Flexible Software Packet Scheduling", NSDI 2019 — https://www.usenix.org/system/files/nsdi19-saeed.pdf
- Sharma et al., "Approximating Fair Queueing on Reconfigurable Switches", NSDI 2018 — https://homes.cs.washington.edu/~arvind/papers/afq.pdf
- Sivaraman et al., "Programmable Packet Scheduling at Line Rate" (PIFO), SIGCOMM 2016 — https://anirudhsk.github.io/papers/pifo-sigcomm.pdf
- Alcoz et al., "SP-PIFO", NSDI 2020 — https://www.usenix.org/conference/nsdi20/presentation/alcoz
- Yu et al., "Programmable Packet Scheduling with a Single Queue" (AIFO), SIGCOMM 2021 — https://www.cs.jhu.edu/~zhuolong/papers/sigcomm21aifo.pdf
- Rizzo et al., "PSPAT: Software packet scheduling at hardware speed", Computer Communications 2018 — https://docenti.ing.unipi.it/l.rizzo/papers/20160921-pspat.pdf
- Marty et al., "Snap: a Microkernel Approach to Host Networking", SOSP 2019 — https://courses.grainger.illinois.edu/CS598HPN/fa2020/papers/snap.pdf
- Gibson et al., "Aquila: A unified, low-latency fabric for datacenter networks", NSDI 2022 — https://www.usenix.org/system/files/nsdi22-paper-gibson.pdf
- Ousterhout et al., "Shenango", NSDI 2019 — https://amyousterhout.com/papers/shenango_nsdi19.pdf
- Fried et al., "Caladan", OSDI 2020 — https://amyousterhout.com/papers/caladan_osdi20.pdf

**Production system docs:**
- Linux kernel scaling.rst (RSS / RPS / RFS / aRFS) — https://docs.kernel.org/networking/scaling.html
- DPDK QoS Framework — https://doc.dpdk.org/guides/prog_guide/qos_framework.html
- FD.io VPP QoS Hierarchical Scheduler — https://docs.fd.io/vpp/20.05/df/dff/qos_doc.html
- NVIDIA/Mellanox MLX5 DPDK driver (rte_flow, symmetric RSS) — https://doc.dpdk.org/guides/nics/mlx5.html
- Linux `tc-fq(8)` — https://man7.org/linux/man-pages/man8/tc-fq.8.html
- Linux `tc-fq_codel(8)` — https://man7.org/linux/man-pages/man8/tc-fq_codel.8.html

**Engineering blogs:**
- APNIC on RSS++ — https://blog.apnic.net/2020/01/28/rss-a-new-model-for-elastic-high-speed-networking/
- Cloudflare on AF_XDP — https://blog.cloudflare.com/a-story-about-af-xdp-network-namespaces-and-a-cookie/
- Meta Katran (symmetric RSS via encapsulation) — https://engineering.fb.com/2018/05/22/open-source/open-sourcing-katran-a-scalable-network-load-balancer/

**Adjacent xpf history:**
- PR #785 — userspace-dp: refactor CoS SFQ promotion + shared_exact hook
- Closed: #705, #711 (SFQ bucket collisions), #691, #693 (per-flow admission on exact queues), #690 (single-owner exact queues), #689 (RR semantics), #747 (per-flow ECN signal), #774, #775 (perf ceiling campaigns)
