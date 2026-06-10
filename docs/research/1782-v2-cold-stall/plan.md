# #1782 v2 — Residual cold-start stall: re-research against current master

**Status:** DRAFT v1 — re-verification of the prior converged plan
(`7c8e9d015`, branch `research/1782-cold-start-stall-residual`) against
current master (`d30cfab84`) plus a 10-reproduction live induction
campaign on the loss userspace cluster (2026-06-10). The prior plan's
neighbor causal chain is real but **was never engaged by the
operator-shaped stall**; the stall reproduces on demand and is pinned
to the **CoS exact-queue token/lease cold-start after idle** (§4). The
PR-2 neighbor fix (Option B first-miss reuse) is recommended for
**PLAN-KILL as the #1782 fix**; a new, CoS-scoped PR-2 is specified
instead (§5).

## 1. What changed since the prior plan converged

| Change | Effect |
|---|---|
| #1771 §2.2 (PR #1779) | `pending_neigh` = FastMap keyed `(egress_ifindex, next_hop)`, keep-OLDEST; H5 sibling-drop site is the tested `pending_neigh_admission` (`neighbor_dispatch.rs:74-82`). |
| #1771 §2.5/§2.6 | ENOBUFS → throttled upsert-only re-dump + `netlink_enobufs/redumps/redump_upserts` (`neighbor.rs:681-730`). The "helper silently misses a NEWNEIGH forever" H2 sub-mechanism is largely closed. |
| #1771 Phase 3 (#1833) | `neighbor_pending_keys`/`neg_neigh_keys` gauges — merged to master AFTER the deployed cluster build `a05a73694` (not yet live there). |
| #1787 learn elision | No change to idle dynamics — §2.4. |
| #1780 Path A | Loop cannot freeze; phase ages on fw1 live-verified within cadence. |
| PR-1 (#1782, `f25b1bca`) | All instruments verified live on fw1; `XPF_DEBUG_NEIGHBOR_KEYS=1` active; membership gauge populated (170 series). |

## 2. Re-verified neighbor code map (current master file:line)

### 2.1 What removes/expires `dynamic_neighbors` during idle

There is **no userspace TTL**. Exhaustive removal paths:

1. Helper netlink monitor: RTM_NEWNEIGH with INCOMPLETE|FAILED
   (`neighbor.rs:374-377`), RTM_DELNEIGH (`neighbor.rs:388`).
2. Manager snapshot replace (`coordinator/mod.rs:151-204`): removes
   only `manager_keys` it previously pushed, atomically under one
   bulk shard acquisition.
3. #1769 resolver authoritative-FAILED revoke
   (`neighbor_resolver.rs:419-426`) — Stage-2 only;
   `resolver_get_attempts` has never been nonzero in the lab
   (#1771 Phase-3 gate + this whole session).

**Kernel-side idle decay:** REACHABLE→STALE after ~30 s; a STALE
entry emits no further netlink events. On this cluster the kernel
never GCs it: `neigh_periodic_work` requires table >
`gc_thresh1=128`; live fw1 has 60 v4 + 50 v6 entries. So
DELNEIGH-from-GC — the prior plan's leading H2 trigger — is
**structurally off** here.

**Go-side keeps the kernel warm:** `forceProbeNeighbors`
(`pkg/daemon/daemon_neighbor_listener.go:361-393`; target set =
published snapshot keys + fabric peers, `:404-521`) probes every 15 s;
`cleanFailedNeighbors` (`pkg/daemon/daemon_neighbor.go:310-356`)
deletes FAILED + reprobes every 5 s. Live-verified: after 9+ h of
data-path idle, fw1's kernel entries for 172.16.80.200 (v4+v6) are
REACHABLE and present in `dynamic_neighbor_present` (dual keys,
ifindex 14 = `ge-7-0-2.80`, 6 = physical).

### 2.2 First-miss (Stage-1) path today

`poll_descriptor/mod.rs` MissingNeighbor arm: `neg_neigh_gate` `:2072`
(3 s TTL, `afxdp/mod.rs:368`); fast-fail counter `:2095-2098`;
resolver enqueue (throttled 100 ms, `neighbor_resolver.rs:103`)
`:2118-2175`; Stage-1 `trigger_kernel_arp_probe` `:2237`; buffer
admission `:2503-2536`. Retry sweep (`neighbor_dispatch.rs:85-310`):
probe re-fire 10/60/260 ms (`:36-40`); timeout→`neg_neigh_record`
(`:142-161`) at `pending_neigh_timeout_ns` — **800 ms fast path
verified ACTIVE on the cluster** (retrans_time_ms=252 ≤ 300 on all
dataplane ifaces + default, `forwarding_build/mod.rs:464-515`; the
"option D inactive" journal hits are from the May 28 boot, not the
current process); dwell recorded at `:196-198`.

### 2.3 The Go→helper republish gap (H2's surviving sub-mechanism)

`RegenerateNeighborSnapshot` (`pkg/dataplane/userspace/manager.go:1040`)
gates the publish on `neighborsEqualForwarding(lastSnapshot, kernel-now)`
(`:1057`) — the helper's actual map content is never consulted, so a
helper-side-only loss heals only via a later kernel event for that
key. In practice the 15 s force-probe drives
STALE→DELAY→PROBE→REACHABLE kernel transitions (each notifies), so
the unhealed window is ≤ ~15 s while the loop is healthy. Residual
risk is real but narrow; it was the pre-#1780 frozen-loop world where
this compounded into hours.

### 2.4 #1787 elision: no change to idle/re-learn dynamics

`learn_dynamic_neighbor` (`neighbor_dispatch.rs:371-433`): the
cheap-first pre-check (`:416-420`) elides only the no-op write; a
missing key still takes the bulk write (`pair_write_needed`
`:367-369`). The 1-entry `last_learned_neighbor` dedup (`:346`) that
actually suppresses re-learn under a steady single source is
pre-#1787. During idle there is no RX traffic at all. Verdict: no
re-examination needed beyond the in-file linearization note
(`:399-415`).

## 3. Live evidence — 10 on-demand reproductions of the operator's stall

Environment: fw1 = node1 = RG0/RG1 primary throughout; deployed build
`a05a73694`; CoS iperf class set loaded (root `reth0.80` shaping
25 Gb/s; queue 1 `iperf-100m` exact, owner worker 1); pending timeout
= 800 ms fast path; no netem anywhere; PR-1 instruments armed.
**Important measurement gotcha (cost ~3 forensic detours):** fw1's
clock runs ~51-52 s BEHIND the client/host clocks — every
cross-machine timestamp in this campaign had to be mapped via a
measured offset (fw epoch↔mono offset 1776962918.33 was stable all
session; skew client→fw = 51.2 s).

### 3.1 The reproduction (R0 + reps A-I)

First parallel TCP connects to 172.16.80.200:5201 after data-path
idle; warm baseline 2-5 ms:

| rep | idle | stall (connect wall) | notes |
|---|---|---|---|
| R0 | hours (unknown) | **0.974-0.975 s ×5** | all released together |
| A | 13 min | 0.130-0.132 ×5 | client/fw pcaps (§3.2) |
| B | 13 min + warm ping | 0.167 ×5 | far host/path exonerated (§3.3) |
| C | 12.8 min | 0.126-0.127 (4 of 8) | class matrix (§3.4) |
| D | 11 min | 0.101-0.102 ×5 | drain top-bucket +1 (§3.5) |
| E | ~8 min | 0.081 ×5 | kick-latency clean |
| F | ~7 min | 0.070-0.071 ×5 | drain top-bucket +1 |
| G | ~7 min | 0.072-0.073 ×5 | drain top-bucket +1 |
| H | 7 min | 0.111-0.113 ×5 | in-window system perf (§3.6) |
| I | ~25 min | 0.105-0.106 ×5 | park-counter delta (§3.7) |
| 60 s control | 60 s | 0.053 ×1 | |
| 2 s control | 2 s | 0.002-0.005 | warm |

**Every PR-1 neighbor instrument stayed at ZERO across all 10
reproductions**: `neg_neigh_fast_fail_total` 0,
`pending_neigh_duplicate_drops_total` 0,
`neighbor_pending_timeout_drops_total` 0, `resolver_get_*` 0, and the
`neighbor_pending_dwell` histogram never moved (count stuck at 4
boot-time samples). `dynamic_neighbor_present` had both .200 keys
present before/after; kernel NUD REACHABLE throughout.
**The operator-shaped residual stall does not involve the neighbor
path at all.**

### 3.2 Rep A localization (pcap)

Client clean: one SYN per flow at t0, zero retransmits; all 5
SYN-ACKs arrive in one 0.5 ms burst at t0+130 ms. No ARP/NS on
VLAN 80 in the window (fw kernel pcap). The far host answered the
15 s force-probe ICMP in **73 µs** 3.6 s before the stall. TS-val
arithmetic on the SYN-ACKs places their generation at ≈arrival time ⇒
the SYN was delayed ~128 ms in the FORWARD direction and the flows
were **held and burst-released, not dropped**.

### 3.3 Rep B — far host and path exonerated

A continuous 5 pps ICMP through the same client→fw→.200 transit
(0.4 ms RTT, riding XSK the whole 13 min window) did NOT prevent a
167 ms stall on all 5 new TCP flows. Far-host wake states, switch
FDB aging, NIC IRQ/DIM idle states, and generic XSK transit are all
ruled out. The hold gates the machinery that only NEW flows touch.

### 3.4 Rep C — class/port matrix

phase1: single closed-port :5999 connect = 4 ms (fast). phase2
(+1 s): 5200-BE 127 ms AND 4 ms (two flows); 5201-100m 127/126 ms;
5202-1g 6 ms; 5203-3g 127 ms; 5999-closed 126 ms. Same port both
fast and slow ⇒ not per-class token state alone; closed port slow ⇒
listener-independent; the grouping matches per-(queue-owner-worker)
cold cost: exact queues drain owner-locally, so all flows of a class
funnel to one worker; BE/non-exact stall per-RX-worker.

### 3.5 Reps D/F/G/I — the hold is inside ONE drain_shaped_tx call

Each reproduction increments
`xpf_cos_drain_latency_ns_bucket{queue_id="1",bucket_hi_ns="33554432"}`
by exactly **+1** (the top/clipping bucket of the 16×(1024·2^k)
histogram — one `drain_shaped_tx` invocation ≥33.5 ms, recorded at
`tx/drain/phase_shaped.rs:44-72`), with `drain_invocations` +8..11.
All 5 flows queue behind the exact queue's owner worker
(`service_exact_guarantee_queue_direct_with_info`,
`cos/queue_service/mod.rs:630-739`) and release together.

### 3.6 Rep H — in-window system-wide perf

With a validated clock mapping, the 12 s `-a` capture (cycles
2 kHz/cpu + sched_switch) covers the 111 ms stall: **no worker CPU
burst** (the on-paper O(idle) suspect `advance_cos_timer_wheel`,
`tx_completion.rs:217-226`, does not appear in any stall-window
sample), **no worker sched gap >15 ms** (rules out vCPU steal for
the stall window; the owner worker sat in its normal 1 ms
`poll()` loop), CPUs ~half idle. Two environmental observations
worth follow-ups: (a) workers burn their idle cycles in
`FlowCache::active_flow_debug_entries` (~5% of all dp CPU,
continuous, stall-independent); (b) the host carries chronic vCPU
steal (cumulative ~8000 s; `/proc/stat` steal ticks observed
incrementing outside stall windows).

### 3.7 Rep I — park-cycle anatomy (the pinned mechanism)

Control-socket CoS queue telemetry across a 105 ms stall (queue 1):
`queue_token_starvation_parks` **+14**, `drain_invocations` +11,
`root_token_starvation_parks` +0, drain-latency buckets +1 top-bucket
+ small entries. The stall is **~14 QueueTokenStarvation park/wake
cycles ≈ 7.5 ms apiece** — the queue repeatedly woke, attempted a
v8 lease top-up (`maybe_top_up_cos_queue_lease`,
`token_bucket.rs:154-249` → `acquire_v8`,
`types/shared_cos_lease/mod.rs:1180+`), failed to accumulate
`head_len` worth of tokens, and re-parked
(`cos/queue_service/mod.rs:988-1009` waterfill site /
`:686-721` direct site; park = `park_cos_queue`,
`tx_completion.rs:79-101`). 7.5 ms ≈ `COS_MIN_BURST_BYTES`
(96 000 B, `token_bucket.rs:25`) at the 12.5 MB/s class rate —
suggesting the effective wait per cycle is a bank/lease quantum at
the class rate, not the parked `head_len` estimate
(`estimate_cos_queue_wakeup_tick` is passed `head_len` at every
park site — the µs-scale estimate is NOT what paces the observed
cycles).

### 3.8 What was NOT re-run

The `ip neigh del` / `nud failed` induced H-chain reps: the operator
already live-confirmed H5 (issue comment 2026-06-09: dup-drop = 1,
exactly the stalled sibling), and this campaign's 10 reproductions
prove the operator-shaped symptom never touches that path. Re-running
inductions would only disturb the cluster for no new information.

## 4. Revised causal model

**The #1782 residual stall is a CoS exact-queue cold-start, not a
neighbor cold-start.**

Chain (all current master refs):
1. During data-path idle no drains run (`should_enter_shaped_drain`
   gate), so per-(worker, root-iface) CoS state — v8 shared-lease
   epoch state (`types/shared_cos_lease/`), `queue.hot.tokens`,
   timer wheel — receives no maintenance.
2. First flows after idle classify into a CoS queue
   (`tx/cos_classify.rs`); exact-queue traffic funnels to the
   queue's owner worker.
3. The first drain finds `queue.hot.tokens < head_len` and the v8
   lease grants ~0 per attempt for ~10-15 cycles spanning
   50-1000 ms (observed 53 ms@60 s idle → 100-170 ms@7-13 min →
   ~1 s@hours; exact functional form unresolved — §7 Q2), each
   cycle ending in a `QueueTokenStarvation` re-park.
4. Every flow behind that owner/queue waits the full ladder; all
   release together when the lease finally grants ⇒ "multiple flows
   hang for a few seconds, then full speed" (operator symptom, with
   overnight idle scaling the ladder into seconds).
5. TCP keeps the SYNs alive (they are buffered in the CoS queue,
   not dropped), so there are no retransmits in the minutes regime;
   in the overnight/multi-second regime client RTOs (1 s, 2 s)
   overlay the recovery, matching the operator's "hanging or not
   performing for a few seconds".

Supporting differentials: warm ping on a different queue/worker does
not help (rep B); same-port flows split fast/slow by worker (rep C);
one ≥33.5 ms drain invocation per event (reps D/F/G/H/I);
+14 queue-token parks per event (rep I); zero neighbor-counter
movement (all reps).

**Where the prior plan's H-chain stands:** H5 (one-representative
pending drop) remains real-but-rare (needs a genuine
`dynamic_neighbors` absence, which on this cluster requires either a
kernel FAILED transition or an operator-induced delete); H1/H3
amplifiers remain code-verified but were never observed armed; H2's
"absent after idle" root was directly REFUTED on the current build —
after 9+ hours idle the keys are still present (§2.1, §3.1).

## 5. PR-2: REVISED (neighbor Option B → PLAN-KILL; CoS cold-start fix)

### 5.1 Neighbor Option B (first-miss reuse via non-blocking mirror): PLAN-KILL as the #1782 fix

The capture-gated severity that justified a dataplane change does not
exist on the current build: the H2 absence does not occur after idle
(§2.1, §3.1), the amplifiers never armed in 10 reproductions, and the
operator symptom is fully accounted for by §4. Keep the design notes
(non-blocking mirror, `insert_confirmed_if_unchanged` epoch guard,
Q7 DELAY-reuse semantics) on file for a future neighbor-loss issue;
do not implement under #1782.

### 5.2 The CoS cold-start fix (new PR-2 scope)

**Step 1 — line-level pin (small, instrumented):** add three cheap
counters/timestamps around the v8 lease zero-grant path
(`acquire_v8` grant=0 with `requested>0` per cause: seqlock-give-up
`:1207-1209`, `cap==0` `:1210-1212`, share-exhausted `:1256-1258`,
class-cap `:1264-1266`, outstanding-cap `:1289-1297`) + a
park-cycle dwell histogram (queued→first-sent per queue). One cold
rep then names the exact starving bound. The candidates, in order
of suspicion: (a) epoch/`cap`/`my_share` state staled by idle and
only recovering via `maybe_rotate_epoch_v8` ladder; (b) the
outstanding-credit ledger (`try_bump_outstanding` vs
`max_total_leased`) left near-cap at idle-entry (banked-but-unspent
tokens from the last active period never returned); (c) per-worker
`active_flow_buckets`/share rehydration after idle.

**Step 2 — the fix (shape, finalized after step 1):** on first
service after an idle gap ≥ some threshold (e.g. epoch_start older
than N epochs), re-initialize the queue's lease/bank state to the
same state a freshly-built queue gets (`builders.rs` initial state:
full burst bank, fresh epoch) instead of replaying the starvation
ladder. This is a cold-path-only change (gated on the idle gap),
preserves the configured exact rate in steady state (Gate-4 hard cap
is enforced by per-epoch grant + tx_completion debit, not by the
cold bank), and cannot re-open #1630/#1743 fairness work — but the
PR MUST re-run the #1628/#1630 fairness gates and the cos-class
smoke to prove it.

**Acceptance for PR-2:** cold-connect wall time after ≥13 min idle
≤ 20 ms (vs 100-170 ms today) for all classes incl. BE; no change
in shaped-class steady-state rates (Gate 1/4); overnight operator
re-test shows no multi-second multi-flow lag.

### 5.3 Optional follow-ups (separate issues, not #1782)

- Workers burn ~5% CPU continuously in
  `FlowCache::active_flow_debug_entries` even at idle (§3.6a) —
  audit its call cadence/gating.
- Host-level chronic vCPU steal on the loss cluster (§3.6b) —
  test-env hygiene, affects latency-sensitive measurements.
- `xpf_cos_drain_latency_ns` top bucket clips at 33.5 ms — extend
  the bucket range so multi-ms drain anomalies are visible (it
  silently absorbed every stall in this campaign).

## 6. Severity (honest) + PLAN-KILL criteria

- Severity: first new flows after idle stall 50-170 ms (minutes-scale
  idle) to ~1 s (hours) to multi-second (overnight, operator-reported;
  extrapolation consistent but not directly measured in this
  campaign). Bounded, self-healing, no packet loss in the minutes
  regime; TCP-visible (RTO) only in the overnight regime. It affects
  every CoS-configured deployment after every idle period —
  deterministic, not probabilistic.
- This is NOT SLO-acceptable for a firewall that advertises CoS:
  every first-flow-after-idle pays it, and the magnitude grows
  unboundedly(?) with idle (Q2). Recommend FIX (not document-the-
  envelope).
- **PLAN-KILL criteria for the new PR-2:** if Step-1 pinning shows
  the stall is ≤ ~50 ms bounded for ANY idle duration on a properly
  configured system and the overnight multi-second report cannot be
  reproduced with CoS loaded (i.e. R0's 975 ms and the operator's
  seconds turn out to be steal/test-env artifacts), downgrade to a
  docs/test-env note and close. If only non-CoS configs matter to
  the deployment, `deactivate class-of-service` is a complete
  operator workaround — worth documenting either way.

## 7. Open questions (for adversarial review)

1. **Q1:** Which exact bound in `acquire_v8` starves the cold queue
   (§5.2 step 1 candidates a/b/c)? Counter evidence pending.
2. **Q2:** What sets the stall duration's idle-scaling
   (53 ms@60 s → ~1 s@hours)? The ~7.5 ms/cycle × ~14 cycles
   anatomy was measured at one idle depth only; the cycle count
   and/or period must grow with idle. Step-1 histograms answer this.
3. **Q3:** Does the same ladder explain the BE-queue stalls in rep C
   (BE is non-exact; its tokens are transparent when
   `transmit_rate_bytes==0` — `token_bucket.rs:167-171` — so why did
   5200-BE stall 127 ms)? Root-lease bank (`maybe_top_up_cos_root_lease`,
   `token_bucket.rs:54-87`, root shaping 25 Gb/s is non-transparent
   here) is the candidate; Step-1 must add the root-lease counters
   too. (`root_token_starvation_parks` stayed 0 in rep I — but rep I
   only ran :5201 flows.)
4. **Q4:** Is the overnight multi-second regime the SAME mechanism
   (bigger ladder) or compounded with a second one (e.g. client RTO
   interleaving, or the chronic host steal)? The operator's overnight
   capture (`capture-cold-stall.sh --monitor-only` + morning
   `--connect`) is STILL worth running once with the §5.2 step-1
   counters live — it would settle Q2/Q4 with one data point.
5. **Q5:** Should the neighbor H-chain follow-ups (#1771 §2.6
   counters, §2.4 invariant test) absorb the Option-B design notes,
   or does a standalone "neighbor-loss resilience" issue carry them?

## 8. Out of scope

- Implementing the CoS fix (that is `/engineer 1782` PR-2 after this
  plan converges).
- The §5.3 follow-ups (file separately).
- Neighbor Option B implementation (killed for #1782; notes retained).
