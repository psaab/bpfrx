# Claude SMR plan-review r1 — #1648 startup/failover neighbor-dump race

**Reviewer framing:** netlink / AF_XDP-startup / HA-failover / neighbor-cache
domain expert. Hostile by mandate (`feedback_triple_review_includes_claude_smr`).
No soft first-pass PLAN-READY.

**Verdict r1: PLAN-NEEDS-REVISION — leaning PLAN-KILL on the headline mechanism.**

The plan's structure (measurement-first, World 1 vs World 2, R2 as the decider)
is correct discipline. But three substantive problems must be fixed before this
is PLAN-READY, and one of them is close to fatal for the issue's own framing.

---

## CRITICAL-1 — The issue's stated mechanism ("dump races a flush") is almost
certainly NOT the cause, and the plan half-buries this.

The plan says (§3 H-B) "H-B alone cannot explain 1.7s" and (§9 OQ-2) raises the
single-dropped-SYN-RTO hypothesis — but then §5 and §10 still lead with
dump-ordering fixes (5.A) as a primary deliverable. That is backwards. Walk the
actual numbers:

- `initial_neighbor_dump` is a ROOT|MATCH dump of the kernel neighbor table. On
  a freshly-restarted firewall with `ip neigh flush all`, that table is **nearly
  empty** — the dump returns in single-digit ms. The dump is not slow.
- The RTMGRP_NEIGH multicast subscription is bound (`neighbor.rs:485`) **before**
  the dump starts (`neighbor.rs:514`). The kernel queues multicast adverts on
  the socket receive buffer while the thread blocks in the dump `recv()` loop.
  They are not lost to the *socket* — the only question is whether the **dump
  parser drops them via the seq-skip** (`neighbor.rs:434`).

So the plan's OWN §5.A.2 finding (the seq-skip drops mid-dump multicast NEW)
is the only mechanism by which dump-ordering could cost 1s — and it can only
cost 1s if (a) a cold SYN arrives during the dump, (b) its probe resolves during
the dump, (c) the RESOLVED advert is dropped by the seq-skip, AND (d) no later
probe in the 10/60/260ms schedule re-resolves it. But (d) is false: after the
dump finishes (single-digit ms on an empty table), the monitor enters the
steady loop, and the next probe at +10ms or +60ms resolves the buffered SYN.
**The buffered SYN does not sit to the 800ms timeout in this scenario.** So
even granting the seq-skip drop, the cost is bounded by ~60ms, not 1.7s.

**Conclusion:** the ~1.7s is overwhelmingly likely a **single dropped SYN →
client TCP RTO (~1s)** (OQ-2), where the drop happens because the SYN arrives in
a window where it is NOT buffered at all — e.g. the binding/forwarding state
isn't ready, or `pending_neigh` push is skipped, or the frame is recycled before
the neighbor resolves. The plan must **promote OQ-2 to the primary hypothesis**
and demote 5.A to a contingency. Right now the plan would send /engineer chasing
the dump ordering, which the plan's own analysis shows can't produce 1.7s.

**Required revision:** Restructure §3 so H-A is "single-dropped-SYN-RTO during
the not-yet-ready window" and the dump-seq-skip is a sub-case to rule in/out,
not the lead. Gate-R R1 must FIRST answer: *is the first SYN buffered or
dropped?* and *is the 1.7s = exactly one client RTO?* (look at the client-side
SYN retransmit timestamps — if connect = ~1s and there are exactly 2 SYNs on the
wire 1s apart, it's an RTO, full stop).

---

## CRITICAL-2 — World 2 (failover already warm) is more likely than the plan's
prior admits, and the plan must state the kill bar quantitatively.

§7 says the author's prior is "World 2 is plausible." As a failover-domain
matter it is more than plausible — here is the mechanism the plan omits:

The newly-promoted node fw1, *before* promotion, is already RX-ing on its
physical member interfaces (bondless RETH: VRRP runs on the physical members,
CLAUDE.md). It sees the on-link host's broadcast ARP / gratuitous ARP / ND, and
— critically — the dataplane's **passive learn path**
(`neighbor_dispatch.rs:320 learn_dynamic_neighbor`) populates `dynamic_neighbors`
from observed inbound L2 frames *on the standby node too*, because the XSK RX
runs regardless of forwarding-active state (forwarding-active gates *admission*,
not *learning* — verify this, but the learn site has no is_forwarding_active
guard). If standby fw1 has seen ANY frame sourced from 172.16.80.200 (e.g. that
host ARPing for the gateway VIP, which fw1's member port receives), its
dataplane neighbor map is already warm at promote.

So World 2 isn't just "kernel table warm" — it's "**dataplane map** possibly
already warm from passive standby learning." This makes the failover-hits-1s
hypothesis weaker, and the plan must say so. **The kill bar must be explicit:**
if R2 first-connect for the on-link target after a clean failover is ≤200ms in
≥4 of 5 trials (both v4 and v6), PLAN-KILL — failover is not affected, and the
residual is a `systemctl restart` artifact that operators never hit in steady
production.

**Required revision:** add the passive-standby-learn mechanism to §7 World 2,
and pin the quantitative kill bar (≤200ms / ≥4-of-5 / v4+v6) into §4 R3.

---

## CRITICAL-3 — 5.C.2 ("warm prior-session on-link peers at promote") is a
plausible-sounding but possibly self-defeating mechanism. Interrogate it.

If World 1 is true (failover DOES hit ~1s), 5.C.2 warms the on-link hosts that
had live sessions before failover. But:
- Those exact hosts are the ones whose **sessions are synced** to fw1 — and
  `handle_activated_rgs` already calls `prewarm_reverse_synced_sessions_for_owner_rgs`
  (`ha.rs:130`) which re-derives reverse entries *including their neighbor
  resolution* (`dynamic_neighbors_ref()` is passed in). So the on-link peers
  with synced sessions may **already be resolved** by the prewarm path. 5.C.2
  could be redundant with existing code.
- Conversely, a brand-new cold flow after failover to a host that had NO prior
  session (the actual "cold connect" the issue measures) is NOT in the session
  table, so 5.C.2 does NOT warm it. **5.C.2 warms exactly the hosts that don't
  need warming and misses the ones that do.** This is the same class of error as
  the `feedback_review_scaffolding_against_consumer` lesson.

**Required revision:** either drop 5.C.2 or re-justify it against the consumer
("the iperf3 cold connect is to a host with NO prior session"). If the target
has no prior session, the ONLY mechanisms that help are (a) make the first-SYN
re-drive fast (already ~5ms steady-state per Gate-M), or (b) warm the *entire
on-link subnet* proactively — which is unbounded and was the killed old-#1648
framing. This strongly suggests that **if World 1 is true, there is no clean
fix** other than ensuring the first dropped SYN is re-driven before the client
RTO — i.e. back to CRITICAL-1's "why does the first SYN drop."

---

## HIGH-1 — Gate-R must measure the CLIENT side, not just fw.
The decisive signal for "is this a single RTO" is on the client: tcpdump the
client's SYNs. Two SYNs ~1s apart = RTO = exactly one dropped SYN. The plan's R1
instruments fw0 (T0–T5) but the RTO signature is only visible client-side. Add
client-side SYN capture to R1 and R2.

## HIGH-2 — "dump-before-admit" (5.A.1) conflicts with forwarding-arm latency.
The plan correctly says 5.A.1 must not be on the promote path. But it also adds
blocking dump time to **daemon start**, which delays forwarding-arm — and the
loss cluster's failback timing (~130ms, CLAUDE.md) includes daemon start +
dataplane load. A blocking pre-dump on an *aged* (non-flushed) kernel table
could be large (full neighbor table). The plan must bound the dump size before
proposing 5.A.1, or drop it. Given CRITICAL-1, 5.A.1 is probably unnecessary
anyway.

## HIGH-3 — The plan never checks whether the first SYN even reaches a bound,
ready worker. At daemon start, XSK bind + fill-ring prime + per-CPU binding
array population (`userspace-xdp`) must complete before a worker can RX. If the
SYN arrives before the binding is steered, it goes XDP_PASS to the kernel — which
has no route/neighbor either and drops/queues it. That XDP_PASS-to-cold-kernel
path is a *different* mechanism than the dataplane neighbor map and could itself
cost an RTO. Gate-R R1 must confirm the SYN is actually processed by the
dataplane (not XDP_PASS'd) at the moment it's slow.

---

## MEDIUM-1 — `neighbor_generation` is stored `1` even on dump *failure*
(`neighbor.rs:520`). If any 5.B gating keys on `generation >= 1`, a failed dump
would falsely signal "seeded." Note this so /engineer doesn't gate on a
liar-flag.

## MEDIUM-2 — §8 test "non-matching-seq NEW during dump is applied not skipped"
(5.A.2 test) bakes in the 5.A.2 fix as if chosen. Per CRITICAL-1 it may be moot.
Keep tests contingent on Gate-R, not pre-committed.

---

## What would move this to PLAN-READY
1. Restructure §3/§5/§10 so the **single-dropped-SYN-RTO** is the primary
   hypothesis and dump-ordering is a contingency (CRITICAL-1).
2. Add the passive-standby-learn World-2 mechanism + quantitative kill bar
   (CRITICAL-2).
3. Re-justify or drop 5.C.2 against "target has no prior session" (CRITICAL-3).
4. Add client-side SYN capture to Gate-R (HIGH-1) and the XDP_PASS-readiness
   check (HIGH-3).

This is a measurement-first research plan and the measurement is cheap, so I am
NOT killing it outright — Gate-R is worth running. But as written it would point
/engineer at the wrong fix (dump ordering) for a cost (1.7s) its own math says
dump ordering cannot produce. Fix the hypothesis ordering and the plan is sound.

**SMR r1 verdict: PLAN-NEEDS-REVISION. Strong lean toward PLAN-KILL if Gate-R
R2 shows failover ≤200ms (World 2), which I assess as the more likely outcome.**
