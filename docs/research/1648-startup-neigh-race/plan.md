# #1648 — Startup/failover neighbor-dump race: first cold connect ~1s

**Status:** v4 (research-only; /research, not /engineer) — AGY r3 found a THIRD
H-0 window (config-reload/ISSU reconcile); pending r4 convergence

> **v3 KEY CORRECTION (AGY r2, verified):** `initial_neighbor_dump` runs **only
> once at daemon startup** (`neighbor.rs:514`, inside the detached
> `neigh_monitor_thread`). The seq=0-multicast-drop (H-0) therefore affects ONLY
> the windows where `xpfd` (re)starts: **daemon-restart / deploy / crash-promote
> where fw1 itself reboots**. A **clean VRRP failover** does NOT restart fw1's
> daemon — fw1's monitor is already in the steady-state `recv()` loop
> (`neighbor.rs:526-556`), which processes seq=0 events with **no seq filter**.
> So **5.A.2 cannot fix a clean-failover ~1s** if one exists; that path has a
> different mechanism (candidate: ENOBUFS desync, AGY r2 (d), or standby map
> aging). The two windows are now analyzed separately.
**Branch:** `research/1648-startup-neigh-race`
**Reviewers:** Codex + AGY + Claude SMR (3-way at /research; Copilot joins at /engineer)
**Scope:** root-cause the residual ~1s first-connect after daemon restart /
long idle / RG-promote; choose a fix (dump-before-admit / gate-until-seeded /
warm-at-promote / combination); prove no ~60ms VRRP-failover regression; decide
production-relevance honestly (failover vs deploy-restart only).

---

## 1. Problem statement

Post-#1636 (PR #1640, `fc3ffe3ca`) and #1651 Gate-M, the steady-state cold
connect is already **0.6–3.7ms** (10 settled-daemon trials, full `ip neigh
flush all` on both firewall and client). This is at the ≤200ms acceptance
target. There is **no per-cold-connect dataplane defect**.

The ~1.7s figure reproduces **only** on the *first* connect after:
- daemon restart, or
- long idle (kernel neighbor entries aged out to `NUD_STALE`/`NUD_FAILED`), or
- HA RG-promote (the new primary enters a startup-like forwarding window).

The issue body (re-scope comment, 2026-05-29) attributes this to
`request_neighbor_dump` (the RTM_GETNEIGH seed) racing a neighbor-cache flush,
leaving the dataplane neighbor map empty until the dump lands.

**This plan must (a) verify the ordering on the cluster, (b) decide a fix per
window, and (c) decide whether failover actually hits the ~1s or whether it is a
deploy-restart-only artifact** — the latter would justify PLAN-KILL.

**Three distinct windows (v4):**
1. **Restart / crash-promote** (xpfd (re)starts → runs `initial_neighbor_dump`):
   candidate mechanism H-0 (seq=0 multicast drop during the dump); fix 5.A.2.
2. **Clean VRRP failover** (xpfd stays up → NO dump): H-0 cannot apply; if a ~1s
   exists here the mechanism is H-D (ENOBUFS desync / standby map aging); fix
   5.E.
3. **Config-reload / ISSU reconcile** (AGY r3, verified): `reconcile` →
   `teardown::tear_down` → `stop_inner` sets `monitor_stop = None`
   (`coordinator/mod.rs:199`) → `bring_up_workers` respawns the monitor
   (`bringup.rs:330`) → a FRESH `initial_neighbor_dump`. So **every commit /
   config-reload is another H-0 window** — and these are far more frequent than
   daemon restart, so H-0/5.A.2 is production-relevant even if BOTH failover
   modes turn out World 2. `make test-failover` uses an unclean reboot
   (crash-promote = window 1); a manual `request chassis cluster failover` is
   clean (window 2); any `commit` is window 3. Gate-R measures all three.

---

## 2. Verified code map (against `origin/master` @ `67258de88`)

All paths in `userspace-dp/src/afxdp/`.

### 2.1 The neighbor map and its two seeders
- `coordinator/reconcile/bringup.rs:330–343` — at coordinator bring-up, the
  helper spawns `neigh_monitor_thread` via `spawn_supervised_aux("neigh-monitor")`
  **after** all worker threads are already spawned (lines ~250–326). Detached;
  no join, no ordering barrier vs the workers.
- `neighbor.rs:465–559` `neigh_monitor_thread`:
  1. creates an `AF_NETLINK`/`NETLINK_ROUTE` socket,
  2. **binds to `RTMGRP_NEIGH`** (line 485) — multicast subscription is live
     from this point,
  3. sets a 500ms `SO_RCVTIMEO`,
  4. calls `initial_neighbor_dump(fd, …)` (line 514) — a **blocking
     RTM_GETNEIGH ROOT|MATCH dump** that `recv()`-loops until `NLMSG_DONE`,
  5. then enters the steady-state `recv()` loop for incremental
     RTM_{NEW,DEL}NEIGH.
  - `neighbor_generation` is stored `1` after the dump (line 516/520), success
     OR failure.
- `neighbor.rs:394–463` `initial_neighbor_dump` — dumps AF_INET then AF_INET6;
  each `parse_neighbor_msg` upsert lands in `dynamic_neighbors`
  (`ShardedNeighborMap`).

### 2.2 The cold-flow path (what a SYN does when the neighbor map is empty)
- `forwarding/mod.rs:1297–1316` (v4; v6 mirror at :1447) — for an on-link
  destination the connected route has **no `next_hop`**, so
  `target = next_hop.unwrap_or(ip)` = the destination IP itself. Resolution
  sets `next_hop: Some(dest_ip)` and disposition `MissingNeighbor` when
  `lookup_neighbor_entry` misses.
- `poll_descriptor/mod.rs:2379–2680` `MissingNeighbor` handler:
  - fires `trigger_kernel_arp_probe(name, next_hop)` **once** (deduped by
    `(egress_ifindex, next_hop)` against `pending_neigh`),
  - creates the session stub so the reverse SYN-ACK matches,
  - **buffers** the SYN frame into `binding.pending_neigh`
    (`MAX_PENDING_NEIGH = 4096`).
- `neighbor.rs:36–118` `trigger_kernel_arp_probe` — opens a `SOCK_RAW` ICMP/
  ICMPv6 socket `SO_BINDTODEVICE`'d to the egress iface and sends one echo;
  the kernel then runs its own ARP/NDP solicitation. Reply is learned by the
  netlink monitor (RTMGRP_NEIGH) → `dynamic_neighbors` upsert.
- `neighbor_dispatch.rs:47–270` `retry_pending_neigh` (post-poll, every tick
  via `worker/lifecycle.rs:135,296`):
  - re-fires the probe per `PROBE_SCHEDULE_NS = [10ms, 60ms, 260ms]`
    (`neighbor_dispatch.rs:33–45`),
  - drops + recycles after `pending_neigh_timeout_ns`,
  - on neighbor-resolved, rewrites + forwards the buffered SYN.
- `types/forwarding.rs:70–82` + `forwarding_build` — `pending_neigh_timeout_ns`
  is **800ms** when the kernel `retrans_time_ms ≤ 300ms` (option D fast path),
  else 2000ms.

### 2.3 The HA RG-promote path (the production-relevant window)
- `ha.rs:4–87` `update_ha_state` (called from `server/handlers/ha.rs` on the
  control socket) → `handle_activated_rgs` (`ha.rs:89–165`):
  - bumps RG epochs, refreshes owner RGs, prewarms reverse synced sessions,
    republishes BPF session entries, and finally calls
    **`on_rg_promote_active()`** (`ha.rs:164`).
- `coordinator/mod.rs:745–750` `on_rg_promote_active` — clears the per-key
  `last_probed_at` rate-limit and fires a **forced** `queue_warm_pass(true)`.
- `coordinator/mod.rs:585–738` `queue_warm_pass` — **CRITICAL SCOPE GAP**: it
  enqueues warm probes only for:
  - `snapshot.routes_v4` / `routes_v6` next-hops (lines 713–732) — these are
    **routed** next-hops only; and
  - `snapshot.fabrics` peers (lines 735–737).
  - It **never iterates `forwarding.connected_v4` / `connected_v6`**
    (`types/forwarding.rs:19,21` — connected/on-link subnets are a *separate*
    field from `routes_v4`). On-link destinations therefore are **never warmed**
    at config-apply OR at RG-promote.

### 2.4 The smoke target is on-link
`docs/ha-cluster-userspace.conf` + `loss-userspace-cluster.env`: the iperf3
target `172.16.80.200` / `2001:559:8585:80::200` is on `reth0.80`
(`172.16.80.8/24`), a **directly-connected subnet** — resolved by direct
ARP/NDP, not a routed next-hop. So the existing warm-at-promote (option C)
**does not cover the exact target the lab watches.** This is verified, not
inferred.

---

## 3. The race, stated precisely (hypothesis to verify at Gate-R)

Two distinct sub-windows. The plan must measure which one (or both) produces
the ~1.7s.

### H-0 (LEAD, 3-way converged): seq=0 multicast-drop inside `initial_neighbor_dump`
All three reviewers (Codex CRITICAL-1, AGY Q4, SMR-revised CRITICAL-1) converge
on this verified structural defect as the most likely 1.7s mechanism:

- The monitor socket is bound to `RTMGRP_NEIGH` (`neighbor.rs:485`) **before**
  `initial_neighbor_dump` runs (`neighbor.rs:514`). So kernel multicast adverts
  (RTM_NEWNEIGH) are delivered to this socket *during* the dump.
- Kernel-pushed multicast adverts carry **`nlmsg_seq == 0`**, while the dump
  request uses `next_seq` = 1 (AF_INET) then 2 (AF_INET6).
- `initial_neighbor_dump` **discards** any message whose seq doesn't match the
  in-flight dump request: `if nlmsg_seq != next_seq { offset += …; continue; }`
  (`neighbor.rs:434-437`). So a live multicast RESOLVED advert that arrives
  mid-dump — including the resolution of the cold flow's *own* on-demand probe —
  is **permanently dropped**, not applied to `dynamic_neighbors`.
- Worked trace (the candidate 1.7s): worker goes live (T0) before the dump
  completes; cold SYN misses → `MissingNeighbor` → buffered into `pending_neigh`
  (`poll_descriptor/mod.rs:2652`) + `trigger_kernel_arp_probe` fires; kernel
  resolves in ~5ms and emits a seq=0 RTM_NEWNEIGH; that advert lands on the
  monitor socket *while the thread is still in the dump loop* → dropped by the
  seq-skip. The probe schedule (10/60/260ms) refires, but each resolution advert
  is again a seq=0 multicast dropped during the dump. After 260ms the schedule
  is exhausted; the SYN sits to `pending_neigh_timeout_ns` (800ms fast / 2000ms
  fallback) → drop + recycle (`neighbor_dispatch.rs:110-112`) → client TCP RTO
  (~1s) → **~1.7s observed**.
- **Why this is the lead and not §3 H-A/H-B:** it explains the full 1.7s without
  requiring a slow dump — the dump can be fast; what matters is that the
  resolution arrives *as a seq=0 multicast during the dump window* and is
  dropped, so the in-flight probe never resolves until after `NLMSG_DONE`.
- **Open uncertainty (Gate-R must resolve):** does the resolution advert
  *always* arrive during the dump (small empty-table dump → narrow window, so
  the probe's reply at +5ms might arrive *after* `NLMSG_DONE` and be caught by
  the steady loop), or is the dump long enough (or the probe fast enough) that
  the seq=0 advert reliably lands inside the window? If the window is too narrow
  to catch the probe reply, H-0 cannot fire and the 1.7s is from elsewhere
  (single dropped SYN never buffered — Codex HIGH-1). **R1 daemon-side counters
  for "seq-mismatch skipped during dump" decide this.**

### H-A: "empty-map + slow re-drive" startup window (daemon restart)
At daemon start the worker threads begin polling **before**
`initial_neighbor_dump` completes (§2.1: workers spawned first; monitor thread
spawned after, and the dump is blocking). For the brief window between
worker-go-live and dump-done:
- a cold SYN misses `dynamic_neighbors` → `MissingNeighbor`,
- the probe fires, the kernel resolves in ~5ms,
- **but** the netlink monitor thread is *blocked inside `initial_neighbor_dump`*
  (§2.1 step 4) and is NOT yet in its steady-state incremental `recv()` loop —
  so the RTM_NEWNEIGH for the just-resolved on-link host may not be consumed
  until the dump finishes. Until then `retry_pending_neigh` keeps missing.
- If the dump is slow (large kernel table, or it itself raced a flush so it
  returns an empty/partial set), the buffered SYN waits through the
  `PROBE_SCHEDULE` (≤260ms) and possibly to the 800ms timeout → drop → client
  TCP RTO (~1s). **This is the candidate mechanism for the ~1.7s.**

**Key uncertainty:** does the kernel multicast RTM_NEWNEIGH get *queued* on the
already-bound socket while the thread is blocked in the dump `recv()` (socket
is bound to RTMGRP_NEIGH at §2.1 step 2, *before* the dump), and merely
processed late — or is it processed *as part of* the dump stream? If the
multicast advert is buffered and consumed right after `NLMSG_DONE`, the window
is only as long as the dump itself (likely <50ms), and H-A cannot produce 1.7s.
**Gate-R must measure dump duration and whether the post-flush RESOLVED advert
is consumed by the dump loop or dropped.**

### H-B: "flush-after-dump" race (long idle / restart)
The issue body's literal framing: the dump lands, *then* a neighbor-cache flush
(or natural NUD aging to FAILED) empties the kernel table, so the seeded map is
stale and the first flow re-resolves from scratch. For this to cost ~1s the
re-resolution must take ~1s — but §2.2 shows the probe+retry schedule resolves
in ~5ms in steady state (Gate-M proved this). **So H-B alone cannot explain
1.7s** unless the re-drive path is itself broken during the startup window (i.e.
H-B collapses into H-A). This must be tested, not assumed.

### H-D (AGY r2, verified): clean-failover ~1s — if real — is NOT H-0
On a **clean VRRP failover**, fw1's `xpfd` stays up; there is no
`initial_neighbor_dump`, so the seq=0 drop (H-0) cannot occur. fw1's monitor is
in the steady-state loop (`neighbor.rs:526-556`) processing seq=0 events with no
filter. Therefore, *if* R2 shows a clean-failover ~1s for a cold target, the
mechanism is one of:
- **H-D.1 ENOBUFS desync (AGY r2 (d)):** the steady-state `recv()` treats any
  `n <= 0` as `continue` (`neighbor.rs:528`) with no error inspection and no
  large `SO_RCVBUF`. A netlink multicast buffer overflow (ENOBUFS) on a
  long-running standby **permanently desynchronizes** `dynamic_neighbors` from
  the kernel — entries learned-then-missed are never re-dumped (the dump is
  startup-only). At promote, the cold target's neighbor may be absent from the
  desynced map even though the kernel has it. **This is a distinct, plausible
  clean-failover root cause that 5.A.2 does NOT fix.** Candidate fix: on ENOBUFS,
  re-run a neighbor dump to resync (NOT startup-only).
- **H-D.2 standby map aging:** `dynamic_neighbors` entries age via RTM_DELNEIGH
  as the kernel ages NUD state on the standby; an idle cold target's entry is
  removed and never re-learned (no traffic on standby). At promote the map is
  cold for that target → first flow re-resolves from scratch (~5ms steady-state
  per Gate-M — so this alone is NOT ~1s unless it compounds with H-D.1).
- **Disposition:** clean-failover World 1 → fix is H-D.1 (ENOBUFS resync), NOT
  5.A.2. Crash-promote World 1 (fw1 reboots) → fix IS 5.A.2 (it's a startup
  window). Gate-R R2 must label which failover mode reproduces, so /engineer
  targets the right mechanism.
- **Window 3 — config-reload / ISSU reconcile (AGY r3, VERIFIED — corrects v3's
  "no third window" error):** `reconcile` (`reconcile/mod.rs:98`) calls
  `teardown::tear_down` (`teardown.rs:28`) → `stop_inner(false)` which does
  `self.neighbors.monitor_stop.take()` (`coordinator/mod.rs:199`) setting it to
  `None`, then `bring_up_workers` re-spawns the monitor because
  `monitor_stop.is_none()` (`bringup.rs:330`) → a fresh `initial_neighbor_dump`
  (`neighbor.rs:514`). So **every commit / config-reload re-opens the H-0
  window**. This is the most frequent H-0 occurrence (commits >> restarts), and
  it makes 5.A.2 production-relevant independent of the failover question.

### H-C: failover does NOT hit the ~1s (the KILL hypothesis)
On RG-promote, `on_rg_promote_active` already fires a forced warm pass — but
**only for routed next-hops + fabric peers, not on-link** (§2.3). So:
- If post-failover traffic is to a **routed** destination, it is already warmed
  → no ~1s. The failover case may already be covered for the cases that matter
  in production (default-gateway-routed flows).
- If post-failover traffic is **on-link** (like the lab target), it is NOT
  warmed → it would hit the same first-connect path. **But** a failover does
  NOT flush the kernel neighbor table on the newly-promoted node — the kernel
  ARP/NDP cache on fw1 is independently populated by fw1's own prior traffic /
  RA / gratuitous-ARP-from-VRRP. **So the new primary may already have a warm
  kernel table even for on-link hosts**, in which case the dataplane map seeds
  fast and there is no ~1s.

**H-C is the decisive measurement.** If a real `make test-failover`-style
promote does NOT reproduce the ~1s for the on-link target, the production case
is already fine and this issue is a **deploy-restart-only artifact** →
PLAN-KILL is the honest outcome.

---

## 4. Gate-R — the bounded measurement that decides everything

Run on `loss:xpf-userspace-fw0/fw1` (FIFO behind in-flight agents). No code
ships from /research; Gate-R may use throwaway instrumentation (reverted after,
per the #1651 precedent).

### R1 — daemon-restart reproduction + window pinning
**Codex CRITICAL-1: external `ip monitor` cannot see what the daemon socket
skipped — add DAEMON-SIDE throwaway counters.** On fw0:
1. `ip neigh flush all` on fw0 and on the client; `systemctl restart xpfd`.
2. Add throwaway daemon instrumentation (reverted after, per #1651 precedent):
   - counter A: "seq-mismatch NEW/DEL skipped during `initial_neighbor_dump`"
     (the `neighbor.rs:434` continue branch),
   - counter B: "NEW/DEL applied during dump",
   - the effective `pending_neigh_timeout_ns` for the run (Codex HIGH-4),
   - "first cold SYN queued vs recycled" (Codex HIGH-1) at
     `poll_descriptor/mod.rs:2644/2652`,
   - SO_RCVBUF size + any ENOBUFS/overflow on the monitor socket (Codex
     MEDIUM-1 + AGY r2 (d): netlink overflow is a competing explanation AND the
     candidate H-D.1 clean-failover root cause — instrument the steady-state
     `recv() <= 0` branch at `neighbor.rs:528` to log errno, esp. ENOBUFS, on
     BOTH the active and the long-running standby node).
3. Also run `ip -ts monitor neigh` on fw0 (separate socket — corroboration only,
   NOT the daemon's view) AND timestamp:
   - T0: worker threads go live (first poll),
   - T1: `neigh_monitor: initial kernel neighbor dump complete` log,
   - T2: first cold SYN observed (xpf debug),
   - T3: `trigger_kernel_arp_probe` fired,
   - T4: kernel RESOLVED advert for the target,
   - T5: buffered SYN forwarded (or dropped at timeout).
4. **Client-side SYN capture (SMR HIGH-1):** `tcpdump` the client's SYNs. Two
   SYNs ~1s apart = exactly one dropped SYN → RTO; this is the RTO signature
   that confirms the 1.7s = single dropped SYN + connect overhead.
5. Immediately (within the window) connect once to `172.16.80.200`. Measure
   connect latency. Repeat 5× with varying delay-after-restart (0ms, 50ms,
   200ms, 500ms, 2s) to map where the ~1.7s lives vs where it has decayed to
   ~ms.
6. **Pin the decisive question (H-0):** does counter A increment for the cold
   target's resolution advert (seq=0 multicast dropped during dump)? How long is
   `initial_neighbor_dump` (T1−T0)? Is T4 inside or after the [T0,T1] window? Is
   the buffered SYN re-driven at the 10/60/260ms schedule, or does it sit to the
   timeout → drop? **If counter A is 0 for the target, H-0 is refuted and the
   1.7s must be the never-buffered single-SYN path (Codex HIGH-1).**
7. **XDP-readiness check (SMR HIGH-3):** confirm the first slow SYN is actually
   processed by the dataplane (in `pending_neigh`), not XDP_PASS'd to the kernel
   because the per-CPU binding array wasn't steered yet.

### R2 — RG-promote (failover) reproduction — THE DECIDER
**Codex HIGH-2 / AGY Q2: control for standby passive-learn contamination.** The
passive learn path (`poll_stages.rs:183`, `neighbor_dispatch.rs:320`) has no
forwarding-active guard, so a standby node populates `dynamic_neighbors` from any
RX frame. AGY's refinement: standby only RX's broadcast/multicast (L2 unicast MAC
learning means an idle cold target is never seen), and NUD aging + RTM_DELNEIGH
cools the cache — so an idle target's neighbor is likely cold at promote (World
1). R2 must measure both:
1. Settle both nodes. fw0 active, fw1 standby. Inspect fw1's `dynamic_neighbors`
   AND kernel neighbor table for the target BEFORE failover (throwaway dump) —
   record warm/cold/stale. Do NOT artificially flush fw1 (production condition).
2. **Two targets (Codex MEDIUM-2):** target A = `172.16.80.200` (may be
   incidentally warm if fw1 saw its broadcast ARP); target B = a *second* on-link
   host fw1 has provably NOT seen any frame from (verify fw1's map has no entry).
3. Trigger a clean VRRP failover (priority-0 burst, or `request chassis cluster
   failover`), so fw1 promotes.
4. Measure: (a) VRRP failover time (must stay ~60ms), (b) first cold connect to
   A and B through the *new* primary fw1, both v4 and v6, both push and `-R`,
   with client-side SYN capture for the RTO signature.
5. Capture `ip -ts monitor neigh` on fw1 across the promote: did each target's
   neighbor already exist (warm) at promote, or was it MISSING and re-resolved
   from scratch?
6. **Aged-standby case (the production worst case):** let fw1 sit standby long
   enough for its `dynamic_neighbors` + kernel neighbor for the targets to age to
   STALE/FAILED (NUD aging + RTM_DELNEIGH propagation), then failover and
   measure. This is the case AGY argues makes World 1 real.

### R2-crash — unclean reboot promote (Codex r2 HIGH-3)
`test/incus/test-failover.sh:188` failover is an **unclean `reboot` of fw0**
(worst-case), not a clean priority-0 handover. Gate-R must measure BOTH:
- clean promote (priority-0 burst / `request chassis cluster failover`), AND
- crash promote (`incus exec fw0 -- reboot`) — the path the project's own
  failover gate exercises.
The crash path is harsher: fw0 stops advertising abruptly, fw1 promotes on the
masterDownInterval (~97ms), and any startup-window seed race on fw1 is more
likely to overlap a cold first connect. Disposition production-relevance on the
crash-promote result, not just clean.

### Quantitative kill bar (SMR CRITICAL-2 + Codex r2 CRITICAL-1 + AGY r2 (b))
**Zero-tolerance on the RTO signature (AGY r2 (b)).** The neighbor race is
probabilistic (VM scheduling / load dependent); a ~20% reproduction rate is a
real HA bug, so a ≥4/5 "mostly fast" bar would WRONGLY kill it. Revised bar:
- Measure against a **NEVER-SEEN / AGED target B** (verified absent from fw1's
  `dynamic_neighbors` before failover — a prelearned target is a false
  negative), under **both clean and crash promote**, v4 and v6.
- **PLAN-KILL only if ZERO trials (out of ≥10 per mode/family) exhibit the
  dropped-SYN RTO signature (~1s connect / two SYNs ~1s apart).** A single RTO
  signature on the cold target in any mode → World 1 confirmed → ship the fix
  for that mode (5.A.2 for crash-promote, 5.E for clean-failover).
- The 200ms ceiling is the steady-state acceptance gate for the *non*-signature
  trials (they should land in the Gate-M 0.6-3.7ms band); it is not the kill
  criterion. The kill criterion is the absence of the RTO signature entirely.

### R3 — decision matrix
| Outcome | Interpretation | Disposition |
|---|---|---|
| R2 first-connect ≤ ~tens of ms (fw1 table warm at promote) | failover does NOT hit the ~1s; only deploy-restart does | **PLAN-KILL** (deploy-restart-only artifact) unless R1 shows a fixable startup bug worth a small fix |
| R2 first-connect ~1s for on-link (fw1 table cold/aged at promote) | failover DOES hit it → production-relevant | ship a fix (§5) — on-link warm-at-promote and/or dump-before-admit |
| R1 shows dump >> probe schedule and SYN sits to 800ms timeout | startup re-drive is broken inside the dump window | ship dump-before-admit / monitor-ordering fix (§5.A) |
| R1 shows kernel RESOLVED advert dropped during dump | monitor mis-orders subscribe vs dump-drain | ship §5.A (drain multicast during dump, or subscribe semantics) |
| VRRP time regresses in any §5 variant | gating is too aggressive | reject that variant; on-link-warm-only (§5.C) |

---

## 5. Fix candidates (verify/refute at /engineer against Gate-R outcome)

### 5.A.2 — Process (don't drop) mid-dump multicast adverts — THE ROOT FIX (3-way)
**Converged lead fix.** In `initial_neighbor_dump`, do NOT `continue` past a
NEW/DEL message whose `nlmsg_seq` doesn't match the dump request
(`neighbor.rs:434-437`). Instead, apply NEW/DEL messages with `nlmsg_seq == 0`
(kernel multicast adverts) into `dynamic_neighbors` during the dump, and only
skip messages whose seq matches a *different* in-flight dump request (there is
only one at a time here). This lets the cold flow's on-demand probe resolution
self-heal in ~5-15ms even while the dump is in progress — making proactive
on-link warming (5.C) unnecessary for the daemon-restart case.
- **Correctness (SMR OQ-4, Codex/AGY verified):** `parse_neighbor_msg`
  (`neighbor.rs:297`) is idempotent — NEW upserts by NUD state, DEL removes only
  INCOMPLETE/FAILED. Applying a seq=0 NEW during the dump cannot corrupt a
  dump-seq entry; worst case it applies the same resolved MAC twice. AGY r2 (a)
  confirms FIFO socket ordering makes eventual consistency hold (a later
  REACHABLE dump entry overwrites an earlier stale DEL). A seq=0 DEL for a
  not-yet-dumped entry is a no-op.
- **MANDATORY guard (AGY r2 (a), verified at `neighbor.rs:438-444`):** the
  NLMSG_DONE / NLMSG_ERROR handling in the dump loop MUST stay gated on
  `nlmsg_seq == next_seq`. If 5.A.2 naively processes all seq values, a seq=0
  multicast message of type NLMSG_DONE/NLMSG_ERROR would prematurely terminate
  or fail the dump. The fix processes **only type-28/29 (NEW/DEL)** for seq=0;
  DONE/ERROR remain seq-matched. This is the precise patch shape — not "process
  all seq=0".
- **MANDATORY ordering design (Codex r3 CRITICAL-2):** processing a live seq=0
  RTM_DELNEIGH (unconditional remove, `neighbor.rs:359`) inline, interleaved
  with older dump rows, can resurrect-then-delete or delete-then-stale depending
  on arrival order. The /engineer implementation MUST either: (i) **stage**
  seq=0 NEW/DEL into a side buffer during the dump and **replay it AFTER
  NLMSG_DONE** (dump rows applied first, then live deltas — last-writer-wins is
  then correct), OR (ii) adopt **5.A.3 dual-socket** where the multicast
  socket's stream is naturally ordered and never mixed with the dump. "Process
  seq=0 immediately inline" is NOT acceptable. This is the gating
  implementation-correctness item.
- **Cost:** ~5-15 LOC in the dump parser. No new threads, no promote-path
  change, driver-agnostic. Fixes daemon-restart + crash-promote (fw1 reboot)
  windows. Does NOT fix clean-failover (see H-D / 5.E).

### 5.A.3 — Dual-socket design (Codex MEDIUM-3 alternative to 5.A.2)
Use **two** netlink sockets: one for the one-shot RTM_GETNEIGH dump (closed
after `NLMSG_DONE`), one bound to RTMGRP_NEIGH for steady-state multicast — with
the multicast socket bound BEFORE the dump so no advert is missed and no seq
mixing occurs. Eliminates the seq-skip hazard structurally rather than
patching the filter. Slightly more code (two fds, two recv loops or a poll set)
but arguably cleaner and easier to prove correct. **Compare against 5.A.2 at
/engineer; pick one.** 5.A.2 is the minimal patch; 5.A.3 is the clean redesign.

### 5.A — Order dump-before-admit / fix monitor ordering (targets H-A)
Make the initial neighbor seed complete (or be reliably re-drivable) before
workers admit cold flows. Sub-options:
- **5.A.1 Pre-dump before worker spawn.** Move a one-shot synchronous neighbor
  dump to *before* the worker-spawn loop in `bringup.rs`, so `dynamic_neighbors`
  is seeded when workers go live. Risk: adds blocking time to the
  forwarding-arm critical path (measured in R1 as dump duration — if <50ms,
  acceptable; this directly competes with the ~60ms VRRP budget at promote, so
  it must NOT be on the promote path — see §6).
- **5.A.2 Guarantee multicast drain during/after dump.** Confirm the
  RTM_NEWNEIGH multicast adverts that arrive *while* `initial_neighbor_dump`
  blocks are consumed immediately after `NLMSG_DONE` (not dropped). If R1 shows
  they are dropped (socket rcvbuf overrun, or seq-filtered by the dump's
  `nlmsg_seq != next_seq` skip at `neighbor.rs:434`), the fix is to not discard
  non-matching-seq NEW/DEL messages during the dump — process them into
  `dynamic_neighbors` instead of skipping. **This is a strong candidate** because
  `initial_neighbor_dump` currently `continue`s past any message whose seq
  doesn't match the dump request (line 434–437), which would silently drop a
  live multicast RESOLVED advert that arrives mid-dump.

### 5.B — Gate cold-flow admission until seeded — REJECTED as written
**Codex CRITICAL-2 / SMR MEDIUM-1: unsound.** `neighbor_generation` is stored
`1` on both dump **success** (`neighbor.rs:516`) AND **failure**
(`neighbor.rs:520`), so gating cold-flow admission on `generation >= 1` would
admit flows even when the seed FAILED — it is a liar-flag for "seeded". Any
seed-complete gate must key on an explicit dump-*success* state, not generation.
Even fixed, this is largely a no-op vs 5.A.2 (cold flows already buffer), so
**drop 5.B**; the value is in 5.A.2's self-heal, not in gating.

### 5.C — On-link warm at config-apply AND at RG-promote (targets H-C, the prize)
Extend `queue_warm_pass` to also warm on-link destinations. The hard part (per
the old #1648 body): on-link hosts are not enumerable from config. Options:
- **5.C.1 Warm connected-route gateways/known hosts only.** Warm the configured
  interface's own subnet anchors (the gateway, any statically-configured
  neighbors, DHCP server, VRRP peers) — NOT every /24 host. Low cost, but does
  NOT warm the arbitrary iperf3 target.
- **5.C.2 Warm observed/recently-active on-link peers at promote — REJECTED
  (3-way).** Codex HIGH-3 / AGY Q3 / SMR CRITICAL-3 converge: a *cold-connect*
  target by definition has **no prior session**, so warming prior-session peers
  warms exactly the hosts that don't need it and misses the one that does.
  Worse, `prewarm_reverse_synced_sessions_for_owner_rgs` (`shared_ops.rs:72`,
  called from `ha.rs:130`) already re-derives synced-session neighbors at
  promote, so 5.C.2 is largely redundant. **Drop 5.C.2.** The only mechanisms
  that help the no-prior-session cold target are (a) fast first-touch self-heal
  (5.A.2) and (b) the steady-state probe path (already ~5ms per Gate-M).
- **5.C.3 First-packet fast-warm (already exists).** The probe schedule
  10/60/260ms is already the first-packet fast-warm. The only lever left is
  lowering the floor — but Gate-M shows steady-state is already ~5ms, so there's
  nothing to gain here outside the startup window.

### 5.D — Likely answer (3-way converged)
**Ship 5.A.2 (or 5.A.3) — the mid-dump multicast self-heal — as the root fix
for BOTH daemon-restart and failover-restart windows.** It is driver-agnostic,
off the promote critical path, and resolves the cold flow in ~5-15ms regardless
of whether the destination is on-link or routed. 5.C (on-link proactive warm),
5.B (admission gate), 5.A.1 (blocking pre-dump) are all rejected or
unnecessary. The daemon-restart AND crash-promote (fw1 reboot) windows share the
SAME root cause (seq=0 multicast drop during the per-restart
`initial_neighbor_dump`), so 5.A.2 covers both — *if* Gate-R confirms H-0.
**A clean VRRP failover is a SEPARATE window with a different mechanism (H-D);
if R2 shows clean-failover World 1, the fix is 5.E, not 5.A.2.**

### 5.E — ENOBUFS resync for the steady-state monitor (targets H-D.1, clean failover)
**Only relevant if Gate-R R2 shows a clean-failover ~1s for a cold target.** The
steady-state monitor loop (`neighbor.rs:526-556`) treats every `recv() <= 0` as
`continue` with no error inspection. A netlink multicast buffer overflow
(ENOBUFS) silently and permanently desyncs `dynamic_neighbors` (the dump is
startup-only, so there is no resync). Fix:
- inspect the `recv()` errno; on **ENOBUFS** (or persistent error), **RECREATE
  the socket (AGY r3 #3):** close the corrupted fd, open+bind+subscribe a fresh
  RTMGRP_NEIGH socket, and dump on the clean socket. Re-dumping on the SAME
  congested socket re-introduces the H-0 seq-mix AND may keep hitting ENOBUFS
  inside the dump loop → permanent desync. Socket-recreation, not reuse.
- set a larger `SO_RCVBUF` on the monitor socket to reduce overflow probability,
- the resync dump MUST use the 5.A.2-fixed/staged parser (5.E depends on 5.A.2),
- add a **permanent** ENOBUFS counter/log (Codex r3 MEDIUM-1) so overflow-induced
  desync is detectable in production, plus throwaway counting in Gate-R R1.
This is off the promote critical path (the resync runs in the monitor thread,
not on `on_rg_promote_active`). **Verify at Gate-R that ENOBUFS actually occurs
before building this — it may be theoretical.**
- **5.E DEPENDS ON 5.A.2:** the ENOBUFS resync re-runs a dump on the *same*
  live socket that is still receiving multicast adverts — so it re-introduces
  the exact seq=0-drop H-0 describes unless the resync uses the 5.A.2-fixed dump
  (process seq=0 NEW/DEL, keep DONE/ERROR seq-matched) or a 5.A.3 dual-socket.
  5.E is therefore not independent of 5.A.2 — ship 5.A.2 first, then 5.E reuses
  the fixed dump. This also means 5.A.2 has standalone value even if Window-1 is
  ruled World 2 (it is a prerequisite for any future resync).

---

## 6. HA-failover safety (no ~60ms VRRP regression)

Hard constraints any /engineer fix MUST satisfy:
- **Never gate VRRP.** VRRP runs in the Go control plane (`pkg/vrrp/`),
  independent of the dataplane neighbor seed. No §5 variant touches it.
- **Never put a blocking dump on the promote critical path.** `on_rg_promote_active`
  must stay non-blocking (it already enqueues to the async warmer). 5.A.1's
  pre-dump-before-spawn is a *daemon-start* fix only — it must NOT be added to
  the promote path, which has no worker re-spawn anyway (promote reuses live
  workers).
- **Gate only the cold `MissingNeighbor` path, briefly.** Established + synced
  sessions forward immediately on the new primary (that's the whole point of
  session sync). Only brand-new cold flows to unresolved on-link hosts are
  affected, and they already buffer-and-retry.
- **Per-RG correctness preserved.** Any warm extension reuses the existing
  per-RG `is_forwarding_active` gate in `queue_warm_pass` (§2.3) so standby RGs
  are never warmed.
- **`make test-failover` MUST pass** (CLAUDE.md hard gate for cluster/VRRP/
  failover-touching code) at /engineer time.

---

## 7. Honest production-relevance assessment

The pivotal question is **R2**. Two plausible worlds:

- **World 1 (fix-worthy):** post-failover the new primary's kernel neighbor
  table is cold/aged for the on-link target, and the dataplane re-resolves from
  scratch → ~1s first connect after every failover. This degrades the ~60ms
  VRRP win to ~1s of user-visible first-flow latency. Production-relevant; ship
  §5.D.
- **World 2 (artifact):** the new primary's kernel table is already warm at
  promote (kept warm by fw1's own background traffic, RA, VRRP gratuitous ARP,
  or the synced-session reverse path), so failover first-connect is ~ms and the
  ~1s reproduces ONLY at `systemctl restart` / `ip neigh flush all` — i.e. a
  **deploy-testing artifact**, not a production failover defect. PLAN-KILL with
  that measurement is the correct outcome (per
  `feedback_retirement_blocker_keep_going` / honest-scope discipline).

**This plan does not pre-judge which world is true.** R2 decides. The author's
prior (to be falsified): given that fw1 carries synced sessions and its own
mgmt/RA traffic, World 2 is *plausible* — but on-link data-path hosts that fw1
never talked to directly may genuinely be cold. The measurement is cheap and
must be run before any code.

---

## 8. Test plan (at /engineer, if a fix ships)

**(5.C.2 is REJECTED — no test for it; Codex r3 HIGH-3 removed the contradiction.)**
- Unit (5.A.2): `initial_neighbor_dump` mid-dump multicast handling — a seq=0
  type-28 NEW arriving during the dump is **staged then replayed after
  NLMSG_DONE** and lands in `dynamic_neighbors`; a seq=0 NLMSG_DONE/NLMSG_ERROR
  is NOT treated as dump-terminating (stays seq-matched); a staged seq=0 DEL
  does not remove a dump REACHABLE row applied earlier in replay order
  (last-writer-wins on the replay).
- Unit (5.A.3, if chosen instead): dual-socket — multicast socket bound before
  the dump captures the resolution advert; dump socket closed after NLMSG_DONE.
- Unit (5.E, only if H-D.1 confirmed): ENOBUFS on the steady-state loop triggers
  socket recreation + resync; the permanent ENOBUFS counter increments.
- Cluster smoke (full matrix): v4+v6 × push+`-R` × CoS-off+CoS-on first-connect
  after restart ≤200ms; after config-reload (commit) ≤200ms; after clean +
  crash failover ≤200ms — zero RTO-signature on the cold target.
- `make test-failover`: zero-drop, VRRP ~60ms unchanged (CLAUDE.md hard gate).

---

## 9. Risks & open questions (≥5, hostile)

1. **Does the bound RTMGRP_NEIGH socket buffer multicast adverts during the
   blocking dump, or drop them?** If buffered+consumed-after-NLMSG_DONE, H-A's
   window is just the dump duration (likely <50ms) and cannot produce 1.7s — the
   ~1.7s must come from elsewhere (TCP RTO from a single dropped SYN at a
   point where NO probe fired?). Gate-R R1 step 4 must resolve this. **If the
   dump is fast and adverts are not dropped, the entire H-A mechanism is wrong
   and the fix target is misidentified.**
2. **Is the ~1.7s actually one client TCP RTO (~1s) + connect overhead, i.e. a
   single dropped SYN?** If so, the question is *why one SYN drops* — is it that
   the very first SYN arrives before ANY probe can fire (worker live, monitor
   not yet seeded, probe fired but kernel hasn't resolved, SYN buffered, but
   then dropped because `pending_neigh_timeout` or a recycle bug)? Or is the SYN
   dropped entirely (not buffered) because the binding isn't ready? Gate-R must
   show whether the SYN is buffered or dropped.
3. **Does failover actually flush/age the new primary's kernel neighbor table?**
   (H-C). If not, 5.C is solving a non-problem for failover and only deploy-
   restart benefits → PLAN-KILL-leaning. This is OQ #1 in priority.
4. **5.A.2 correctness:** processing non-matching-seq NEW/DEL during the dump —
   is the seq-skip at `neighbor.rs:434` there to avoid double-counting dump
   entries vs multicast? Could processing them cause a stale DEL to remove a
   just-dumped entry? Must verify the NUD-state guard in `parse_neighbor_msg`
   makes this idempotent.
5. **Window-3 frequency:** every `commit` re-opens the H-0 window (AGY r3). Does
   a commit during active traffic actually drop the first cold flow's resolution
   advert, or is the commit-time quiesce (`teardown` 500ms sleep) long enough
   that no cold flow arrives during the new dump? Gate-R should reproduce a
   commit-during-cold-connect, not just a restart.
6. **Persistent-errno busy loop (AGY r3 #2):** the steady-state loop
   (`neighbor.rs:528`) and dump loop (`neighbor.rs:407-414`) `continue` on
   non-WouldBlock errors with no errno inspection — EBADF/EINVAL → 100% CPU
   spin. Any 5.E touching this path MUST add a persistent-error break/recreate.
7. **Silent CAP_NET_RAW failure (AGY r3 #4):** `trigger_kernel_arp_probe`
   (`neighbor.rs:36-118`) opens SOCK_RAW; if CAP_NET_RAW is dropped (hardened
   containers) the probe silently no-ops → cold resolution never fires. Not the
   ~1.7s cause on the cluster (the daemon has the cap), but a latent ops hazard;
   log on EACCES/EPERM + document the requirement. Out of scope for the fix but
   noted.
8. **mlx5/native-XDP specificity:** Gate-M ran on mlx5 VFs. Does the standalone
   i40e PF-passthrough env behave differently for the dump-window race? The fix
   must not be mlx5-specific (the seq=0 drop is driver-agnostic).
9. **5.A.2 staging memory bound:** the staging buffer for seq=0 deltas during a
   dump must be bounded (a long dump under heavy neighbor churn could accumulate
   many staged deltas). Cap it; on overflow, fall back to a post-dump full
   re-dump rather than unbounded growth.

---

## 10. Recommendation (3-way converged, pre-Gate-R)

**PLAN-READY for Gate-R.** Gate-R confirms the mechanism per window and decides
which fix (if any) ships. The two windows are now distinct (AGY r2):

- **Daemon-restart + crash-promote (fw1 reboots):** if R1 counter A confirms H-0
  (seq=0 resolution advert dropped during `initial_neighbor_dump`), ship
  **5.A.2** (or 5.A.3 dual-socket) — process seq=0 NEW/DEL during the dump while
  keeping NLMSG_DONE/ERROR seq-matched (AGY r2 (a) guard). ~5-15 LOC,
  driver-agnostic, no promote-path / VRRP impact.
- **Clean VRRP failover (fw1 daemon stays up):** H-0 cannot apply here (no dump
  at promote). If R2 shows clean-failover World 1 on the cold target, the fix is
  **5.E** (ENOBUFS resync of the steady-state monitor + larger SO_RCVBUF), NOT
  5.A.2 — but only build 5.E if R1/R2 show ENOBUFS actually occurs (H-D.1).
- **If R1 refutes H-0** (counter A = 0; resolution arrives after `NLMSG_DONE`):
  the restart 1.7s is a never-buffered single-SYN drop (Codex HIGH-1) →
  investigate the recycle / XDP-readiness path.
- **Disposition is per-scope (Codex r3 MEDIUM-2):** the failover scope and the
  restart/config-reload scope are decided independently. If the cold target
  shows ZERO RTO-signature trials in BOTH failover modes → PLAN-KILL the
  *failover* scope. Separately, if Window-1 (restart) OR Window-3 (config-reload)
  shows the RTO signature → ship 5.A.2 for that scope (this is NOT "ship anyway
  after a kill" — it is a distinct, independently-justified scope). Given AGY
  r3's Window-3 finding (every commit re-opens H-0), 5.A.2 is very likely
  justified on the config-reload scope alone, independent of failover.
- **Rejected:** 5.B (liar-flag gate, `neighbor.rs:516/520`), 5.C.1/5.C.2
  (on-link warm misses the no-prior-session cold target; 5.C.2 redundant with
  prewarm), 5.A.1 (blocking pre-dump risks forwarding-arm/failback latency).

The decisive Gate-R deliverables: (1) **R1 daemon counter A** + dump duration —
confirms/refutes H-0 for the restart/crash-promote window; (2) **R2 on an aged,
never-seen target across BOTH clean and crash promote** — tells us which window
(if any) is World 1 and therefore which fix (5.A.2 vs 5.E) applies; (3) **ENOBUFS
counting on the standby** — confirms/refutes H-D.1. All cheap; run before code.

---

## 11. Reviewer convergence log

See `reviewer-ids.md` for task IDs. Per-round verdicts appended below.

- **r1:** 3-way HOSTILE round complete.
  - **Codex** (`codex-plan-r1.md`): "Not PLAN-READY for Gate-R yet … risks a
    wrong root-cause decision because the core measurements do not directly
    observe daemon-side netlink behavior." 2 CRITICAL / 4 HIGH / 3 MEDIUM / 1
    LOW — all ACCEPTED into v2 (`plan-findings-r1.md`). Key: CRITICAL-1
    (external `ip monitor` blind to daemon seq-skip → add daemon counters),
    CRITICAL-2 (5.B generation liar-flag), HIGH-1 (first SYN may be dropped not
    buffered), HIGH-3 (5.C.2 misses no-prior-session class), MEDIUM-3
    (dual-socket alternative → 5.A.3).
  - **AGY** (`agy-plan-r1.md`): "Plan READY for the Gate-R measurement" with a
    decisive verified finding: the 1.7s is the seq=0 multicast-drop during
    `initial_neighbor_dump` (`neighbor.rs:434-437`) → buffered SYN to 800ms
    timeout → client 1s RTO. World 1 (failover affected) likely — standby only
    learns from broadcast/multicast + NUD aging cools the cache. Reject 5.C.2;
    ship 5.A.2.
  - **Claude SMR** (`claude-smr-plan-r1.md`): PLAN-NEEDS-REVISION (r1) →
    addressed in v2. CRITICAL-1 (hypothesis ordering — AGY's seq=0 trace is the
    correction: dump-ordering CAN produce 1.7s via the dropped resolution
    advert), CRITICAL-2 (passive-standby-learn + quantitative kill bar),
    CRITICAL-3 (5.C.2 self-defeating). All folded into v2.
  - **Convergence:** all three converge on (a) 5.A.2 mid-dump multicast
    self-heal as the root fix, (b) reject 5.B/5.C.2, (c) Gate-R needs
    daemon-side counters + aged-never-seen-target failover measurement. v2 is
    PLAN-READY pending the Gate-R run at /engineer.

- **r2:** v2 reviewed.
  - **Codex r2** (`codex-plan-r2.md`): 1C/4H/2M/1L. Two genuinely-new
    actionable points: CRITICAL-1 (kill bar can false-negative on a prelearned
    target — tighten to the cold target) and HIGH-3 (`test-failover.sh:188` is
    an unclean reboot — Gate-R must test crash-promote too). Rest re-confirm r1
    (already in v2). All ACCEPTED (`codex-findings-r2.md`); folded into v2.1.
  - **AGY r2** (`agy-plan-r2.md`): **PLAN-NEEDS-REVISION** with a DECISIVE new
    finding (verified): `initial_neighbor_dump` is **startup-only**
    (`neighbor.rs:514`), so H-0 cannot affect a clean VRRP failover (fw1 daemon
    stays up, steady-state loop processes seq=0 with no filter,
    `neighbor.rs:526-556`). Also: (a) 5.A.2 must keep NLMSG_DONE/ERROR
    seq-matched; (b) kill bar must be zero-tolerance on the RTO signature (20%
    repro is a real HA bug); (d) ENOBUFS on the steady-state loop silently
    desyncs the standby map permanently (candidate clean-failover root cause).
  - **Claude SMR r2** (`claude-smr-plan-r2.md`): PLAN-READY on v2's scope, but
    AGY r2's startup-only finding supersedes — I had also missed it.
  - **Outcome:** NOT converged at r2. v3 splits the analysis into two windows
    (restart/crash-promote = H-0/5.A.2; clean-failover = H-D/5.E), adds the
    5.A.2 DONE/ERROR guard, the zero-tolerance kill bar, crash-promote coverage,
    and ENOBUFS instrumentation + the 5.E fix.

- **r3:** v3.1 reviewed.
  - **Codex r3** (`codex-plan-r3.md`): 2C/3H/2M. CRITICAL-1 independently
    confirms the restart-vs-failover split (already in v3). CRITICAL-2 (NEW): 5.A.2
    needs an explicit ordering/replay design, not "process seq=0 inline" — a live
    DEL interleaved with dump rows can resurrect/remove by arrival order. HIGH-3
    (NEW): §8 still had a rejected-5.C.2 test (internal contradiction). All
    ACCEPTED (`codex-findings-r3.md`); folded into v4.
  - **AGY r3** (`agy-plan-r3.md`): **PLAN-NEEDS-REVISION** with a verified
    counter-example to v3's "no third window" claim: `reconcile` →
    `teardown::tear_down` → `stop_inner` (`coordinator/mod.rs:199`, sets
    monitor_stop None) → `bring_up_workers` respawns the monitor
    (`bringup.rs:330`) → fresh `initial_neighbor_dump`. **Every config-reload is
    a third H-0 window.** Plus: persistent-errno busy loop (#2), 5.E must recreate
    the socket not reuse it (#3), silent CAP_NET_RAW (#4). Endorsed the
    zero-tolerance kill bar (#5).
  - **Claude SMR:** I had ALSO missed Window-3; AGY r3's trace is verified
    correct. v3's "no third window" was my error (Codex r3 echoed it as
    confirmation). Corrected in v4.
  - **Outcome:** NOT converged at r3. v4 adds Window-3 (config-reload), the 5.A.2
    staging-replay ordering design (Codex r3 C-2), socket-recreation for 5.E (AGY
    r3 #3), removes the 5.C.2 test contradiction (Codex r3 H-3), and adds
    busy-loop / CAP_NET_RAW / staging-bound hardening (AGY r3 #2/#4 + new OQ-9).

- **r4:** v4 addresses every r3 finding. Awaiting r4 confirmation (Codex + AGY)
  that Window-3 + the 5.A.2 ordering design + 5.E socket-recreation are correct
  with no new blockers.
