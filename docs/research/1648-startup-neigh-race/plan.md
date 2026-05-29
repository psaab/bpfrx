# #1648 — Startup/failover neighbor-dump race: first cold connect ~1s

**Status:** v5 (research-only; /research, not /engineer) — r4 closed with Codex
PLAN-NEEDS-MINOR + AGY PLAN-NEEDS-REVISION (verified NEW Window-3 stale-entry
leak; staging-overflow fallback unsound). v5 upgrades 5.A.2 to a **Double-Buffered
Atomic Swap** (fixes seq=0 drop AND the stale-entry leak in one mechanism),
adopts a **Key-Collapsed Staging Map**, replaces the steady-state-converge
fallback with a **bounded re-dump**, mandates monitor **respawn-on-panic**,
tightens the kill bar to **RTO-signature AND daemon-counter**, narrows Window-3 to
**binding reconcile / worker rebuild** (not policy-only commit), and fixes the
stale R3 clean-failover matrix cell. Pending r5 convergence.

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
3. **Config-reload / ISSU reconcile** (AGY r3, verified; **scope-narrowed at
   r4**): `reconcile` (`reconcile/mod.rs:112` is the only caller of
   `bring_up_workers`) → `teardown::tear_down` → `stop_inner` sets
   `monitor_stop = None` (`coordinator/mod.rs:199`) → `bring_up_workers` respawns
   the monitor (`bringup.rs:330`) → a FRESH `initial_neighbor_dump`. **r4
   correction (Codex r4 finding 1):** this is NOT "every commit." A *same-plan*
   snapshot apply takes the `refresh_runtime_snapshot()` fast-path
   (`server/handlers/snapshot.rs:84` `same_plan` branch →
   `coordinator/mod.rs:457`) which does NOT call `reconcile`/`tear_down` and
   therefore does NOT respawn the monitor. So Window-3 = **every accepted BINDING
   reconcile / worker rebuild** (a binding/topology change, or a same-plan apply
   that still `needs_binding_reconcile`), NOT a policy-only / filter-only commit.
   It is still **more frequent than daemon restart** (any binding change re-opens
   it), so H-0/5.A.2 is production-relevant even if BOTH failover modes turn out
   World 2. `make test-failover` uses an unclean reboot (crash-promote = window
   1); a manual `request chassis cluster failover` is clean (window 2); a
   **binding-changing** `commit` is window 3. Gate-R measures all three.

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
- **Window 3 — config-reload / ISSU BINDING reconcile (AGY r3, VERIFIED;
  scope-narrowed r4):** `reconcile` (`reconcile/mod.rs:98`, sole
  `bring_up_workers` caller at `:112`) calls `teardown::tear_down`
  (`teardown.rs:28`) → `stop_inner(false)` which does
  `self.neighbors.monitor_stop.take()` (`coordinator/mod.rs:199`) setting it to
  `None`, then `bring_up_workers` re-spawns the monitor because
  `monitor_stop.is_none()` (`bringup.rs:330`) → a fresh `initial_neighbor_dump`
  (`neighbor.rs:514`). **r4 narrowing (Codex r4 finding 1):** a *same-plan*
  snapshot apply bypasses reconcile via `refresh_runtime_snapshot`
  (`server/handlers/snapshot.rs:84` → `coordinator/mod.rs:457`), so this is
  **every accepted BINDING reconcile / worker rebuild**, NOT every policy-only
  commit. It is still far more frequent than daemon restart (any binding/topology
  change re-opens it), so 5.A.2 is production-relevant independent of the
  failover question.

### H-E (AGY r4, VERIFIED): Window-3 stale-entry cache leak (pre-existing bug)
**Distinct from the latency race — a correctness/security bug AGY r4 found while
verifying the dump path. It exists on `master` today, independent of this plan.**

- `dynamic_neighbors` (`ShardedNeighborMap`) is a **long-lived** structure owned
  by `Coordinator` and shared with workers.
- On a Window-3 BINDING reconcile, `teardown::tear_down` (`teardown.rs:28`) →
  `stop_inner` clears `monitor_stop` / `warm_stop` / `warm_queue`
  (`coordinator/mod.rs:199+`) but **never clears or resets
  `self.neighbors.dynamic`** (verified by parent: stop_inner touches the stop
  flags and the warm queue only).
- When `bring_up_workers` respawns the monitor, `initial_neighbor_dump` runs
  against the **same dirty map** (`bringup.rs:338`). The dump's `28 | 29`
  (NEW/DEL) path **only upserts** (`neighbor.rs:446`); it never removes entries
  the dump didn't see.
- **Consequence:** any neighbor that was **deleted in the kernel** during the
  teardown/reload window (e.g. an IP reallocation, a host that left, NUD aging to
  FAILED+GC) **remains in `dynamic_neighbors` permanently** — a stale `(ifindex,
  IP) → MAC` mapping that survives every subsequent reload. If that IP is later
  reassigned to a different host, the dataplane forwards to the **stale MAC** → an
  **L2 traffic leak / blackhole**. This is a latent correctness/security defect,
  not a latency defect.
- **Why this matters for the fix selection:** the v5 root fix (5.A.2 Double-
  Buffered Atomic Swap) **replaces** the active map atomically rather than
  upserting into it, so it fixes H-E (stale-entry leak) **and** H-0 (seq=0 drop)
  with one mechanism. H-E is called out so /engineer knows the swap is doing
  double duty — and so the unit/cluster tests cover the leak, not just the
  latency. (Gate-R does not need to *prove* H-E to justify the fix — it is a
  code-verified pre-existing bug; Gate-R proves H-0.)

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
- Measure against a **NEVER-SEEN / AGED target B**, under **both clean and crash
  promote**, v4 and v6.
- **Both-signal World-1 bar (AGY r4 finding 6 + Codex r4 finding 6):** calling a
  trial "World 1" requires **BOTH** (a) the dropped-SYN RTO signature (~1s
  connect / two SYNs ~1s apart on the client capture) **AND** (b) a daemon
  throwaway counter incremented for that flow (seq-mismatch-skipped-during-dump
  counter A, or the MissingNeighbor pending-buffer-timeout counter). Normal
  network packet loss can mimic the RTO signature alone — the daemon counter
  disambiguates a neighbor-race RTO from a generic-loss RTO. RTO-signature
  WITHOUT a corresponding daemon counter is NOT World 1; it is generic loss and
  must be re-run.
- **Programmatic target-B absence (AGY r4 finding 6):** immediately before
  triggering promotion, the harness MUST verify target B is absent from **BOTH**
  the kernel cache (`ip neigh show` shows no valid entry) **AND** fw1's
  `dynamic_neighbors` (throwaway dump). Background RA / IPv6 DAD multicast can
  silently warm target B → a prelearned target is a false negative. A trial where
  target B was present at promote is discarded, not counted.
- **PLAN-KILL only if ZERO valid trials (out of ≥10 per mode/family, each with
  target B verified-absent at promote) exhibit the both-signal World-1
  condition.** A single both-signal trial on the cold target in any mode → World
  1 confirmed → ship the fix for that mode (5.A.2 for crash-promote, 5.E for
  clean-failover-with-ENOBUFS).
- The 200ms ceiling is the steady-state acceptance gate for the *non*-signature
  trials (they should land in the Gate-M 0.6-3.7ms band); it is not the kill
  criterion. The kill criterion is the absence of the both-signal World-1
  condition entirely.

### R3 — decision matrix
**Disposition is per-scope. "Ship a fix" never means "ship any fix"; each row
names the specific fix justified by that signal (Codex r4 finding 6).**

| Outcome | Interpretation | Disposition |
|---|---|---|
| R2 first-connect ≤ ~tens of ms, target-B warm at promote (kernel + `dynamic_neighbors`) | failover does NOT hit the ~1s; only restart/binding-reconcile does | **PLAN-KILL the failover scope** (deploy/restart-only artifact); restart/W3 scope decided separately by R1 |
| **Crash promote** both-signal World-1 (fw1 daemon rebooted → fresh `initial_neighbor_dump`) | startup-window seq=0 drop on the new primary | ship **5.A.2** (Double-Buffered Atomic Swap) — it is a startup window |
| **Clean failover** both-signal World-1 **AND** ENOBUFS observed on fw1's steady-state monitor (H-D.1) | netlink overflow desynced the standby map | ship **5.E** (ENOBUFS resync + socket-recreation), which depends on 5.A.2 |
| **Clean failover** both-signal World-1 **but ENOBUFS == 0** (Codex r4 finding 3) | UNKNOWN H-D / first-packet path — neither 5.A.2 (no dump at clean promote) nor 5.E (no overflow) applies | **do NOT ship either fix; escalate** — re-instrument the steady-state loop + standby map aging path; this cell is unresolved by the current hypotheses |
| R1 counter A increments for the target's resolution advert (seq=0 dropped during dump) | restart-window seq=0 drop confirmed (H-0) | ship **5.A.2** for the restart/W3 scope |
| R1 counter A == 0 for the target | H-0 refuted at restart; 1.7s is a never-buffered single-SYN drop (Codex HIGH-1) | investigate recycle / XDP-readiness path, NOT 5.A.2 |
| VRRP time regresses in any §5 variant | gating is too aggressive | reject that variant (no §5 variant should touch the promote/VRRP path — see §6) |

---

## 5. Fix candidates (verify/refute at /engineer against Gate-R outcome)

### 5.A.2 — Double-Buffered Atomic Swap — THE ROOT FIX (3-way, upgraded v5)
**Converged lead fix, upgraded at r4 from "patch the dump-parser seq-skip in
place" to a full double-buffered atomic swap. This single mechanism fixes BOTH
the H-0 seq=0 multicast drop AND the H-E Window-3 stale-entry leak.**

The old v4 shape ("apply seq=0 NEW/DEL into `dynamic_neighbors` during the dump,
staging-then-replay") fixes H-0 but does NOT fix H-E: it still *upserts* into the
long-lived map and never removes entries the new dump didn't see, so kernel-
deleted neighbors leak forever (§3 H-E). AGY r4's verified fix is to build the
new neighbor table **off to the side** and **atomically replace** the active map.

**Mechanism (the precise patch shape):**
1. `initial_neighbor_dump` builds a **thread-local, empty temporary map**
   `FastMap<(i32, IpAddr), NeighborEntry>` (or equivalent) — NOT the live map.
2. Populate the local map from the GETNEIGH dump rows (the existing `28 | 29`
   parse path at `neighbor.rs:446`, retargeted at the local map).
3. **Stage** every `seq == 0` (multicast) NEW/DEL into a **Key-Collapsed Staging
   Map** (see below) instead of `continue`-skipping it (`neighbor.rs:434-437`).
4. After `NLMSG_DONE`, **replay** the staged deltas onto the local map (dump rows
   first, then live deltas → last-writer-wins is correct).
5. **Atomic swap:** lock the active `dynamic_neighbors` via `with_all_shards`
   (`sharded_neighbor.rs:135`), **clear every shard**, then copy the local map
   into the shards — all under the single bulk lock. Readers (workers) see either
   the entire pre-swap set or the entire post-swap set, never a half-replaced
   one.
- **This is an established in-tree pattern, not a new primitive.** The #949
  manager-key path at `coordinator/mod.rs:169` already does exactly
  "replace + insert under a single `with_all_shards` bulk acquisition so readers
  see either the pre-replace or post-replace state, never a half-replaced set …
  locks all 64 shards in shard-index order (deadlock-free invariant)." 5.A.2
  reuses that pattern for the full-table swap. The clear-then-copy variant is the
  natural extension of the existing `replace`-branch remove+insert.

**Key-Collapsed Staging Map (replaces the v4 FIFO-Vec; AGY r4 finding 3 + Codex
r4 check 1 + SMR r4 NIT-1):**
- Stage seq=0 deltas in a map keyed by `(ifindex, IP)` storing only the **latest
  state** for each key (NEW overwrites; DEL records a tombstone/removal-intent).
- This is **order-independent on replay** — each key has exactly one final entry,
  so the map's iteration order is irrelevant and last-writer-wins holds naturally.
  It supersedes the FIFO-Vec, which required strict arrival-order replay to be
  correct (SMR r4 NIT-1's concern is dissolved: there is no ordering contract to
  get wrong because each key collapses to its final state as it is staged).
- **DEL-then-NEW vs NEW-then-DEL on the same key:** both resolve correctly because
  staging is applied *in arrival order as messages are read* (each incoming seq=0
  message overwrites that key's staged state), so the staged map already holds the
  last-writer state before replay begins. The replay then applies that single
  final state. (Verify at /engineer: the stage step must overwrite on each
  message; a DEL after a staged NEW must replace the NEW with the removal-intent,
  and vice-versa.)
- **Memory bound:** naturally bounded by the number of unique neighbor IPs (kernel
  neigh table size, already capped by `gc_thresh*`). No unbounded growth.

- **MANDATORY guard (AGY r2 (a), verified at `neighbor.rs:438-444`):** NLMSG_DONE
  / NLMSG_ERROR handling MUST stay gated on `nlmsg_seq == next_seq`. The fix
  stages **only type-28/29 (NEW/DEL)** for seq=0; DONE/ERROR remain seq-matched.
  A seq=0 NLMSG_DONE/ERROR must NOT terminate or fail the dump. Not "process all
  seq=0".
- **Concurrency correctness (r5 review target):** the swap holds all 64 shards
  (`with_all_shards`, shard-index order, deadlock-free per the #949 invariant)
  for the clear+copy. A worker doing `lookup_neighbor_entry` mid-swap blocks on
  the shard lock and then sees the post-swap state. There is **no lookup-miss
  window** that wasn't already present in the #949 replace path — and crucially
  the swap is a one-shot at dump-completion, not per-packet, so the brief bulk-
  lock hold (copy of ≤ kernel-neigh-table entries) is off the hot path.
- **Cost:** moderate — a thread-local map + staging map + the swap. No new
  threads, no promote-path change, driver-agnostic. Fixes daemon-restart +
  crash-promote (fw1 reboot) windows (H-0) AND the Window-3 stale-entry leak
  (H-E) in one mechanism. Does NOT fix clean-failover-without-restart (see
  H-D / 5.E) — but 5.E reuses this same swap for its resync dump.

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
- **5.A.2 (the lead) — Double-Buffered Atomic Swap.** See the full §5.A.2
  sub-section above. In short: the dump's `nlmsg_seq != next_seq` skip at
  `neighbor.rs:434-437` currently silently drops live multicast RESOLVED adverts
  that arrive mid-dump; the fix builds the table off to the side (dump rows +
  key-collapsed staged seq=0 deltas), then atomically swaps it into
  `dynamic_neighbors` under `with_all_shards`. This both stops the seq=0 drop
  (H-0) and clears the stale-entry leak (H-E).

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

### 5.D — Likely answer (3-way converged, v5)
**Ship 5.A.2 (Double-Buffered Atomic Swap; 5.A.3 dual-socket as the alternative
to weigh at /engineer) as the root fix for BOTH daemon-restart and
failover-restart (crash-promote) windows AND the Window-3 BINDING-reconcile
window.** It is driver-agnostic, off the promote critical path, resolves the cold
flow in ~5-15ms regardless of on-link vs routed, and additionally fixes the
verified H-E stale-entry leak in the same swap. 5.C (on-link proactive warm),
5.B (admission gate), 5.A.1 (blocking pre-dump) are all rejected or unnecessary.
The daemon-restart, crash-promote (fw1 reboot), and Window-3 BINDING-reconcile
windows share the SAME root cause (seq=0 multicast drop + stale-entry leak during
the per-respawn `initial_neighbor_dump`), so 5.A.2 covers all three — *if* Gate-R
confirms H-0 (H-E needs no Gate-R; it is code-verified). Ship 5.F
(respawn-on-panic) as hardening alongside.
**A clean VRRP failover (no restart) is a SEPARATE window with a different
mechanism (H-D); if R2 shows clean-failover both-signal World-1 WITH ENOBUFS, the
fix is 5.E. If clean-failover World-1 with ENOBUFS==0, the path is unknown —
escalate, do NOT ship 5.A.2 or 5.E (R3 matrix row 4).**

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
- **5.E DEPENDS ON 5.A.2:** the ENOBUFS resync re-runs a dump on a socket that is
  still receiving multicast adverts — so it re-introduces the exact seq=0-drop H-0
  describes unless the resync uses the 5.A.2 double-buffered swap (stage seq=0
  NEW/DEL, keep DONE/ERROR seq-matched, atomic clear+copy) or a 5.A.3 dual-socket.
  5.E is therefore not independent of 5.A.2 — ship 5.A.2 first, then 5.E reuses
  the swap. This also means **5.A.2 has standalone value even if Window-1 is ruled
  World 2** (it is a prerequisite for any future resync, and independently it
  fixes the H-E stale-entry leak that exists on master today).

### 5.E.1 — Staging-overflow fallback: bounded re-dump (NOT steady-state-converge)
**Retraction (Codex r4 finding 2 + AGY r4 finding 4 — both confirm; SMR r4 NIT-2
self-corrected).** SMR r4 NIT-2 proposed: on staging-buffer overflow, "stop
staging, finish the dump, and let the steady-state loop catch up — no re-dump."
**This is UNSOUND and is retracted.** To finish parsing the dump rows the loop
must keep calling `recv()` (`neighbor.rs:406`/`:434`), which **consumes** the
seq=0 multicast messages off the socket queue. If staging is "stopped" on
overflow, those already-consumed REACHABLE adverts are **permanently discarded** —
the steady-state loop (`neighbor.rs:526`) only ever sees *later* messages and will
never replay the dropped ones → permanent desync for those IPs.

**Correct fallback:**
- With the Key-Collapsed Staging Map the buffer is naturally bounded by unique
  neighbor IPs (kernel `gc_thresh*` cap), so overflow should be rare.
- If a defensive cap (e.g. 8192 unique IPs) is still hit: mark the dump **dirty**,
  finish the current dump, then schedule **exactly one** async re-dump (clean
  socket-recreate) after a ~1s delay; on a second overflow, **stop re-dumping and
  emit a degraded log + permanent metric** (accept eventual consistency rather
  than livelock under sustained churn).
- This bounds the re-dump (≤1 retry) to avoid the livelock SMR NIT-2 correctly
  feared, WITHOUT the discard-and-converge unsoundness it introduced.

### 5.F — Monitor thread respawn-on-panic (AGY r4 finding 5 — hardening)
`neigh_monitor_thread` is spawned via `spawn_supervised_aux("neigh-monitor", …)`
at `bringup.rs:338`, which (per its own `#925-A` comment at `bringup.rs:336`)
wraps the body in `catch_unwind` so a panic doesn't kill the daemon — **but has
NO respawn policy.** A malformed netlink frame or a persistent OS error that
panics the thread kills the monitor **permanently**, freezing
`dynamic_neighbors`: no further RTM_{NEW,DEL}NEIGH are processed, every new cold
flow re-probes and re-buffers, and there is no recovery short of a daemon restart.
- **Fix:** give the neighbor monitor a respawn-on-panic/exit policy (bounded
  restart loop with backoff, or convert `spawn_supervised_aux` to a respawning
  supervisor for this specific thread). The respawned monitor re-runs
  `initial_neighbor_dump` (now the 5.A.2 swap, so no stale leak / no seq=0 drop).
- **Ordering vs persistent-error busy-loop (OQ-6):** the respawn loop must back
  off on a tight crash loop (e.g. an unrecoverable EBADF) rather than respawn at
  100% CPU — pair this with the OQ-6 persistent-errno break/recreate.
- **Scope:** hardening, shippable with 5.A.2 or independently; it does not depend
  on Gate-R outcome (it is a code-verified latent freeze hazard).

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
- Unit (5.A.2 swap): `initial_neighbor_dump` builds a side table and atomically
  swaps it in. A seq=0 type-28 NEW arriving during the dump is **staged
  (key-collapsed) then replayed onto the local table** and lands in
  `dynamic_neighbors` after the swap; a seq=0 NLMSG_DONE/NLMSG_ERROR is NOT
  treated as dump-terminating (stays seq-matched).
- Unit (5.A.2 last-writer-wins): for the **same key**, DEL-then-NEW ⇒ entry
  **present** after swap; NEW-then-DEL ⇒ entry **removed** after swap (the
  key-collapsed staging map holds the last-writer state; replay applies it once).
- Unit (5.A.2 stale-entry leak / H-E): an entry present in `dynamic_neighbors`
  before the dump but ABSENT from the dump rows (kernel-deleted) is **gone after
  the swap** (the clear+copy removes it). This is the regression test for the
  pre-existing leak.
- Unit (5.A.2 atomicity): a concurrent reader either sees the full pre-swap set
  or the full post-swap set — never a partial set (exercise via the
  `with_all_shards` bulk-lock path, mirroring the #949 invariant).
- Unit (5.E.1 overflow fallback): staging overflow marks dirty + schedules ≤1
  re-dump; a second overflow stops re-dumping and increments the degraded metric
  (NO unbounded re-dump; NO silent discard-and-converge).
- Unit (5.F respawn): a panic in the monitor body respawns the monitor (bounded
  backoff), and the respawned monitor re-runs the dump/swap.
- Unit (5.A.3, if chosen instead): dual-socket — multicast socket bound before
  the dump captures the resolution advert; dump socket closed after NLMSG_DONE.
- Unit (5.E, only if H-D.1 confirmed): ENOBUFS on the steady-state loop triggers
  socket recreation + resync (via the 5.A.2 swap); the permanent ENOBUFS counter
  increments.
- Cluster smoke (full matrix): v4+v6 × push+`-R` × CoS-off+CoS-on first-connect
  after restart ≤200ms; after BINDING-reconcile commit ≤200ms; after clean +
  crash failover ≤200ms — zero both-signal World-1 condition on the cold target.
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
9. **5.A.2 staging memory bound + overflow fallback (RESOLVED to bounded
   re-dump; v5):** the Key-Collapsed Staging Map is naturally bounded by unique
   neighbor IPs (kernel `gc_thresh*`). If a defensive cap is still hit, the
   fallback is **mark-dirty + ≤1 async re-dump (clean socket-recreate) after ~1s,
   then degraded log/metric** — NOT unbounded re-dump, and explicitly NOT
   "stop staging and let steady-state converge" (Codex r4 finding 2 + AGY r4
   finding 4: the dump already consumed those seq=0 messages; the steady-state
   loop only sees *later* ones, so discard = permanent desync). SMR r4 NIT-2 is
   retracted. See §5.E.1.
10. **Monitor respawn-on-panic (AGY r4 finding 5; RESOLVED to §5.F):**
    `spawn_supervised_aux` at `bringup.rs:338` catches the panic (`#925-A`) but
    does NOT respawn → a panic permanently freezes the neighbor cache. §5.F
    mandates a bounded respawn-on-panic with backoff (paired with OQ-6's
    persistent-errno break/recreate to avoid a 100%-CPU crash loop).
11. **Double-buffered swap concurrency (r5 review target):** does the
    clear+copy-under-`with_all_shards` swap (`sharded_neighbor.rs:135`) introduce
    a lookup-miss window for workers mid-swap, or does the bulk lock make the swap
    atomic to readers as the #949 path claims (`coordinator/mod.rs:169`)? The swap
    is one-shot at dump completion (not per-packet), so the brief bulk-lock hold
    is off the hot path — but /engineer must confirm no reader path bypasses the
    shard lock.

---

## 10. Recommendation (3-way converged, v5, pre-Gate-R)

**PLAN-READY for Gate-R.** Gate-R confirms the latency mechanism per window and
decides which fix (if any) ships for the failover scope. The fix shape is now
fixed (the Double-Buffered Atomic Swap); Gate-R decides *scope*, not *mechanism*.

- **Daemon-restart + crash-promote (fw1 reboots) + Window-3 BINDING reconcile:**
  if R1 counter A confirms H-0 (seq=0 resolution advert dropped during
  `initial_neighbor_dump`), ship **5.A.2 — the Double-Buffered Atomic Swap**
  (5.A.3 dual-socket is the alternative to weigh at /engineer): build the table
  off to the side from dump rows + key-collapsed staged seq=0 deltas, keep
  NLMSG_DONE/ERROR seq-matched (AGY r2 (a) guard), then atomically clear+copy
  under `with_all_shards` (the established #949 pattern at
  `coordinator/mod.rs:169`). This fixes H-0 (seq=0 drop) AND the **verified H-E
  stale-entry leak** in one mechanism, driver-agnostic, off the promote / VRRP
  path. Ship **5.F (respawn-on-panic)** as hardening alongside, and **5.E.1
  bounded-re-dump** overflow fallback.
- **Clean VRRP failover (fw1 daemon stays up):** H-0 cannot apply (no dump at
  promote). The fix depends on what R2 shows (R3 matrix):
  - both-signal World-1 **WITH** ENOBUFS → ship **5.E** (ENOBUFS resync via the
    5.A.2 swap + socket-recreation + larger SO_RCVBUF). Build 5.E only if ENOBUFS
    is actually observed (H-D.1).
  - both-signal World-1 **with ENOBUFS==0** → **UNKNOWN path; escalate, ship
    neither** (Codex r4 finding 3).
- **If R1 refutes H-0** (counter A == 0; resolution arrives after `NLMSG_DONE`):
  the restart 1.7s is a never-buffered single-SYN drop (Codex HIGH-1) →
  investigate the recycle / XDP-readiness path.
- **Disposition is per-scope (Codex r3 MEDIUM-2 + Codex r4 finding 6):** failover
  scope vs restart/Window-3 scope decided independently with the **both-signal**
  bar (RTO signature AND daemon counter; target B verified-absent at promote). If
  the cold target shows ZERO both-signal trials in BOTH failover modes → PLAN-KILL
  the *failover* scope. Separately, if Window-1 (restart) OR Window-3
  (BINDING-reconcile) shows the both-signal condition → ship 5.A.2 for that scope
  (NOT "ship anyway after a kill" — a distinct, independently-justified scope).
- **H-E (stale-entry leak) is independent of Gate-R:** it is a code-verified
  pre-existing correctness bug on master, fixed opportunistically by the same
  swap. Even if every latency scope turned World 2, the swap is still justified to
  close H-E (and as the 5.E prerequisite).
- **Rejected:** 5.B (liar-flag gate, `neighbor.rs:516/520`), 5.C.1/5.C.2
  (on-link warm misses the no-prior-session cold target; 5.C.2 redundant with
  prewarm), 5.A.1 (blocking pre-dump risks forwarding-arm/failback latency),
  SMR r4 NIT-2 steady-state-converge fallback (unsound — retracted in §5.E.1).

The decisive Gate-R deliverables: (1) **R1 daemon counter A** + dump duration —
confirms/refutes H-0 for the restart/crash-promote/Window-3 scope; (2) **R2 on an
aged, never-seen target B (verified-absent at promote) across BOTH clean and crash
promote, both-signal bar** — tells us which window (if any) is World 1 and which
fix (5.A.2 vs 5.E vs escalate) applies; (3) **ENOBUFS counting on the standby** —
confirms/refutes H-D.1. All cheap; run before code.

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

- **r4:** v4 reviewed.
  - **Codex r4** (`codex-plan-r4.md`, `task-mpr1hywo-cxrf47`):
    **PLAN-NEEDS-MINOR.** Three contract fixes: (1) Window-3 overclaimed — same-plan
    snapshot apply bypasses reconcile via `refresh_runtime_snapshot`
    (`snapshot.rs:84` → `coordinator/mod.rs:457`), so Window-3 = "every accepted
    BINDING reconcile / worker rebuild," NOT every policy-only commit. (2) SMR
    r4 NIT-2 "let steady-state converge" fallback is UNSOUND — the dump already
    consumed the seq=0 msgs (`neighbor.rs:406/434`); the steady-state loop
    (`:526`) only sees later msgs → permanent desync; use bounded re-dump. (3) R3
    clean-failover cell stale (`plan.md:376` vs `:648`) — add the
    clean-failover-RTO + cold + ENOBUFS=0 = unknown branch. 6-checks: no 4th
    window; FIFO/collapsed replay required; DONE/ERROR seq-matched; only seq=0
    type-28/29 staged; 5.A.2 standalone value confirmed; per-scope kill crisp but
    stale matrix wording must be fixed.
  - **AGY r4** (`agy-plan-r4.md`, `adversarial-review-mpr1hhma-hbycu7`):
    **PLAN-NEEDS-REVISION.** (1) No 4th window (3 exhaustive: `tear_down`,
    `stop`, `stop_with_event_stream`; monitor spawned only at `bringup.rs:338`).
    (2) **CRITICAL NEW BUG — Window-3 stale-entry leak:** `dynamic_neighbors` is
    long-lived; `tear_down`/`stop_inner` never clear it; `initial_neighbor_dump`
    only upserts (`neighbor.rs:446`) → kernel-deleted neighbors persist forever →
    L2 stale-MAC leak. Fix = Double-Buffered Atomic Swap (thread-local table →
    dump rows + staged seq=0 → replay → clear+copy under `with_all_shards`
    `sharded_neighbor.rs:135`). (3) Key-Collapsed Staging Map supersedes the
    FIFO-Vec (order-independent + memory-bounded). (4) Overflow fallback = bounded
    re-dump, NOT discard (concurs with Codex; SMR NIT-2 retracted). (5) Thread
    supervision: monitor via `spawn_supervised_aux` has no respawn-on-panic →
    permanent cache freeze; mandate respawn. (6) Kill-bar: require BOTH RTO
    signature AND daemon counter; programmatically verify target B absent (kernel
    + `dynamic_neighbors`) before promote.
  - **Claude SMR r4** (`claude-smr-plan-r4.md`): PLAN-READY with 2 NITs; **NIT-2
    self-corrected** — Codex+AGY proved the steady-state-converge fallback unsound
    (dump consumes the messages). Window-3 re-verified unconditional *once
    reconcile is called*, but Codex's same-plan-bypass narrowing is the precise
    scope.
  - **Outcome:** NOT converged at r4. Parent verified AGY's stale-leak
    (CONFIRMED: `stop_inner` at `coordinator/mod.rs:199` clears stop flags + warm
    queue but NOT `self.neighbors.dynamic`), the #949 swap primitive already
    exists at `coordinator/mod.rs:169` (`with_all_shards` clear+copy), and Codex's
    same-plan bypass. **v5 changes:** §1/§3 Window-3 narrowed to BINDING
    reconcile + same-plan-bypass citation; §3 new **H-E** stale-entry-leak
    sub-section (pre-existing master bug); §5.A.2 upgraded to the **Double-Buffered
    Atomic Swap** (fixes H-0 + H-E) with **Key-Collapsed Staging Map**; new
    **§5.E.1** bounded-re-dump overflow fallback (retracts SMR NIT-2 as unsound);
    new **§5.F** respawn-on-panic; §4 kill bar upgraded to **both-signal + target-B
    verified-absent**; §4 R3 matrix rebuilt (per-row named fix + ENOBUFS=0
    escalate cell); §8 tests + §9 OQ-9/10/11 + §10 recommendation updated.

- **r5:** v5 addresses every r4 finding. Awaiting r5 confirmation (Codex + AGY)
  that the Double-Buffered Atomic Swap is correct under concurrent worker reads,
  the key-collapsed staging is last-writer-correct for DEL/NEW both orders, the
  bounded re-dump fallback + respawn-on-panic + both-signal kill bar are sound,
  and no stale matrix/World wording or new blocker remains.
