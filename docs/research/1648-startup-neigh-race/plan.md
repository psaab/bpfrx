# #1648 — Startup/failover neighbor-dump race: first cold connect ~1s

**Status:** DRAFT v1 (research-only; /research, not /engineer)
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

**This plan must (a) verify that exact ordering on the cluster, (b) decide a
fix, and (c) decide whether failover actually hits the ~1s or whether it is a
deploy-restart-only artifact** — the latter would justify PLAN-KILL.

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
On fw0:
1. `ip neigh flush all` on fw0 and on the client; `systemctl restart xpfd`.
2. Run `ip -ts monitor neigh` on fw0 (capture the RTM_NEWNEIGH stream the
   monitor consumes) AND timestamp:
   - T0: worker threads go live (first poll),
   - T1: `neigh_monitor: initial kernel neighbor dump complete` log,
   - T2: first cold SYN observed (xpf debug),
   - T3: `trigger_kernel_arp_probe` fired,
   - T4: kernel RESOLVED advert for the target,
   - T5: buffered SYN forwarded (or dropped at timeout).
3. Immediately (within the window) connect once to `172.16.80.200`. Measure
   connect latency. Repeat 5× with varying delay-after-restart (0ms, 50ms,
   200ms, 500ms, 2s) to map where the ~1.7s lives vs where it has decayed to
   ~ms.
4. **Pin: how long is `initial_neighbor_dump` (T1−T0)?** Is T4 (kernel resolved)
   consumed by the monitor before or after T1? Is the buffered SYN re-driven at
   the 10/60/260ms schedule, or does it sit to the 800ms timeout → drop?

### R2 — RG-promote (failover) reproduction — THE DECIDER
1. Settle both nodes. fw0 active, fw1 standby. Ensure fw1's kernel neighbor
   table state for the on-link target is in its **natural** post-standby state
   (do NOT artificially flush fw1 — we want the production condition).
2. Trigger a clean VRRP failover (priority-0 burst, or `request chassis cluster
   failover`), so fw1 promotes.
3. Measure: (a) VRRP failover time (must stay ~60ms), (b) first cold connect to
   `172.16.80.200` through the *new* primary fw1, both v4 and v6, both push and
   `-R`.
4. Capture `ip -ts monitor neigh` on fw1 across the promote: did the on-link
   target's neighbor already exist (warm) at promote, or was it MISSING and
   re-resolved from scratch?
5. Repeat the standby-aged case: let fw1 sit standby long enough for its kernel
   neighbor for the target to age to STALE/FAILED, then failover and measure.

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

### 5.B — Gate cold-flow admission until seeded (targets H-A, HA-risky)
Hold cold-flow neighbor resolution (NOT all forwarding) until
`neighbor_generation >= 1` (dump done). Fall the cold SYN to buffer-and-retry
(already happens) but ensure the retry re-drives aggressively. **HA risk:** must
NOT gate VRRP or established/synced-session forwarding — only the
`MissingNeighbor` cold path. Since cold flows already buffer, this is largely a
no-op vs 5.A unless it adds a faster re-drive trigger keyed on the
generation-bump. Low marginal value; likely folded into 5.A.

### 5.C — On-link warm at config-apply AND at RG-promote (targets H-C, the prize)
Extend `queue_warm_pass` to also warm on-link destinations. The hard part (per
the old #1648 body): on-link hosts are not enumerable from config. Options:
- **5.C.1 Warm connected-route gateways/known hosts only.** Warm the configured
  interface's own subnet anchors (the gateway, any statically-configured
  neighbors, DHCP server, VRRP peers) — NOT every /24 host. Low cost, but does
  NOT warm the arbitrary iperf3 target.
- **5.C.2 Warm observed/recently-active on-link peers at promote.** At
  RG-promote, re-warm the on-link hosts that had live sessions before failover
  (drawn from the synced session table's on-link destinations). This directly
  warms the hosts that matter post-failover. **Strong candidate if R2 shows
  on-link failover hits the ~1s.** Bounded cardinality (active sessions), per-RG
  gated, fired off the hot path via the existing warmer worker.
- **5.C.3 First-packet fast-warm (already exists).** The probe schedule
  10/60/260ms is already the first-packet fast-warm. The only lever left is
  lowering the floor — but Gate-M shows steady-state is already ~5ms, so there's
  nothing to gain here outside the startup window.

### 5.D — Combination (likely answer)
If R1 confirms H-A (dump-window re-drive broken) AND R2 confirms on-link
failover hits ~1s: ship **5.A.2** (process mid-dump multicast adverts so the
startup window self-heals in ~5ms) + **5.C.2** (warm prior-session on-link peers
at promote). If R2 shows failover does NOT hit it: ship only **5.A.2** as a
small deploy-restart polish, or PLAN-KILL if the startup window is also already
<200ms.

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

- Unit: extend `queue_warm_pass` tests (`coordinator/tests.rs:1468+`) for the
  on-link / connected-route enqueue path; add a test that
  `on_rg_promote_active` warms prior-session on-link peers (5.C.2).
- Unit: `initial_neighbor_dump` mid-dump multicast handling (5.A.2) — a test
  that a NEW advert with non-matching seq during a dump is applied, not skipped.
- Cluster smoke (full matrix): v4+v6 × push+`-R` × CoS-off+CoS-on first-connect
  after restart ≤200ms; after failover ≤200ms.
- `make test-failover`: zero-drop, VRRP ~60ms unchanged.

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
5. **5.C.2 cardinality & cost:** warming all prior-session on-link peers at
   promote — under a large session table, how many probes does that fire? Must
   be bounded + rate-limited + per-RG gated; otherwise promote triggers a probe
   storm that itself delays the warmer queue. Reuses `WARM_QUEUE_DEPTH` bound —
   verify it's adequate.
6. **mlx5/native-XDP specificity:** Gate-M ran on mlx5 VFs. Does the standalone
   i40e PF-passthrough env behave differently for the dump-window race? The fix
   must not be mlx5-specific (the connected-route warm gap is driver-agnostic).
7. **Is `connected_v4`/`connected_v6` even populated with the data needed to
   warm on-link?** §2.3 says `queue_warm_pass` never reads it; verify it carries
   the egress ifindex + subnet but NOT individual hosts (so 5.C.1 can warm the
   gateway but not arbitrary hosts — confirming on-link host warm needs the
   session-derived list of 5.C.2).

---

## 10. Recommendation (provisional, pre-Gate-R)

**PLAN-READY for Gate-R; fix shape conditional on R1/R2.** Do NOT ship code
until R2 decides production-relevance:
- **If R2 = World 1** (failover hits ~1s for on-link): ship **§5.D** = 5.A.2
  (mid-dump multicast drain so the startup window self-heals) **+** 5.C.2
  (warm prior-session on-link peers at RG-promote, off the hot path, per-RG
  gated, bounded). Expected: failover first-connect ~1s → ≤200ms; VRRP
  unchanged at ~60ms.
- **If R2 = World 2** (failover already ~ms; only deploy-restart hits ~1s):
  **PLAN-KILL** as a deploy-testing artifact, OR ship only the cheap 5.A.2
  startup polish if R1 shows a clear dropped-SYN bug. Document the measurement.

The single most important deliverable is the **R2 failover measurement** — it
is the difference between a real production fix and gold-plating a deploy
artifact.

---

## 11. Reviewer convergence log

See `reviewer-ids.md` for task IDs. Per-round verdicts appended below.

- **r1 (draft):** pending Codex + AGY + Claude SMR.
