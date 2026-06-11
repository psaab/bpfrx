# #1760 — NAT reverse-key 1:N collision, stage-2 revisit (post-eBPF-retirement)

**Revision:** v4 (convergence — round-3 verdicts: Codex PLAN-NEEDS-MINOR
(single scoped-wording finding, folded in below), AGY PLAN-READY, Claude
SMR PLAN-READY. v4 scopes the watch claims to forward-NAT-vs-forward-NAT
collisions and documents the LocalMiss primary-tuple-shadow as a separate
open observation, per Codex r3.)
**Date:** 2026-06-10
**Branch:** `research/1760-reverse-key-v2`
**Issue:** #1760 (stage-1 counter shipped #1762; stage-2 SHELVED 2026-06-06,
plan-kill label; prior design-of-record at
`docs/research/1760-nat-collision-structural-fix/plan.md` on
`research/1760-nat-collision-counter`)
**Mode:** /research — PLAN-READY or PLAN-KILL only. Keep-watch and close are
fully legitimate outcomes; PLAN-KILL is explicitly invited (§11 Q5).

---

## 1. Why revisit a justified shelve

The 2026-06-06 shelve rested on three pillars:

1. **0 observed incidence** — the #1762 counter
   (`xpf_userspace_session_nat_reverse_key_collisions_total`) stayed 0, so
   "keep the counter watching; revisit if nonzero".
2. **"Userspace can't see TCP state — BPF offloads the fast path"** (AGY,
   round 2) — killed any liveness predicate richer than expiry-only and was
   cited as a reason install-time refusal needs an HA-protocol redesign.
3. **No deterministic HA arbitration winner** for the active/active
   transition window + **shared-map liveness undefinable**
   (`SyncedSessionEntry` has no `last_seen`/`closing`).

This revisit re-verified each pillar against the post-#1373-complete tree
(origin/master `aa6fa6fc8`) and live cluster. **Pillar 2 is false today, and
pillar 1's watch is structurally much weaker than the shelve assumed.**
Pillar 3 stands. The honest question for this round is therefore NOT "was the
shelve wrong" (its conclusion may still be right) but "is the *watch* sound
enough to justify continuing to lean on it, and did the refusal design get
cheaper".

## 1.7 Round-1 disposition (v2 changes)

Verdicts: **Codex** (`task-mq912xff-4iym1m`) PLAN-NEEDS-MINOR, "Path W is
still the right ship"; **AGY** (`adversarial-review-mq90z9rb-438t86`)
PLAN-KILL; **Claude SMR** PLAN-NEEDS-MINOR. Not converged; v2 dispositions:

| r1 finding (reviewer) | v2 disposition |
|---|---|
| §2.4 overstates session-table TCP-state consumption: pure ACKs (`(tcp_flags & 0x17) == 0x10`) are consumed by the userspace **flow cache** (`flow_cache.rs:215`, `poll_descriptor/mod.rs:235` `Consumed => continue`) without per-packet session-table flag handling (Codex 1) | **Accepted.** §2.4 rewritten: userspace *receives* every transit packet (the load-bearing claim — the prior shelve's pillar 2 is still dead), but an `established` bit is NOT a free one-field change; it must hook the flow-cache path or tolerate seeing only non-pure-ACK packets. A1's predicate stays expiry-only; nothing in Path W depends on TCP state. |
| A1's shared-map guard is not race-free as sketched: local install (`poll_descriptor:1274`) precedes `publish_shared_session` (`:1311`); two workers can both see K absent (Codex 2 = SMR F1 TOCTOU) | **Accepted.** §5/A1 now states a race-free guard requires atomic check-and-reserve of K under the `shared_nat_sessions` lock BEFORE local/BPF commit — a commit-order inversion, not just an added check. Strengthens W over A1. |
| Stale "misses 5/6" text in Path K contradicts the corrected §2.3 (Codex 3) | **Fixed** (§5 Path K rewritten). |
| §2.7 needs the cross-host factor: ≈ C(F,2)·(1−1/H)/28232 (Codex 4 = SMR F3) | **Fixed** in §2.7 main text. |
| W2 needs explicit SNAT-mode preflight + flow-1-reverse-path-works precondition (Codex 5 = SMR F2) | **Accepted** — and the preflight was executed live this round: fw0 active config confirmed `source-nat { interface; }` for lan→wan v4+v6 (flocked read, 2026-06-10). §6 W2 adds both assertions. |
| Watch counter is "forgetful": after the winner's value-guarded removal deletes K (`session/mod.rs:1459-1467`), a later S3 collision inserts with `prev=None` — uncounted (AGY 1, High, kill-driver) | **Partially accepted; severity refuted with source.** The mechanism is real but the blackout is bounded: the live loser re-wins K on its next session refresh — `update_session` unconditionally re-asserts secondary ADDS (`session/mod.rs:928-940`), and *each* S1↔S2 alternation increments the counter (`:1399-1405`); the original S1/S2 displacement was already counted at S2's install. The counter is an **event detector** (≥1 count per colliding pair that passes traffic), not a census — exactly what a watch needs. The uncounted corner (loser goes permanently silent before any re-assert AND a third flow collides inside the absent-K window) does not erase the already-counted first event. §2.3 now documents this. |
| Failed-install wart is Critical and shipping watch-only is "poor priority alignment" (AGY 2) | **Accepted in spirit.** The wart (§2.5) is promoted from "out of scope, maybe file" to a **named Path-W deliverable: file the dedicated issue immediately** (it is independent of #1760's collision semantics and reachable today via `max_sessions`). Fixing it stays its own issue/PR — bundling an install-path behavior change into a watch-only PR would force failover gating onto an observation change. |
| A1 presence check on `shared_nat_sessions` introduces "critical lock contention"; installs are "completely worker-local and lock-free" today (AGY 3, High) | **Refuted on premise:** every install already takes the same three shared-map mutexes via `publish_shared_session` (`poll_descriptor:1311`, `shared_ops.rs:655/667/...`). One added presence check is marginal; the real A1 cost is the commit-order inversion (Codex 2). §5/A1 notes both. |
| W1 per-worker 60s throttle can still emit workers×1/min lines (AGY 4) | **Accepted.** W1 throttle is now **process-global** (`static AtomicU64` CAS, the existing pattern at `bpf_map/mod.rs:867-880`): ≤1 line/min per process regardless of worker count. |
| W3 shared-map counter adds sync overhead for a redundant metric (AGY 5) | **Accepted — W3 dropped** from the recommendation (already redundant per §2.3). |
| W-vs-K hinges on whether a multi-host/production deployment is anticipated; surface as explicit operator conditional (SMR F5) | **Accepted** — §5 recommendation restated as a conditional; AGY's K vote recorded there. |
| W1 eprintln-on-worker-thread safety (SMR F4) | **Accepted** — §6 W1 notes the ≤1/min global bound and the existing `xpf-ha:` stderr precedent. |

## 1.8 Round-2 disposition (v3 changes)

Verdicts: **Codex r2** (`task-mq91i26m-ke7g4c`) PLAN-NEEDS-MAJOR ("amended W
remains plausible; K only honest for lab-only posture; A1 still not
justified"); **AGY r2** (`adversarial-review-mq91hvda-u43zjb`)
PLAN-NEEDS-MAJOR. The two external reviewers independently converged on the
same factual refutation of v2; all accepted findings are folded in here.

| r2 finding (reviewer) | v3 disposition |
|---|---|
| **`MissingNeighborSeed` installs are never replicated** — `poll_descriptor/mod.rs:2447-2502` installs + shared-publishes + BPF-publishes with NO `replicate_session_upsert`; `MissingNeighborSeed` is not promotable (`entry.rs:85-87,105`) and emits no delta (`mod.rs:727`); the neighbor-resolution replay forwards buffered frames without touching sessions (`neighbor_dispatch.rs:205-266`). Two cold-neighbor colliding flows on different workers are NEVER counted by the per-worker #1762 counter — a realistic first-event miss (cold egress neighbor + two LAN hosts, the exact #1782-family idle scenario) (Codex r2 F1, High). | **Accepted — verified end-to-end** (no replication call in the block; no promotion site exists; replay path session-free). Consequence: the per-worker counter alone is NOT a sound watch. Path W amended (§5): the shared-publish displacement detector (v1's W3) is REVIVED as the *primary* event detector — `publish_shared_session` is the single choke point every forward NAT session passes through *including seeds* (`:2466`), so displacement there catches the seed case. |
| **v2's "loser re-wins K on its next refresh" is false** — `refresh_local` is `#[cfg_attr(not(test), allow(dead_code))]` (test-only, `session/mod.rs:960`); ordinary traffic refreshes go through `lookup_with_origin`/`touch` which update timestamps/wheel only and never call `index_forward_nat_key_parts`; flow-cache hits `touch` every 64 hits. After winner expiry the loser NEVER re-asserts K: its reverse path is permanently dead, and a later S3 collision on K inserts `prev=None`, uncounted (Codex r2 F2 Medium + AGY r2 F1 High — independently converged). | **Accepted — v2's event-detector defense is RETRACTED.** §2.3 rewritten. The per-worker counter counts install/replica-time displacements only (still ≥1 for a normal-path pair: the second install's replica displaces the first in every sibling table). The post-winner-expiry standing collision (S3 vs unindexed live S1) is invisible to BOTH displacement detectors (K is also removed from the shared map on winner teardown) — only a live-pair AUDIT can see it. Path W gains an optional incremental audit (W5) and W-lite explicitly documents this blind window if W5 is not taken. AGY r1 F1's thrust was more right than v2 credited. |
| W2 preflight no longer sufficient: warm-path-only validation deliberately avoids the seed path (Codex r2 F3, Medium) | **Accepted** — W2 gains a cold-neighbor variant (flush/age the egress neighbor, start both flows simultaneously from two source IPs, assert the SHARED detector fires even when the per-worker counter does not). |
| W1 throttle precedent miscited: `bpf_map/mod.rs:867-880` are plain counters, not a CAS throttle (Codex r2 F4, Low) | **Fixed** — precedent is the warm-sweep CAS throttle `coordinator/mod.rs:760-775` (load → window check → `compare_exchange` claim). |
| Failed-install wart has a second face: at `max_sessions-1` the FORWARD install succeeds and the REVERSE install fails (`mod.rs:690` cap check) with no forward rollback → permanent one-way blackhole; the v2-documented face (forward fails, reverse still installed) leaks half-open reverse entries (AGY r2 F2, Medium) | **Accepted** — both faces go into the W4 issue body. Still its own issue/PR (install-path behavior + failover gating). |
| W1 warn/help text must state the watch's real semantics (AGY r2 Q2) | **Accepted** — text now: "counts install-time displacement events; a standing collision against an already-unindexed session is not counted (see plan §2.3); ≥1 ⇒ at least one real collision occurred". |

## 2. Fresh evidence (2026-06-10/11)

### 2.1 Live counter — 0, but the window is tiny

Both nodes, all 12 workers, read 2026-06-11 (flocked):
`xpf_userspace_session_nat_reverse_key_collisions_total 0` and all
`...worker_session...{worker_id=0..5} 0` on fw0 and fw1. Journals: 0 hits for
any reverse-key string (and code grep confirms **no journald warn exists** —
the #1762 ship is counter-only).

But `systemctl show xpfd -p ActiveEnterTimestamp` = **2026-06-11 04:06:47 /
04:07:00 UTC** — the daemons restarted *hours* ago. The counter lives in
process memory (`SessionTable::nat_reverse_key_collisions`,
`session/mod.rs:174`) and resets on every restart; this cluster is redeployed
many times per day for smoke. "0 since 2026-06-06" is really "0 across many
short windows", with no durable artifact (no warn line, no Prometheus
long-term store in the lab) that would survive a reset.

### 2.2 Lab traffic structurally cannot collide

A collision needs two *distinct internal hosts* (or one host to two DNAT
VIPs) that pick the **same source port** toward the same external
(dst_ip, dst_port) through a portless NAT mode. A single client's kernel
never assigns the same ephemeral port twice to the same destination
(`inet_hash_connect` uniqueness is per 4-tuple), and the loss-cluster smoke
drives iperf3 from essentially **one** LAN host. So the lab watch is reading
a population in which the event is near-impossible regardless of the bug.
**0 is data, but it is data about the lab, not about the defect.**

### 2.3 Watch coverage audit — replica fanout closes the cross-worker gap; the real gaps are durability and population

I initially hypothesized a cross-worker blind spot (session tables are
per-worker; two colliding forward tuples RSS to the same worker with only
~1/6 probability with 6 queues). **That hypothesis is WRONG, verified
against the whole path:** every locally-installed forward session is fanned
out to ALL sibling workers via `replicate_session_upsert`
(`session_glue/mod.rs:596`, called at `poll_descriptor/mod.rs:1325`) →
`WorkerCommand::UpsertSynced` → `handle_upsert_synced`
(`session_glue/commands/upsert_synced.rs:18`) →
`upsert_synced_with_origin` (`session/mod.rs:766`), which calls
`index_forward_nat_key` and therefore runs the SAME #1762 displacement
branch (`session/mod.rs:1393-1406`). Cross-node likewise: HA import pushes
`UpsertSynced` (`ha.rs:331`). So once replicas land, every worker's table
contains both colliding forward sessions and the counter fires (with up to
worker-count multiplicity — it is an over-counting upper bound, as the
#1762 docs already state). **The counter's event coverage is sound.**

What the audit DID find:

- `publish_shared_session` (`shared_ops.rs:648-690`) plain-`insert`s the
  reverse-wire and reverse-canonical keys into `shared_nat_sessions` with
  no displacement check. This surface is *redundantly* covered by the
  local-replica detection above, so it is a consistency gap, not a blind
  spot; a counter there is optional belt-and-suspenders (it would also be
  the only signal if a replica command were ever lost).
- The counter emits **no durable artifact**: no journald warn, in-process
  value reset by every restart, no long-term Prometheus store in the lab
  (§2.1). A collision that happened yesterday before a redeploy is
  unobservable today.
- **Counter semantics (corrected in v3 after both r2 reviewers refuted
  v2's reading):** the counter fires ONLY at install/replica/promote-time
  index inserts. Ordinary traffic never re-asserts indices
  (`lookup_with_origin`/`touch` update timestamps/wheel only;
  `refresh_local` is test-only, `session/mod.rs:960`). Consequences:
  (a) a normal-path colliding pair IS counted at least once — the second
  session's install or replica displaces the first in every sibling table;
  (b) after the winner's value-guarded removal deletes K
  (`session/mod.rs:1459-1467`), the live loser NEVER re-wins K — its
  reverse path is permanently dead (this is the bug itself), and a later
  S3 collision on the now-absent K inserts `prev=None`, uncounted;
  (c) **`MissingNeighborSeed` installs are never replicated**
  (`poll_descriptor/mod.rs:2447-2502`, no `replicate_session_upsert`; not
  promotable, `entry.rs:85-87,105`), so two cold-neighbor colliding flows
  on different workers are never counted at all — a realistic first-event
  miss (Codex r2 F1).
  A displacement-based detector is therefore sound only at the
  **shared-publish choke point** (`publish_shared_session`,
  `poll_descriptor:2466` — seeds publish too), and even there a standing
  collision against an already-unindexed live session (case b) is
  invisible; only a periodic live-pair audit sees that. Path W (§5) is
  built around exactly this coverage map.

  **Scope (Codex r3):** everything above — and all of Path W — concerns
  **forward-NAT-vs-forward-NAT** collisions (the #1760 domain). Codex r3
  confirmed no other production *transit* forward-NAT creation path
  bypasses `publish_shared_session` (normal `poll_descriptor:1311`, seed
  `:2466`, promote `promote.rs:124`, HA sync `ha.rs:262`, tunnel
  `tunnel.rs:306`). A separate, adjacent observation — NOT a #1760
  collision and NOT closed by W3′ or W5 — is the **local-delivery
  primary-tuple shadow**: `install_helper_local_session_on_miss`
  (`forwarding/mod.rs:1069`, `SessionOrigin::LocalMiss`, LocalDelivery,
  is_reverse=false, no shared publish, no replication) installs a session
  whose PRIMARY key can equal the on-wire reply tuple of a transit SNAT
  flow, and direct session lookup runs before NAT reverse lookup
  (`session_glue/mod.rs:911` vs `:1015`). AGY r3 argues the tuples are
  disjoint in practice (a transit reverse-wire K carries the backend/
  remote as src, the local session the interface IP); Codex r3 keeps it
  as a tuple-shadowing risk worth a one-line note. Recorded here as an
  open observation for any future flow-ambiguity audit; out of scope for
  this plan's watch.

**Net: the watch detects the event if it happens while you are looking, but
resets on every deploy and observes a lab that cannot generate the event
(§2.2).** The revisit trigger "counter goes nonzero" is currently close to
unfalsifiable — not because the counter misses collisions, but because the
window is short-lived and the population is degenerate.

### 2.4 NEW — pillar 2 is false: userspace sees every transit packet

The eBPF retirement (#1373) is complete; the AF_XDP shim
(`userspace-xdp/src/lib.rs:530-690`) makes exactly two choices per transit
packet: **redirect to the userspace XSK** (session hit *and* session miss)
or **pass to kernel for local delivery**. `live_userspace_session_action`
(`lib.rs:1331`) gates *which* of those, never a kernel-forwarding fast path
for established transit flows. Therefore **userspace receives SYN, SYN-ACK,
ACK, FIN — the full handshake — for every transit flow.** That kills the
prior shelve's pillar 2 as stated ("userspace never sees SYN-ACK/ACK").

Precision required by Codex r1 (finding 1): "receives" ≠ "the session table
consumes the flags of every packet". Pure ACKs
(`(tcp_flags & 0x17) == 0x10`, `flow_cache.rs:215`) on cached flows are
consumed by the per-worker userspace **flow cache**
(`poll_descriptor/mod.rs:235`, `Consumed => continue`) without touching
session-table flag handling; the table sees FIN/RST (`closing`,
`session/mod.rs:565-588`) and all non-pure-ACK slow-path packets (SYN and
SYN-ACK are never cache-eligible). So an `established` bit is *feasible*
(the handshake's SYN-ACK reaches slow path) but is NOT the free one-field
change v1 claimed if it must also observe pure-ACK liveness — it would
need a flow-cache hook. Nothing in Path W (or A1's expiry-only predicate)
depends on TCP state; this matters only to the optional A1 refinement.

What this does NOT change: a *peer-synced* session's TCP state is still
opaque on the standby (the standby never sees the packets), and
`SyncedSessionEntry` (`afxdp/worker/mod.rs:278`) still carries no
`last_seen`/`closing`. Pillar 3 (shared-map liveness + HA arbitration)
stands.

### 2.5 Confirmed — the failed-install control-flow wart is live

`poll_descriptor/mod.rs` (~1274-1450): when
`install_with_protocol_with_origin` returns `false` (today only the
`max_sessions` cap), the code rolls back the SNAT allocation — then **still
computes the reverse resolution, still installs the reverse session, and
still forwards the packet**. Any refusal mechanism must place its guard
before all commits (Codex round-2 finding, re-verified at head), and this
wart is worth fixing even independently of #1760.

### 2.6 Blast radius walk (question 2 of the revisit)

`reverse_wire_key` emits the full reply 5-tuple, so
`reply_matches_forward_session` passes for **both** colliding sessions — the
verify step cannot disambiguate. Concretely, with S1 and S2 sharing K:

- While both live: the index (local or shared) points at the last writer;
  **every** reply for either flow is un-NAT'd into that one session's
  internal tuple. The loser's replies are delivered to the *winner's*
  internal host/port — wrong-host data delivery (a real, if narrow,
  cross-flow information leak), typically answered by RST/ICMP and killing
  the winner too.
- On winner expiry: value-guarded removal (`session/mod.rs:1459-1467`)
  deletes K while the loser lives → the loser's replies become session
  misses → policy drop → loser hangs until timeout.

**Bounded to the colliding pair** (no spread to other sessions, no table
corruption, no crash), but within the pair it is silent mis-delivery, not
just a drop. Severity per incident: moderate; aggregate severity scales with
incidence.

### 2.7 Production incidence math (question 4)

Interface-SNAT, F concurrent flows from H ≥ 2 internal hosts (equal
traffic share) to one (dst_ip, dst_port), Linux ephemeral range ≈ 28,232
ports: only cross-host pairs can collide (kernel 4-tuple uniqueness is
per source IP), so expected concurrent collisions ≈
**C(F,2)·(1 − 1/H)/28232**. For H ≥ 10 the correction is <10%: F=100 →
~0.16-0.18 expected live collisions at any instant; F=250 → ~1.0;
F=500 → ~4. A real
deployment behind interface-SNAT (the **default** mode, used by the smoke
config itself) whose users hit a shared resolver/CDN/proxy endpoint with a
few hundred concurrent flows **will collide routinely**. DNAT-shared-backend
needs only ONE client whose kernel reuses a local port across two VIPs
(normal: port uniqueness is per-destination) — plausible at much lower flow
counts. The lab sits at the F≈12-from-one-host corner where P≈0.

## 3. Adjudication of the four revisit questions

1. **Does the post-retirement world change the shelve rationale?**
   Partially. The TCP-state-invisibility pillar is gone (§2.4): a local
   liveness predicate richer than expiry-only is now *possible* (though the
   minimal design below still uses expiry-only and treats `established` as
   an optional refinement). The HA pillars stand: no synced liveness fields,
   no deterministic transition-window arbiter. **Install-time refusal that
   is fully correct under HA is still a redesign; install-time refusal that
   is correct in steady state and degrades to today's behavior in the
   transition window is now a contained change** (§6, Path A1).
2. **Blast radius**: §2.6 — bounded to the pair, but silent wrong-host
   delivery while both live; worse than a clean drop.
3. **Is refusal now small?** The *local* guard is small, and thanks to
   replica fanout (§2.3) each worker's local table eventually holds all
   forward sessions, so a local-table check has good (not perfect — replica
   latency is a poll-tick) coverage. A race-free guard still needs the
   in-process `shared_nat_sessions` map (presence-based, no liveness),
   which is lock-cheap on the install slow path, but presence-based refusal
   against a stale synced entry can false-refuse for the GC+delete-sync
   latency window. Bounded, recoverable (SYN retransmit), but real. §6
   sketches it; §8 risks it.
4. **Incidence**: §2.2/§2.7 — lab 0 is near-zero-information; production
   interface-SNAT incidence is plausibly daily. There is no production
   deployment feeding this watch today, which cuts BOTH ways: no user is
   being hurt now (supports keep-shelved), and no watch data will ever
   arrive from the lab (the current revisit trigger never fires even if the
   bug is common in the field).

## 4. What this round must decide

The prior shelve's *conclusion* (don't build the HA redesign at current
incidence) can survive this evidence. What cannot survive unmodified is the
*watch*: it resets per deploy, emits no durable artifact, and observes a
population where the event is near-impossible (one LAN client cannot reuse
an ephemeral port to the same destination). "Revisit when nonzero" is
currently a trigger that structurally cannot fire from this lab.

## 5. Path options

### Path W (v3-amended) — repair the watch, keep stage-2 shelved (RECOMMENDED, conditional)

Observation-only, no dataplane behavior change. v3 restructures W around
the §2.3 coverage map (both r2 reviewers refuted v2's W):

- **W3′ — shared-publish displacement counter (PRIMARY detector,
  revived).** In `publish_shared_session` (`shared_ops.rs:648-690`), the
  `shared_nat_sessions.insert(...)` returns the displaced
  `SyncedSessionEntry`; count when `displaced.key != entry.key`
  (different forward session owning the same reverse key), excluding the
  reverse-canonical alias of the same entry. This is the single choke
  point ALL forward NAT sessions pass through — normal installs
  (`poll_descriptor:1311`), `MissingNeighborSeed` installs (`:2466`),
  and promotes — so it catches the Codex r2 F1 seed case the per-worker
  counter misses. Process-global `AtomicU64`; wire-additive export per
  the #1762 template. (v2 dropped this as "redundant" on the strength of
  the replica-fanout argument; Codex r2 F1 broke that argument — AGY r1
  F5's redundancy objection is superseded.)
- **W1 — durable artifact.** Rate-limited `eprintln!` journald warn when
  EITHER the per-worker counter (snapshot point `loop_body/mod.rs:187`)
  or W3′ increments. Throttle is **process-global** via the warm-sweep
  CAS pattern (`coordinator/mod.rs:760-775`: load → window check →
  `compare_exchange` claim), ≤1 line/min per process. Warn + Prometheus
  help text state the honest semantics: "counts install-time displacement
  events; a standing collision against an already-unindexed session is
  not counted; ≥1 ⇒ at least one real collision occurred". Journald
  persists across daemon restarts — the durable artifact the watch lacks.
- **W5 (optional) — incremental live-pair audit.** The one
  forward-NAT-vs-forward-NAT case no displacement detector can see (§2.3
  case b: S3 collides with a live loser whose K was already removed)
  needs a *condition* check, not an *event* check: an incremental sweep (bounded slots per maintenance
  tick, single-writer, no locks) over the worker's own slab building K
  counts for live forward entries; count>1 → live-collision gauge +
  W1 warn. Replica fanout means each worker's table contains all
  normal-path sessions; the seed-only corner is already covered by W3′
  at install time. **W-lite = W1+W2+W3′+W4 without W5** is a legitimate
  reduced ship that documents this blind window instead of closing it.
- **W2 — live-fire validation (warm + cold variants).** Preflight: active
  config portless interface-SNAT (verified live on fw0 this round) AND
  flow-1 reverse path proven before flow 2 starts. Warm variant: two
  source IPs on the LAN host, same bound source port, same dst:port →
  per-worker counter and/or W3′ nonzero + W1 warn + observed corruption
  shape recorded. Cold variant (Codex r2 F3): age/flush the egress
  neighbor first, start both flows simultaneously → assert W3′ fires
  even if the per-worker counter does not. NOT part of smoke (it
  deliberately corrupts flows).
- **W4 — file the failed-install wart issue** (§2.5) with BOTH faces:
  (i) forward install fails → SNAT rolled back but reverse session still
  installed + packet forwarded (half-open reverse leak); (ii) at
  `max_sessions-1` the forward install succeeds and the REVERSE install
  fails (`mod.rs:690` cap) with no forward rollback → permanent one-way
  blackhole (AGY r2 F2). Independent of #1760 semantics; fixed in its own
  PR (install-path behavior ⇒ failover gating a watch-only PR must not
  absorb).
- Issue disposition: stays open, keeps `plan-kill` on the structural fix;
  issue comment records the repaired watch; **new revisit trigger** =
  any collision counter/gauge nonzero OR W1 warn in any journal — or
  first real multi-host deployment behind interface-SNAT, whichever
  first.

**Recommendation conditional (SMR r1 F5; both r2 reviewers concur):** W is
worth its cost iff a multi-host or production deployment is plausibly in
this product's future — in the lab the population cannot collide, so even
a perfect watch reads 0 except under W2's synthetic fire. If the posture
is "lab-only, indefinitely", Path K (close as accepted-risk) dominates
(AGY r1 voted exactly that; Codex r2: "K is only honest for a lab-only
operator posture"). If silent cross-flow misdelivery is unacceptable for a
future deployment, A1-with-commit-order-inversion is the eventual fix and
W's detectors are its prerequisite incidence instrument. This is an
operator call the converged plan surfaces rather than buries; the default
if W is chosen: **W-lite** (W1+W2+W3′+W4), W5 only if the operator wants
the standing-collision window closed.

### Path A1 — steady-state install-time refusal (window = status quo)

The contained version of the prior Path A, now viable because pillar 2 fell:

- Guard at session install in `poll_descriptor` (the non-reverse,
  NAT-identity-rewriting, new-flow branch) **before** any commit: compute
  `K = reverse_wire_key(key, nat)`; refuse if EITHER
  (a) local `nat_reverse_index`/`key_to_handle` holds a different,
  **unexpired** handle (expiry-only predicate — `closing` incumbents still
  block per Codex round-2; an optional `established` refinement is possible
  now but NOT load-bearing and not free, §2.4), or (b) `shared_nat_sessions`
  holds an entry whose forward key differs (presence-based — no liveness
  available).
- **Race-freedom (Codex r1 F2 + SMR r1 F1):** as sketched above the guard
  is read-then-commit and two workers installing colliding flows in the
  same poll interval both pass it. A correct A1 must do an **atomic
  check-and-reserve of K under the `shared_nat_sessions` mutex BEFORE the
  local table install and BPF publish** — inverting today's commit order
  (local install `poll_descriptor:1274` → BPF publish → shared publish
  `:1311`) — with an unwind path if a later install step fails. Note the
  lock itself is not new cost: every install already takes these mutexes
  in `publish_shared_session` (AGY r1 F3's "lock-free today" premise is
  wrong); the cost is the control-flow inversion and its failure unwind.
- Disposition: hard drop — no forward install, no BPF publish, no shared
  publish, **no reverse-session install** (fixes §2.5 for this outcome),
  frame recycled; `nat_reverse_key_refused_total` counter (wire-additive).
- HA invariant: the guard does NOT run on `upsert_synced*` import (owner
  arbitrated; synced sessions install verbatim — refusal holds identically
  for locally-created flows on both nodes because a refused session is
  never published, so the peer never learns it: admit→both-have,
  refuse→neither-has).
- Honest residuals (carried from round 2, NOT solved here):
  (i) active/active or failover transition window — both nodes admit
  independently; import stays last-writer-wins = exactly today's behavior;
  the fix is "strictly better in steady state, never worse in the window",
  NOT full convergence. (ii) presence-based shared-map refusal can
  false-refuse against a stale (dead-on-owner, not-yet-delete-synced)
  incumbent for the GC+sync latency window; TCP recovers by retransmit,
  long-lived UDP may stall for that window.
- Requires `make test-failover` (session-install/HA path) + collision unit
  matrix + smoke.

### Path A2 — full HA convergence (prior round's redesign)

A1 plus: synced liveness fields on `SyncedSessionEntry` (wire change),
deterministic import tiebreaker (e.g. lexicographic forward-key or
origin-node rule applied identically on both nodes), guard on import.
**Still a genuine HA-protocol redesign; still not justified at current
(unmeasured) incidence.** Documented for completeness; not recommended.

### Path K — keep the shelve exactly as-is (or close)

Zero cost. But with §2.1/§2.2 on the record, "watch the counter" is
quasi-accept-forever: the counter's event coverage is sound (§2.3), but
the trigger cannot fire from the lab population and the value resets on
every deploy with no durable artifact. If the project's honest posture is
"this product has no multi-host production deployment and won't soon",
**closing the issue as accepted-risk** is more truthful than an
unfalsifiable watch — this is AGY r1's verdict. PLAN-KILL of this whole
revisit (leaving everything untouched) also remains on the table.

## 6. Concrete design (Path W, the recommended ship)

Default ship = **W-lite** (W1+W2+W3′+W4); W5 separately decidable.

1. **W3′ counter**: in `publish_shared_session`, capture the
   `shared_nat_sessions.insert` returns for the reverse-wire and (when
   distinct) reverse-canonical keys; if `displaced.key != entry.key`,
   `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.fetch_add(1)` (process-global
   `static AtomicU64`). Same-session republish (same forward key) and the
   self-alias case do not count. Export per the #1762 wire-additive
   template: `ProcessStatus` field (serde default) → fixture regen →
   `protocol.go` → `pkg/api` descriptor
   `xpf_userspace_session_nat_reverse_key_shared_displacements_total` +
   key-absent pins both sides + `show system buffers` row (suppressed
   at 0).
2. **W1 warn**: at the per-tick counters snapshot
   (`afxdp/worker/loop_body/mod.rs:187`), compare previous per-worker
   counter value AND the W3′ global; on any increase, claim a
   **process-global 60s CAS throttle** (warm-sweep pattern,
   `coordinator/mod.rs:760-775`) and emit one
   `eprintln!("xpf-dp: NAT reverse-key collision detected (worker={} local_total={} shared_total={}) — #1760 ...")`
   with the honest-semantics tail from §5. Zero per-packet work; ≤1
   line/min process-wide; established `xpf-ha:` stderr precedent.
   Prometheus help strings updated with the same language.
3. **W2 harness**: `test/incus/reverse-key-collision-probe.sh` — preflight
   (i) portless interface-SNAT active (verified live on fw0 this round,
   lan→wan v4+v6), (ii) flow-1 reverse path proven before flow 2. Warm
   variant + cold-neighbor variant per §5; asserts counters/warn and
   records the observed corruption shape for §2.6. Rerunnable; NOT part
   of smoke.
4. **W4 issue filing**: file the §2.5 wart with both faces (forward-fail
   half-open reverse leak; reverse-fail-at-cap one-way blackhole) —
   done as part of the disposition, fixed in its own PR.
5. **W5 (only if taken)**: incremental slab sweep on the worker
   maintenance tick — cursor over slot ranges (bounded slots/tick), local
   `FxHashMap<K,count>` across a full pass over live, non-reverse,
   NAT-rewriting entries; count>1 → live-collision gauge + W1 warn. The
   sweep must tolerate slab mutation between chunks (false negatives
   across a pass boundary are acceptable for a watch; document).
6. Tests: W3′ alias/republish negatives + displacement-positive; W1
   throttle pins (no flood on burst; lost CAS race no double-warn);
   protocol fixture round-trip with the new field absent (old-Go ↔
   new-Rust); `go test ./...`.
7. Issue comment updating the watch description + new revisit trigger.

No per-packet cost; no dataplane behavior change; no HA semantics touched.
One wire-additive field (W3′) — the #1762 template applies verbatim.

## 7. Public API / invariants preserved

- Path W: zero dataplane behavior change; wire-additive counters only;
  reverse-lookup contract untouched; #1762 counter semantics unchanged.
- Path A1 (if chosen instead): no `SessionKey`/index type change; refusal
  only ever prevents an install; `find_forward_nat_match` untouched;
  import path verbatim (HA invariant above).

## 8. Risk assessment

| Risk | Path | Level | Note |
|---|---|---|---|
| Log flood from W1 warn | W | LOW | process-global 60s CAS throttle; counters are 0 today; throttle unit-pinned |
| W2 harness leaves cluster state dirty | W | LOW | scripted teardown; flows time out; run under cluster flock |
| W3′ mutex hold-time growth | W | LOW | one key compare under a mutex already held per install |
| Standing-collision blind window (no W5) | W-lite | accepted | documented in §2.3/§5; W5 closes it if taken |
| W5 sweep cost / poll-tick stall | W5 | MED | bounded slots/tick; single-writer no-lock; gate on measured tick budget |
| Counter misread (event count, not census; fanout over-counts; §2.3 cases b/c under-count without W3′/W5) | W | LOW | exact semantics in descriptor help + warn text (§2.3) |
| False refusal on stale synced incumbent | A1 | MED | bounded by GC+delete-sync latency; UDP worst case |
| Cross-worker TOCTOU without commit-order inversion | A1 | HIGH | guard must check-and-reserve under shared lock before local/BPF commit (§5) |
| Transition-window divergence unchanged | A1 | accepted | explicitly status quo, documented |
| HA redesign scope creep | A2 | HIGH | why it stays unrecommended |

## 9. Test plan (Path W)

- `cargo test --release` full (awk-aggregated all "test result" lines);
  known flakes (wg `reconcile_peers_snapshot`, worker_queue
  `concurrent_recovery`) proven standalone before attribution.
- W3′ + W1 unit tests (per §6.6); protocol fixture key-absent pins;
  `go test ./...`.
- **W2 live-fire on the loss cluster** (under the cluster flock): warm
  variant (counters + warn + corruption shape) AND cold-neighbor variant
  (W3′ fires when the per-worker counter cannot); teardown and confirm
  counters stable afterward.
- Smoke A+B on loss userspace cluster (counters stay 0 under normal
  traffic — no false positives at line rate); failover NOT mandatory for W
  (no session-install or HA semantics change — observation only).

## 10. Out of scope

- Path B (PAT port-disambiguation) — separate feature per round 1.
- Path C (multi-valued index) — REJECTED, §2 of the prior plan stands
  (wire-indistinguishable replies); unchanged by this revisit.
- FIXING §2.5 (failed-install continues into reverse work) — the issue is
  FILED as Path-W deliverable W4 (§6.3), but the fix is its own PR with
  failover gating (it changes install-path behavior); A1 would subsume
  only the refusal-outcome case.
- Adding an `established` bit / flow-cache TCP-state hook (§2.4) — only
  relevant to an A1 refinement nobody is shipping this round.

## 11. Open questions for adversarial review (round 3)

Settled in rounds 1-2 (do not re-litigate without new evidence): shim
never bypasses userspace for transit; replica fanout covers normal-path
installs but NOT seeds (Codex r2 F1, verified); ordinary traffic never
re-asserts indices — v2's "loser re-wins" is retracted (Codex r2 F2 + AGY
r2 F1); A1 requires commit-order inversion; the failed-install wart has
two faces (W4). Round-3 questions:

1. Is the §2.3 coverage map complete for the v3 detector set — i.e. with
   W3′ at `publish_shared_session` (every forward NAT session, incl.
   seeds) plus the per-worker install/replica counter, is the ONLY
   remaining blind case the standing collision against an
   already-unindexed live session (closed by W5)? Known candidate the
   author flags for adjudication: `install_helper_local_session_on_miss`
   (`forwarding/mod.rs:1069`, caller `poll_descriptor:840`,
   `SessionOrigin::LocalMiss`, LocalDelivery disposition, is_reverse=false)
   installs into `nat_reverse_index` WITHOUT shared publish or
   replication — can a local-delivery session genuinely share K with a
   transit NAT session (interface-NAT to the same interface IP), or is it
   outside the collision domain?
2. Is W3′'s predicate (`displaced.key != entry.key`, alias-excluded)
   free of false positives across RG migration, promote
   (`SharedPromote` republish of the SAME logical session), HA re-sync,
   and NAT64 alias shapes?
3. Is W-lite (W1+W2+W3′+W4, standing-collision window documented-open) an
   acceptable reduced ship, or does honesty require W5 in the same PR?
4. Final path verdict on the DOCUMENT: W-conditional-on-deployment-posture
   (default W-lite) vs K (close as accepted-risk) vs A1. PLAN-READY here
   means "the plan, including its operator conditional, is converged and
   honest"; attack the framing, not settled facts.
5. **PLAN-KILL invitation stands:** if a reviewer shows W3′ still misses a
   realistic first event, or that the amended W's cost exceeds its
   conditional value, PLAN-KILL (keep shelve as-is or close) remains fully
   legitimate.
