# #1760 — NAT reverse-key 1:N collision, stage-2 revisit (post-eBPF-retirement)

**Revision:** v2 (round 2 — integrates Codex r1 PLAN-NEEDS-MINOR, AGY r1
PLAN-KILL, Claude SMR r1 PLAN-NEEDS-MINOR; disposition table in §1.7)
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
- **Counter semantics are event-detection, not a census** (AGY r1 F1,
  adjudicated §1.7): after the winner's value-guarded removal deletes K
  (`session/mod.rs:1459-1467`), the index has no K entry until the live
  loser's next session refresh re-asserts it (`update_session`
  unconditionally re-asserts secondary ADDS, `session/mod.rs:928-940`); a
  third colliding flow installing inside that window inserts `prev=None`
  and is not counted. But the first S1/S2 displacement was already counted
  at install, and every subsequent S1↔S2 alternation counts again — a
  colliding pair that passes traffic produces ≥1 count. For a watch whose
  trigger is "nonzero", that is sufficient; W1's warn text and the
  Prometheus help string must say "≥1 ⇒ real collision occurred; value is
  neither a pair count nor exhaustive".

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

### Path W — repair the watch, keep stage-2 shelved (RECOMMENDED)

Small, dataplane-behavior-neutral, makes the shelve rationale sound:

- **W1 — durable artifact.** Rate-limited `eprintln!` journald warn when
  `nat_reverse_key_collisions` increments (detected at the existing
  per-tick snapshot point in `loop_body/mod.rs:187`, NOT in the per-packet
  index path — log-hygiene). Throttle is **process-global** (a `static
  AtomicU64` last-warn timestamp + CAS, the existing pattern at
  `bpf_map/mod.rs:867-880`), ≤1 line/min per process regardless of worker
  count (AGY r1 F4). Journald persists across daemon restarts — this is
  what makes the watch survive the per-deploy counter reset. This is the
  core of Path W.
- **W2 — live-fire validation of the watch.** A one-time (scripted,
  rerunnable) harness exercise on the loss cluster that *forces* a real
  collision through interface-SNAT — two source IPs (or netns) on the LAN
  host, each binding the SAME source port to the same external dst:port —
  and asserts the counter goes nonzero and the W1 warn appears. Per
  `feedback_runnable_repro_before_measurement_claim`, the watch is only
  trustworthy once it has been proven to fire end-to-end on live traffic
  (the #1762 unit tests prove the table-level mechanism; nothing has ever
  proven the deployed pipeline). This also empirically re-confirms §2.6's
  blast radius on a live system, turning the corruption claim from
  research-probe into observed behavior.
- **W3 — DROPPED in v2** (was: optional shared-map displacement counter in
  `publish_shared_session`). Redundant with local-replica detection
  (§2.3) and adds sync + wire churn for a metric nobody triggers on
  (AGY r1 F5). Recorded here so a future round doesn't re-derive it.
- **W4 — file the failed-install wart issue** (§2.5) immediately as its
  own tracked bug (AGY r1 F2): on `install_with_protocol_with_origin`
  returning false, the packet path rolls back SNAT but still installs the
  reverse session and forwards. Independent of #1760 semantics; fix in its
  own PR (it touches install-path behavior and therefore failover gating,
  which a watch-only PR must not absorb).
- Issue disposition: stays open, keeps `plan-kill` on the structural fix;
  issue comment records the repaired watch; **new revisit trigger** =
  collision counter nonzero OR W1 warn in any journal (now durable and
  proven fireable) — or first real multi-host deployment behind
  interface-SNAT, whichever first.

**Recommendation conditional (SMR r1 F5, AGY r1 verdict):** W is worth its
(small) cost iff a multi-host or production deployment is plausibly in this
product's future — W's durable warn is what would make that deployment's
incidence visible. If the operator's posture is "lab-only, indefinitely",
Path K (close as accepted-risk) dominates; AGY r1 voted exactly that
(PLAN-KILL → close). This is an operator call the converged plan surfaces
rather than buries.

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

1. **W1 warn**: at the existing once-per-tick counters snapshot
   (`afxdp/worker/loop_body/mod.rs:187`, where
   `sessions.nat_reverse_key_collisions()` is already read), keep the
   previous value in the worker; on increase, attempt a **process-global**
   60s throttle (`static AtomicU64` last-warn-ns + CAS, pattern at
   `bpf_map/mod.rs:867-880`) and on winning emit
   `eprintln!("xpf-dp: NAT reverse-key collision detected on worker {}:
   total={} (#1760 latent 1:N reverse-path corruption; >=1 means a real
   collision occurred — value is an event count, not a pair census)")`.
   No per-packet work; zero cost while the counter is 0 (one u64 compare
   per tick). eprintln→journald from a worker thread is the established
   `xpf-ha:` stderr pattern and is bounded at ≤1 line/min process-wide.
   Update the two Prometheus descriptor help strings with the same
   event-count (not census) language (§2.3).
2. **W2 harness**: `test/incus/reverse-key-collision-probe.sh` —
   preflight asserts (i) active config has portless interface-SNAT on the
   traversal path (`source-nat { interface; }` — verified live on fw0
   this round, lan→wan v4+v6) and (ii) flow 1 established AND its reverse
   path passes traffic before flow 2 starts (so a non-firing counter is
   distinguishable from a routing/NAT-mode failure). Then: two source IPs
   (or netns) on the LAN host, sockets bound to an identical source port
   toward the same dst:port, asserts (a) counter nonzero on the active
   node, (b) W1 journald warn present, (c) records the observed
   wrong-flow behavior (mis-delivery or drop) for §2.6. Documented as
   rerunnable; NOT part of smoke (it deliberately corrupts two flows).
3. **W4 issue filing**: file the §2.5 failed-install wart as its own bug
   (title, repro = `max_sessions` cap, blast radius = reverse session
   installed + packet forwarded with rolled-back SNAT state) — done as
   part of the disposition, fixed in its own PR.
4. Tests: unit pin that the warn throttles (no log flood on a counter
   burst) and that a counter increase with a lost CAS race does not
   deadlock or double-warn.
5. Issue comment updating the watch description + new revisit trigger.

No per-packet cost; no dataplane behavior change; no HA semantics touched;
no wire-format change (W3 dropped — the warn + existing counters suffice).

## 7. Public API / invariants preserved

- Path W: zero dataplane behavior change; wire-additive counters only;
  reverse-lookup contract untouched; #1762 counter semantics unchanged.
- Path A1 (if chosen instead): no `SessionKey`/index type change; refusal
  only ever prevents an install; `find_forward_nat_match` untouched;
  import path verbatim (HA invariant above).

## 8. Risk assessment

| Risk | Path | Level | Note |
|---|---|---|---|
| Log flood from W1 warn | W | LOW | process-global 60s throttle; counter is 0 today; throttle unit-pinned |
| W2 harness leaves cluster state dirty | W | LOW | scripted teardown; flows time out; run under cluster flock |
| Counter misread (event count, not census; replica fanout over-counts; post-removal window under-counts) | W | LOW | exact semantics in descriptor help + warn text (§2.3) |
| False refusal on stale synced incumbent | A1 | MED | bounded by GC+delete-sync latency; UDP worst case |
| Cross-worker TOCTOU without commit-order inversion | A1 | HIGH | guard must check-and-reserve under shared lock before local/BPF commit (§5) |
| Transition-window divergence unchanged | A1 | accepted | explicitly status quo, documented |
| HA redesign scope creep | A2 | HIGH | why it stays unrecommended |

## 9. Test plan (Path W)

- `cargo test --release` full (awk-aggregated all "test result" lines);
  known flakes (wg `reconcile_peers_snapshot`, worker_queue
  `concurrent_recovery`) proven standalone before attribution.
- W1 throttle unit tests (per §6.4). `go test ./...` for the descriptor
  help-string updates.
- **W2 live-fire on the loss cluster** (under the cluster flock):
  preflight (SNAT mode + flow-1 reverse path) → forced collision →
  counter nonzero + warn present + observed corruption shape recorded;
  then teardown and confirm counter stable afterward.
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

## 11. Open questions for adversarial review (round 2)

Round-1 questions 1, 2 and 6 were answered (replica-fanout coverage
confirmed by both reviewers; shim-bypass confirmed dead by both; math
correction folded in). Round-2 questions:

1. Does the §1.7/§2.3 adjudication of AGY r1 F1 hold — is "event detector,
   ≥1 count per colliding pair that passes traffic" the correct reading of
   the alternation + re-assert behavior (`session/mod.rs:928-940`,
   `:1399-1405`), and is event-detection sufficient for the watch's
   purpose? AGY: if you maintain that the corner (loser permanently silent
   after winner removal + third flow collides in the absent-K window)
   breaks the watch, provide the concrete traffic pattern in which the
   FIRST displacement was also never counted.
2. Is W1's process-global CAS throttle + warn text + descriptor-help
   wording (§6.1) acceptable log-hygiene and operator-honest counter
   semantics?
3. Is the W2 preflight (§6.2) now sufficient to make a non-firing live
   test attributable (NAT-mode vs routing vs counter defect)?
4. Path verdict: W (repair watch, keep stage-2 shelved, file W4) vs K
   (close as accepted-risk — AGY r1's vote) vs A1-with-commit-order-
   inversion. The recommendation conditional (§5) makes this an operator
   call; reviewers should attack the *framing*, not re-litigate settled
   facts.
5. **PLAN-KILL invitation stands:** if a reviewer shows the watch cannot
   detect a realistic collision pattern even with W1 (counter + warn), or
   that W's cost exceeds its conditional value, PLAN-KILL (keep shelve
   as-is or close) is a fully legitimate verdict.
