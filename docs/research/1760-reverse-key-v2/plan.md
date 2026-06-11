# #1760 — NAT reverse-key 1:N collision, stage-2 revisit (post-eBPF-retirement)

**Revision:** v1 (round 1)
**Date:** 2026-06-10
**Branch:** `research/1760-reverse-key-v2`
**Issue:** #1760 (stage-1 counter shipped #1762; stage-2 SHELVED 2026-06-06,
plan-kill label; prior design-of-record at
`docs/research/1760-nat-collision-structural-fix/plan.md` on
`research/1760-nat-collision-counter`)
**Mode:** /research — PLAN-READY or PLAN-KILL only. Keep-watch and close are
fully legitimate outcomes; PLAN-KILL is explicitly invited (§11 Q6).

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
for established transit flows. Therefore **userspace sees SYN, SYN-ACK, ACK,
FIN — the full handshake — for every transit flow.** The session table
already consumes `tcp_flags` per packet (sets `closing` on FIN/RST,
`session/mod.rs:565-588`). It has no `established` bit today, but the
*information* arrives for free; adding the bit is a one-field, slow-path
change, not a dataplane redesign. AGY's round-2 refutation ("userspace never
sees SYN-ACK/ACK") described the pre-#1476 architecture and is not true of
the only dataplane that exists now.

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

Interface-SNAT, F concurrent flows from ≥2 internal hosts to one
(dst_ip, dst_port), Linux ephemeral range ≈ 28,232 ports: expected
concurrent collisions ≈ C(F,2)/28232 (birthday). F=100 → ~0.18 expected
live collisions at any instant; F=250 → ~1.1; F=500 → ~4.4. A real
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

- **W1 — durable artifact.** Rate-limited (e.g. 1/min) `eprintln!`
  journald warn when `nat_reverse_key_collisions` increments (detected at
  the existing per-tick snapshot point in `loop_body/mod.rs:187`, NOT in
  the per-packet index path — log-hygiene), with af/proto/ports only (no
  addresses). Journald persists across daemon restarts — this is what
  makes the watch survive the per-deploy counter reset. This is the core
  of Path W.
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
- **W3 (optional belt) — shared-map displacement counter.** In
  `publish_shared_session`, the `shared_nat_sessions.insert(...)` calls
  already return the displaced `SyncedSessionEntry`; count when
  `displaced.key != entry.key`, excluding the reverse-canonical alias of
  the same entry. Redundant with local-replica detection (§2.3) in normal
  operation; catches the replica-loss corner. Process-global `AtomicU64`,
  wire-additive export per the #1762 template. Drop W3 if reviewers judge
  the redundancy not worth the wire churn.
- Issue disposition: stays open, keeps `plan-kill` on the structural fix;
  issue comment records the repaired watch; **new revisit trigger** =
  collision counter nonzero OR W1 warn in any journal (now durable and
  proven fireable) — or first real multi-host deployment behind
  interface-SNAT, whichever first.

### Path A1 — steady-state install-time refusal (window = status quo)

The contained version of the prior Path A, now viable because pillar 2 fell:

- Guard at session install in `poll_descriptor` (the non-reverse,
  NAT-identity-rewriting, new-flow branch) **before** any commit: compute
  `K = reverse_wire_key(key, nat)`; refuse if EITHER
  (a) local `nat_reverse_index`/`key_to_handle` holds a different,
  **unexpired** handle (expiry-only predicate — `closing` incumbents still
  block per Codex round-2; an optional `established` refinement is possible
  now but NOT load-bearing), or (b) `shared_nat_sessions` holds an entry
  whose forward key differs (presence-based — no liveness available).
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

Zero cost. But with §2.2/§2.3 on the record, "watch the counter" is
quasi-accept-forever: the trigger cannot fire from the lab and misses 5/6
of events even if it could. If the project's honest posture is "this
product has no multi-host production deployment and won't soon", **closing
the issue as accepted-risk** is more truthful than an unfalsifiable watch.
PLAN-KILL of this whole revisit (leaving everything untouched) is also on
the table if reviewers refute §2.3 or §2.7.

## 6. Concrete design (Path W, the recommended ship)

1. **W1 warn**: at the existing once-per-tick counters snapshot
   (`afxdp/worker/loop_body/mod.rs:187`, where
   `sessions.nat_reverse_key_collisions()` is already read), keep the
   previous value in the worker; on increase, emit a rate-limited (60s,
   per-worker `last_warn_ns`) `eprintln!("xpf-dp: NAT reverse-key
   collision detected on worker {}: total={} (latent 1:N reverse-path
   corruption, #1760)")`. No per-packet work; zero cost while the counter
   is 0 (one u64 compare per tick).
2. **W2 harness**: `test/incus/reverse-key-collision-probe.sh` — adds two
   IPs (or netns) on the LAN host, `nc`/python sockets bound to an
   identical source port toward the same dst:port through the
   interface-SNAT path, asserts (a) counter nonzero on the active node,
   (b) journald warn present, (c) records the observed wrong-flow behavior
   (mis-delivery or drop) for §2.6. Documented as rerunnable; NOT part of
   smoke (it deliberately corrupts two flows).
3. **W3 (optional)**: shared-map displacement counter per §5; if dropped,
   say why in the PR notes.
4. Tests: unit pin that the warn throttles (no log flood on a counter
   burst); W3's alias/republish negatives if W3 ships.
5. Issue comment updating the watch description + new revisit trigger.

No per-packet cost; no dataplane behavior change; no HA semantics touched.

## 7. Public API / invariants preserved

- Path W: zero dataplane behavior change; wire-additive counters only;
  reverse-lookup contract untouched; #1762 counter semantics unchanged.
- Path A1 (if chosen instead): no `SessionKey`/index type change; refusal
  only ever prevents an install; `find_forward_nat_match` untouched;
  import path verbatim (HA invariant above).

## 8. Risk assessment

| Risk | Path | Level | Note |
|---|---|---|---|
| Log flood from W1 warn | W | LOW | rate-limited 60s/worker; counter is 0 today; throttle unit-pinned |
| W2 harness leaves cluster state dirty | W | LOW | scripted teardown; flows time out; run under cluster flock |
| W3 mutex hold-time / wire churn | W | LOW | one key compare under held lock; wire-additive; W3 optional |
| Counter multiplicity misread (replica fanout over-counts) | W | LOW | document "upper bound, ≥1 ⇒ real collision" in descriptor help |
| False refusal on stale synced incumbent | A1 | MED | bounded by GC+delete-sync latency; UDP worst case |
| Transition-window divergence unchanged | A1 | accepted | explicitly status quo, documented |
| HA redesign scope creep | A2 | HIGH | why it stays unrecommended |

## 9. Test plan (Path W)

- `cargo test --release` full (awk-aggregated all "test result" lines);
  known flakes (wg `reconcile_peers_snapshot`, worker_queue
  `concurrent_recovery`) proven standalone before attribution.
- W1 throttle unit test; if W3 ships: alias/republish negatives +
  protocol fixture round-trip with field absent (old-Go ↔ new-Rust pins)
  + `go test ./...`.
- **W2 live-fire on the loss cluster** (under the cluster flock): forced
  collision → counter nonzero + warn present + observed corruption shape
  recorded; then teardown and confirm counter stable afterward.
- Smoke A+B on loss userspace cluster (counters stay 0 under normal
  traffic — no false positives at line rate); failover NOT mandatory for W
  (no session-install or HA semantics change — observation only).

## 10. Out of scope

- Path B (PAT port-disambiguation) — separate feature per round 1.
- Path C (multi-valued index) — REJECTED, §2 of the prior plan stands
  (wire-indistinguishable replies); unchanged by this revisit.
- Fixing §2.5 (failed-install continues into reverse work) — real but
  independent; file as its own issue if W is chosen (A1 would subsume the
  refusal-outcome case).

## 11. Open questions for adversarial review

1. Is the §2.3 audit conclusion right — does replica fanout
   (`replicate_session_upsert` → `handle_upsert_synced` →
   `upsert_synced_with_origin` → `index_forward_nat_key`) really guarantee
   the #1762 counter observes cross-worker collisions, or is there a path
   where the replica skips indexing (e.g. the `allow_replace_local`
   early-return, HAInactive filtering in `handle_upsert_synced`) so a
   collision stays invisible?
2. Is §2.4 right that the AF_XDP shim never bypasses userspace for
   established transit flows (i.e. the prior round's "userspace never sees
   SYN-ACK/ACK" refutation is definitively dead, not merely weakened)?
3. Does W1's journald warn meet the project log-hygiene bar (per-tick
   compare, 60s throttle, no per-packet logging), and is the snapshot
   point (`loop_body/mod.rs:187`) the right hook?
4. Is W2 (live forced-collision validation) worth the cluster time, and is
   the two-source-IP same-source-port construction actually sufficient to
   force the collision through interface-SNAT on this topology?
5. Given §2.4 (TCP state IS visible now), should A1 be preferred over W in
   THIS round — i.e. is "steady-state-correct, window-status-quo" refusal
   now small enough to ship at 0 measured incidence, or does
   measure-first discipline still win?
6. Is the §2.7 birthday math right (per-(dst_ip,dst_port) population,
   cross-host fraction), and does it change the keep-shelved calculus?
7. **PLAN-KILL invitation:** if reviewers find §2.3/§2.4/§2.7 wrong, or
   judge that even the watch repair isn't worth its review/merge cost for
   a lab-only product, PLAN-KILL (keep shelve exactly as-is, optionally
   close the issue as accepted-risk) is a fully legitimate verdict.
