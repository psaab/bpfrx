# Claude SMR hostile plan review — round 4 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v5 (@ 078009c78),
Codex r4 verdict (PLAN NO, 4B/4H/1M/1L), AGY r4 verdict (PLAN YES, 1L).
Every Codex finding was re-derived against the code before folding; the
AGY attack analyses were spot-verified (provenance call sites, fabric
stamp site).

**Verdict: PLAN NO for v5 (v6 required) — Codex's four blockers are all
real; two of them (fabric authority, frozen trusted anchors) are defects
I introduced in v4.1/v5 and should have caught. v6 deletes more than it
adds — the trust model is converging to minimalism.**

## Adjudication of Codex r4

1. **BLOCKER — fabric-ingress is not sequence authority: CONFIRMED, my
   error (v4.1).** I added the "peer-vouched" refinement on the premise
   that fabric-ingress means "the owner forwarded it." False: an inactive
   node converts ordinary external traffic into FabricRedirect
   (`poll_descriptor/mod.rs:3438-3476`, `fabric.rs:331-342`) — the stamp
   proves "arrived via the fabric link," nothing about placement,
   acceptance, or validation. A blind packet redirected by the non-owner
   would authenticate a planted anchor on the new owner's zero-trust
   import and revive the two-packet post-failover kill. AGY verified the
   stamp site is unspoofable from non-fabric ports
   (`inspect.rs:1916-1944` requires `ingress_is_fabric` on the physical
   ifindex) — but that only covers direct marker forgery, not the
   redirect path, which is the real channel. v6 removes the refinement
   outright.

2. **BLOCKER — refused promotion arms Close authority + suppresses
   self-heal: CONFIRMED.** v5 kept the origin flip + Open delta on a
   refused closing promote ("ownership truth"). Codex's chain: the flip
   to `SharedPromote` (not peer-synced, `entry.rs:245-250`) means any
   later ordinary expiry emits Close (`expire.rs:342-377` — marked or
   not), and it suppresses the import's RG-activation self-heal
   (`expire.rs:213-237`) — a blind first close post-failover can convert
   a silent standby reap into an authoritative, possibly accelerated,
   Close. My §9 "emits NO Close" test expectation was also wrong for the
   promoted case. v6's rule is simpler and stronger than Codex's
   suggested alternatives: **closing packets never promote at all** (no
   origin flip; the packet forwards on the current decision; ownership
   promotes on the next non-close packet). Cluster hygiene for a legit
   close-first-after-failover flow is preserved by the OLD owner's
   authoritative copy, whose natural reap emits the Close. Verified the
   partial-promote transaction semantics I specified in v5 are thereby
   deleted — nothing partial remains.

3. **BLOCKER — v5's transaction rules freeze trusted anchors: CONFIRMED,
   and the worst legit regression of the round.** "Every slide requires
   segment authentication" + "authentication is exclusively
   cross-directional" means a one-direction-observed LocalDelivery flow
   (firewall-originated BGP/SSH — inbound packets only) can NEVER advance
   its trusted inbound anchor past the SYN-ACK seed: no opposite trusted
   field exists to prove against. Every post-handshake legit close on the
   issue's named victim class would soft-refuse forever. Scaled-window
   full-duplex (seq ahead of opposite ack by up to the window) stalls the
   same way. v6: trusted sides self-slide on their own bounded
   continuity gate (`s.wrapping_sub(cur) ∈ (0, FWD_SLACK]`); cross-proofs
   only convert untrusted→trusted. Attack difficulty unchanged — the
   first in-window guess is the hard part; walking buys nothing because
   the acceptance window follows the anchor.

4. **BLOCKER — OPENING state representation: CONFIRMED both halves.**
   (a) The interval `[isn+1, isn+SEG.LEN]` needs its lower endpoint
   stored; the anchor kept only `seq_hi` (the upper). v6 adds
   `open_ack_lo` per direction (+8 B → 32 B). (b) The in-borrow
   established-promote (`lookup.rs:146-149`) fires on ANY reverse
   SYN-ACK pre-proof — and on master it fires UNAUTHENTICATED
   (#4109 requires only is_syn_ack + reverse): a blind SYN-ACK with a
   known tuple already pins a half-open entry into the 300 s established
   window today. v6 gates the promote on the strong handshake proof
   (exact interval) at the post-borrow phase — strictly stronger than
   master, and it subsumes the TTL-expired/filtered SYN-ACK edge.
   (c) The TFO entropy footnote corrected toward 1/2^20 at the 4,096-byte
   frame ceiling.

5. **HIGH — commit hooks still pre-transmission: CONFIRMED.** The v5
   hooks sit at request-build; dispatch validation (binding, MTU,
   translation build, oversize — `dispatch/mod.rs:512-573, :728-747`) can
   still drop afterward, and those drops are attacker-steerable per flow
   (oversized frames on an MTU-bound egress; NAT64's protocol reject of
   AH+TCP parsed as TCP). v6 moves the apply to the successful arms:
   dispatch-enqueue success (slow path), rewrite success (cache path),
   reinject acceptance (LocalDelivery). Documented residual: post-enqueue
   TX-completion/queue-pressure failures (transient, not attacker-timed).
   #2501 counter placement unchanged.

6. **HIGH — segment-wide weak adoption: CONFIRMED, and Codex's
   alternative beats my r3 adjudication.** My deadlock defense
   (per-field adoption deadlocks `seq_hi(rev)`↔`ack_hi(fwd)`) was correct
   as far as it went, but I missed the clean escape Codex names: **the
   close packet can carry its own proof** — an ACK-bearing close
   validates when its OWN ack proves inside `window(seq_hi(O))` trusted
   (rule 1 leg 3). No arbitrary-seq blessing is ever needed; the
   deadlock pair simply stays untrusted and is irrelevant. Bare no-ACK
   RSTs in that state soft-refuse — a bounded residual (delivery
   unaffected; the RFC 9293 §3.5.2 reset forms and FIN+ACK both carry
   acks). v6 deletes segment-wide weak adoption entirely; the 0→1/2^13
   race channel I accepted in v5 is gone. Credit Codex; my v5 dissent
   is withdrawn.

7. **HIGH — Phase 2 transport: CONFIRMED both halves.** (a) No version
   bitmap exists (`sync.go:21-36`, `sync_auth.go:60-75`) — but the
   existing payload framing tolerates trailing length-gated fields
   (`sync_protocol.go:95-102, :470-497`), so the tail's PRESENCE per
   delta is the rolling gate (simpler than the fictional bitmap).
   (b) Open-only carriage is stale by failover; the anchor must ride the
   ~1 s incremental sweep (`sync_conn_sweep.go:137-169`). Honest
   consequence I checked: 1 s of flow progress at line rate ≫ slack, so
   the wire anchor is exact for QUIET flows (the idle SSH/BGP/mgmt class
   — the issue's actual victims) and refuse-biased for bulk flows (whose
   churn cost is lowest). That is the right trade and it is now stated
   as design intent. Phase 1 + Phase 2 are one feature, two ordered PRs,
   both fully specified — the "unspecified fast-follow" objection is
   answered.

8. **HIGH — LocalMiss replacement context: CONFIRMED.** The LocalMiss
   installer can displace a peer-synced LocalDelivery entry
   (`local_delivery.rs:75-113`, `take_synced_local` at
   `lookup.rs:407-418`); "LocalMiss self-authenticates" would let a
   driving SYN reclassify a synced victim as fresh. v6: provenance is
   `(origin, context)` — `FreshPrimary` self-authenticates,
   `ReplacedSyncedLocal` adopts untrusted. Mandatory replacement test.

9. **MEDIUM — contradictions + validation gaps: CONFIRMED.** §7's
   forward-wire "demote-free" and PASS_TO_KERNEL "builds trust" lines
   contradicted §3/§2 — swept. Pre-packet `wnd` for proofs specified.
   Exact tracker deltas + the new mandatory cases added to §9. Counter
   export via the ordinary metrics surface + rate-limited structured
   event (also AGY r4's LOW).

10. **LOW — negative checks: verified.** Constructor table maps
    conservatively; the SYN-cookie ACK path creates no session; the
    refused spray is inert outside finding 2 (accounting touches only
    counters/observed flags; wheel uses unchanged canonical state).

## AGY r4 (PLAN YES, 1L) — dispositions

Its seven attack analyses all verified sound (provenance matrix complete
against the call graph; deadlock confirmation; commit coverage;
fabric-stamp unspoofability from non-fabric ports — correct as far as the
stamp itself, superseded by Codex's redirect-channel refutation of the
whole refinement; Phase-2 mixed-version safety; spray inertness). The 1L
(metrics-surface export) is folded. Its PLAN YES was against v5 as
written; Codex's r4 blockers were all in v5's NEW surfaces, which AGY's
prompt did not emphasize — the reviews are complementary, not
contradictory.

## Bottom line

Round 4 was the deletion round: fabric authority gone, segment-wide
adoption gone, partial-promote semantics gone, cross-proof-per-slide
gone. The v6 trust model is smaller and every surviving rule is
load-bearing: refuse-demote, per-field proofs + own-ack leg, strong
OPENING proof with stored interval, trusted continuity slides,
closing-never-promote, commit-at-dispatch-success, provenance with
context, Phase-2 presence-gated sweep transport. My verdict on v6:
implementation-ready modulo round-5 verification of the seven §11
questions.
