# Claude SMR hostile plan review — round 6 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v7 (@ 238038949)
and v7.1 interim (@ 02871f673), Codex r6 verdict (PLAN NO, 5B/3H/1M/1L),
AGY r6 single-question runs (2 SOUND, 2 UNSOUND). Every Codex blocker was
re-traced; the AGY UNSOUNDs were folded into v7.1 mid-round (Codex's run
predates that commit, so its findings 1-2 are adjudicated against both).

**Verdict: PLAN NO for v7/v7.1 (v7.2 required).** The round-6 findings
are about system integration — per-worker fanout, wire contracts,
ordering, terminal states — not about the trust model, which has now
survived three rounds unchanged (refuse-demote, per-field proofs,
own-ack leg, immutable OPENING interval, trusted continuity slides,
closing-never-promote).

## Adjudication of Codex r6

1. **BLOCKER — self-heal flip is not single-authority: CONFIRMED, and it
   kills the origin-flip design (mine, v7).** Imports fan out to every
   worker (`session_import.rs:215`); each worker's wheel would
   independently flip → concurrent duplicate authoritative Closes. And
   `fabric_ingress` returns Age before the self-heal predicate
   (`expire.rs:544`) — those imports never flip, the r5 stale-alias
   failure survives. v7.1's live-ownership gate (my interim fix, folded
   from AGY's lazy-window UNSOUND) removes the flip but not the fanout:
   every worker's copy reaps and every worker computes "RG active
   locally" → N duplicate Closes + N duplicate RT_FLOW records. v7.2's
   answer: **the node-local shared alias is the single-producer ticket**
   — an imported entry emits Close only after winning the alias delete
   (the deletion IS the stranded-alias cleanup). No coordinator
   transaction needed; the shared map is the coordination point it
   already was. Codex 1's `fabric_ingress` bypass is moot (the gate
   doesn't consult self-heal).

2. **BLOCKER — lazy/unfenced authority + gen-zero: PARTIALLY SUPERSEDED
   by v7.1/v7.2.** The publication-ordering observation (old ForwardFlow
   can emit an old-owner Close during whole-node demotion before the
   retag lands) is a real pre-existing race — documented, unchanged by
   this plan. The gen-zero concern dissolves under the shared-delete
   race: the winning worker's Close carries the import's stored
   generation, so a newer same-key incarnation on the peer wins the gen
   compare; no Open-on-promote is required for authority. The
   "coordinator-serialized activation transaction" is replaced by the
   race, which is simpler and has exactly one winner.

3. **BLOCKER — Phase-2 wire contract: CONFIRMED on every point.** v7's
   18 B tail omitted the seqno, both wnds, the four OPENING endpoints,
   and an incarnation identity; `MSG_SESSION_UPDATE` decodes as a full
   session → "open" (`eventstream.go:559`) so a dedicated opcode is
   required; the Rust helper protocol has only upsert/delete
   (`sync_session.rs:19`); and the reconnect authoritative bulk
   (`sync_bulk.go:40, :95` over the anchorless BPF store) would wipe
   quiet-flow anchors — meaning Go must STORE anchors (fed by
   AnchorUpdate) and carry them in bulk, making v7's "decode/re-encode
   only" scope guard impossible. v7.2 §10.5 specifies all of it: ~50 B
   tail with `session_id` incarnation binding, dedicated opcode + Rust
   `anchor_update` op + in-place apply to shared aliases and worker
   replicas, Go store fields + bulk tail, honest Go surface.

4. **BLOCKER — dirty-ring terminal states + stale-trusted wrong-accept:
   CONFIRMED both.** (a) The cumulative-since-last-emit filter
   permanently stops emitting once a flow crosses one slack (even after
   it quiets). v7.2: re-baseline silently on over-threshold intervals —
   the standby gets an anchor ≤1 interval stale whenever the flow is
   quiet. (b) A stale-but-trusted standby anchor accepts blind closes in
   dead sequence space forever at normal guess difficulty — a wrong-
   accept channel, not refuse-biased as I claimed. v7.2: receiver trust
   decay (unrefreshed > T_anchor → untrusted). Decay converts every loss
   mode (eviction, overflow, suppression) into the Phase-1 posture.
   (c) The ring is fillable by permitted clients — true; the aggregate
   cap + decay bound the blast to refuse-biased.

5. **BLOCKER — commit boundary: CONFIRMED, and it moves the commit one
   final stage.** Cache "rewrite success" appends a PreparedTxRequest;
   CoS admission drops on flow-share/buffer pressure returning `Ok(())`
   (`cos_classify.rs:1449, :1527`); pending queues evict
   (`drain/mod.rs:33`). v7.2: apply at FINAL ADMISSION success (the
   admission layer reports drops — a signature fix), with the
   TX-completion tail documented as irreducible and not
   sequence-targeted. The pending-neighbor gap is real too:
   `PendingNeighPacket` carries no token and `retry_pending_neigh` has
   no `SessionTable` — a buffered SYN-ACK would deliver without its
   promote and could reap a live flow at 20 s. v7.2: the packet carries
   an incarnation-bound mutation token; the retry applies updates +
   promote only on successful final enqueue. Demote marking for an
   accepted close stays at resolve (master parity).

6. **HIGH — seqno namespace/volume: CONFIRMED.** Different workers could
   emit equal seqnos for different directions — but the shim's flow-hash
   steering binds both directions to ONE worker, so "only the observing
   worker emits" restores the single-writer property for free (v7.2
   states it). Per-packet increments wrap the half-space in ~58 s at
   25 Gbit/s min-size — v7.2 increments per emission interval (≤1/s →
   2^31 s). Volume: v7.1's aggregate cap stands + batched messages
   (~64 records/message) against the peer's 4,096-message queue and the
   CLAUDE.md control-socket budget.

7. **HIGH — scaled-window ack stalls: CONFIRMED, and the adjudication
   is to accept a NARROWED residual.** A loss-induced repair jump can
   legally exceed the ≤131,070 raw-wnd gate by megabytes (effective
   window ≫ raw). But only leg 2 (restart-RST) consults `ack_hi(O)`;
   legs 1 (seq_hi) and 3 (own ack vs seq_hi(O)) are loss-immune (the
   firewall forwards the data). A gate wide enough for multi-MB jumps
   (≥1 MiB) triples the blind acceptance interval; a "K dup-acks then
   accept the jump" hatch is stageable for free (dup acks cost nothing).
   v7.2 documents the residual precisely: restart-RST soft-refuse on
   stalled fat flows (peer already dead; entry idles ≤ timeout), no
   wscale tracking.

8. **HIGH — OPENING interval validity predicate: CONFIRMED — a live
   seq=0 accept.** The un-seeded direction's default `[0,0]` interval
   passes the self-abort leg's membership test for a bare seq=0 RST.
   v7.2: `open_valid` bits (valid.byte bit4/bit5) set only when the
   direction's SYN actually seeds; both rule-2 legs require the bit.

9. **MEDIUM — arithmetic: CONFIRMED.** Leg 3 at cap is symmetric
   ±131,070 → 262,141 values; disjoint total 655,355 ≈ 1/6,554 (6.55 s
   at 1,000 pps). A RST|ACK carries TWO independent values, not three.
   And the honest bottom line stands corrected: the firewall remains the
   weaker validator vs an endpoint's exact RCV.NXT; the win is 1 packet
   → ~6.5–16 s of sustained spray plus endpoint backstop.

10. **LOW — tests: CONFIRMED.** The provenance bullet's "promoted entry
    emits NO Close" was still wrong (fixed: unpromoted → silent; a
    later non-close promote → natural authoritative Close). New
    mandatory cases added: shared-delete race single-producer, fabric_
    ingress, flap gen-rules, gen-compare vs re-seed, Phase-2 contract
    round-trip, trust decay, re-baseline, aggregate budget, ack-stall
    residual, pending-neigh token.

## AGY r6 (single-question runs, after 4 documented 5m timeouts)

- **Q1 (AnchorUpdate volume): UNSOUND → fixed in v7.1** (per-entry
  limits scale linearly; per-worker aggregate cap added, carried into
  v7.2 with batching).
- **Q3 (lazy authority window): UNSOUND → fixed in v7.1/v7.2** (the
  origin flip was replaced first by the live-ownership gate, then by
  the gate + shared-delete race; the window is gone).
- **Q2 (spray inertness), Q4/Q5 (flap safety, emission suppression):
  SOUND** — verified and consistent with v7.2.

## Bottom line

v7.2 closes the integration layer: authority is computed at the reap
from live HA state with the shared alias as the single-producer ticket;
Phase 2 has a real contract (incarnation-bound payload, dedicated
opcode, batched + capped + decaying transport, in-place apply); the
commit point is final admission with a pending-neigh token; the last
two spec bugs (seq=0 interval accept, leg-3 width) are fixed; the
scaled-window ack stall is a named, narrow residual. The trust model
itself is unchanged since v6 and has survived three rounds. My verdict
on v7.2: implementation-ready modulo round-7 verification of the seven
§11 questions — the residual risk has moved from design to
implementation fidelity.
