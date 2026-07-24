# Claude SMR hostile plan review — round 3 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v4.2 (@ f99e1df0e),
Codex r3 verdict (PLAN NO, 4B/4H/2M), AGY r3 verdict (PLAN YES, 1M/1L).
Every finding below was re-derived against the code; Codex's ten findings
were each re-traced line by line before folding. This review adjudicates
all of them and states the one place the plan deliberately does NOT take
Codex's prescription.

**Verdict: PLAN NO for v4.2 (v5 required) — but the architecture has
converged; round 3 found spec-level defects, not structural ones.**

## Adjudication of Codex r3 (all ten findings)

1. **BLOCKER — constructor self-authentication revives the kill:
   CONFIRMED, my error.** v4.1's segment-authentication rule let ANY
   creating packet self-authenticate, and `materialize_shared_session_hit`
   is a creating path threaded with the wire packet (`session_glue/
   mod.rs:1092-1115` → `install.rs:399-400`). Trace: non-close packet
   seq=X materializes a shared victim → self-authenticates X → promote
   retags `SharedPromote` → RST at X validates → 2 s reap → Close delta →
   cluster kill. Two packets, the exact r2 trace revived through the trust
   back door. v5 fix: provenance matrix — self-authentication ONLY for
   primary miss installs of genuinely new flows (`ForwardFlow`/`LocalMiss`/
   `MissingNeighborSeed` + LocalDelivery new-flow); imports/materialize/
   synth/upsert NEVER. Correct and necessary.

2. **BLOCKER — OPENING authentication: CONFIRMED in both halves.** (a)
   windowed cross-bound vs exact equality — same hole AGY found (its
   MEDIUM); a windowed SYN-ACK acceptance drops the handshake proof from
   1/2^32 to ~1/2^13. (b) TFO partial-ack — RFC 7413 §4.2.2 lets a server
   reject SYN data and ack only the SYN, so exact `ack == isn+SEG.LEN`
   would refuse a legit TFO-reject RST|ACK. v5 fix: the exact interval
   `[isn+1, isn+SEG.LEN]` (RFC 9293 SYN-SENT's `ISS < SEG.ACK <= SND.NXT`)
   for both handshake authentication and OPENING close validation;
   collapses to a point for bare SYN. Spoof cost ≥ 2^32/(1+MSS) — no
   windowing.

3. **BLOCKER — trust transitions undefined: CONFIRMED, three sub-defects.**
   (a) The one-sided-pickup amplification is real (0 → 1/2^13 for an
   unobserved direction's close via a weak segment proof) — but see the
   dissent below; v5 keeps segment-wide adoption with the trade
   documented. (b) untrusted-storage poisoning (planted X blessed or
   unrepaired) — v5's transaction rule: authenticated samples REPLACE
   untrusted storage, never max-merge. (c) monotonicity (SYN retransmit
   must not clear the trusted seed) — v5 rule: unauthenticated samples
   adopt only into `!valid` slots, never alter existing state.

4. **BLOCKER — absorbing state honesty: CONFIRMED.** Three v4 lines
   claimed local observation restores trust ("converge on first traffic",
   "re-establishes trust") — false under the transaction semantics (no
   trusted bootstrap ⇒ nothing authenticates). v5 states the absorbing
   state plainly, including the cap-bypass note (`install.rs:295-323`
   synced upserts exceed the local cap — 131,072 is an admission ceiling,
   not headroom) and per-app timeouts to 86,400 s. The HA-wire anchor is
   promoted from optional follow-up to REQUIRED Phase 2 with a full spec
   (§10.5: 18 B additive field, only `trusted` sides cross the wire,
   version-gated, mixed pairs degrade to Phase-1 behavior). This is the
   adjudicated middle: Codex wanted it in-scope; the plan keeps Phase 1
   wire-free (rolling-upgrade story) and makes Phase 2 a scheduled,
   specified requirement rather than a maybe. The user decides at
   /engineer whether to land both phases in one PR.

5. **HIGH — plumbing types: CONFIRMED, all four.** `ForwardSessionMatch`
   scope erasure (`shared_ops.rs:638-665` can pick shared while a local
   fabric placeholder coexists) → carry scope + anchor snapshot;
   `SessionInstall` is the synced-upsert context only (`ctx.rs:8-17`) →
   seg threads BOTH install paths; `TcpSegView` gains `tcp_flags` (the
   OPENING `has_ack` predicate); `seg=None` reserved for no-packet
   control paths, unparseable wire close → refuse (not None).

6. **HIGH — commit-point poisoning: CONFIRMED and it changes v5's
   observation model.** The TTL=1 walk: bounded in-window data expiring
   at the firewall slides a trusted anchor >BACK_SLACK; the endpoint's
   later legit close (at the real position) is refused — a griefing
   regression master lacks. v4's rebuttal ("master's existing trust
   boundary") covered the DEMOTE side but not the ANCHOR-POISON side.
   v5 moves anchor updates out of `lookup_with_origin` entirely to
   per-disposition forwarding-commit hooks (post input-filter,
   admission, TTL, output-filter/CoS drop). `account_packet` counters
   keep their placement (#2501 semantics untouched). This also SIMPLIFIES
   the site story: transit classes were already covered at the forward
   build; site (b) existed only for LocalDelivery, which now gets a
   post-admission hook.

7. **HIGH — forward-wire not demote-free: CONFIRMED.** The immutable
   match (`lookup.rs:258-293`) returns a copy, but a promotable-origin
   hit continues to `maybe_promote_synced_session` → `update_session`,
   which marks closing/reset from packet flags on master. v5 corrects
   the inventory: never marks DIRECTLY; the promote-mediated mark is
   gated like every promote. And the refused-promote transaction rule
   (no flag seeds, no last_seen/wheel refresh; ownership flip + Open
   delta still fire — forwarding truth, not close state) answers the
   pinning variant (sprayed refused closes at a synced entry would
   otherwise hold it at established timeout vs master's 2 s post-spray).

8. **MEDIUM — arithmetic residuals: CONFIRMED.** Overlap range is
   1/32768..1/21845 (not "halves toward 1/32768"); the precursor's
   two-channel guesses are additive (~2× optimism); `wnd` from
   unauthenticated zero-length samples widens FWD_SLACK for free →
   wnd updates only from authenticated segments; wscale wording
   direction fixed; "no-op via max" specified as serial max
   (`s.wrapping_sub(cur) ∈ (0, FWD_SLACK]`), tracker wrap tested
   separately from validator wrap.

9. **MEDIUM — tests: CONFIRMED.** Deterministic out-of-window values
   replace "thousands of random"; new mandatory cases added (provenance
   matrix, TFO interval ends, untrusted replacement, monotonicity, wnd
   poisoning, TTL/filter poisoning, re-import wipe, transactional
   SessionUpdate refusal, match-provenance placeholder selection,
   tracker wrap). The smoke post-failover expectation corrected:
   trust does NOT return (absorbing state) — entries linger; Phase 2's
   gate re-runs the test expecting 2 s reaps.

10. **LOW — mechanics + 24 B: CONFIRMED.** 4×u32 + 2×u16 + u8 + u8 +
    pad2 = 24 B. Closing-packet promote skip endorsed (SYN-ACK+RST is an
    abort; FIN is not a SYN-SENT promote signal).

## The one dissent (Codex 3a): segment-wide weak authentication stays

Codex prescribes per-field authentication except a narrow OPENING
handshake proof. Per-field deadlocks the asymmetric bootstrap — verified
independently: a one-sided pickup trusts only `seq_hi(fwd)`; a reverse
packet's ack authenticates against it, but `seq_hi(rev)` can only prove
against `ack_hi(fwd)`, which can only prove against `seq_hi(rev)` —
neither side can ever authenticate, so legit closes on the #3152
mid-stream-pickup class (common under asymmetry; the feature exists
precisely for those flows) would refuse for the entry's whole life.
Segment-wide weak adoption breaks the deadlock at a bounded cost: a
0 → 1/2^13 channel in the first-observation race for an unobserved
direction — the attacker must beat the real reverse traffic, and
difficulty never drops below the 1/2^13..1/2^14 floor anywhere else.
Refuse-forever on a common legit class is the worse failure. Documented
in §5.2 rule 4 with the deadlock proof; flagged for round-4 verification
(§11 Q2).

## AGY r3 (PLAN YES, 1M/1L) — dispositions

- MEDIUM (OPENING windowed-vs-exact): same hole as Codex 2a; v5's exact
  interval resolves it. AGY's adjudication (SYN-ACK is the first reverse
  segment; no retransmit/SACK edge precedes it) holds for the point-seed
  bootstrap; the interval form covers TFO.
- LOW (post-failover lingering): correctly bounded; v5 states it
  unvarnished and assigns the fix to Phase 2 (§10.5).
- Its (a)-(f) attack analyses (handshake bootstrap completeness,
  zero-amplification, closing-promote compliance) verified sound and are
  cited in v5.

## Bottom line

Round 3 was the spec-precision round: the v4 architecture (refuse-demote,
trust model, constructor gating, never-drop) survived; the defects were
unwritten invariants (who may self-authenticate, how trust transitions,
where updates run, what the types carry). v5 writes them all down. My
verdict on v5: the remaining exposures are the documented residuals
(absorbing state until Phase 2, weak-auth race window, stall classes) —
each bounded, each honest, none a kill. Expect convergence next round on
the v5 text.
