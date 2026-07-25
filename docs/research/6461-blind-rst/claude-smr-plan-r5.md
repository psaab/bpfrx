# Claude SMR hostile plan review — round 5 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v6 (@ e1f58e4e8),
Codex r5 verdict (PLAN NO, 3B/4H/1M/1L), AGY r5 verdict (PLAN YES, 0
findings). Codex's three blockers were re-traced against the code;
findings 4-9 verified line by line.

**Verdict: PLAN NO for v6 (v7 required).** Codex found one false premise
I asserted without checking (old-owner cleanup), one mutability hole in
the proof I designed (OPENING endpoints), and one transport I specified
against a sweep I misread. AGY's clean pass covered the v6 mechanics that
survive. v7 folds everything; notably the trust model did not grow this
time — the fixes are precision (immutable endpoints, per-stream slack,
activation-driven authority), not new machinery.

## Adjudication of Codex r5

1. **BLOCKER — no authoritative cleanup producer: CONFIRMED, my false
   premise.** v6 rule 5 claimed the OLD owner's copy emits the eventual
   Close. Owner demotion retags entries `SyncImport` (`install.rs:572`,
   `shared_ops.rs:179-206` — verified) — peer-synced — so after a close-
   first failover BOTH copies are peer-synced and NEITHER emits Close
   (`expire.rs:342-345`); shared-map deletion is Close-driven
   (`session_delta.rs:406-452`); a stale shared NAT alias can
   rematerialize after allocator reuse (`session_glue/mod.rs:1092`,
   `upsert_synced.rs:80` skips the reservation). v7's fix is the one
   Codex offered first: **authority transfers at RG activation, never
   from packets** — the existing activation self-heal
   (`expire.rs:213-237`) also flips origin to locally-authoritative.
   Verified this reintroduces no packet-driven authority: blind closes
   stay inert (no mark/refresh), natural reaps become authoritative
   (correct hygiene), exactly one Close producer exists per
   activation/demotion cycle, and r4-2's self-heal suppression is gone
   (the flip is the self-heal's own act).

2. **BLOCKER — mutable OPENING proof endpoints: CONFIRMED, and I should
   have seen it when adding `open_ack_lo`.** The proof ceiling and the
   self-abort coordinate both used the LIVE `seq_hi`, which any committed
   in-window sample slides at ~1/2^16 guess cost — the "1/2^32 handshake
   proof" was fictional once anything slid. v7: the immutable
   `[open_ack_lo, open_ack_hi]` pair (+8 B, 40 B total) is the ONLY input
   to both OPENING legs; `seq_hi` free-runs for ESTABLISHED tracking.
   The sent-data-then-abort edge (client RSTs beyond its SYN interval)
   soft-refuses inside the 20 s window — documented, negligible.

3. **BLOCKER — Phase-2 transport has no viable producer: CONFIRMED, I
   misread the sweep.** `sync_conn_sweep.go:125-137` keys on `Created`
   and skips on unchanged counters; `Sessions()` is the anchorless
   `SessionValue`; the userspace sweep is 15 s/60 s, not 1 s. v7 spec:
   the anchor rides (i) the Open-delta tail and (ii) a new `AnchorUpdate`
   delta kind on the existing Rust→Go event stream (the unused
   `MSG_SESSION_UPDATE` wire type) — per-worker bounded dirty ring,
   ≤1/entry/s, **quiet-flow emission filter** (skip entries whose anchor
   advanced > one slack — they'd be useless at the standby anyway, so
   volume tracks the quiet class, not line rate), per-entry
   `anchor_seqno` with serial-compare in-place import (no
   `remove_entry`), lossy-with-watermark posture (a dropped update =
   older standby anchor = refuse-biased, never a wrong accept).

4. **HIGH — own-ack leg wnd direction: CONFIRMED (independently caught
   in my own pass while Codex ran).** A `seg.ack` candidate is a
   stream-O quantity; its lag behind `seq_hi(O)` is O's unacked
   in-flight, bounded by D's advertised window. v6 used `wnd(O)`
   uniformly — wrong for leg 3 and for `ack_hi(D)` slides. v7 states
   the general rule: **slack derives from the receiver of the
   quantity's stream** — seq legs use `wnd(O)`, ack leg/slides use
   `wnd(D)`.

5. **HIGH — three-leg probability understated: CONFIRMED.** With leg 3,
   a blind RST|ACK guesses against up to three independent windows:
   worst ≈ 3×196,607/2^32 ≈ 1/7,282 (cap) / 1/10,923 (floor); ~7–11 s
   at 1,000 pps. §2 restated; the "~2^12–2^14 per guess" framing is
   preserved and still honest about what the fix does and does not buy.

6. **HIGH — commit boundary: CONFIRMED both halves.**
   `push_redirect_inbox` discards at capacity WITHOUT error
   (`umem/mod.rs:1305`) — "successful enqueue" was not confirmed, and
   queue pressure is traffic-driven (steerable); v7 requires the discard
   be reported and applies only on true acceptance. The ForwardCandidate
   dispatch-failure fallback (`dispatch/mod.rs:898, :1378` →
   `slow_path.rs:223, :297`) successfully enqueues to tunnel/kernel —
   accepted traffic v6 left untracked; v7 adds the arm.

7. **HIGH — establishment promote pre-commit: CONFIRMED.** The proof is
   computed at resolve (pre-packet anchor) but v6 applied the promote at
   the post-borrow phase — still pre-filter/TTL/commit. v7: the promote
   APPLIES in the packet's commit arm; a proved-but-undelivered SYN-ACK
   does not promote.

8. **MEDIUM — simultaneous-open transitions: CONFIRMED as a documented
   residual, not a new transition.** Master also requires
   is_syn_ack+reverse to promote — a lost reverse SYN-ACK leaves OPENING
   on master too, so this is pre-existing behavior, not a plan
   regression. The normal crossed SYN-ACK case is covered (ack in the
   immutable interval → strong proof → promote). Noted with a test; no
   new state machine transitions in this change.

9. **LOW — impossible test + arithmetic hygiene: CONFIRMED.** The
   SharedPromote test's "no Close" expectation was wrong for the
   promoted case (ordinary expiry of an authoritative forward entry
   DOES emit Close — correctly); v7's test distinguishes pre-activation
   (silent) from post-activation (natural authoritative) and from
   attacker-accelerated (must not exist). `wrapping_add` for
   `seq+SEG.LEN` and the compile-time layout assert specified.

## AGY r5 (PLAN YES, 0 findings) — dispositions

Its seven analyses (own-ack legit forms + garbage-SEQ irrelevance,
close-first hygiene, walk cost model, SYN-ACK interval coverage, commit
arm audit, Phase-2 quiet/bulk arithmetic, counter export) verified
sound; two premises it endorsed were subsequently falsified by Codex
(the old-owner Close producer; the sweep transport) — v7 corrects both,
and AGY's zero-finding verdict otherwise stands against the v6
mechanics that survive.

## Bottom line

Five rounds in, the finding profile has shifted from architecture (r1-2)
to edge policy (r3) to invariants (r4) to precision (r5): false premises
about existing HA machinery, mutable proof state, transport reality,
window direction, arithmetic. v7's design is otherwise v6's — small,
and every rule load-bearing: refuse-demote; per-field proofs with
per-stream slack; own-ack leg; immutable OPENING interval; trusted
continuity slides; closing-never-promote; activation-time authority;
confirmed-commit apply; provenance with context; a real Phase-2
pipeline. My verdict on v7: implementation-ready modulo round-6
verification of the six §11 questions.
