# Claude SMR hostile plan-review — round 121 (v10.37.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — forty-first
pass; I authored the v10.37.0 fold of Codex r121's 6B/3H/2M. Verdict:
**PLAN YES** (fold verification + hostile sweep below).

## 1. Fold verification (Codex r121)

**r121-1 (B — admission semantics).** The fold REDEFINES "committed" =
admitted to the worker's TX pipeline (the `!recycle_now` postblock)
rather than adding request-riding machinery. I attacked the redefinition
itself: does a dispatch-dropped packet's anchor sample give the
off-path attacker anything? No — the attacker cannot observe or induce
a dispatch drop, and the sample still had to pass the in-window/proof
gate; a blind attacker who already guessed an in-window data position
never needed the dispatch outcome. The residual is real (a
never-dispatched packet can advance the anchor) but attacker-inert, and
the postblock is strictly stricter than master's own pre-construction
`account_packet` admission. Codex's dispatch/overflow citations
(`tx/dispatch/mod.rs:512-573`, `umem/mod.rs:1257-1321`) are adopted as
traced; the residual argument does not depend on their exact mechanics.

**r121-2/3 (B — full alias family + producers).** The invalidation now
covers the complete accepted-query alias family (old and new
identities; the site-2c displaced-family set,
`session/mod.rs:1895-1948`), and the carrier is concrete: a drainable
table-side `pending_invalidations` buffer on the `drain_deltas`
precedent (`session/mod.rs:1676-1690` — verified the drain pattern
exists), the in-poll installs draining into the `WorkerScratch`
accumulator before the next descriptor, and the worker-command paths
accumulating during the command drain with an all-binding fan-out at
loop top before the next RX batch. No `bool`-returning install site
changes signature.

**r121-4 (B — the discriminator is the carried id).** The
`(nat, is_reverse)` compare is replaced: the `SessionUpdate` gains the
incoming family id; equal-plus-key → same-family in-place refresh;
different-or-zero → remove+install with full authority-state reinit.
The local real-traffic refresh caller passes the entry's OWN id
(always equal, always in-place — the hot refresh path is unchanged).
This directly answers "carry and compare stable incarnation identity;
zero must fail closed."

**r121-5 (B — the expectation IS the binding).** The promote-time bind
step is deleted (grep-verified: every "bind" mention is now a
supersession note). `fwd_companion_id` stores the producer-supplied
expected id at install; every hop verifies probed-id == expected +
key+NAT; 0 never verifies. The storage question (Codex's "nowhere to
retain expected-but-unverified") dissolves — the same 8 B field holds
the expectation; there is no second state. Producer completeness: (a)
positional explicit; (b) site-2b Local via the match's gained id, and
Shared now carries the shared row's `session_id` as the expectation
(sound because the materialize-adopt adopts the same wire id; a
legacy zero-id row → UNBOUND); (c) the imported reverse's
synthesis-stamped `expected_fwd_id`; the reverse SharedPromote/
positional constructors are covered by (a)/(b). Tunnel: 0, permanent
UNBOUND, stated.

**r121-6/7 (B/H — materialize seed + promote publication).** The seed
is exactly the replica's stored close bits (a blind current RST cannot
upgrade an alive/FIN-only replica — the naive merge is explicitly
rejected); the promote publication carries the entry's effective
stored state with raw flags controlling eligibility only
(`session_glue/mod.rs:1235-1252`, `promote.rs:99-138` as traced).

**r121-8 (H — Optional family handle).** `family_handle: Option` —
zero-expectation reverses suppress all forward-family authority while
matched-R operations proceed; never an occupant capture.

**r121-9 (H — pre-install source).** The site-2b ordering is now
re-probe-FIRST (identity + closing/reset snapshot), then install with
the inherited seed, then mark — the v9 install-first order is
corrected; the Shared-scope source is the shared row's carried
`tcp_flags` (the across-scopes wrapper gains it).

**r121-10 (M).** The fallback extends to the Local identity-agreeing
`ValidatorRefused` class (forwarded but reverse-install-skipped —
`account_packet` misses R and returns before deriving F); Shared and
identity-mismatch refusals never produce a target.

**r121-11 (M).** The `account_packet` text now reads "keeps #2501
counter PLACEMENT, gains one additive `-> bool`" at both normative
sites; the constructor-gating test seeds site-2c close state from the
replica's bits and covers the capacity-refused accept; §11 is
re-labeled v10.37.0 with the current end-state inventory.

## 2. Hostile sweep of v10.37.0

- The per-hop verify's cost: the family probe already exists on the
  reverse hop on master (`session/mod.rs:1183-1205`); the verify adds
  compares, not a probe. The early-check family probe for a
  reverse-direction cache hit remains the second probe accounted in
  §8/§6.
- The Shared-expectation refinement cannot verify wrongly: the hop
  resolves the LOCAL forward entry; a cross-worker (non-owner) hit
  finds no local F → suppress; a stranger local K has a different id →
  suppress; only the materialize-adopted real family matches.
- The zero-expectation classes (tunnel, legacy Shared rows) are
  fail-closed with the §2 imported-class posture — bounded lingering,
  forward-direction validation unaffected.
- The admission redefinition is the round's honest retreat: it trades
  an unmechanizable invariant (dispatch-level authority) for a stated
  one (TX-pipeline admission) with an attacker-inert residual.

## 3. Bottom line

PLAN YES for v10.37.0 as the round-122 review basis. The gate
(§5.1–§5.4, §5.7) is untouched for the thirty-sixth consecutive round.
