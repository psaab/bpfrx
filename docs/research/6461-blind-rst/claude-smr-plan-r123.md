# Claude SMR hostile plan-review — round 123 (v10.38.0): THE WRONG-TARGET ASSESSMENT

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — forty-third
pass. This is not a fold-verification pass: Codex r122 and r123 both
landed with every prior disposition UNRESOLVED, and the r123 findings
are qualitatively different from r118-r122's — they say the
commit-admission layer the plan grew across rounds 119-122 is
architecturally unfit for the codebase. Verdict: **PLAN
NEEDS-STRUCTURAL-REVISION — the admission layer is the wrong target;
the round-124 agenda is THE ADMISSION RETREAT.**

## 1. Why r123 is the wall, not another fold round

Codex r123's blockers 1-3 are not pointwise mechanical gaps — they are
the TX pipeline's actual shape refusing the design:

- `TxRequest` conversions strip the payload (`types/tx.rs:11-57`,
  dispatch `tx/dispatch/mod.rs:641-680`, `:886-915`, `:1218-1244`; CoS
  cross-binding `cos/cross_binding.rs:195-220`, `:248-264`) — the
  payload would have to be re-attached at every conversion site.
- `drain_pending_tx` has no `SessionTable` (`tx/drain/mod.rs:85-118`),
  and the ring-committed prefix is known only in finalization
  (`tx/transmit/finalise.rs:19-60`) — the apply point that satisfies
  "wire commit" needs a table reference the TX layer does not own.
- Redirect-inbox success is MPSC admission, not delivery
(`umem/mod.rs:1257-1334`;
  the target can still discard at CoS admission, bounded local queues,
  cleanup, or TX submission) — and the target-side apply is the
  per-packet cross-worker callback §5.2 explicitly rejected.
- TCP segmentation splits one ingress segment into child requests with
  different sequence ranges and prefix-only ring commits
  (`tx/tcp_segmentation.rs:147-163`, `:208-213`, `:311-334`) — a single
  segment summary cannot authorize any child.

Taken together: wire-exact anchor admission requires re-architecting
the TX pipeline to carry session-table authority end-to-end. That is
the #946-Phase-2/#961 pattern — a wrong-target architecture the
standing rules say to kill at plan time. Folding further machinery
into this layer (v10.39.0-as-more-of-the-same) would produce r124
PLAN NO with the next layer of TX-pipeline facts.

## 2. The supporting evidence that this is the unfold pattern

- r119: 6B/1H/1M/1L → r120: 11B/1H/1M/1L → r121: 6B/3H/2M → r122:
  8B/1H/1M → r123: 9B/1H/1M, with r121-r123 dispositions fully
  UNRESOLVED three rounds running. Each fold round added a carrier
  (token → handle → payload) and each carrier collided with a real
  ownership boundary (encapsulated borrows → batch ownership → TX
  conversions).
- r123-8 documents what the doc itself now shows: the normative
  copies disagree (the site inventory, the constructor algorithm, the
  SSOT contract block, and the §9 tests describe different
  lifecycles). The document has outgrown its consistency budget.
- r123-5 shows the newest layer now cannibalizes an already-retracted
  acceleration (the transient-purge cache parity, rounds 95-98) — the
  fold space is consuming its own retreats.

## 3. What survives the wall (and is independently sound)

The CORE of the plan is untouched and unattacked for 37+ rounds:

- **§5.1-§5.4, §5.7 — the demote gate itself**: the two-direction
  anchor on the canonical forward entry, the provenance/trust rules,
  the close-plausibility validation, the closing-never-learn/
  never-promote rules. This is the actual fix for the issue and no
  reviewer has found a design flaw in it.
- **The per-hop expectation verify (rounds 118-121's good output)**:
  `fwd_companion_id` storing the producer-supplied expected stable
  session id, verified per reverse→forward hop against the probed
  entry's id + key+NAT. Cheap (8 B), sound, no bind step, no
  cross-layer carriage. It answers the ABA concern without the cache
  token apparatus.
- **The site-2b/2c constructor rules** (proof-gated synth, the
  scope/state/flags table, the effective-seed inheritance, the
  replica-bits materialize seed, the live-entry promote source).

## 4. The retreat shape (round-124 agenda — proposal, not yet folded)

Amputate the admission-perfection layer back to what the codebase
supports:

1. **Anchor apply returns to the #2501/#4109 accounting chokepoints**
   (telemetry-grade admission: post-policy, pre-construction). The
   committed-packet invariant is RESTATED as admitted-for-forwarding
   observation; the residual analysis (blind attacker cannot chain
   without feedback; overrun yields only fail-closed legit-close
   refusals, bounded lingering) is already written and holds.
2. **The cache-token identity check, the precedence-invalidation
   system, and the dispatch payload are KILLED** (not deferred) —
   they exist to make the cache-hit anchor write identity-exact and
   admission-exact, and the codebase's TX/cache ownership does not
   support either exactness without re-architecture. The cache-hit
   anchor write instead rides `account_packet`'s existing borrow with
   the per-hop expectation verify (identity-safe for the anchor's
   purpose); the probation commit-hook operations keep their
   rounds-88-114 matched-entry direct check (v10.28.0) which stands
   without the cache token.
3. **The stale-cache ABA cases the token covered are re-homed**: the
   rounds 98-101 alias-set invalidation at adopt/reap/probation
   transitions (already built, already converged) plus master's own
   validity gate carry the load; the residual (a same-key+NAT+
   same-id-collision window) is the #6311-class documented residual.
4. **§5.2's wire-commit text is amended** to the admitted-for-
   forwarding semantics with the no-learn list retained (the
   exceptional paths stay no-learn: NoRoute/MissingNeighbor reinjection,
   build-failure fallback).
5. The v10.34-38 id machinery that is INDEPENDENT of the admission
   layer stays: the id-population completion (promote republication,
   bulk export), the zero-always-mint rule, the carried-id family
   discriminator on `update_session`, the node bit, the allocator
   skip — these are sound, cheap, and reviewer-verified.

This retreat is a plan REVISION, not a PLAN-KILL: the issue's fix
survives intact. It needs one full Codex round against the amputated
doc before convergence can be claimed.

## 5. Bottom line

Do not fold v10.39.0 as more-of-the-same. The round-124 agenda is the
admission retreat above, then Codex + AGY + SMR on the amputated doc.
Session state: all reviews, the ledger, and v10.38.0 are committed on
`research/6461-blind-rst`; this assessment is the next session's
starting point.
