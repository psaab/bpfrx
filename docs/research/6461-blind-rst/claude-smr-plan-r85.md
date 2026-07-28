# Claude SMR hostile plan-review — round 85 (v10.2.0 retreat + fold verification)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10.2.0 folds including the pending-neighbor RETREAT; this pass attacks
them. Verdict: **PLAN NO for v10.2.0** — two precision nits (both folded
in the same revision); no LOW or above. Codex r84's findings are
individually verified against the code and the fold text.

## The retreat adjudication (round-84 Codex 2/5/6)

The v10.1 re-resolve-once + interim-expiry-hold design was MY
simplification of the v7.5 machinery-era rule, and it was wrong in the
direction of added machinery: findings 2 (no typed family identity;
`Some(resolved)` ≠ live entry across the `promote.rs:167` transient
purge), 5 (per-binding pending timeouts give no cumulative per-session
bound), and 6 (wheel reinsertion/bounding unspecified) share one root
cause — defending a never-transmit-stale improvement that is outside
this issue's blast radius. The v10.2.0 retreat restores master's
buffered-decision retry byte-for-byte: the admitted-close delivery that
r83-B3 showed the re-resolve dropping is master-parity again; the
stale-decision window is documented as pre-existing (§7 race d) with the
typed-outcome hardening deferred to §10.6.2. I verified the retreat
reintroduces no gate bypass: the demote verdict is terminal at resolve
(refuse = no mark, accept = marked at resolve), so the retry needs no
re-validation; anchor hooks, promotes, and probation clears never run on
the table-less retry path (fail-toward-refuse; a skipped update cannot
walk or poison an anchor); a buffered SYN-ACK delivering without its
promote is master's OPENING-window outcome exactly.

## Fold verification (against this branch's code)

- **Site-9 typed outcomes (r84-1):** the arm's seed-only work
  (NAT derivation `poll_descriptor/mod.rs:4680`, allocation
  `source_nat_decision_for_flow:4745`, install `:4787`, publish
  `:4823`/`:4879`) is skipped wholesale for `ExistingResolved`; the
  unowned-allocation trace (`nat/source.rs:1548` GC-exempt
  `live_by_flow`, `allocator.rs:2134`) is dead by construction — no
  allocation runs. The NAT-stability question is answered correctly:
  the hit keeps its admitted (stored) NAT decision, matching master's
  hit path.
- **Seed lifecycle (r84-3):** the flip + owner-identity alias cleanup
  closes the zero-producer trace (a flipped entry is non-transient, so
  `expire.rs:342-350`'s exclusion no longer applies) and the stale-alias
  trace (transient seeds never reach the `session_delta.rs:406` drain on
  master). The flipped-vs-unflipped expiry split is coherent: flipped →
  normal ForwardFlow expiry + Close drain; unflipped → the new explicit
  alias cleanup with the owner-identity guard (the #6522-class
  shared-state residual unchanged).
- **Site-2b scope/identity (r84-4):** `lookup_forward_nat_across_scopes`
  (`shared_ops.rs:638`) really does return one shape for both scopes
  (`entry.rs:208`: key/decision/metadata only) — the v10.1.x
  Local-vs-Shared rule was not implementable on it. The scope tag +
  identity-agreement re-probe + Shared-refuses-even-if-locally-occupied
  closes the `K/NAT1`-vs-`K/NAT2` wrong-flow mark.
- **Retreat side-condition:** `ExistingResolved` buffering for a
  2b-REFUSED close buffers with the synthesized decision
  (`created=false, install_failed=true` — cache insertion suppressed,
  `poll_descriptor/mod.rs:3900`) and the retry transmits it — delivery
  preserved.

## Finding 1 (nit — the flip's commit-arm enumeration missed the cache-hit arm)

v10.2.0 (pre-fold) said the flip runs on "a fresh slow-path packet at
its commit arm" — but pure-ACK TCP on a cached seed flow commits at
`flow_cache_hit.rs:312`'s arm, not the slow path. Folded: the flip runs
at the packet's commit arm, slow-path OR cache-hit.

## Finding 2 (nit — the flip's telemetry/sync posture was unstated)

The flip re-attributes origin for emission gating; whether it emits a
new Open, re-syncs, or rewrites shared state was not said (an
implementer could emit a second Open or push a shared update). Folded:
no new Open delta, no re-sync, no shared-map rewrite; any HA-peer copy
ages on the synced timeout exactly as master.

## Bottom line

The retreat is the right call: master's retry is byte-identical, the two
reviewed alternatives both produced BLOCKERs, and the window is
pre-existing and out of the issue's scope. The three kept folds
(typed-outcome gate, seed lifecycle, 2b scope/identity) are local,
verified against the code, and each closes a trace the cut itself made
load-bearing. Two nits folded. If Codex r85 verifies and finds nothing
new at LOW+, this plan is at convergence.
