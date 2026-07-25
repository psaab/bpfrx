# Claude SMR hostile plan-review — round 40 (v9.9.25 @ 034570672)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.24/v9.9.25 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.25-as-committed** — four state-it-explicitly gaps (one MEDIUM: the
barrier's end condition and the dual-simultaneous-obligation case are
unspecified; three LOWs). Nothing found invalidates a mechanism; all four
are precision clauses that a hostile implementer needs written down.

## Finding 1 (MEDIUM — the barrier's end condition and the dual-obligation case)

The fold never says what RELEASES B's refusal. If it is purely time-based
(≥ the slow-detector bound + margin), the fold must state: the refusal
ends when (a) the barrier timer expires AND (b) B observes both of ITS OWN
slots empty — and, critically, the refusal must NOT be message-bound: if
BOTH nodes raise obligations in the same window (both close-both, both
refuse), a message-bound refusal deadlocks (each waiting for the other's
repair bulk it is itself refusing). Time-bound refusal makes the dual case
safe by construction: both barriers expire independently, both nodes have
drained, the first install cold-primes. State both halves.

## Finding 2 (LOW — the sendLoop join needs a re-queue rule)

The quiesce-and-join says the retry loop is joined — but a fabric flap
mid-join re-queues pre-cutoff frames through the (paused) enqueue gate.
The fold must say: frames re-queued during the join are tagged pre-cutoff
and DISCARDED (the cutoff snapshot subsumes their state), so the join's
completion is a real fixed point (no frame that entered the system before
the cutoff can land after `BulkEnd`).

## Finding 3 (LOW — the post-release new-credit case is a re-resolution; say so)

Codex r40-Q3's edge: a same-(K,P) claim arriving AFTER the pending release
committed (P freed, possibly claimed by a third flow). The fold's
"genuinely NEW credit" is correct but must be characterized: the pending
release committing means the reservation was legitimately dead (no live
holders); the later claim is a FRESH allocation (new generation, possibly
a different port — a re-resolution), not a continuation. Stating it
prevents an implementer from trying to "revive" the old reservation.

## Finding 4 (LOW — registry retirement + conversion-vs-repromote)

Two statements needed: (a) command execution takes a strong registry
reference at dequeue (claim-then-execute, the same pattern as the
pending-command claim), so registry retirement can never race a
rehydrating worker; (b) the DirectHold→GroupHold conversion fires only
for a peer replacement that PASSES the owner re-validation — a demoted
entry re-promoted locally (`SharedPromote`) before the peer replacement
lands is locally authoritative and IMMUNE to the replacement (the
mixed-version matrix's candidate-class re-validation), so the conversion
and the re-promote can never race (the replacement is skipped first).

## Verified sound this round (my own re-trace)

- The pending-release ticket: allocation + claim + cancel all serialize
  on the allocator live lock; (generation, ticket) comparison is
  ABA-complete.
- Transactional bulk: staged members+gen-map with validating-BulkEnd
  commit makes O1-after-O2 harmless; the sender cutoff makes post-BulkEnd
  pre-cutoff arrivals impossible by construction.
- The barrier's refusal via immediate-close composes with A's per-install
  cold-prime gate.

## Verdict

**PLAN NO for v9.9.25** — fold Findings 1-4 as v9.9.26 (precision clauses;
no design change). Part A remains converged and untouched.
