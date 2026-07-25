# Claude SMR hostile plan-review — round 38 (v9.9.22 @ 60cb8e2e1)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.22 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.22-as-committed** — one self-found MEDIUM (the first-EOF cascade's
obligation-ownership is muddled between the two resync paths: in the
close-both PRIMARY path the SENDER has no obligation — it cannot know the
receiver overflowed — so the cascade as written requires state that does not
exist on the primary path) plus two nits. Everything else verifies sound.

## Finding 1 (MEDIUM — cascade ownership: implicit on the primary path, explicit only on the request path)

The v9.9.22 text says "with an obligation outstanding for the peer, the
SENDER's first EOF on either fabric cascades — atomically clears BOTH
slots". But in the close-both primary path the obligation is RECEIVER-side:
B overflowed and closed both fabrics; A (the sender) holds no obligation and
cannot distinguish B's deliberate full-close from an ordinary single-fabric
flap — where cascading (clearing the surviving slot1) would be an
availability regression of exactly the class this plan forbids elsewhere.
The honest per-path statement: (a) PRIMARY — no explicit cascade exists or
is needed: B's atomic close produces near-simultaneous EOFs on A; A's
both-empty detection at `installConn` (`sync_conn.go:244-248`) is
unaffected by which EOF landed first; B holds a BOUNDED reconnect barrier
(≥ 2× heartbeat timeout + RTT margin) before redialing, so both EOFs have
landed on A by redial time in all but pathological scheduling; and B's
inbound-repair obligation is DURABLE — if a pathological delay still
produces `wasDisconnected == false` (no cold-prime, no bulk arrives), the
obligation never clears, and B escalates to a second close-both with
exponential backoff (the barrier grows past any feasible EOF-processing
delay, so the retry terminates); (b) RESYNC_REQUEST path — the request
ARMS the sender-side outbound obligation, and only THERE does the explicit
first-EOF cascade exist (the armed sender declines survivor traffic on the
first EOF and treats the peer as fully disconnected — safe because the arm
is unambiguous sender state).

## Finding 2 (nit — the repair covers sender-side in-flight loss; state it)

During the close→cascade window, A's outbound queue on the survivor keeps
accepting and transmitting deltas into dying sockets (sender-side in-flight
loss). The cold-prime FULL bulk covers these identically (full table
iteration, `sync_bulk.go:93,:134`) — the repair is not limited to
receiver-park drops. One sentence.

## Finding 3 (nit — the deferred-release drain context must be named with a progress rule)

The deferred-release queue needs its drain context pinned (a coordinator
task woken on enqueue, or the worker loop's lock-free section at a defined
point) and a progress statement (drain runs at least once per reconcile/
migration span and on every enqueue wake; a finalizer's reservation lives
at most one drain interval — never less, bounded more).

## Verified sound this round (my own re-trace)

- Two-stage cleanup vs materialize race: the materialize's clone-acquire
  takes the canonical lock; stage-2's removal takes the same lock with the
  incarnation recheck INSIDE its critical section — either the materialize
  clones first (stage 2 sees the new external holder and aborts) or finds
  the family gone (lookup None → re-seed). No window.
- Identity-conditional replacement: the check is (incarnation, allocation)
  — a same-incarnation/different-allocation replacement (NAT re-resolution)
  takes the install-G2-first arm, which is the safe arm for both cases.
- Immutable provenance: no path re-derives the variant from entry state —
  replay/detached paths carry the enum tag on the entry; the only
  constructor sites are local admission (DirectHold) and the coordinator
  import (GroupHold).
- Repair-ID: the echo through BulkStart/BulkEnd/ACK closes the
  pre-request-masquerade trace; the sender-local bulk epoch remains for
  legacy peers (rolling-gated trailing field).

## Verdict

**PLAN NO for v9.9.22** — fold Finding 1 (per-path cascade ownership +
bounded barrier + durable escalation) and Findings 2-3 as v9.9.23. Part A
remains converged and untouched.
