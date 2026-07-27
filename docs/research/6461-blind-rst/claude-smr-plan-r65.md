# Claude SMR hostile plan-review — round 65 (v9.9.54.19 @ b5312f9cc)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.19 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.19-as-committed** — seven precision pins (1 LOW, 6 nit; no new
design defect found). All eight r64 folds are operative; the
three-class commit rules, the watermark, and the CommitUncertain claim
verify against the code citations. One under-specification has
operational weight (Finding 1).

## Finding 1 (LOW — the DisruptiveTransfer claim's write-ahead store is the peer, but the disruptive case is defined by the peer being unreachable)

The H7 fold says the disruptive claim enters the SAME lifecycle as an
ordinary transfer — "the ONLY difference from an ordinary transfer is
the admission predicate". That is false in a second place: the
ordinary write-ahead PONR marker is the PEER's commit record
(v9.9.54.18), and the CommitUncertain resolution is the peer's
definitive answer (v9.9.54.19) — but the disruptive mode exists
precisely for the case where the peer is down or unreachable (the
permanent-loss fence-lift of v9.9.54.18). A disruptive commit cannot be
ACKed by a dead peer; the query cannot be answered; the claim retains
forever — a new stall class shipped inside the emergency path. State
the peer-absent variant: the operator's confirmed intent (named,
audited, exact RG set and generations) is the durable marker when the
peer is unreachable; the claim never waits on a dead peer's answer;
and on the peer's return the quiesced revalidation reconciles the
disruptive transition exactly like a CommitUncertain resolution
(applied-by-operator-intent → forward; the returning peer re-seeds
from the surviving cluster state).

## Finding 2 (nit — the 'explicit authenticated v0 declaration' is dead text)

The B1 fold offers two v0 commit paths: a complete ordinary frame with
no record, or "an explicit authenticated v0 declaration". A v0 peer is
by definition pre-machinery current code — it cannot send the
declaration; a peer new enough to send the declaration is new enough
to send a capability record (with zero repair bits — which already
min()s to v0 without any declaration). Delete the declaration
alternative or define it as "a record carrying no repair bits" — one
of the two offered mechanisms is unreachable by every peer that would
need it.

## Finding 3 (nit — the abort consistency rule for the journaled-but-unACKed set is unstated)

The B2 fold's abort "RELEASES the freeze and unseals (the transaction
already retains ownership)". The peer-ACK drain can abort with some
deltas journaled on A but unACKed by B (mid-drain flap). State the
consistency rule: A's table remains authoritative (A retains primary),
B's partial journal is superseded by the next bulk/repair, and no
un-sealing on A resurrects a delta the seal already covered — the
abort is a no-op for dataplane state on both sides.

## Finding 4 (nit — B's cleared restore lease after a B-crash resolution is untraced)

The CommitUncertain query can resolve not-applied after B ALSO crashed
(B's applied record is volatile): B restarts quiesced, answers
not-applied, A aborts cleanly. But B had become secondary and CLEARED
its restore lease (`failover.go:471`, `daemon_ha_sync.go:1045`) before
crashing. B's restart default for the lease, and whether the
not-applied resolution re-arms or confirms-clears it, is unstated —
one sentence: the lease is volatile and restart-defaults to absent,
which is CORRECT for a not-applied resolution (the transfer never
happened), and the revalidation confirms the default rather than
re-arming (A's `ManualFailover` latch retains — the dual-secondary
outcome is operator-visible by design).

## Finding 5 (nit — the reconciliation epoch needs a stated ordering against the PromotionPermit)

The H5 fold adds ONE reconciliation epoch serializing `UpdateInstances`
passes; the permit fold has the run loop's commit holding the
PromotionPermit. A reconciliation pass holding the epoch joins a
stopped instance's run loop; that run loop, mid-`becomeMaster`, holds
the permit. No cycle exists only if the permit path NEVER acquires the
reconciliation epoch — state it (epoch → join → run-loop → permit is
safe iff permit → epoch never happens).

## Finding 6 (nit — the publication bound is per-OPERATION, not per-call)

The H6 fold bounds publication "STRICTLY BELOW the peer's master-down
horizon". `addVIPsLocked` loops N addresses (`instance_vip.go:185-208`)
and both family adverts follow; N × per-call latency can exceed the
horizon even when every single call is bounded. State the bound is on
the WHOLE publication operation (all VIPs + both family adverts +
direct-mode publishes), with per-step budgets derived from it.

## Finding 7 (nit — §9 d14 still says 'consumed once' for the disruptive claim)

The d14 line describes the DisruptiveTransfer claim as "consumed once"
— the one-shot-consumption phrasing the v9.9.54.19 lifecycle fold
superseded (the claim is CLAIMED once; its stages validate the
immutable claim, never re-consume). Amend d14 to "claimed once (each
stage validates the immutable claim)".

## Bottom line

The v9.9.54.19 fold set closes all eight r64 findings in the
prescribed direction; the class-commit soundness rule (v1-extras-inactive
on CONFIRM timeout, v0 only on a complete ordinary frame) and the
CommitUncertain query protocol are the right shapes. Finding 1 is the
only pin with operational weight: the disruptive mode's emergency path
currently inherits a write-ahead store that does not exist in the
scenario the mode is for.
