# Claude SMR hostile plan-review — round 64 (v9.9.54.18 @ 507ab32eb)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.18 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.18-as-committed** — nine precision pins (1 LOW, 8 nit; no new
design defect found). The eight r63 folds are all operative and the
three-class version definitions verify against the code citations. One
fold (the admission freeze) has a genuine policy ambiguity with an
unpriced traffic cost — that is the LOW.

## Finding 1 (LOW — the admission freeze is ambiguous between two policies, and one of them stalls production new-flows for the whole drain)

The B2 fold says the sequence "FREEZES new session admissions/publishes
at snapshot time (a frozen admission either waits or is tagged into the
repair's journal up to the freeze) … and holds the freeze THROUGH the
demotion". Two readings: (a) FREEZE — no new session installs from
snapshot to demotion: the node is still PRIMARY carrying production
traffic for the whole forced-repair → `JOURNAL_END` → revalidate →
demote sequence (seconds), and every new flow in that window fails or
stalls — a traffic impact the plan never prices, and a regression
against today's drain behavior in the opposite direction of the fix
(today the drain loses E2 silently; reading (a) makes ALL new flows
wait explicitly); (b) CONTINUE-AND-JOURNAL — admissions continue, every
post-snapshot admission is tagged into the repair's journal, and the
cutoff predicate is a SECOND barrier immediately before the demote
covering everything journaled up to that point — no traffic impact,
and the "freeze" is only a fence on UN-journaled publishes. "Either
waits or is tagged" picks per-flow nondeterministically. Pick ONE:
reading (b) is strictly better for a drain operation (the ISSU case is
the only consumer of this path) — state that admissions continue under
the journal, the terminal cutoff is a second pre-demote barrier, and
the freeze applies only to non-journaled state (NAT pool releases,
config-epoch publications).

## Finding 2 (nit — the v0 commit has two triggers; the fold names one)

The B1 fold commits v0 at "the first buffered ordinary frame". The
older latched rule (d10) commits the baseline class on "zero bytes
consumed → retain and legacy-latch" — a TIMEOUT trigger for a peer
that sends nothing at all. The two compose (whichever fires first),
but the three-class definition should say so: v0 commits at the first
ordinary frame OR the record-absence timeout, whichever first; a peer
that sends a record is never v0 regardless of later frame timing.

## Finding 3 (nit — the drain predicate must count accepted-not-published)

The freeze fold drains "every in-flight commit (deadline-bounded)".
The dataplane's accept-then-publish is a two-step
(`poll_descriptor/mod.rs:2560` accept → `:2591` publish): an event
ACCEPTED before the freeze but not yet PUBLISHED at drain time is
invisible to a queue-empty predicate. Define in-flight =
accepted-not-yet-acked (accepted, published, queued, and
peer-acknowledged), so the barrier cannot outrun a mid-two-step event.

## Finding 4 (nit — the lease-expiry restore is itself a promotion and must be quiesced after a restart)

The B3 fold says the old owner's lease-expiry restore "CHECKS the
commit record first", and separately that a restarted node "revalidates
… WITH THE PEER before any promotion". The commit record is volatile;
the old owner that crashes after the claimer's commit lands restarts
with no record — its lease-expiry restore would fire unless the
restore is ITSELF classified as a promotion subject to the quiesced
revalidation. One sentence: after ANY restart, the lease-expiry
restore is quiesced exactly like a fresh promotion (it is one).

## Finding 5 (nit — the stop-set is captured by identity, never by key)

The B4 fold has `UpdateInstances` collect its stop-set under
`Manager.mu` and join after release. Between collect and join a newer
reconcile can re-create the same instance KEY. Captured by key, the
deferred join stops the NEW instance (flap/dead-configured-interface);
captured by identity (the old `*Instance` pointers — `m.instances`
deletion already happens under the mutex, so a re-created key maps a
NEW object), the join can only stop the collected objects. State the
identity rule.

## Finding 6 (nit — the never-reused RG incarnation needs its restart-persistence derivation)

The H6 fold's "never-reused per-RG incarnation (`ResetFailover`
supersedes by BUMPING, never resetting)" survives process restart only
if the incarnation is derived, not stored: name it —
`(process_incarnation, per-RG counter)` — so a daemon restart can
never collide with the peer's remembered incarnation (the capability
record already carries `process_incarnation`).

## Finding 7 (nit — the DisruptiveTransfer claim rides the SAME transaction machinery)

The H7 fold says the claim is "consumed once, validated under the
`PromotionPermit` for ONLY that transition" — but the disruptive
transition is itself multi-stage (demote + activate), the same shape
whose one-shot consumption r61-B2 killed. State that the
`DisruptiveTransfer` claim rides the SAME
`Authorized → Claimed → Applied` transaction (stage ledger, PONR,
per-stage validation) — the ONLY difference from an ordinary transfer
is the admission predicate (the five-class gate is bypassed by
operator confirmation; nothing else changes).

## Finding 8 (nit — the reordered peer commit must be ACKNOWLEDGED before the first mutation)

The B3 fold reorders "the final peer commit BEFORE the first
VIP/netlink ownership mutation" with "the PEER is its durable store".
A commit SENT but not RECEIVED is not a durable store: the write-ahead
requires the peer's commit-ACK to land before the first mutation (and
the ACK's absence aborts the transition pre-PONR — which is exactly
the safe case).

## Finding 9 (nit — the §11 rolling-upgrade row still says "legacy paths")

The §11 row (line ~5388) says "intermediate peers get the legacy paths
via the version bits". Under the three-class definitions that is
"v1/v0 class paths" — "legacy" unqualified re-invites the
v1-is-buffered-legacy conflation the round-63 fold killed.
Housekeeping sweep.

## Bottom line

The v9.9.54.18 folds close all eight r63 findings in the prescribed
direction; the three-class version machine, the peer-as-durable-store
PONR, and the permit's readiness-loss participation all verify against
code. Finding 1 is the only pin with operational weight — an ISSU
drain that stalls new flows for seconds would be a regression shipped
in the name of closing a silent-loss window — and it is one sentence
of policy to fix.
