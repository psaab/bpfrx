# Claude SMR hostile plan-review — round 68 (v9.9.54.22 @ 05831e4f0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.22 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.22-as-committed** — seven precision pins (1 LOW, 6 nit; no new
design defect found). All eight r67 folds are operative; the per-frame
predicates, the install-only v0 gate, the admission ticket, and the
two-state-plus-terminal receipt verify against the code citations.

## Finding 1 (LOW — a rollback during DRAINING can deadlock against the fence the fold just built)

The B3 fold makes a failed journal append fail the admission and
"rollback the install", and separately makes the fence's DRAINING
state reject NEW readers. If the rollback needs a read permit (it
touches dataplane state — the same machinery the permit covers), a
rollback that becomes necessary while the fence is DRAINING deadlocks:
the drain waits for held permits, the rollback waits for a reader,
and the fence's millisecond deadline fires ABORTED — with the
rolled-back install now unjournaled on A AND the transaction aborted.
The escape is real and simple: the rollback is EXEMPT from the read
permit (it only removes state — and its delete deltas journal only
the APPENDED prefix: if the append failed before any durable write,
the peer never saw the cohort and the rollback is LOCAL-ONLY — no
delete delta is emitted, because the peer has nothing to forget; if a
prefix was appended, the delete rides the same ticket so the peer can
reconcile exactly that prefix). State the exemption and the
prefix-rule; without them the fence and the rollback compose into a
deadlock-then-inconsistency.

## Finding 2 (nit — the frame predicates never say the evaluation point, and the pre-dispatch order is what saves them)

The B1 fold assigns per-frame entry predicates (33-34 → v2, 35-37 →
v1+, 38-39 → reset-v1) but never says when legality is evaluated. A
repair frame arriving before the class COMMITS (at the ACK'd
installation) would be illegal under the committed-class rule on a
connection about to commit v1. The pre-dispatch order (hello → proof
→ wrapper → CONFIRM → DECISION+ACK → slot install → session
dispatch) makes the case unreachable — repair frames ride the
ESTABLISHED connection, which exists only after slot install, which
follows the ACK'd decision. Say so: legality is evaluated against the
committed class at receipt, and the pre-dispatch order guarantees no
repair/decision/reset frame can arrive before the commit.

## Finding 3 (nit — the reset bit on a recorded-v0 record must be ZEROED, not 'refused')

The H5 fold says "the reset negotiation REFUSES reset_version >
repair_version". On the recorded-v0 evidence path (a record with
repair bits zero but `reset-vN` set), "refuses" reads as refusing the
CONNECTION — but the peer is a perfectly good v0 peer. The correct
rule is intersection semantics: the reset capability ZEROES whenever
repair_version = 0 (the connection commits v0 with no reset lane and
nobody is refused); the "refusal" applies only to a negotiated
reset_version ABOVE the negotiated repair_version on a repair ≥ 1
connection. One sentence separates the two cases.

## Finding 4 (nit — the record-less recovery's default leg is unstated, and removal loses information)

The B4 fold offers "persists `Rejected/Aborted` (or atomically
removes `Prepared`)" as alternatives. They are not equivalent: with
NO receipt, the new-incarnation recovery transaction must pick
restore-B's-lease vs complete-A's-transfer blind. State the default:
the record-less recovery ALWAYS restores the demoting node's
ownership (the claimer's completeness is unproven without a record —
the conservative leg), which makes PERSISTING `Rejected/Aborted`
strictly better than removing `Prepared` (the persist keeps the
true-reject information; removal should be reserved for receipts
that were never definitively answered and whose regeneration is
idempotent).

## Finding 5 (nit — the high-water mark's comparison semantics)

The H6 fold's "retirement high-water mark" needs its comparator:
state that the mark IS the retired `process_incarnation`, heartbeats
carrying that incarnation or older are LIVENESS-ONLY, and a NEWER
incarnation (a restarted peer) is not fenced by the mark — it
proceeds to the quiesced revalidation that teaches it the retirement
(so a lagging legitimate incarnation is never falsely fenced: only
the exact retired one is).

## Finding 6 (nit — the responder's post-enqueue window needs its bound named)

The M7 fold has the responder commit on "successful full ACK
write/enqueue on the ordered stream". Enqueued bytes can still never
leave the kernel; the owner then never commits while the responder
holds a committed class. The window is bounded by the connection's
own failure detection (the next write's error, or the read deadline)
and contained by the class's connection-scoping (every dispatch in
the window dies with the connection). State both halves so the
"commit on enqueue" choice is auditable rather than silent.

## Finding 7 (nit — the v0 priming stale-entry window should be priced, not just named)

The install-only priming leaves the receiver's stale entries to "its
own aging/invalidation/sweep machinery" — a window of minutes during
which a packet matching a stale entry forwards on stale state. This
is the pre-existing legacy behavior (v9.9.13), and v0 IS the
legacy-behavior class, so the window is the accepted status quo —
but the fold should price it (the applicable aging timeouts, and the
fabric-forward/backstop behavior for the HA case) so the acceptance
is explicit rather than inherited.

## Bottom line

The v9.9.54.22 fold set closes all eight r67 findings in the
prescribed direction, and the v0 install-only restatement removes a
genuine delete channel (recorded-v0 mid-bulk flip → key-delete E2 +
companions). Finding 1 is the pin with teeth: the fence and the
admission-rollback compose into a deadlock-then-inconsistency unless
the rollback is exempt and prefix-scoped — one sentence each, but
load-bearing.
