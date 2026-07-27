# Claude SMR hostile plan-review — round 75 (v9.9.54.29 @ 72465705c)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.29 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.29-as-committed** — seven precision pins (1 LOW, 6 nit; no
new design defect found). All seven r74 Codex folds are operative;
the cohort ROOT, the quiescence proof, the incarnation-qualified
ledger, and the notice lifecycle verify against the code citations.

## Finding 1 (LOW — the quiescence drain never fences NEW admissions on the excess RGs, so the proof may never converge)

The B2 fold requires a generation-tagged proof that every excess RG
is quiesced "across VRRP, direct/private VIP, dataplane, and session
ownership", and the transition rechecks under election
serialization. But the fence is ELECTION-scoped: B remains
dataplane-primary for the excess RG3 by default (A can't take over
an RG it doesn't have configured), so sessions on RG3 keep living —
and NOTHING in the fold stops NEW admissions on RG3 while the drain
runs. A busy RG3's session count never reaches zero, the proof
never completes, and the whole-incarnation fence (which is what
keeps RG3's failover correct) never resolves — a quiet form of the
same stall the fence exists to avoid, now on the drain path. The
fix is one sentence and follows the cutoff's own discipline: the
quiescence drain includes an ADMISSION FENCE on the excess RGs
(new admissions on a draining RG are refused — drop, not RST — from
the proof's start), and the proof's completion requires the excess
session count to reach zero AND hold at zero through the
serialized transition (a post-proof admission reopens the proof).

## Finding 2 (nit — the reverse-direction indirection fires once per flow, and no pre-commit cache entry can exist)

The B1 fold's alias→root indirection reads twice on the reply
path's first packet. It is worth stating why this is cheap AND
correct: the flow cache can never hold a pre-commit entry (a hidden
cohort cannot forward, so it cannot seed the cache), so every
cached entry already carries the resolved verdict; the
alias→root indirection fires exactly once per flow (at seed time).

## Finding 3 (nit — the removed-RG fence's epoch binding)

The B3 fold's union merge never says what happens to a fence whose
RG a config replace REMOVES. State it: the fence binds `(RG id,
retirement generation, membership epoch)`; a removed RG's fence
persists (displayed as pending-stale) while the membership epoch is
current; a re-added RG within the same epoch inherits the fence
(same logical RG); across an epoch boundary the re-added RG is a
new instance and the stale fence expires naturally (never GC'd
actively — an active GC could race the re-addition).

## Finding 4 (nit — the RELEASE_PENDING deadline and the forward-while-pending rule)

The H4 fold never says how long a session may sit
live-but-pending or who completes a wedged release. State:
packets continue to match a pending session (the pending record is
a journal intent about the ALLOCATION, not a teardown of the
session's forwarding); the removal retries with a deadline, and on
repeated failure the teardown-failed latch arms (the v9.9.37
discipline — rebind/reconcile prohibited until every unquiesced
old worker exits or a restart, operator-visible).

## Finding 5 (nit — the install gate is 'class committed', and cold-prime shares it)

The H5 fold's conditional sequence never says what the slot
install's gate IS at min()=1. State: the install's precondition is
"the class is committed" by whichever matrix row applies
(proof-verified transcript for (v2-proof, v1); CONFIRM for
(v1-proof, recorded); first ordinary frame for (v1-proof,
v0-recordless)) — never "the decision completed" — and
cold-prime's start shares the same gate (it follows the install,
not the decision frame).

## Finding 6 (nit — the AwaitingClearance resume/retransmit rules)

The H6 fold's AwaitingClearance state needs two rules: an authority
restart RESUMES the await from the durable store (never re-issues
as new — the notice's generation is already spent), and the
state's timeout retransmits the fence with backoff — idempotent at
the receiver by the namespace dedup (the fence is already applied;
the retransmit is a no-op there and completes only the authority's
bookkeeping).

## Finding 7 (nit — the replacement ACK covers BOTH stages)

The H7 fold's install+ACK-before-tombstone needs the completion
rule: B holds the UNION of F1 and F2 until the F1 tombstone lands
(safe — union is the conservative state), the stage ledger resumes
across B's restart in that window, and A2 treats the replacement
as complete ONLY when the tombstone has landed (the ACK is of the
REPLACEMENT — install plus tombstone — not of the install alone).

## Bottom line

The v9.9.54.29 fold set closes the r74 set in the prescribed
direction; the cohort-ROOT construction is the first publication
rule in this arc that answers "atomic across how many values" by
construction rather than by ordering. Finding 1 is the pin with
teeth: the quiescence proof exists to release a fence, and as
written it can wait forever on a drain it never actually starts —
one sentence of admission-fence on the draining RGs closes it.
