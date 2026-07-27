# Claude SMR hostile plan-review — round 70 (v9.9.54.24 @ 9bbdb445d)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.24 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.24-as-committed** — six precision pins (all nit-level; no
design defect found — the first SMR round of this arc with no LOW or
above). All six r69 folds are operative; the two-phase journal
record, the 32-byte schema, the counted scope, and the canonical
repair-ID verify against the code citations. The pins are the folds'
own unspecified edges.

## Finding 1 (nit — INSTALLED must be defined as ALL publish points, with the partial-publish unwind stated)

The B1 fold marks `INSTALLED` "atomically ONLY after canonical
publication", but the canonical publication is MULTI-POINT (shared
map + sibling workers, `poll_descriptor/mod.rs:2578, :2591`). State:
`INSTALLED` requires EVERY publish point confirmed; a partial publish
(a failure at any point) unwinds ALL points (each is an idempotent
set/delete), the ticket NEVER marks `INSTALLED` on a partial publish,
and the unwind rides the pre-publication rollback path (safe —
nothing was matchable yet at the unpublished points).

## Finding 2 (nit — the frame-32/transcript byte-identity must be a compile-time invariant, not a discipline)

The B2 fold states the frame-32 payload IS the transcript capability
record byte-for-byte. As a documented discipline two encoders can
drift; state that ONE encoder produces both (the transcript term and
the frame payload are the same encode function's output) — the
golden vectors then cover the frame's wire form by construction, and
a future field addition breaks the vectors loudly instead of
silently forking the two encodings.

## Finding 3 (nit — the pending fence is stored PER-RG (expanded at mark), and count=0 needs its sentinel disambiguation)

The B3 fold's counted scope record + `count=0 = ALL` sentinel leaves
the fence's storage form unstated. State: the pending fence is stored
PER-RG — a mark EXPANDS its scope into per-(namespace, rg) elements
at application time (an ALL mark expands to the then-current RG set;
a config adding an RG after the mark does NOT fence the new RG — it
was never retired — which is the correct semantics and must be
stated); a clearance CASes per-element; and `count=0` is the ALL
sentinel, NEVER an empty scope (an empty scope is unencodable — a
retirement of nothing is rejected at the API).

## Finding 4 (nit — the authoritative-absence proof's sufficiency rests on the never-rollback retention; say so)

The H4 fold clears a dirty ticket on "identity-matching
AUTHORITATIVE ABSENCE". The worried case (the cohort's tuple P
reissued to E3) is closed by construction — the never-rollback rule
keeps P bound to the retained session for its whole natural life, so
P is never reissued while the ticket is open — but the fold never
says that, so the absence proof looks under-powered. One sentence:
absence-of-identity is sufficient BECAUSE the retention keeps the
tuple bound for the session's natural life; if the session ends
naturally before the repair covers it, the cohort is genuinely gone
and absence-of-identity is the correct clear.

## Finding 5 (nit — the completed-repair receipt's dedup key is the full terminal tuple)

The M5 fold carries the canonical pair end-to-end but never says what
the completed-repair receipt keys on. State: the receipt keys on the
full terminal tuple `(sender_incarnation, request_seqno,
journal_epoch, terminal_seqno)` — delayed `JOURNAL_ACK`s dedup
exactly on all four fields (the pair alone cannot distinguish two
repairs that share a request_seqno across epochs).

## Finding 6 (nit — the STAGED record's journal GC rule)

The B1 fold treats uncommitted `STAGED` records as absent during
recovery, but never says when a `STAGED` record is GC'd on the LIVE
path (a worker that minted a ticket and died without publishing
leaves a `STAGED` record behind with no crash of the NODE — the
record is durable): state that a `STAGED` record whose ticket's
worker is gone (worker-liveness, same discipline as the executor's
per-ticket workers) is rolled back by the same recovery rule — no
node crash required, and the allocation frees exactly as in the
node-crash case.

## Bottom line

The v9.9.54.24 fold set closes all six r69 findings in the
prescribed direction, and r68/r69's six cumulative RESOLVED
dispositions (non-circular predicates, ACK serialization,
generational seals, v0 install-only, rejected-Prepared replay,
reset ≤ repair) are holding. This is the first SMR round with no
LOW-or-above finding: the remaining pins are "state the obvious
before someone implements the other reading" — which, at this plan's
precision level and review history, is exactly where the next
round's BLOCKERs come from if left unsaid.
