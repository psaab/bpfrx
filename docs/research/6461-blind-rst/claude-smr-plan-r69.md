# Claude SMR hostile plan-review — round 69 (v9.9.54.23 @ a54f46b08)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.23 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.23-as-committed** — six precision pins (1 LOW, 5 nit; no new
design defect found). All eight r68 folds are operative; the
non-circular predicates, the serialization edge, the publication-split
append policy, and the generational seal transitions verify against
the code citations.

## Finding 1 (LOW — the 'append at ticket mint' can journal a cohort the dataplane never installs, and the repair would replicate the ghost)

The B3 fold says "the append is attempted EARLY (at ticket mint,
before any publication)". Read literally, the durable journal record
lands BEFORE the dataplane install — a crash between append-success
and install leaves the journal holding a cohort the dataplane never
installed, and the next repair replicates it: B installs a session
that never existed on A, complete with a NAT reservation B now holds
for a phantom. The fold's intent (durable receipt precedes
success-return) is right; the staging is wrong by one notch. State
the two-phase record: the mint-time record is STAGED (an intent
marker, never replicatable); it transitions to INSTALLED when the
dataplane install completes (the transition is journaled); the
cutoff's durable-acceptance predicate counts ONLY INSTALLED records;
the repair replicates ONLY INSTALLED records; and recovery rolls an
orphaned STAGED record back (safe — nothing was ever installed or
published, so its allocation frees cleanly). The pre-publication
rollback path then reads consistently: install → append (STAGED →
INSTALLED) → publish, with rollback safe anywhere before publish.

## Finding 2 (nit — the tentative-phase allowlist needs its exact frame set)

The B1 fold makes 33-34 legal during the pre-install decision phase
and everything else illegal until the commit. The round-58
allowlisted reader should be stated in the new frame-ID terms: during
the decision phase the allowlist is EXACTLY {32 (`CAPABILITY_CONFIRM`
stragglers on a re-exchange), 33, 34}; every other frame type
(including 35-39) before the ACK'd commit is a protocol violation
and closes.

## Finding 3 (nit — the serialization-failure stale tentative state needs its discard sentence)

The B2 fold's synchronous serialization can itself fail (the stream
dies mid-write): the responder's receipt never completes, the
responder never commits — safe — but it holds a validated,
uninstalled tentative state. One sentence: the tentative state is
connection-scoped and is DISCARDED with the connection; the retry
runs on a fresh stream with a fresh setup token and derives
everything from the new exchange (nothing carries across).

## Finding 4 (nit — the OPEN(g+1) surge and the aborted generation's DIRTY folding)

The H4 fold reopens the fence as `OPEN(g+1)` after an abort. State
that admissions from `OPEN(g+1)` ride generation g+1's journal FROM
MINT (the next cutoff's watermark covers them by construction), and
that the aborted generation's `UNCOVERED/DIRTY` ticket set is folded
INTO g+1's repair obligation explicitly (the bump names the set, so
the next repair's completeness proof accounts for exactly those
cohorts — not just "a repair happens sometime").

## Finding 5 (nit — rg_scope semantics and the overlapping-scope CAS rule)

The H5 fold gives the clearance namespace an `rg_scope u32` without
semantics. State: `rg_scope` is a BITMAP of redundancy groups; the
pending fence is per-(namespace, rg)-element; a clearance CASes ONLY
the matching element fences — an `ACK(R1, scope={1,2})` clears R1's
fences on rg1 and rg2 and can NEVER clear R2's fence on rg2
(different retirement generation in the namespace); an all-RG
retirement (`ForceSecondary`) is one mark with scope=~0, and its
clearance is per-element.

## Finding 6 (nit — the CAPABILITY_CONFIRM payload must be stated byte-identical to the transcript record)

The M6 grammars give frame 32's payload as the §5.8 record grammar;
the transcript vectors hash `dialer_cap`/`acceptor_cap` in the same
layout. State the identity explicitly: the frame-32 payload IS the
transcript capability record byte-for-byte — so the golden vectors
already cover the wire encoding of the frame, and no second encoding
can drift from the hashed one.

## Bottom line

The v9.9.54.23 fold set closes all eight r68 findings in the
prescribed direction, and r67's three RESOLVED dispositions (v0
install-only, rejected-Prepared replay, reset ≤ repair) are the
first multi-resolve round of the arc — the fold classes are landing
durably. Finding 1 is the pin with teeth: 'append at mint' as
written journals admissions that may never exist, and the repair
would faithfully replicate the ghost — the STAGED/INSTALLED
two-phase record is one paragraph and closes it.
