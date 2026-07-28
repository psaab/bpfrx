# Claude SMR hostile plan-review — round 79 (v9.9.54.33 @ 793f5327d)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.33 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.33-as-committed** — six precision pins (1 LOW, 5 nit; no new
design defect found). All seven r78 Codex folds are operative; the
PREPARING contract, the root-table ABI, the mint authority, and the
required_version binding verify against the code citations.

## Finding 1 (LOW — a pending pre-downgrade record's interaction with a newer retirement issued during the downgrade is unstated, and the wrong answer re-fences stale)

The B4 fold persists a required_version=2 record PENDING across a
downgrade and redrives it when v2 returns. Walk the downgrade
window further: the operator issues a NEWER retirement (G2) for the
same target while G1 sits pending. At v2-return the store holds
both. Two bad answers are available to an implementer: (a) redrive
G1 first (it is older) — G1's supersedes references a G1-era fence,
and its completion replaces G2's newer fence semantics with older
ones; (b) evaluate G2 first and silently strand G1's union state
(F1+F2 applied, no completion path). The fold never says. The right
answer follows the store's own discipline and should be stated:
a pending record participates in supersession EXACTLY like a fresh
one — at v2-return the store evaluates pending records BEFORE any
redrive (equivalent scope → the newer supersedes; different scope →
MERGE per the H7 rule), and the result is ONE replacement at the
max generation covering the merged scope; a superseded pending
record's union state resolves through the newer replacement's
completion (never through its own stale redrive).

## Finding 2 (nit — no cross-candidate race is possible by the unique-shadow construction; say so)

The B1 fold's EXPIRED reclaim cleans the dead candidate's shadow
space while other workers stage. It cannot race a new PREPARING BY
CONSTRUCTION: the root record itself is never touched by a dead
PREPARING (the incumbent's value persists — the flip never
happened), so a new PREPARING can start immediately; and the
cleaning reclaims only the dead candidate's OWN unique shadow space
(per-candidate by construction), so no cross-candidate race exists.
One sentence preempts the cleaning-state question.

## Finding 3 (nit — the seqlock odd state spans exactly the root record's write)

The B2 fold's bounded-slow-path reader rule needs the window's
scope: the dependents stage in shadow space (invisible by the
namespace regardless of the seqlock), so the odd state covers ONLY
the root record's own write (sub-microsecond — one record, three
writes), never the whole staging duration. Without the sentence a
reader models the window as milliseconds and prices the slow path
wrong.

## Finding 4 (nit — the mint block is scoped to clustered deployments; standalone is self-authority; peer-down is priced)

The B3 fold's partition-mint block needs its edges: it applies ONLY
to clustered deployments (`/etc/xpf/node-id` present); a standalone
firewall is its own authority and self-mints (no block ever); and a
clustered node whose peer is simply DOWN (the ISSU drain case)
cannot mint new RGs for the block's duration — operator-visible
(`show cluster mint-status` plus an alarm on any apply attempt
during the block, so an operator's ISSU plan is never silently
surprised).

## Finding 5 (nit — the permit is per-worker, deadline-revoked, and re-taken only by a fresh packet)

The H5 fold's permit needs its cost and lifecycle discipline: the
permit is PER-WORKER (a per-worker counter per RG family; the drain
sums across workers — no cross-worker contention on the hot path);
a permit older than the deadline is REVOKED (its packet drops — it
never resumes, so there is no resume-after-revoke case); and a
retransmit takes a FRESH permit (registered anew into the drain's
accounting).

## Finding 6 (nit — the convergence merge applies floors before actives)

The H7 fold's monotone water line needs its merge ordering against
a partition-diverged peer: on convergence the floor sync applies
BEFORE any delayed active records from the same peer's backlog (a
delayed `Active(R10)` is evaluated against the already-merged water
line — rejected if at or below (its clear was learned), accepted
only if legitimately newer than the line (a pre-partition issue
whose clear never happened — and the peer's own records then show
it)).

## Bottom line

The v9.9.54.33 fold set closes the r78 set in the prescribed
direction, and the round's three-way overlap was again exact (Codex
B1 = AGY T1 = SMR F2 on the PREPARING orphan; Codex H5 = AGY T3 on
the permit; Codex B4 = AGY T4 = SMR F3 on the downgrade union).
Finding 1 is the pin with teeth: the downgrade window now has a
well-defined pending state, and the first thing an operator does
inside a window is issue the next retirement — the fold currently
lets two valid implementations resolve that overlap two different
ways, one of them wrong.
