# Claude SMR hostile plan-review — round 82 (v9.9.54.36 @ 14e2b1b35)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.36 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.36-as-committed** — seven precision pins (all nit-level; no
LOW or above). All eight r81 Codex folds are operative; the
double-collect, the write-only-inactive rule, the widened keys,
the HEAD CAS, the floor_sync_id, the CONFIG_APPLIED_ACK, and the
single mint token verify against the code citations.

## Finding 1 (nit — the upsert's generation check is the normative guard; the double-collect is the bounded early-exit)

The B1 fold presents the double-collect as the gate, but the
upsert's OWN generation check (`session_glue/mod.rs:1157`
validates on every insert) already catches the lifted case at
the insert point. Say which is which: the upsert check is the
NORMATIVE backstop (every insert validates, no exceptions);
the double-collect is the early-exit optimization that avoids
the wasted materialize work (catching the tear at lookup time
instead of at upsert time); and the double-collect's retry is
BOUNDED (exhaustion drops the packet — a retransmit retries
fresh; at 100k+/s churn on a hot RG the fallback is the drop,
never a livelock).

## Finding 2 (nit — a reader never completes at an older version than the selector at its completion time)

The B2 fold's OLD-copy retention lets a long-lived slow-path
reader acquire at V+1 and race V+2's write. The completion rule
belongs in the text: a reader's completion RE-VALIDATES against
the CURRENT selector (a reader whose acquired version is older
than the selector's at completion restarts at the CURRENT
version — its packet always completes at the newest cohort,
never at a stale one); and the reader's acquire/re-validate
loop is bounded by the slow path's own deadline.

## Finding 3 (nit — a KEY-shape migration rebuilds from the authoritative Go session table, never key-translates)

The B3 fold's key widening (tuple → tuple+scope) changes the
canonical maps' key SHAPE — bigger than the r73-B1 value-shape
migration (old entries cannot be re-keyed in place). State the
path: the upgrade's drain window rebuilds the new map from the
authoritative Go session table (the control plane re-drives
every session into the new shape), the new map's content is
verified against the authoritative table, and the old map is
retired only after the verification — never a key-by-key
translation.

## Finding 4 (nit — the HEAD CAS has the CommitUncertain lifecycle: generation, timeout, operator-visible, operator-clearable)

The B4 fold's per-target HEAD CAS can stall on a partitioned
peer and block every later retirement for that target. Give it
the plan's own durable-uncertainty discipline: the head carries
a generation and a timeout; a stalled head is operator-visible
in the retirement display; the escape is the same
operator-confirmed clear class as `CommitUncertain`'s
peer-absent clear; and the queue behind the head is bounded
with an operator-visible rejection at the bound.

## Finding 5 (nit — the floor_sync_id is monotone across the authority's LIFETIME, persisted with the ledger)

The B5 fold's "monotone id per sync" needs its restart rule:
the id counter is durable state in the fence ledger (persisted
with the same write-ahead discipline), is monotone across the
authority's LIFETIME (not just its process lifetime), and a
restarted authority re-issuing a sync with a LOWER id than a
pre-restart sync is rejected as stale (never accepted).

## Finding 6 (nit — the backfill rides the confirmed-commit rollback path; a failed adoption rolls back the whole candidate)

The B6 fold's adopt-failure needs its reconciliation with the
existing config machinery: a failed runtime adoption is a
FAILED APPLY and rides the confirmed-commit rollback path (the
whole candidate — including the backfilled fields — rolls
back; the retry re-mints under a new candidate, never patching
the failed one).

## Finding 7 (nit — the authority state is mirrored into a Store.mu-readable cell, written before the change takes effect)

The H8 fold's self-contained token must be validated against
CURRENT authority state at promotion, which lives under
`Manager.mu` — untakeable under `Store.mu`. State the mirror:
the authority publishes its state (incarnation, lease epoch)
into a `Store.mu`-readable mirror cell under `Manager.mu`
BEFORE any authority change takes effect (the mirror is the
promotion-time truth source; the token's revalidation reads
the mirror, never `Manager.mu`; and the mirror is written on
authority change before the change takes effect, so the
promotion's read is exact at the linearization point).

## Bottom line

The v9.9.54.36 fold set closes the r81 set in the prescribed
direction; the write-only-inactive rule and the widened keys
are the first folds in their mechanisms with no residual
failure window by construction. This is the third consecutive
all-nit SMR round. The remaining pins are the same class:
state the invariant that makes the fold auditable. Every pin
above is one sentence; none opens a new mechanism.
