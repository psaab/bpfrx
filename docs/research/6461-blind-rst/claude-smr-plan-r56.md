# Claude SMR hostile plan-review — round 56 (v9.9.54.4 @ ec58d4759)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.4 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.4-as-committed** — three precision pins (all LOW; no design
defect found). The v9.9.54.4 mechanisms verify sound in direction
against code.

## Finding 1 (nit — the decision's place in the pre-dispatch order)

State the full pre-dispatch order explicitly: hello → proof → wrapper
→ CONFIRM declarations → `CAPABILITY_DECISION` + ACK → slot install →
session dispatch/cold-prime. The decision therefore ALWAYS completes
before `sync_conn.go:138-194`'s cold-prime — a side that declared
repair-era locally has dispatched NOTHING when the decision arrives, so
the reversal is safe by construction.

## Finding 2 (nit — owner death mid-decision)

State: if the address-ordered owner dies before publishing, the
decision is UNCOMMITTED — the connection closes and retries with
bounded backoff; the retry's new connection may elect a different owner
per the same deterministic address-ordered rule, and the decision is
idempotent (the same declarations yield the same class regardless of
who publishes).

## Finding 3 (nit — the readiness generation lives in a shared atomic; no lock nesting)

State: the `(connection, protocol, activation)` generation and the
obligation-armed flag live in shared ATOMICS both sides respect; a
readiness writer's CAS (`shared_gen == my_gen && !obligation_armed`)
evaluates under `Manager.m.mu` reading only atomics (the manager never
takes the `SessionSync` mutex; the sync layer writes only atomics) —
the callback captures its generation AT QUEUE TIME
(`sync_conn_read.go:246`), so a delayed callback's stale generation
fails the CAS deterministically, and no lock nesting exists.

## Verified sound this round (my own re-trace)

- r55-B1 fold: the shared commit + reversal-before-dispatch + bounded
  retry close the split-class wedge (with Findings 1-2's pins).
- r55-H2 fold: the generationed readiness writers close the stale
  callback/timer writes (with Finding 3's pin).
- r54-1's independently-recomputed vectors hold.

## Verdict

**PLAN NO for v9.9.54.4** — fold Findings 1-3 as v9.9.54.5 (precision
pins; no design change). Part A remains converged and untouched.
