# Claude SMR hostile plan-review — round 61 (v9.9.54.14 @ 0f98f0c29)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.14 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.14-as-committed** — four precision pins (all LOW; no design
defect found). The v9.9.54.14 mechanisms verify sound in direction
against code.

## Finding 1 (nit — the intersection is computed once and latched for the connection's lifetime)

State: the capability intersection is computed ONCE at the capability
exchange and the protocol class latches for the connection's lifetime
— a capability-record replacement mid-connection (a newer record with
fewer bits) does NOT re-open the intersection: the recomputation is
ignored for the current connection (no class change is possible
mid-connection) and takes effect only on the NEXT connection.

## Finding 2 (nit — the ownership-commit revalidation serializes under Manager.mu)

State: the promotion's ownership commit (`becomeMaster`,
`instance.go:839`) and the hold acquisition's instance update
(`SetSyncHold`, `manager.go:354`) are BOTH Manager-mutex operations, so
the generation revalidation serializes naturally — the commit reads the
readiness generation under `Manager.mu`, the acquisition's update
writes under `Manager.mu`, and whichever lands second re-checks and
fails if the generation moved.

## Finding 3 (nit — the forced repair's state is mastership-independent)

State: the forced repair transfers the DEMOTING NODE'S OWN table, which
exists independent of which node is master — a mid-repair VRRP priority
drop (demotion cost or priority-0 advertisements) does not invalidate
the repair (the peer needs A's table regardless of who holds
mastership), and the override's barrier follows the repair's completion
regardless of the then-current master.

## Finding 4 (nit — the abandoned attempt's completion is rejected by the API's completion-time validation)

State: every target API validates ticket AND generation at BOTH
submission and completion — an attempt whose ticket was abandoned while
it blocked is rejected at completion (the ticket is no longer current),
so a stale completion can never land an effect.

## Verified sound this round (my own re-trace)

- r60-B1 fold: the intersection rule closes the asymmetric activation
  (with Finding 1's latch).
- r60-B2 fold: the five-class predicate + commit revalidation close the
  park-satisfies-predicate and acquisition-races-promotion traces (with
  Finding 2's serialization).
- r60-B3/B4/H5 folds are coherent (with Findings 3-4).

## Verdict

**PLAN NO for v9.9.54.14** — fold Findings 1-4 as v9.9.54.15
(precision pins; no design change). Part A remains converged and
untouched.
