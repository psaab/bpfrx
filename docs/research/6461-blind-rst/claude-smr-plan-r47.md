# Claude SMR hostile plan-review — round 47 (v9.9.39 @ e6bec91c1)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.39 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.39-as-committed** — three precision pins (all LOW; no design defect
found). The v9.9.39 mechanisms verify sound in direction against code.

## Finding 1 (nit — the family-transaction permit's home and the drain bound)

State: the family-transaction permit is HELPER-ISSUED (Go acquires it
with the family's first write, identified by the canonical key; the
helper tracks outstanding permits in the same transaction context as
`replace(slot, T1, T2, token_epoch)`), because the map writes are
helper-owned state and the replacement transaction is helper-acknowledged
— a Go-only permit would leave the reverse/DNAT writes (which today
bypass helper validation) outside the drain's reach; and the drain never
WAits indefinitely — a family transaction carries its own deadline
(µs-ms for three sequential map writes), after which `replace`
CAS-invalidates it rather than waiting (availability preserved).

## Finding 2 (nit — the lane's incarnation freshness on peer restart)

State: a peer restart mid-lane kills the lane with the connection (TCP
reset or the silence teardown — the lane inherits the connection's
lifecycle); the new lane re-handshakes with the new incarnation; and an
old-incarnation `RESET_ACK` arriving on a NEW lane is discarded (the
frame's incarnation must equal the LANE's bound incarnation, not just
any recently-seen one).

## Finding 3 (nit — the §8 risk row needs the teardown-latch row, not just text)

Cosmetic but load-bearing for the implementer: the §8 HA row now mentions
the teardown-failed latch inline; it should be its own row (availability
class: operator-intervention-on-stuck-worker, LOW probability, defined
recovery action) so the risk table actually enumerates the new terminal
state.

## Verified sound this round (my own re-trace)

- r46-B1 fold: the discharge-direction sweep is complete — my grep finds
  no remaining clause clearing an obligation/readiness/latch on anything
  other than `JOURNAL_END` (inbound) or `JOURNAL_ACK` (outbound).
- r46-H2 fold: the permit + token-conditional CAS rollback close the
  family-rollback race (with Finding 1's home/bound pins).
- r46-H3 fold: the lane confinement is complete (with Finding 2's
  freshness pin).

## Verdict

**PLAN NO for v9.9.39** — fold Findings 1-3 as v9.9.40 (precision pins;
no design change). Part A remains converged and untouched.
