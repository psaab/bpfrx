# Claude SMR hostile plan-review — round 62 (v9.9.54.16 @ 75fa2eabe)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — the v9.9.54.16
folds landed under a prior session of this same reviewer role; this pass
attacks them. Verdict: **PLAN NO for v9.9.54.16-as-committed** — eight
precision pins (3 LOW, 5 nit; no design defect found). All seven r61
findings have operative folds in the direction Codex prescribed; the pins
below are the internal-consistency and failure-path-definition gaps those
folds left behind. M7 verifies RESOLVED on the bytes.

## Per-finding dispositions on the r61 set

- **r61-B1 (mixed-version capability) → folded, with three stragglers
  (Findings 1-3 below).** The repair-v2 / MAX-COMMON-VERSION mechanism is
  operative at 4176-4190 and closes the class split Codex traced.
- **r61-B2 (durable activation transaction) → folded (4428-4442), with a
  failure-path gap (Finding 4).**
- **r61-B3 (fence-first supersession) → folded (4601-4615), with one
  coverage pin (Finding 5).**
- **r61-H4 (one named promotion permit) → folded (4339-4351), with one
  lock-order pin (Finding 6).**
- **r61-H5 (ISSU ForceSecondary) → folded (4391-4401), with an unstated
  timeout/fallback (Finding 7).**
- **r61-M6 (no unconditional-progress promise) → folded (4470-4482), with
  one post-condition pin (Finding 8).**
- **r61-M7 (BIT-5 literal) → RESOLVED.** `dialer_cap` now ends
  `3f000000` (4770), the label says 0x3F (4772), both complete inputs at
  4779/4783 carry `3f000000` twice, and the published digests
  (`6a56876c…`, `f46254ed…`) match AGY's r61 independently verified
  values. Bytes, labels, and digests are mutually consistent.

## Finding 1 (nit — the assignment table still specifies the retracted bit-flag semantics)

The §5.8 assignment table at 4747-4753 still reads "BIT 5 =
DECISION-PROTOCOL … the decision-phase entry predicate reads BIT 5
explicitly and NEVER infers decision support from `repair-vN` (an
intermediate peer carrying `repair-vN` but not bit 5 is legacy for the
decision class and gets the buffered-first-frame path)". v9.9.54.16
redefined BIT 5 as `repair-v2` with a MAX-COMMON-VERSION entry predicate
(min(own_max, peer_max) ≥ v2). The two phrasings agree on every
two-version combination (both require BIT 5 on both records), so the
trace outcomes are identical — but they specify DIFFERENT mechanisms
(bit-flag presence vs version comparison) under ONE bit name, and they
diverge the day a repair-v3 exists (under the table's "reads BIT 5
explicitly", a v3∩v2 pair activates "the decision protocol" with no
version floor; under the fold, min() = v2 governs). One name, one
predicate: the table must say "BIT 5 = repair-v2 (the decision phase);
the entry predicate is the negotiated min-version", and drop the
"NEVER infers … from repair-vN" clause, which under the versioned
reading is a contradiction (BIT 5 IS the repair version).

## Finding 2 (nit — the stale "trailing tolerance" justification survives the fold that retracted it)

4194-4195 still says "B's OLD decoder skips the unknown BIT 5 (trailing
tolerance)" — the v9.9.54.14 justification Codex r61 explicitly rejected
("BIT 5 is inside the existing fixed-width capability word, not an
additive trailing field") — and the v9.9.54.16 fold three lines earlier
adopts that rejection ("and it sits inside the existing fixed-width
capability word, not an additive trailing field"). The surviving phrase
now contradicts its own fold. The load-bearing decode rule the versioned
mechanism actually needs — "a conforming v1 decoder IGNORES unknown set
capability bits (never rejects the record)" — is asserted ("old B
ignores BIT 5") but never stated as a normative v1 decode contract;
"bits 6-31 reserved-zero" (4753-4754) is an ENCODE rule and a
defensible reading of it is reject-on-set. State the decode tolerance
explicitly and delete "(trailing tolerance)"; the same stale phrase
rides the §11 rolling-upgrade row at 5246 for additive frames (that one
is legitimate — those ARE trailing fields — keep it, but do not let it
cite BIT 5).

## Finding 3 (nit — "A's advertised max is conditional on the peer's record" contradicts the fold's own trace)

4189-4190: "A never asserts v2 support toward a v1 peer (A's advertised
max is conditional on the peer's record)". The fold's own mechanism has
A's capability record carrying BIT 5 ON THE WIRE to B before A can know
B's version — B "sees A's `repair=1` … ignores BIT 5" (4179-4181), i.e.
B SEES the assertion. A one-round simultaneous exchange cannot make the
advertised bytes conditional on the peer's record; a two-round
ADVERTISEMENT→conditional-CONFIRM could, but the plan specifies no such
second round for the version (the v1-proof CONFIRM rule at 4210-4214 is
an activation gate, not an advertisement rewrite). The true property is
"A never ACTIVATES v2 semantics toward a v1 peer" — which min()
delivers. Delete the conditional-advertisement parenthetical or specify
the second round.

## Finding 4 (LOW — the B2 transaction's failure path is undefined at the demoted old owner)

4428-4442 folds Codex's `Authorized → Claimed → Applied` contract
verbatim, including "failure rolls back or retains the old-owner
lease". Under the H5 fold (and the existing ManualFailover ordering),
the old owner's RG-secondary marking completes BEFORE the token
sequence reaches the peer — so when a mid-sequence activation failure
fires, "the old-owner lease" is a node that has ALREADY demoted.
"Retains" is undefined: does the old owner re-primary (revert the
ManualFailover/ForceSecondary marking — `failover.go:159` sets
`ManualFailover = true`, which retains the secondary state until
operator reset)? Does the cluster sit dual-secondary, and is that
operator-visible? And "rolls back" is undefined for the wire-visible
stages — a stage that already ran `ForceRGMaster` has emitted VRRP
advertisements and GARP; rollback can only be compensating action
(re-demote, re-advertise), which the plan never names. The conservative
outcome (dual-secondary, alarmed, operator-visible) is acceptable and
in the plan's spirit — SAY it, name the per-stage compensating action,
and state that `ManualFailover`'s latch is what the "lease retention"
concretely rides.

## Finding 5 (nit — the fence-first fold never says the fence re-covers instances G1 already released)

4601-4615: "G2 FIRST revokes T1, publishes `G2/not-ready`, and
establishes the ownership fence, and ONLY THEN drains or abandons G1".
Codex's B3 trace had G1 restoring ONE instance (clearing its hold at
`manager.go:389`) before blocking in the remaining multi-instance
release. The fold's "establishes the ownership fence" presumably
re-acquires the election hold on EVERY instance including the one G1
already released — but it never says so, and "publishes G2/not-ready"
reads as an aggregate word, not a per-instance re-hold. One sentence:
the fence re-covers every instance G1 touched, explicitly.

## Finding 6 (nit — the named promotion permit's lock-order position is unstated)

4339-4351: the permit is "held from generation validation THROUGH the
final ownership publication". The publication path crosses `vipMu`
(released at `instance.go:1305`, published at `:1330`) and the
Manager-mutex domain the SMR r61 F2 serialization relies on. A single
named permit serializes its holders, so the only deadlock shape is
AB-BA: permit → `Manager.mu` (publication) against `Manager.mu` →
permit (readiness advance). State the rule: the permit is never
acquired while holding `Manager.mu` (the readiness advancer, which
runs under it, never takes the permit), and the permit is acquired
BEFORE the generation read it validates.

## Finding 7 (LOW — the ISSU forced-repair has no timeout or failure fallback)

4391-4401 folds "ForceSecondary runs the same forced-repair →
JOURNAL_END → token sequence BEFORE marking RGs secondary". The
peer-unreachable case is genuinely gated today — `ForceSecondary`
errors out unless `m.peerAlive` (`failover.go:144-146`) — so the
standard ISSU drain has a live peer to repair toward. But
`ForceSecondary` is today a bounded, immediate operation
(`failover.go:140-165`: mark and return); the fold makes it block on a
repair → `JOURNAL_END` → token sequence with no stated bound. If the
live peer is slow (bulk backlog, its own upgrade prep), the drain
hangs the ISSU run indefinitely; if the repair FAILS (connection drop
mid-journal), the fallback is unstated — abort the ISSU (operator
re-drives) or proceed without the transfer (re-opening exactly the
demote-without-repair window the fold exists to close). Name the
timeout, name the fallback (abort-the-drain, operator-visible), and
state that the `peerAlive` gate is re-validated at sequence start.

## Finding 8 (nit — the disruptive mode's post-transfer readiness discipline is unstated)

4470-4482: the only bypass is "a SEPARATELY EXPLICIT disruptive mode
(operator-confirmed, named, and alarming)". After a disruptive transfer
completes, the receiving node owns RGs whose state never satisfied the
five-class predicate. Unless the plan says the receiver remains
published-not-ready and alarming until the predicate re-clears (or the
disruptive mode carries its own post-transfer repair obligation), the
mode is a standing bypass of the gate, not an emergency override of
it. One sentence pins it.

## Bottom line

All seven r61 folds are operative and in the direction Codex
prescribed; M7 verifies on the bytes. The eight pins are the same
class as r61's SMR set — precision and failure-path definitions, no
design defect — with one addition worth Codex's attention: Finding 1's
table/fold mechanism split only matters when a repair-v3 exists, and
fixing it now (one name, one predicate) is cheaper than a round-63
finding about it.
