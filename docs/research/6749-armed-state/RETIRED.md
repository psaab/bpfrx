# #6749 armed-state plan — RETIRED (not now, and why)

**Status: retired 2026-08-31. The plan is parked, not abandoned, and not
deleted.** The branch `research/6749-armed-state` (head `352a9869c`) still
carries `docs/research/6749-armed-state/plan.md` at v8.41, CONVERGED
PLAN-READY after 45 review rounds.

> **Cite correction.** #7546's body places the plan under a `docs/pr/…`
> directory for this issue number. It is not there. The plan is at
> `docs/research/6749-armed-state/plan.md`, and it exists **only on the
> research branch** — which is why that path is registered in
> `pkg/docsref/testdata/known_dangling.txt`. A reader following the wrong
> directory finds nothing and could reasonably conclude the plan was deleted,
> which would make a parked decision look like an abandoned one.

## 1. What shipped, and what deliberately did not

**Shipped (#6749 → PR #7544):** the outage half. A newly registered binding
slot inherits the global applied/requested arm state instead of defaulting to
unarmed, so a binding-plan expansion no longer drops all transit indefinitely.
That fix stands on its own and is not affected by this retirement.

**Deliberately not taken:** the provenance half — preserving arm state by
stable binding identity, and per-binding convergence. Real, bounded, and not
currently producing an operator-visible wrong answer.

## 2. Why the two "remaining" items are not separable

#7546 lists two items as though they were small and independent. They are the
two halves of option C, and the plan says a half-C is worse than none.

### Item 2 — "make Go's convergence check include each registered binding"

This is **option B**, and §5-B's verdict is verbatim:

> **REJECT B-as-Go-converger.**

with three stated reasons: B alone leaves a ~1 poll-tick total transit outage
per expansion commit (A/C close it to zero at the source); **B alone keeps the
wrong-identity carry defect** — it converges the armed bit but leaves
`registered`/`last_error`/counter provenance wrong; and the override registry
is new manager state with staleness and slot-renumbering hazards.

The plan also answers this issue's exact wording rather than by implication:

> *"The issue's third fix-direction leg ('make Go's convergence check include
> each registered binding') is answered in detection form by option D below —
> whose predicate the marker now makes exact (`!Armed && !ActivationPending` =
> genuine drift, not pending activation)."*

So item 2 is answered as **detection**, not convergence — and D's predicate is
exact **only because of** C's `activation_state` marker. Built without C, D
reports every pending activation as drift: a false-positive warning on every
expansion commit.

### Item 1 — "preserve arm state by stable identity"

The safe form is the plan's **R3**, which carries
`{armed, registered, activation_state, last_change}` keyed on
**configured-name** `(interface, queue_id)` — the qualifier matters, since the
configured name is not the kernel name. `activation_state` is C's wire field, so R3 is not
standalone either.

## 3. The counterexample that settles it

The naive form of item 1 — carry `armed` across a replan — is "arm-at-replan",
listed among the shapes that died to named counterexamples in rounds 1-5. The
counterexample, verified in-plan:

> *"a post-teardown `WorkerSpawn` failure returns WITHOUT `stop_inner` —
> already-launched workers KEEP their records (bringup.rs:172-183) — and the
> reconcile refreshes actual partial state before returning `Err`
> (reconcile/mod.rs:391). An arm-at-replan model therefore reports
> `enabled=true` against a partially-dead worker set (the #869 gate ignores
> `ready`/`bound`), and Go can publish READY rows for the surviving subset.
> Activation must follow reconcile SUCCESS (or be reverted on failure) — §5-C
> S4."*

**Read that against #7546's own "Before building" warning.** The issue warns
that hardcoding `armed: true` for a *new* slot is a forwarding fail-open —
it arms a box that is deliberately disarmed. True, and guarded.

Nobody had noticed that preserving `armed` **by identity** has the same failure
mode **through a different door**: on partial bring-up it reports `enabled=true`
against workers that are not there, and Go publishes READY rows for them.

This is the paragraph that matters most to a future implementer, because the
identity-preserving shape is the one they will reach for *precisely because it
looks like the careful option*.

## 4. What would justify taking it later

A condition, not a shrug. Take C+D when **either** of these becomes true:

1. **Provenance drift produces an operator-visible wrong answer.** Today the
   drift is internal: `registered`/`last_error`/counter provenance can be wrong
   after a reshuffle without anyone seeing an incorrect output. The moment a
   `show` surface, an alarm, or an HA decision is observed to read the wrong
   binding's state, the bounded cost stops being bounded.
2. **Something else forces a wire change in this area.** C's cost is dominated
   by touching the wire, HA authority, and the defer window together. If a
   different piece of work is already opening that surface — a
   `ConfigSnapshot` field, a `BindingStatus` field, a defer-window change — then
   C becomes cheap by comparison and should be reconsidered in that context
   rather than on its own.

Absent either, the residual stays parked.

## 5. Why "not now" rather than "not ever"

The plan is CONVERGED and PLAN-READY; it is not wrong, and it is not being
rejected on its merits. It is a wire-touching, HA-touching, multi-thousand-line
change whose own recommendation is *"Ship option C + option D … Retreat: none
lighter survives review."* A change of that shape must be resourced and
reviewed deliberately — which is exactly what the plan itself asks for by
awaiting manual approval via `/engineer 6749`.

Absorbing it as a "residual" of a closed outage issue is the one way to get it
wrong. Choosing *"not now, and here is the trigger"* is a disposition; drifting
is not.
