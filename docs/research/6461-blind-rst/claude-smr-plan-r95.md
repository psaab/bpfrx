# Claude SMR hostile plan-review — round 95 (v10.11.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — fifteenth
pass; I authored the v10.11.0 fold (the RWoLB retraction). Verdict:
**PLAN YES**.

## 1. The retraction, attacked

The v10.11.0 fold removes the v10.4.1 re-entry outright. The attack
questions: does the retraction resurrect any r83-r87 finding the
re-entry was folded to fix, and does it close r94's five?

**r83-r87 replay check (what the typed gate was FOR):** the site-9
defect was the arm replacing a live/marked entry with a transient
raw-flags seed. The typed-outcome gate (ExistingResolved → buffer
only; SeedInstalled/SeedRefused → master's miss paths) stands
unchanged — the retraction does not touch it. The r86/87 findings
behind the re-entry were (a) v10.4.0's own two-decision split
(stored-outer feeding reinjection while the arm's cleaned decision fed
install/buffer/replay) and (b) blanket NAT clearing erasing legitimate
pre-routing DNAT — both were defects of the PLAN's intermediate
shapes, not of master. Master has one retained decision consumed
uniformly (`session_glue/mod.rs:1194-1196` keeps the hit branch), and
no install from it. The round-87 staleness concern (a mid-dispatch
config change leaves the retained decision referencing a deleted
rule) is forwarding-only on this dispatch and is master's documented
pre-existing window (§7 race (d), v10.2.0 retreat); no stale decision
is ever installed because the install only happens on the later clean
miss, which derives fresh against current config (the round-87
correctness property preserved where it matters).

**r94-1 (dropped reservation-failed closes):** closed by removing the
path — with no re-entry, there is no #4400 drop on this class; a
purged close forwards with the retained lookup exactly as master
(never-drop restored). The reservation condition that created the
fallback is retracted with it.

**r94-2 (unowned P2):** closed by removing the derivation — no
allocation happens on the retained dispatch, so nothing can leak or be
freed-then-transmitted.

**r94-3 (cache suppression):** closed by master-verbatim — master's
sessionless cache insert (`poll_descriptor/mod.rs:3856-3960`) and the
cache-hit forwarding for the eligible subclass are untouched.

**r94-4/6 (success bit not a fence / undefined shape):** the condition
is retracted; retention is unconditional; the interaction is
documented in §7 with the exact bound (retained conflicted rows
forward closes until the first non-close purge or expiry, inside the
pre-existing #6600 broken state) and the exact-fence pointer
(#6522/#6600).

**r94-5 (overdue-K split-brain):** the adopt now writes S2's
decision/metadata IN PLACE for overdue K, preserves K's
`last_seen_ns`/`expires_after_ns` verbatim, and runs no re-queue — the
existing hint fires on schedule. Self-attack: a committed non-close on
the adopted entry clears probation and refreshes — preserving S2
(correct liveness: a real packet committed); the pin required the
re-queue, which is gone; §9 asserts both decision agreement and the
GC regression.

**r94-7 (two decision consumers):** moot for the purged class (the
single retained decision feeds every consumer); master's own
outer/pending split on the SeedInstalled path is pre-existing and
untouched by the typed gate (ExistingResolved buffers the resolver's
single stored decision; the reinjection consumes the buffered one).

**r94-8 (internal contradiction / "state-mutation-free"):** the
retraction deleted the contradictory text; the surviving claims are
parity claims (the purge itself is master's mutation, stated).

## 2. What the plan now changes on the RWoLB path (the whole list)

One predicate: a closing-flagged packet never triggers the transient
purge (unconditional retention → `ExistingResolved` → buffer with the
stored decision → deliver; validator refuse-demotes for lack of an
anchor). That is the entire Part-B surface on this path — the simplest
shape of the arc, and it closes r89-1 (no install for a close to
reach), r91-2 (retention kills the one-shot), and every subsequent
variant by having no machinery left to be wrong.

## 3. Consistency sweep

- All live text verified: §5.2 (iv) master-verbatim; §5.8 clause and
  site-9 row name the retraction; §5.6 site-3 supplement unconditional
  retention; §7 residuals carry the #6599 packet-parity statement and
  the #6600 interaction bound; §9 tests rewritten (master-verbatim
  dispatch, clean-miss install correctness tests, overdue-K in-place
  adopt, defense-in-depth oracle removed with the tag); §11(e)
  retargeted; header history complete through round 94. Grep: the only
  "install-free"/"re-entry" survivors are retraction narratives.
- The gate (§5.1–§5.4, §5.7) untouched for the tenth consecutive
  round.

## 4. Bottom line

PLAN YES for v10.11.0. The arc's Part-B shape has converged by
subtraction to: the gate, the constructor gates (2b/2c), the probation
discipline with its fence, the close-aware purge gate, the
ReplacedSyncedLocal skip, and the typed-outcome arm gate — everything
else on the RWoLB path is master's own code.
