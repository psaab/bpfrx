# Claude SMR hostile plan-review — round 100 (v10.16.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twentieth
pass; I authored the v10.16.0 fold of Codex r99's 5B/1H/1L. Verdict:
**PLAN YES**.

## 1. Fold verification

**r99-1 (B — retraction incomplete in normative text).** The four
stale spots (site-3 row's provenance bound, §5.8 bullet, §9
purged-class bullet, §11 3(a)) all claimed the retracted cache
suppression or the never-purge behavior. All four now say
master-split with full cache parity, with master's cache-eligibility
of a purged pure-ACK cited (`flow_cache.rs:352-394`,
`poll_descriptor/mod.rs:3900-3959`). Grep-verified no live text
describes the retracted line.

**r99-2 (B — FULL MASTER PARITY behaviorally false).** This was the
round's real catch and it is a PHRASING correction with a documented
cost, not a design change: the local lookup runs before the purge
decision (`shared_ops.rs:594-635`, `session_glue/mod.rs:1157-1196`),
so master's close marks the matched entry and propagates the
shortened lifetime to its companion (`lookup.rs:105-128`,
`:198-218`, `session/mod.rs:1232-1277`) before the purge deletes only
the matched key + forward aliases (`promote.rs:181-207`,
`shared_ops.rs:960-1013`). The gate's refusal on an anchorless
peer-synced entry is Part A working as designed on a HIT — and its
cost here (the reverse replica lingers on its ordinary trajectory
instead of the 2 s/30 s closing window) is precisely the §2
absorbing-state residual, now stated for this path in §5.2 (iv) with
the mechanism trace. The parity claim is scoped: purge DECISION and
dispatch master-identical; the demote refusal is the deliberate,
documented exception.

**r99-3 (B — OverdueSkipped transport/composition).** The outcome now
rides `ResolvedFlowSessionDecision` as a new field
(`shared_ops.rs:563-578`); the composition rule sends an
OverdueSkipped + MissingNeighbor result to the live-backed
ExistingResolved buffer-only arm (never the seed block,
`poll_descriptor/mod.rs:4662-4829`); the five-consumer set is
explicit (teardown, anchor hook, cache insert, probation
clear+refresh, promote — the last already gated by the probation
flag itself); accounting is explicitly allowed (#2501 semantics on
the packet query tuple); §9 tests the propagation across the three
teardown sites (`:698`, `:768`, `:824`).

**r99-4 (B — alias set still incomplete).** The full set is now
specified against the lookup/reply code (`lookup.rs:62-100`,
`:222-250`, `:253-315`, `key.rs:19-26`; exact-key invalidation
`flow_cache.rs:1105-1120`): canonical, reverse companion,
reverse-translated aliases, forward-wire aliases, reply-match tuples
— and, because an S1→S2 adoption changes identity while
`ExpiredSession` carries only the final one (`entry.rs:337-343`),
every adoption invalidates the PRIOR identity's full set at adopt
time (both identities are in hand there).

**r99-5 (H — conceded-chain rationale).** The "no closing flags"
rationale is replaced everywhere (§7 residual, §10.6.2, §11 Q6): the
state creation is constructor-side; the SYN|close variant's closing
flag only accelerates the fresh entry's own reap; the chain needs a
warm next hop or a lapsed seed (cold: packet two hits the transient
seed). The scope conclusion is unchanged and now honestly argued.

**r99-6 (L).** Both candidate-deadline additions are spelled
`saturating_add`, matching the wheel (`expire.rs:50-57`).

## 2. Consistency sweep

The v10.16.0 edit pass touched §3, §5.2 (iv), §5.6, §5.8, §7, §9,
§10.6.2, §11, and the header; each mutated paragraph was re-read in
place (no splice damage; the version-tag audit trail intact). The
gate (§5.1–§5.4, §5.7) is untouched for the fifteenth consecutive
round.

## 3. Bottom line

The fresh-thread rounds 93-99 have driven the purge path to its
honest terminal shape: master-identical except for the gate's own
deliberate refusal, with every pre-existing corner documented with
its trace and every surviving mechanism carrying its full consumer
set. PLAN YES for v10.16.0.
