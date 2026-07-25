# Claude SMR hostile plan-review — round 31 (v9.9.15 @ 842904ac2)

Reviewer: Claude SMR (in-conversation, this agent). Posture: HOSTILE — I wrote
the v9.9.15 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.15-as-committed** — two self-found defects (one HIGH precision gap in the
B2 fold, one MEDIUM stale sentence the M5 fold missed), plus three
nit/accepted-residual items that must be stated explicitly. None of the five
r30 folds is wrong in direction; two are imprecise in text and would draw
justified Codex fire.

## Finding 1 (HIGH — B2 fold precision): the persistent-ADDRESS-ONLY lease arm is not named

The B2 fold ("Persistent-lease ORDINARY peer INSTALLs") speaks only of the
port-bearing persistent lease (`PersistentSourceKey`, `persistent_key:
Some(key)`). But the standby's address-only arm of
`reserve_synced_source_nat_allocation` (`source.rs:894-912`, the
`nat.rewrite_src_port == None` branch) mints a plain per-flow
`reserve_address_only` token — while the ACTIVE node, for a
`persistent-nat` address-only pool, uses the #6041 SHARED lease
(`reserve_address_only_persistent`, `source.rs:1504-1512` v4 /
`source.rs:1615-1623` v6). Same bug class as the port-bearing trace: two
co-holder flows sharing one #6041 address-pinned lease import on the standby
as two independent tokens; the second import's collision behavior and the
post-failover release path diverge from the active node's lease semantics.
The fold's rule ("every initial or replayed peer install of an entry whose
decision belongs to a persistent pool performs an ATOMIC exact
lease-create-or-retain") is correct in generality but the text never names
the address-only persistent arm or `reserve_address_only_persistent`, so an
implementer could close only the port-bearing half. Fix: extend the B2
paragraph to name BOTH arms explicitly (port-bearing persistent →
`persistent_key` lease create-or-retain; address-only persistent →
`reserve_address_only_persistent`-equivalent lease create-or-retain), and
state the derived-key claim for each (the permit is rule config,
`source.rs:302-305`, identical on the standby via config sync — verified:
`PersistentNatPermit` is a rule field, not per-flow state, so no wire
carriage is needed for either arm).

## Finding 2 (MEDIUM — M5 straggler): "never wire-carried in Phase 1" is now false for two fields

The NODE-LOCAL shared-map sentence (§5.8 tail, end of the wire-schema block)
says the additive shared-map fields are "never wire-carried in Phase 1, so
rolling-upgrade safe". Since v9.9.14, `stable_rule_id_hash` and
`admission_config_version` (and `flow_incarnation_id`) ARE wire-carried in
Part B's rolling-gated INSTALL tail — the same section says so three
paragraphs earlier. Only `last_touch_ns` / `expires_after_ns` are truly
node-local. The sentence must be split: identity + selector fields ride the
Part-B tail (trailing-field tolerance, `sync_protocol.go:95-102, :470-497`);
the family-clock fields are node-local only; the shared-map growth itself is
rolling-upgrade safe either way. This is exactly the class of internal
contradiction Codex's r30-H4/M5 pattern hunts — leaving it would be a
self-inflicted round-32 finding.

## Finding 3 (nit — B3): escrow re-entrancy and the never-rebind pin must be stated

The B3 fold generalizes the durable escrow to temporary stops but does not
state: (a) WHY two teardown sequences cannot interleave (stop_inner takes
`&mut self`; the server handlers serialize on the guard mutex; the escrow is
one coordinator-owned object — structural, but say it); (b) what bounds the
pin if rebind never comes (link stays down): workers are down, no reaper
runs, the preserved maps + escrowed ports pin until process exit or rebind —
accepted residual, escape is the operator's permanent stop; state it in §8.
(c) The status.rs:377 disarmed-stop case (`!should_run_afxdp`) now preserves
+ replays sessions whose config may have vanished — the replay's
re-resolution/verify-and-retain (upsert_synced.rs:55-63 HAInactive gate,
incompatible-collision-domain invalidation) is the safety net; the fold
should say so explicitly rather than by implication.

## Finding 4 (nit — B1a): the mode taxonomy must be exhaustive

"PAT / no-translation / ownership mode" omits DETERMINISTIC CGNAT (mode 1) /
NAPT64 (mode 2) (`#5178`, `deterministic_v4`). If deterministic is a sub-mode
of PAT for collision purposes, say so; if it is its own mode, list it. One
sentence.

## Finding 5 (accepted residual — B2): install-rejection standby gap

Rejecting a failed lease-create-or-retain means the standby silently lacks
that co-holder copy until the next resend. Periodic resend + bulk re-sync
make this self-healing; a counter (`nat_persistent_import_rejected_total`)
should be named so the gap is observable. Not verdict-driving.

## Dispositions of r30 findings (my own verification before dispatch)

- r30-B1a: folded (mode in collision domain, structural cross-mode occupancy
  both directions, dual-record/quiesce bridge) — direction correct; Finding 4
  outstanding.
- r30-B2: folded with Finding 1's gap (address-only persistent arm unnamed).
- r30-B3: folded with Finding 3's unstated invariants. Direction verified:
  `stop_workers.rs:7` → `stop()` → `stop_inner(true)`; the synced-map wipe
  moves to the permanent path; rebind bring-up = consuming dataplane. The
  #1921 EBUSY gate is unaffected (records still clear at stop; Go's 1s
  `linkCycleRebindSleep` covers the rebind path).
- r30-H4: folded; full-document grep for "tail ignored" / "falls back" /
  "content version" / "gen-based delete" shows only descriptive mentions of
  legacy-receiver behavior (plan.md:1645 region) consistent with suppression.
- r30-M5: folded except Finding 2's straggler.

## Verdict

**PLAN NO for v9.9.15** — fold Findings 1+2 (text precision, no design
change) as v9.9.15.1, state Findings 3-5 explicitly, then the plan is
convergence-ready pending Codex/AGY round-31 verdicts. Part A remains
untouched and converged since round 12; nothing in this round reopens it.
