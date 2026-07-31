# Claude SMR hostile plan-review — round 99 (v10.15.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — nineteenth
pass; I authored the v10.15.0 fold (the purge-path retraction). The
review must attack the RETRACTION decision itself. Verdict: **PLAN
YES**.

## 1. The retraction, attacked

The question: does retracting the close-aware purge gate (full master
parity on the transient-purge path, closing packets included) reopen
any close-class kill this plan was chartered to close?

**The issue's core harm is untouched by the retraction.** The blind
off-path RST/FIN demote on a session-HIT entry (lookup.rs:105-128),
its companion propagation, the constructor seeds (2b/2c/3), the
MissingNeighbor arm, and the HA Close propagation are all gated by
Part A + the surviving Part-B rules, none of which the retraction
touches.

**What the retraction concedes:** the close-on-purged-provenance chain
(close #1 purges a peer-synced translated-forward row; a SYN-bearing
close #2 clean-misses and FreshPrimary-installs with closing seeded +
Open; the latest-generation-wins upsert overwrites the peer's family).
Verified against the code at every step across rounds 89-98. The
concession argument: (a) the chain is master's own behavior TODAY —
the purge machinery, the #4400 SYN pass, the raw install + Open, and
the latest-wins overwrite are all unmodified master code paths; (b)
the harm vector is the identity-less Open, which is #6599's subject
(sync-layer identity), not the demote gate's; (c) six rounds (93-98)
demonstrated that every packet-level deviation on this path either
diverges unsafely from master or requires the identity machinery that
IS #6599's fix — the marker's identity-safe lifecycle
(`shared_ops.rs:482-505` unlocked clone, `session_import.rs:42-60`
separate generation check, `:897-958` blind publication replace), its
cross-worker topology (import fan-out `session_import.rs:215-223`;
per-worker purge `promote.rs:167-207`/`shared_ops.rs:960-1013`), and
its cache fencing (`poll_descriptor/mod.rs:298-327` pre-resolution
consumption; no import-side invalidation) are all sync-identity
problems. (d) The cost ledger is one-sided: the gate defended a
master-identical corner while generating 6B/3H of new-plan defects
per round; the retraction deletes the entire defect surface.

**What survives (and why each is safe to keep):** the demote gate (14
rounds finding-free); rule 5 (closing-never-promote — a pure skip);
the 2b/2c constructor gates + probation discipline (local-worker
machinery, extensively fenced rounds 83-98); the `ReplacedSyncedLocal`
close skip (self-contained deliver-without-displace; confirmed sound
by Codex at r91 and unchallenged since); the site-9 typed-outcome arm
gate (the r83-87 live-replacement fix; the purged class rides
master's own split); the overdue-materialize rule (skip-wholesale +
never-refresh-on-overdue + the typed `OverdueSkipped` outcome +
alias-complete cache invalidation at reap).

**The r98-4/5 amendments, verified:** the `OverdueSkipped` outcome
suppresses the terminal teardown on that dispatch (nothing was
installed — the `session_glue/mod.rs:467-581` teardown would
otherwise delete K's family from S2's identity), suppresses the
anchor write (consistent with the never-refresh guard), and
suppresses the cache insert; the probation reap's alias-complete
cache invalidation (`flow_cache.rs:578-580` forward-key vs
`entry.rs:337-343` canonical-key) removes the sessionless-alias
residual — and note master's normal GC invalidates per-key
(`worker/loop_body/mod.rs:1445-1480`), so the probation reap's
alias-complete invalidation is strictly stronger than the natural
expiry path for the alias case.

## 2. Consistency sweep

Every live mention of the retracted line was excised or converted to
retraction narrative (grep-verified: "close-aware", "never purges",
"keeps the shared backing", "UNCONDITIONAL", "marker-conditioned"
survive only in header history and retraction text). §5.2 (iv), §5.8,
§5.6 site-3, site-9 row, §7 residuals, §9 tests, §11 all say master
parity for the purge path with the same words. The gate (§5.1-§5.4,
§5.7) is untouched for the fourteenth consecutive round.

## 3. Bottom line

The plan's Part-B surface has converged by subtraction to the minimal
set that closes the issue's own blast radius. The transient-purge
corner belongs to #6599 and says so with its full trace. PLAN YES for
v10.15.0.
