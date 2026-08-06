# Claude SMR — hostile plan review r5 of `plan.md` v6-r5 (#2387)

Reviewed at `e80db2eae`. This is my convergence pass. I re-read the whole document
hostile rather than checking off my own r4 list, because a reviewer confirming their
own resolved findings is not a review.

## Disposition of my r4 findings — I lost both, correctly

- **SMR-12 (FLUSH → MARK): conceded.** AGY's rebuttal is stronger than my objection.
  The entries are standby replicas so no live traffic is interrupted, and the duration
  asymmetry is decisive — a seconds-long resync window against a fail-open lasting the
  full remaining lifetime of every affected session. For a cross-tenant hijack that
  trade is clear. I verified the scoping primitive AGY cited: `is_peer_synced()` at
  `session/entry.rs:245` over `SessionOrigin::SyncImport` (`:221`). Real.
- **SMR-13 (900k band): withdrawn.** A config whose RIs collide in that band is already
  rejected today, so reusing the value adds no new commit failure. What survives is a
  preference, and the plan now states it as one.

## Fresh pass — three stale-text defects found and fixed in v6-r5

The r4 change deleted the interner, but three places still described it as live scope:
the Path C cost line, the recommendation paragraph, and the C-P0 ownership note (which
still claimed C-P0 "is more than plumbing" on the strength of a table that no longer
exists). All three now read against the pure-function design. This is exactly the class
of defect this project's own convention warns about — a doc whose body contradicts its
own changelog — and it was worth a full re-read to catch.

## What I checked and did not find wrong

- **Domain 0 reservation.** With derivation into the `[100000, 999999]` band, 0 is
  disjoint by construction. If the implementer takes the plan's *preference* and
  derives into a full `u32` instead, **0 is no longer disjoint by construction** and
  must be explicitly reserved. The plan says "domain 0 must stay reserved", so the
  obligation is stated — but this is the one place where following the plan's
  preference makes a property that is otherwise free into something that must be
  actively maintained. Worth an implementer's attention; not a plan defect.
- **The three PRs are independently gated** and C-P0 is now genuinely stateless, so the
  series can stop after C-P0 or C-P2 without leaving a half-built mechanism.
- **§7a inventory** — two reviewers now agree on its contents, including the deliberate
  exclusion of VXLAN and IP-in-IP, which AGY conceded were its own error.
- **The unmeasured "~1-3%"** from the prior decision record remains struck, and §4.4
  still states the measurement obligations rather than a number. No performance claim
  has crept back in across five revisions.

## The honest terminal position

The defect is real, reachable, and I proved the reachability ordering first-hand rather
than inheriting it. The two objections that drove the previous PLAN-DEFER are both
retired — the wire objection by §4.3, the interner objection by reusing machinery that
already exists. The design is now stateless, rolling-compatible, and staged into three
independently gated PRs.

**One thing remains a judgement call and I will not pretend otherwise:** §4.3b requires
changing `parseHAProtocolCompatible` from exact equality to a declared-floor
comparison. That gate decides whether *any* release is rolling-upgradable. Adopting the
vestigial `MinCompatHAProtocolVersion` is what its doc comment describes, but it has
never been wired, so this is a new contract rather than a restoration. A maintainer may
reasonably decline that for a niche config. **If reviewers conclude the cost is not
justified, PLAN-KILL is an acceptable verdict** — and §3a records the obligation that
comes with it: the shipped A.1 warning promises isolation is coming, so a PLAN-KILL
must rewrite that text into a statement of permanent non-support.

**VERDICT: PLAN-READY**

Ready for `/engineer` as a three-PR series, C-P0 → C-P2 → C-P3, with the maintainer
decision on the ISSU predicate taken before C-P3 is started (C-P0 and C-P2 do not
depend on it, so the series can begin either way).
