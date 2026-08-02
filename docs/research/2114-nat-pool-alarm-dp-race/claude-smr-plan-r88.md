# Claude SMR hostile plan-review — round 88 (plan v90)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r87 pass
accepted v88's "complete 11-site" inventory claim after my own sweep —
but my sweep only looked for NON-comma-ok reads, missing that Codex's
r87 finding was about the OPTIONAL class (if-ok reads included), so I
verified the wrong set. AGY r88 then caught v89's arithmetic
contradiction (summary "13+3=16" vs body's 14 enumerated) and the
missing §9 IsLoaded leg. Recorded: an inventory verification must
classify EVERY read, not only the shape outliers. This pass classifies
all 135 reads, then the rest. NOTE: this review targets v90 (the fold
of AGY r88's two blocking minors); Codex r88 (task-msbc0207-pjmnbd) is
still running against v89 and its log shows it independently found both
defects — its verdict lands on a superseded revision and will be
verified against v90 on arrival.

## A. Fold verification (AGY r88 findings → v90)

### 1. AGY b1 (the missing §9 IsLoaded-window test leg) — FOLDED

The v89 text claimed "the §9 teardown legs assert this directly" with
no named leg — verified the absence at v89 (§9 had legs (1)-(4)
only). v90 adds leg (5),
`TestManager_ArmedGate_CloseWindowIsLoaded`: Close held at a hook
after the entry Store(false) (loader.go:1206), a concurrent
IsLoaded / REST health.go:107 / gRPC server_show_status.go:22 read
observes DataplaneLoaded==false during the window where master
(flip at :1217's exit) reports true. The chain re-verified against
the tree: IsLoaded at loader.go:456-458, the adapter at
legacy_dataplane.go:86, the REST read at health.go:107
(statusHandler), the gRPC read at server_show_status.go:22
(GetStatus). FOLDED.

### 2. AGY b2 (arithmetic + terminology) — FOLDED

My full 135-read classification this pass (not a shape-outlier
sweep): 79 required (error on absent), 17 mixed-subset optional
(14 if-ok: maps_nat.go:261/:274/:300/:328, maps_stale.go:224/:241/
:285/:291/:322/:328/:336, maps_session.go:327/:337, loader.go:730;
3 nil-guard: compiler.go:353, loader.go:591, loader.go:700), the
single-map neutral set (12 stale cleanups at maps_stale.go:18/:41/
:65/:93/:117/:148/:178/:201/:262/:309/:348/:371 + maps_counters.go:181
+ maps_stats.go:72), the mixed-method neutral-returns (maps_nat.go:400/
:435, maps_policy.go:253, maps_session.go:612, loader.go:910/:928,
maps_counters.go:233), 3 publisher writes, 2 getter returns, 1
NewEventSource nil-check. v90's text now says 14+3=17 for the mixed
subset, scopes it explicitly against the ~41 total neutral-outcome
accesses, and names the single-map neutral set with line numbers.
The arithmetic is now internally consistent (header narrative,
inventory body, and §11 item 7 all agree; the two remaining "13+3=16"
strings are the historical narrative describing v89's error, correctly
attributed). FOLDED.

## B. Fresh attacks on the v90 delta

**Attack 1 (FAILED) — the single-map neutral set is misclassified.**
The 12 stale cleanups are void methods with `!ok → return`
(verified: DeleteStaleIfaceZone at maps_stale.go:16-20,
DeleteStaleVlanIface at :40-44 — absent map means silent no-op).
Under the plan's precedence rule (class-2 = neutral missing-map
outcome, any signature) they classify class-2, and their absent
outcome is preserved byte-for-byte. No error-signature method is in
the set. FAILED.

**Attack 2 (FAILED) — the mixed-method neutral-returns break the
class-1 row.** ClearNATRuleCounters (maps_nat.go:396-400) resets the
offsets then `!ok → return nil` on nat_rule_counters — its METHOD is
error-signature (class-1/2 boundary), but the per-access rule wraps
the lookup and keeps master's neutral return on absent. The class-1
matrix row governs only the method's REQUIRED accesses; this access
is optional/neutral. Consistent. FAILED.

**Attack 3 (FAILED) — leg (5)'s hook is unimplementable.** The hook
sits between the entry Store(false) (:1206) and the link closes —
the same instance-scoped ownership-hook protocol as the other legs
(one hook armed per test). Close's body is a straight-line sequence;
the interval contains the hook call by construction (the /engineer
pass places it). FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v90 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the inventory is now complete AND correctly scoped
(full 135-read classification this pass: 79 required, 17 mixed
optional, 14 single-map neutral, 7 mixed-method neutral-returns, 3
writes, 2 getters, 1 NewEventSource check), the arithmetic is
internally consistent, and the §9 oracle set carries the IsLoaded
window leg. My r87 verification-of-the-wrong-set miss is recorded;
this pass classified every read. Codex r88's verdict on v89 lands
separately; its two independently-found defects are exactly the two
v90 folds.
