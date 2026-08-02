# Claude SMR hostile plan-review — round 86 (plan v87 @ `66256246946b`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r85 pass
verified the typed pair's escape shape but, like AGY, did not enumerate
the (class × state × presence) cells against real methods — Codex r85
found the class-2/class-4 outcome contract was not total. Recorded: a
signature-level pass that skips the cell enumeration is not a review of
an outcome contract. This pass walks the cells first. All line numbers
re-verified against the worktree.

## A. Fold verification (r85 findings → v87)

### 1. Codex M1 (total outcome matrix) — FOLDED

The matrix is now a full class × (fresh / armed-or-retained-absent /
armed-or-retained-present) table. Cell-walked against real methods:

- Class-1 (`swapXDPEntryProg`, loader.go:609-611): fresh → typed
  error (replaces master's "%s not found" on the empty registry);
  armed+absent → master's missing-map error (:610's `!ok` branch);
  present → proceed. All three cells match.
- Class-1 carve-out set (`AttachXDP` loader.go:490-497, `AttachTC`
  :1082-1088): master produces a missing-PROGRAM error for absent
  keys (:496 "%s not found", :1087 "tc_main_prog not found") — the
  matrix's class-1 armed+absent cell holds for the carve-out set
  too. No class-1 method nil-panics or silently proceeds on absent
  keys — every production comma-ok lookup has an error/continue
  branch (the 127 comma-ok reads per Codex r85's verified pass).
- Class-2 (`SessionCount` maps_session.go:326-330, `ClearSessionCounts`
  maps_screen.go:57-62, `GetMapStats` maps_stats.go:69-75): fresh →
  neutral (empty counts / nil / empty stats — master's behavior on an
  empty registry); armed/retained+absent → master's missing outcome
  (skip/continue — the `!ok` branches); present → proceed (count /
  mutate / report). All cells match.
- Class-3 (ClearAllCounters raw-helper composition): state-independent
  pinned legacy behavior — the class-3-LIKE DetachXDP delegation
  (cleanup always runs) matches.
- Class-4 (`Map`/`Program` getters, loader.go:1150-1157): fresh →
  nil (master's empty-registry return); armed/retained+absent → nil
  (master's missing-key return); present → the handle. All cells
  match.
- The fresh+present production-unreachable note is CORRECT: the
  two-state predicate reads `m.maps` emptiness (:3696), so a
  program-only seed is FRESH — which is exactly what m4's fixture
  fix accounts for.
- No residual v86 partial phrasing: the only "present→proceed"
  occurrences are the v87 fold texts themselves.

### 2. Codex m2 (pluralization) — FOLDED

All four sites verified: the uniform registry-access rule (:3676-3679
now names the helper pair), the §4.7 inventory bullet (:4141-4144
"helper PAIR"), the `m.mu` contract comment (:4330-4335 "helper
PAIR"), the ownership test (:4791-4795 "exercises BOTH typed
helpers"). A fifth-site hunt: zero "single `m.mu`-scoped" / "single
registry helper" occurrences remain (grep count 0).

### 3. Codex m3 (fourth teardown site) — FOLDED

§9's fixture-scope rationale (:4746-4751) now reads "an ARMED
Manager's Close and Teardown both present loaded=false + a nonempty
registry" with the loader.go:89 evidence. Zero "Close and Teardown
both" unqualified occurrences remain.

### 4. Codex m4 (swap fixture state) — FOLDED

The fixture (:4726-4736) now seeds `m.programs["test_prog"]` PLUS any
one `m.maps` entry, classifying RETAINED under the two-state
predicate; the text explains the v86 defect (program-only seed →
fresh → gate fires before :632) and the consistency with the
predicate (`m.maps` emptiness is the discriminator).

## B. Fresh attacks on the v87 delta

**Attack 1 (FAILED) — the matrix contradicts the loaded-check
carve-out.** The carve-out set (AttachXDP/AttachTC/CompileConfig)
preempts the helper on BOTH unarmed states per the matrix's own
footnote row — and the class-3 row's state-independence cannot
conflict because no carve-out method is class-3 (the plan assigns
the attach family class-1, §4.7's inventory bullet). FAILED.

**Attack 2 (FAILED) — class-3's "state-independent" row hides a
fresh-cell defect.** Class-3 methods are required-side-effect
hybrids whose outcomes are pinned to master's regardless of state;
on a fresh registry master's outcome is the pinned legacy behavior
itself (e.g. ClearAllCounters' composed error text) — the row
reproduces it verbatim. FAILED.

**Attack 3 (FAILED) — the fresh+present-wins-fresh rule creates a
hazard.** Fresh+present is production-unreachable for MAP lookups
(the publisher's whole-batch hold means a map-present registry is
never observed with loaded==false except via Close's retention,
which is retained-not-fresh by construction since m.maps is
nonempty). If a test constructs it artificially, fresh wins — the
conservative direction (typed error, not a silent proceed). FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v87 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the outcome matrix is now total and reproduces
master's observable behavior in every reachable cell I walked (all
four classes, real methods, comma-ok patterns verified); the
pluralization, the fourth teardown qualification, and the fixture
state fix all verified against the tree. My r85 miss (skipping the
cell enumeration) is recorded; this pass ran it first.
