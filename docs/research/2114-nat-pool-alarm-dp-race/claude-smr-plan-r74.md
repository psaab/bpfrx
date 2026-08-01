# Claude SMR hostile plan-review — round 74 (plan v75 @ `e42b3429c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r73 nit
(the trio deadlock + the fourth writer) was independently found by all
three reviewers — first full triple-confirmation of the run. This pass
attacks the v75 fold; all line numbers re-verified against the worktree.

## A. Fold verification (r73 findings → v75)

### 1. The locked-helper scheme (Codex M2 / AGY item 1-2 / SMR r73 m1) — FOLDED

The scheme as specified avoids both hazards: `xdpEntryProgramLocked()`
raw helper; each public accessor takes `m.mu` ONCE and delegates —
`Using...` locks once and calls the helper, never the public getter (no
re-entrancy); `swapXDPEntryProg`'s :632 write moves under a SCOPED
section (never whole-method — verified swapXDPEntryProg calls the getter
and performs link updates, so whole-method locking would recurse AND
hold across updates). Full access inventory: :47 decl, :97 init
(pre-publication), :106/:109 getter, :115 selector, :632 swap — every
access covered; the status readers (maps_sync.go:481/:947) call the
public getter, which locks. FOLDED.

### 2. DetachXDP mixed classification (Codex M1) — FOLDED

Verified the shape: absent-link early return at :640-642 reads only the
construction link map (category-G nil preserved); the nonempty path
delegates to `setXDPAttachedFlag` (:650), which reads `m.maps`
(:700/:730 — verified the no-map early return at :699-704 returns nil
as "no-op success", identical to master's pre-arm behavior). The
delegation target as a class-2 internal (gate-false → that same nil
path) preserves behavior on re-arm and closes the race. Callers of
setXDPAttachedFlag are exactly :515 (AttachXDP) and :650 (DetachXDP) —
both classed paths. The seeded re-arm leg is in the matrix. FOLDED.

### 3. The dedicated XDP test seam (Codex M3) — FOLDED

The population-only barrier objection is real (the :154 selector write
precedes the population barrier); the second entered/resume barrier
around :154 with getter/predicate/swap driven across it proves the
synchronization under -race. FOLDED.

### 4. SwapToUserspaceXDPShimEntryProgram → class 1 (AGY) — FOLDED

Verified :604 delegates to swapXDPEntryProg reading `m.programs` (:609)
— Start-populated; class-1's typed error replaces the pre-arm "XDP
program not found", the intended class-1 change. FOLDED.

### 5. The VlanSubInterfaces adjudication — CONFIRMED SOUND

Independently re-verified Codex's scoping: `userspace.Manager.Start`
only delegates to Load (manager.go:370); the status loop starts at
`ensureStatusLoopLocked` (manager_compile.go:399) only after a
successful Compile; the field's writers are Compile-time
(loader.go:201, compiler.go:441) plus the swap-path read (:622). No
Start-window overlap exists, so the residual does not violate the L2
claim's scope. The disposition (residual + completed inventory + named
first cheap-follow-up fix) is honest and keeps the fatal-crash-class
hazard visible with a concrete fix. FOLDED/CONFIRMED.

### 6. Minors (oracle wording, §5.1/§5.5/§6 alignment) — FOLDED

§9 asserts TOTALITY (matching §4's honest oracle); §5.1 carries the
locking edits + the Swap assignment; §5.5's m.mu comment names the
field; §6 reads side-effect-plus-PINNED-OUTCOME. FOLDED.

## B. Fresh attacks on the v75 delta

**Attack 1 (FAILED) — an uncovered xdpEntryProg access remains.** The
full-access grep (:47/:97/:106/:109/:115/:632 + the two status-path
callers through the public getter) is closed under the scheme. FAILED.

**Attack 2 (FAILED) — the class-2 internal for setXDPAttachedFlag
changes master's error surface.** Master's pre-arm nonempty-detach path
returns nil via the no-map early return (:699-704); the class-2
internal returns the same nil on gate-false. No divergence. FAILED.

**Attack 3 (FAILED) — the seeded re-arm leg is unconstructable.** The
matrix test builds a Manager, inserts into `xdpLinks` directly (same
package), and never arms — plain. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None — the v75 folds are precise, and the r73 triple-confirmed deadlock
is correctly repaired by the locked-helper scheme.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v75 keeps PR-1 self-contained.

## Verdict

**PLAN-READY**.
