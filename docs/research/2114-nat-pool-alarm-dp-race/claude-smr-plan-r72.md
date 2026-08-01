# Claude SMR hostile plan-review — round 72 (plan v73 @ `e33ab4a3a`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r71 pass
returned PLAN-READY-WITH-NITS on v72 while Codex r71 found three MAJORs in
the partition (class-2 synchronization, the 157-method inventory, nested-
call composition) — my r71 enumeration checked outcomes but not the
per-class synchronization rules or composition. Recorded. This pass
attacks the v73 categorized partition directly; all line numbers
re-verified against the worktree.

## A. Fold verification (r71 findings → v73)

### 1. Codex M1 (class-2 synchronization rule) — FOLDED

v73 class-2 acquire-loads `loaded` before the first Start-state access
and returns master's exact missing-map outcome on false. Spot-verified
the named twenty-two: `ClearSessionCounts` (skip-on-absent),
`ClearStaticNATEntries` (guard-per-map), `UpdatePolicyScheduleState`
(deliberate nil, #3780 comment present), `SessionCount`, `GetMapStats` —
each returns its neutral value on gate-false, which IS today's
missing-map outcome. No `m.mu` needed: gated ⇒ no lookup until
population complete. Class-2 joins the blocked-Start overlap. FOLDED.

### 2. Codex M2 (categorized partition + precedence) — FOLDED

Categories L/F/G now cover the fourteen lifecycle/facade methods and the
eleven offset helpers; the escape-first precedence resolves the r71
overlap set (`IsLoaded` → G as the gate read; `Map`/`Program` → 4;
`NewEventSource` → 4 with its error signature); `Mode()`'s home is
corrected to `userspace.Manager` (manager.go:437 — verified).
FOLDED.

### 3. Codex M3 (raw-helper nested-call rule) — FOLDED

`ClearAllCounters` (maps_counters.go:245-262 — verified it calls the
public `ClearInterfaceCounters` at :246 today) now composes through
internal raw helpers per the rule; the pinned legacy error text
(manager_counters_test.go:552) survives. The matrix asserts the
raw-helper shape. FOLDED.

### 4. Codex m1 (residual writers + XDPLinks hazard) — FOLDED

§7 item 12 / §10 now cite :534 (pinned-link reuse, reachable via
manager_compile.go:168's ignored pin-removal errors), :575, :661, the
late-admission schedule (daemon_scheduler.go:170-183,
daemon_apply_commit.go:629), and the raw-`XDPLinks` hazard
(maps_sync.go:943 1 Hz range vs Compile's pre-m.mu mutation) stated as
pre-existing, not worsened. FOLDED.

### 5. Codex m2 (m.mu comment) — FOLDED

loader.go:49's comment joins the §5.5 sweep. FOLDED.

## B. Fresh attacks on the v73 delta

**Attack 1 (FAILED) — category F facades read Start-state at call
time.** `Link()`/`HA()`/`Sessions()`/`Telemetry()` (apply.go:217-235)
construct FRESH controller handles wrapping `m` at call time
(`NewDataPlaneHAController(m)` etc.) and read no Start-populated state;
the returned controllers' methods route to the gated Manager methods
(the r70-verified `HA().SetRGActive` → `bpfShim.UpdateRGActive` chain).
Category F stands. FAILED.

**Attack 2 (FAILED) — category G's IncrementGlobalCounter touches
m.maps.** Its body (maps_counters.go:50-60) takes `m.mu` and writes only
`userspaceCounterOffsets` — Go state, never `m.maps`. Category G
stands. FAILED.

**Attack 3 (FAILED) — the arming-order invariant is violable.** The
attach flow's data dependency forces the order: `AttachXDP` needs
`m.programs`/`m.maps` handles that exist only after
`loadUserspaceShimObjects` completes, and `LoadUserspaceShim`
(:152-166) Stores true as its last statement without attaching; the
attach runs via CompileUserspaceShim, driven post-Load. A future
reordering hits the §9 matrix's pre-arm `AttachXDP` tripwire. FAILED.

**Attack 4 (FAILED) — the class-2 overlap leg cannot discriminate.**
Under `-race`, an UNGATED class-2 lookup racing the population write
trips the detector regardless of the returned value — gated-neutral
and ungated-lucky-neutral are distinguishable by the race report, not
the outcome. The leg discriminates. FAILED.

**Attack 5 (FAILED) — the precedence rule is still prose.** The matrix
asserts one label per method plus the precedence disjointness; the
classification input is each method's actual Start-state access
(enumerated in the audit, re-derived by the AST inventory). A method
whose access pattern changes moves class and fails the matrix until
re-classed — the enforcement is mechanical at the access level, which
is where the r70/v71/v72 prose partitions failed. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None. (r71's nit — the attach-family placement with the arming-order
invariant — is folded in v73's category L text and verified above.)

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v73 keeps PR-1 self-contained.

## Verdict

**PLAN-READY**. Four documented attacks failed against the tree; the
r68-r71 fold chain (armed-state race → universal gate falsified →
partition incomplete → synchronization/categories/composition) is closed
by mechanisms, not wording: the acquire-load gate, the scoped class-3
locking, the raw-helper rule, and the AST-matrix totality net.
