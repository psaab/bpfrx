# Claude SMR hostile plan-review — round 76 (plan v77 @ `0efb3e398`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r75 nit
(xdpFlagClaims locking) was correctly falsified by Codex r75 (Start never
touches the field) and is withdrawn in v77 — my first over-reach of this
run, recorded. This pass attacks the v77 two-state fold; all line numbers
re-verified against the worktree.

## A. Fold verification (r75 findings → v77)

### 1. Codex M1 (two-state predicate) — FOLDED

Verified the retention facts: `Close` (:1206-1218) closes link handles
only, sets loaded=false, and its own doc comment states the
hitless-restart intent ("leaves pinned maps and links in the kernel for
the next daemon to reuse"); bootstrap retains the Manager
(`bootstrap.go:470`). The two-state rule (fresh: gate fires where master
returned map-not-found; retained: proceed exactly as master) is the
correct preservation semantics, and the watchdog case
(`manager_ha.go:807-815` — the never-throttled timestamp write keeping
the BPF ~2s stale window alive) proves suppression would have been a
live regression, not a wording issue. FOLDED.

### 2. Codex M2 (lock-ownership assertion) — FOLDED

The mutant schedule is real (getter-unlock synchronizes-before the
swap's earlier sections → the read happens-before the mutant write →
-race silent). The in-section hook with the getter-blocks-until-release
assertion (or in-section TryLock) proves ownership, not just execution.
FOLDED.

### 3. Codex m1/m2/m3 (label, Detach leg, fixture mechanism) — FOLDED

§5.1 reads class-3-LIKE; the named Detach leg matches the -run pattern
and carries the error-order qualification (verified :730/:747 return
before any claim mutation); the fixture migration rides the existing
`injectShimMap` reflect/unsafe pattern (manager_testhelpers_test.go:22 —
verified present) with the honest ~30-test inventory. FOLDED.

## B. Fresh attacks on the v77 delta

**Attack 1 (FAILED) — the empty-check discriminator races the first
insert.** The discriminator (loaded==false AND m.maps empty, under
m.mu) versus re-population: the population insert loops take m.mu under
A3, and — verified at loader_userspace_shim.go:175-195 — the inserts
run only AFTER all `ensureUserspaceMapPinned` calls succeed; the error
path closes the collection and returns WITHOUT touching m.maps. So
m.maps is empty (fresh or failed-load — both master's map-not-found
surface) or fully populated; no partial state exists for the
discriminator to misread. FAILED.

**Attack 2 (FAILED) — retained-proceed reintroduces the r68 race.**
A retained-proceed method's Go-map lookup runs under m.mu (the class-2/
3 mechanism), which re-population also takes; the post-lookup library
calls operate on pinned/shared kernel maps via the handle
(`ensureUserspaceMapPinned` reuses shared maps) — library-safe, and the
kernel state is live by design (hitless). FAILED.

**Attack 3 (FAILED) — retained class-1 mutation breaks the L2 claim.**
The L2 claim's final form (§4 A1): fresh-unarmed → the typed error;
mid-re-population → serialized by m.mu; retained-stable → master's
exact behavior. A retained `UpdateRGActive` writes the live retained
rg_active map — that is master's hitless-restart semantics, and the
claim now says exactly that. FAILED.

**Attack 4 (FAILED) — a third unsynchronized field.** The struct sweep
(loader.go:30-60) plus Codex's 4(c) ruling (xdpFlagClaims: Start never
touches it) plus the r73 sweep leave nothing unclassified. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None. (My r75 nit was withdrawn — Codex's ruling verified correct:
xdpFlagClaims writers are all post-arm, and the exposure belongs to
the post-arm residual class, not A3's window.)

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v77 keeps PR-1 self-contained.

## Verdict

**PLAN-READY**. The two-state predicate is the correct preservation
semantics and its discriminator has no partial state to misread; the
ownership assertion closes the last test-proof gap.

---

**ERRATUM (added at v78 fold time)**: attacks 1 and 2 above were
marked FAILED but Codex r76 M1 and AGY r76 M1 proved the
retained-proceed registry race REAL the same round — locking the
writer never protected the unlocked readers, and my attack-2
reasoning covered the Go-map lookup under `m.mu` while the v77 text
left class-1/2/4 post-gate lookups unlocked. The verdict above stood
on v77 as written; v78 folds the uniform registry rule + whole-batch
publication that close it. My attack-1 (no partial state) was
confirmed correct by Codex's partial-load PASS. The SMR pass's
self-correction record for this run now reads: r68 missed the
armed-state race entirely, r69 missed the signature surface, r70
checked outcomes not synchronization, r71 missed the trio's plain
field, r72 missed the stubs + detach shape, r73 caught the deadlock
(triple-confirmed), r74 missed the retained-claim cleanup, r75
over-reached (withdrawn), r76 missed the unlocked-reader race.
