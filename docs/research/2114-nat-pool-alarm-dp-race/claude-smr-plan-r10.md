# Claude SMR hostile plan-review — round 10 (plan v10 @ `b4f1c6548`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r10 targeted
the v10 delta (double shutdown guard, compiled-topology predicate) and
independently verified the parallel Codex/AGY r10 findings against worktree
code. All line numbers re-verified (origin/master `ed6999000` +
plan-doc-only branch).

## A. Independent verification of the v10 delta

1. **Double guard determinism** — `runCtx` as Run's signal child
   (`daemon_run.go:86` derives it via `startupSignalContext`, captured at
   the TOP of Run): ctx cancellation is synchronous, so the `Err()` arm
   is race-free for every signal-driven path. VERIFIED sound as far as
   v10 specified it — but see M1/M2 below; the v10 text left two holes.
2. **Compiled-topology predicate** — `ActiveConfig()` returns `s.compiled`
   (`store_format.go:55-60`); `s.compiled` assigned at
   `store_persist.go:111` before recovery at :113; the compile-failed
   path returns at :108 WITHOUT reaching recovery (so the guard never
   sees a nil compiled from that path); runtime cluster construction
   reads the compiled config (`daemon_run_bringup.go:161-164`).
   VERIFIED sound.
3. **Honest in-flight bound** — `applyCloseoutDrainTimeout = 5s`
   (`daemon_run_shutdown.go:15`); drain-then-proceed (:50-58). The v10
   framing was directionally honest but over-claimed "not worsened" (see
   m3).

## B. Findings (2 MAJOR, 4 MINOR — independently reached; all match the
## parallel Codex r10 set, which I verified line-by-line before folding)

### MAJOR

**M1. `stopping` publication placement is under-specified — "before the
drain" admits a post-`applyCancel` placement with a live admission
window.** `runShutdownSequence` opens with `d.applyCancel()` inside
`if d.applyCancel != nil` (`daemon_run_shutdown.go:34-35`), THEN the
drain (:50-58). v10 pinned the Store only "BEFORE its applySem drain
block". An implementation placing it between `applyCancel()` and the
drain satisfies v10 while leaving the interactive-exit path (no ctx
cancellation, `daemon_run.go:741-748`) open: a timer admitted in the
applyCancel→Store window observes both guards false and starts
non-cancellable work. Verified against the shutdown-source structure.
REQUIRED: first-statement placement (before `applyCancel`) + an
injected-`applyCancel` ordering assertion in the actual-path test leg.

**M2. The GuardedHash binding is computed over the Load-MUTATED tree — a
pre-existing #5835 stale-drop that also bypasses work item H.** Load
mutates the on-disk tree before recovery: `rewriteRetiredDataplaneType`
(`store_persist.go:65`) drops retired leaves with NO Inactive check
(`isRetiredDataplaneLeaf`, `dataplane_retire.go:215-224` — I read the
function; it keys only on `child.Keys[0] == "dataplane-type"` +
membership in `retiredDataplaneTypes`), and `SanitizeTreeControlChars`
scrubs in place (:75-82). Recovery binds `rec.GuardedHash` against
`journalConfigHash(s.active)` (:159) — the MUTATED tree — while the
commit persisted the hash of the RAW promoted tree
(`store_commit.go:543-549`). A current-build candidate carrying
`inactive: system dataplane-type ebpf` commits cleanly (compiler prunes
inactive subtrees FIRST, `config/compiler.go:2257-2268` — verified the
#2008 H1 comment), and the reboot-time rewrite deletes the leaf → hash
diverges → record dropped as stale → unconfirmed config stands. This is
a master #4577 violation TODAY for every record class (not just H's);
in the r8 recurrence state it silently bypasses H. REQUIRED: capture the
on-disk hash BEFORE all Load migrations and bind against it; regression
test (viii). (The retire-rewrite-skips-inactive alternative is rejected:
it changes migration behavior and leaves the sanitize pass as a
divergence source.)

### MINOR

**m1. Nil-`runCtx` panic.** `.Err()` on a nil `context.Context`
interface panics; the executor fixtures construct `&Daemon{}` directly.
REQUIRED: nil-safe guard + fixture `runCtx: context.Background()` (also
AGY f1; the `runCtxOrBackground()` helper mirrors `applyCancelCtx`,
`daemon_apply.go:118-125`).

**m2. Production `runCtx` binding not fail-on-revert tested.** The
manual-injection legs stay green if Run stores the raw parent or omits
the assignment. REQUIRED: signal-child wiring assertion (pattern
`startup_signal_5807_test.go:16-42`).

**m3. "Not worsened" over-claim.** The gate delays an early-fired timer
to END-of-PHASE-5; master dispatches immediately. Overlap LIKELIHOOD
can increase (no longer body, no larger worst case). REQUIRED: narrowed
claim, stated openly.

**m4. Docs sweep misses `db.go:161-168`** (confirmRecord doc promises
unconditional re-arm). REQUIRED: add to §5.5.

## C. The finding I adjudicate DIFFERENTLY from Codex (M3 — recorded
## openly for reviewer overrule)

Codex M3: "H's revert can be undone by bootstrapFromFile in the same
boot" — proposing recovery suppress the file import. My verification of
the chain: post-guard state (empty tree, `compiled=nil`,
`everCommitted=false`) is BIT-IDENTICAL to the expired-during-downtime
FirstCommit path — and master's expired path flows into the SAME
`shouldBootstrapFromFile` import (`bootstrap.go:77-79`,
`daemon_run_bringup.go:313-334`). The daemon NEVER writes DB state back
to the seed file (verified: config writes go to `.configdb/` via
fsatomic; `xpf.conf` is read-only seed). So the import cannot resurrect
the unconfirmed DB config — only the operator's baked seed; the
unconfirmed delta is gone, which IS the rollback contract. On an HA
node the boot class resolves NORMAL via the node-id guard
(`bootstrap.go:243-245`), never bootstrap — no hybrid can arise, which
is the guard's actual safety goal. Suppression would strand the node
config-less and diverge from #4577's own expired-path semantics.
ADJUDICATED: document the consistency + parity regression (ix); reject
suppression. If Codex/AGY insist on suppression in r11 with a concrete
harm scenario the parity argument doesn't cover, I will re-weigh.

## D. Verdict

**NEEDS-REVISION** (2 MAJOR + 4 MINOR, all folded into v11; plus the M3
adjudication documented). The dpCell architecture and work-item-G/H
shapes remain sound; v11's holes were placement/binding/doc specifics,
not structure.
