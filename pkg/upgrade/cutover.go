package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade/manifest"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// Options modify a single Run.
type Options struct {
	// SkipStartHealthRollback disables the post-start auto-rollback (used
	// by the HA path, where rollback is operator-driven, plan §8 inv. 8).
	SkipStartHealthRollback bool

	// UnitAlreadyStopped tells Run to SKIP the STOP step because the caller
	// already stopped the unit. Default false => Run owns the stop (the
	// standalone single-node flow). The HA rolling driver currently does
	// NOT set this — Runner.Run performs the stop after the node has been
	// drained to its peer via the cluster state machine, so the cluster
	// keeps forwarding regardless.
	UnitAlreadyStopped bool

	// LockAlreadyHeld tells Run NOT to acquire the host-wide upgrade lock
	// because a caller higher in the stack already holds it (#1965). The
	// `--rolling` driver (RunRolling) acquires the lock at its entry and
	// holds it through the peer-check + drain + cut + rejoin; the inner
	// r.Run() it invokes MUST set this, because a second flock on a fresh
	// fd of the same file returns EWOULDBLOCK and would abort the rolling
	// upgrade. The standalone single-node flow (and the postinst cut) leave
	// it false so Run owns the lock.
	LockAlreadyHeld bool

	// AllowNoRollbackFirstCut sanctions a cut whose PreviousVersion is empty
	// (#1964 mechanism C). C is an UNCONDITIONAL pre-STOP invariant (plan §8
	// inv. C): the cut NEVER calls StopUnit unless either a restorable
	// rollback target exists (PreviousVersion != "" — flip/start failure can
	// recover by re-flipping the previous version) OR this flag explicitly
	// sanctions a no-rollback first cut (no prior daemon to preserve). In the
	// sanctioned case a flip failure still restarts the first-install binary
	// from versions/current so the daemon is never left offline.
	//
	// With the #1964 first-install seed (A) and legacy-migration snapshot
	// (B), versions/current — and therefore a non-empty PreviousVersion —
	// exists on every field host, so an unsanctioned PreviousVersion=="" cut
	// is refused as an unexpected loss of the rollback target rather than
	// silently stopping a daemon it cannot recover. This flag is set only by
	// the deliberate first-cut path (e.g. seeding failed and the operator
	// chose to proceed), never by the routine postinst/operator cut.
	AllowNoRollbackFirstCut bool
}

// errNoSourceGeneration is the INIT sentinel for "no published staged
// generation to cut from" (#1981 Option B). The caller refuses pre-PREFLIGHT
// with no journal written and no DB snapshot taken.
var errNoSourceGeneration = fmt.Errorf("no published staged generation")

// resolveSource determines the VERSION-COMPARISON source and the source
// generation a FRESH cut would pin (#1981 Option B). The returned dir is used
// only to read the staged version (which keys the resume-vs-fresh decision);
// the COPY itself reads j.SourceGeneration (pinned at INIT) — copyStaged
// resolves that independently. The returned genid is what the INIT block pins
// into j.SourceGeneration for a fresh cut.
//
// Resolution prefers the LATEST published generation (current-gen) for BOTH
// fresh and resume, so that a newer apt install that PUBLISHED a new generation
// is detected by the resume-vs-fresh version compare (a superseded cut then
// recovers + starts fresh against the new generation) rather than silently
// resuming the abandoned one. A same-version republish leaves the version
// unchanged, so the resume-vs-fresh compare does NOT trip and the resume keeps
// its ORIGINALLY-pinned generation (B-P3: a resume never switches sources
// mid-cut — copyStaged still reads j.SourceGeneration).
//
//   - current-gen present: comparison source = current-gen dir; the genid a
//     FRESH cut would pin = current-gen.
//   - current-gen ABSENT but the journal pinned a generation that still exists
//     (a resume whose generation has not been GC'd): comparison source = the
//     pinned generation dir, so a resume is NOT blocked by a missing
//     current-gen. genid = the pinned generation.
//   - current-gen ABSENT, no pinned generation, but an already-COPIED journal:
//     the pre-#1981 legacy in-flight case — comparison source = live staged/,
//     genid = "" (copyStaged keeps reading live staged/). Back-compat so the
//     runner never blocks recovery of an in-flight pre-B cut (plan §10 AGY r4).
//   - current-gen ABSENT, fresh cut: errNoSourceGeneration (the caller refuses
//     pre-PREFLIGHT — no journal, no DB snapshot).
func (r *Runner) resolveSource(j *Journal) (genid, dir string, err error) {
	sg := r.stagedGenConfig()

	if j.SourceGeneration != "" && !stagedgen.ValidGenID(j.SourceGeneration) {
		return "", "", fmt.Errorf("journal source generation %q is not a safe path segment",
			j.SourceGeneration)
	}

	cur, rerr := sg.ResolveCurrent()
	if rerr != nil {
		return "", "", fmt.Errorf("resolve staged generation: %w", rerr)
	}
	if cur != "" {
		// Latest published generation drives the version compare AND the
		// fresh-INIT pin.
		return cur, sg.GenDir(cur), nil
	}

	// No current-gen. Do not block a resume whose pinned generation still
	// exists (defensive: it is protected from GC while journaled).
	if j.SourceGeneration != "" {
		d := sg.GenDir(j.SourceGeneration)
		if fi, serr := os.Stat(d); serr == nil && fi.IsDir() {
			return j.SourceGeneration, d, nil
		}
		// No %w-with-nil: the error is the same whether Stat failed or the path
		// is not a directory — the pinned generation is unusable and there is no
		// current-gen to fall back to.
		return "", "", fmt.Errorf("pinned source generation %s missing or not a directory "+
			"and no current-gen (re-run after re-publishing the staged set)", j.SourceGeneration)
	}

	// Pre-#1981 legacy in-flight journal that already copied from live staged/.
	if j.State.atLeast(StateCopied) {
		return "", r.cfg.StagedDir, nil
	}

	// Fresh cut with no published generation.
	return "", "", errNoSourceGeneration
}

// Run executes (or resumes) the cut-over to the staged version. It is
// idempotent: a crashed run re-invokes Run and resumes from the journal.
//
// The standalone single-node flow. The HA rolling driver wraps this with
// a controlled drain (rolling.go).
func (r *Runner) Run(opts Options) (err error) {
	// Acquire the host-wide upgrade lock BEFORE any journal read or live
	// mutation, unless a caller higher in the stack already holds it (the
	// --rolling driver — #1965). Holding the lock from here through return
	// serializes this cut against a concurrent operator cut, the postinst
	// cut, and a `kernel arm`. Release on every exit path (normal, error,
	// panic) via defer. The standalone single-node flow owns the lock; the
	// rolling driver sets LockAlreadyHeld so the inner cut does not try to
	// re-flock the same file (which would EWOULDBLOCK and abort).
	if !opts.LockAlreadyHeld {
		h, lerr := acquireUpgradeLock("upgrade", "")
		if lerr != nil {
			return fmt.Errorf("upgrade: %w", lerr)
		}
		defer func() { _ = h.Release() }()
	}

	j, err := r.loadJournal()
	if err != nil {
		return err
	}

	// A loaded journal's version fields key versions/<ver>, the .dbsnap
	// dotfile, the `current` symlink, and the unit drop-in (#1964 C1). A
	// crafted/format-drifted journal must not escape VersionsDir, so validate
	// them BEFORE any path use — including the rollback-resume below, whose
	// flip(j.PreviousVersion) keys paths by the previous version. An empty
	// PreviousVersion is the legitimate first-cut case, so it is exempt here
	// (the refuse-before-STOP guard handles "no previous").
	if j.TargetVersion != "" {
		if verr := ValidateVersionSegment(j.TargetVersion); verr != nil {
			return fmt.Errorf("journal target version unsafe: %w", verr)
		}
	}
	if j.PreviousVersion != "" {
		if verr := ValidateVersionSegment(j.PreviousVersion); verr != nil {
			return fmt.Errorf("journal previous version unsafe: %w", verr)
		}
	}

	// Resume an interrupted auto-rollback FIRST (Codex r1 Critical#1): a
	// crash mid-rollback must complete the rollback to PreviousVersion, not
	// resume the failed forward cut. rollback() clears the journal on
	// success.
	if j.State == StateRollingBack {
		r.logf("upgrade: resuming interrupted rollback to %s", j.PreviousVersion)
		if rbErr := r.rollback(j); rbErr != nil {
			return fmt.Errorf("resume rollback: %w", rbErr)
		}
		return nil
	}

	// Resolve the SOURCE the cut copies from (#1981 Option B). A B-aware cut
	// reads a PINNED, immutable staged-gen/<genid>/ that dpkg is NOT rewriting,
	// never live staged/. resolveSource returns:
	//   - a non-empty srcGen + its directory when current-gen is present (a
	//     fresh cut) or the journal already pinned a generation (a resume);
	//   - ("", StagedDir, nil) for a pre-#1981 legacy in-flight journal that
	//     was already copied from live staged/ — back-compat so a B-aware
	//     runner never blocks recovery of an old cut (plan §10 AGY r4);
	//   - noSrcGen for a fresh cut with NO published generation — the caller
	//     refuses pre-PREFLIGHT (no journal, no DB snapshot).
	srcGen, srcDir, srcErr := r.resolveSource(j)
	if srcErr == errNoSourceGeneration {
		// REFUSE-AT-INIT, no source generation: a fresh cut cannot proceed
		// without a published staged-gen/current-gen. Refuse BEFORE any journal
		// write or DB snapshot (Codex r1-#3 closed by construction). Clear any
		// lingering on-disk journal from a just-completed resume-vs-fresh
		// recovery so a re-run starts clean.
		if cerr := r.clearJournal(); cerr != nil {
			r.logf("upgrade: WARN clear stale journal on no-source refuse: %v", cerr)
		}
		return fmt.Errorf("refuse-before-PREFLIGHT: no published staged generation "+
			"(%s/%s is absent); the package operation has not finished publishing the "+
			"staged set, or the runtime needs seeding. Let `apt`/`dpkg` finish, run "+
			"`xpfd publish-generation` (or `dpkg-reconfigure xpf`), then re-run the "+
			"upgrade", r.cfg.StagedGenDir, stagedgen.CurrentGenLink)
	}
	if srcErr != nil {
		return srcErr
	}

	// Re-pin a pre-#1981 legacy resume that has NOT yet copied (Codex r5-#4):
	// a journal at STAGED/PREFLIGHT with an empty SourceGeneration was written
	// by an old (pre-B) binary. If a generation is now published, adopt it as
	// the pinned source (and persist) so copyStaged reads the pinned generation
	// rather than falling back to live staged/. A State >= COPIED legacy
	// journal already copied from live staged/, so it keeps the legacy source
	// (its bytes are already on disk); only the not-yet-copied case is re-pinned.
	if srcGen != "" && j.SourceGeneration == "" && j.State.atLeast(StateStaged) && !j.State.atLeast(StateCopied) {
		r.logf("upgrade: re-pinning a pre-#1981 resume (state %s) to published generation %s", j.State, srcGen)
		j.SourceGeneration = srcGen
		if serr := r.saveJournal(j); serr != nil {
			return fmt.Errorf("persist re-pinned source generation: %w", serr)
		}
	}

	// Identify the staged version from the RESOLVED source (the pinned
	// generation, never live staged/). It keys versions/<ver> et al. on a
	// fresh cut, so validate it as a safe single path segment BEFORE any path
	// use (#1964 C1) — `git describe`-derived versions can carry a `/` (a
	// branch-named tag), which would otherwise escape VersionsDir.
	stagedXpfd := filepath.Join(srcDir, "xpfd")
	stagedVer, err := r.cfg.Sys.BinaryVersion(stagedXpfd)
	if err != nil {
		return fmt.Errorf("read staged version (%s): %w", stagedXpfd, err)
	}
	if verr := ValidateVersionSegment(stagedVer); verr != nil {
		return fmt.Errorf("staged version is not a safe path segment "+
			"(refusing to key versions/ by it): %w", verr)
	}

	// Resume-vs-fresh: if a journal exists for a DIFFERENT target than the
	// now-staged version, the previous attempt was superseded by a newer
	// apt install. Recover the live system to a consistent state BEFORE
	// starting fresh, so the new cut's PreviousVersion (read from `current`)
	// is always a verified-live version, never an unstarted half-cut
	// (Codex r1 High#2 / r2 High).
	if j.State != StateInit && j.TargetVersion != stagedVer {
		if j.State.atLeast(StateFlipped) && !j.State.atLeast(StateStarted) {
			// The stale cut already flipped `current` + the unit to its
			// target but never health-confirmed it. FINISH that cut
			// (start + health-confirm) to completion so `current` is a
			// known-good version. If it is unhealthy, fall through to its
			// own auto-rollback — we do NOT silently adopt an unstarted
			// half-cut as the next rollback base.
			r.logf("upgrade: finishing a stale half-cut to %s before the new %s cut",
				j.TargetVersion, stagedVer)
			// C3 diagnostic (#1967): if the stale half-cut's flipped-in dir
			// vanished (GC/disk event) starting it is doomed; treat that exactly
			// like an unhealthy half-cut and route to its auto-rollback rather
			// than letting systemd exec a missing binary. Skip the doomed
			// StartUnit and reuse the unhealthy path below.
			startErr := r.versionDirComplete(j.TargetVersion)
			if startErr == nil {
				startErr = r.cfg.Sys.StartUnit(r.cfg.Unit)
			}
			var healthErr error
			if startErr == nil {
				healthErr = r.cfg.Sys.HelperHealthy(j.TargetVersion, r.cfg.StartHealthDeadline)
			}
			if finishErr := firstNonNil(startErr, healthErr); finishErr != nil {
				r.logf("upgrade: stale half-cut %s failed to come up (%v); AUTO-ROLLBACK before the new cut",
					j.TargetVersion, finishErr)
				if rbErr := r.rollback(j); rbErr != nil {
					return fmt.Errorf("stale half-cut unhealthy (%v) AND rollback failed: %w", finishErr, rbErr)
				}
				// Rollback cleared the journal and restored PreviousVersion;
				// re-enter fresh for the new staged version.
				j = &Journal{State: StateInit}
			} else {
				// Stale cut healthy: commit it (GC) then start fresh.
				if err := r.gc(j); err != nil {
					r.logf("upgrade: WARN gc of finished stale cut failed: %v", err)
				}
				_ = r.clearJournal()
				r.removeAllPartials()
				j = &Journal{State: StateInit}
			}
		} else {
			// STAGED/PREFLIGHT/COPIED/VERIFIED (pure, live untouched) or
			// STOPPED (unit down, `current` still OLD). Restart the unit if
			// it was stopped, sweep partials, begin anew.
			r.logf("upgrade: staged version %s differs from journaled target %s; "+
				"recovering and starting fresh", stagedVer, j.TargetVersion)
			if j.State == StateStopped {
				if startErr := r.cfg.Sys.StartUnit(r.cfg.Unit); startErr != nil {
					r.logf("upgrade: WARN failed to restart unit after stale-stop recovery: %v", startErr)
				}
			}
			r.removeAllPartials()
			j = &Journal{State: StateInit}
		}
	}

	// Initialize a fresh journal entry.
	if j.State == StateInit {
		prev, perr := r.readCurrentVersion()
		if perr != nil {
			return perr
		}
		if prev != "" {
			if verr := ValidateVersionSegment(prev); verr != nil {
				return fmt.Errorf("current version (rollback target) is not a safe "+
					"path segment: %w", verr)
			}
		}
		// REFUSE-AT-INIT (mechanism C, Codex r2): an unsanctioned cut with no
		// rollback target must be refused BEFORE any journal is persisted. If
		// we instead let it run preflight/copy/verify and only refused at the
		// pre-STOP guard, the journal would be left at StateVerified with
		// PreviousVersion=="" — and a re-run (even after the operator re-seeds
		// versions/current as the error advises) would RESUME that stale
		// journal, never re-read `current`, and stay refused forever (stuck).
		// Refusing here writes no journal, so a post-seed re-run starts fresh,
		// reads the new `current`, and proceeds with a real rollback target.
		// Also clear any lingering on-disk journal from a just-completed
		// resume-vs-fresh recovery (which resets j in memory but does not
		// remove the stale on-disk record), so the refuse leaves a fully
		// clean state and a re-run does not re-run recovery.
		if prev == "" && !opts.AllowNoRollbackFirstCut {
			if cerr := r.clearJournal(); cerr != nil {
				r.logf("upgrade: WARN clear stale journal on refuse: %v", cerr)
			}
			return fmt.Errorf("refuse-before-STOP: no previous version to roll back to "+
				"(versions/current is absent or unreadable) and this is not a sanctioned "+
				"first cut; refusing the %s cut because a flip/start failure would leave "+
				"the daemon offline with no recovery target. Seed the versioned runtime "+
				"(xpfd seed-runtime), then re-run the upgrade", stagedVer)
		}
		// REFUSE-AT-INIT (#1981 B-P3b OPT1, Codex r5-#2 / r6): a same-version cut
		// whose target version dir already EXISTS, is the LIVE current or the
		// rollback target, and does NOT match this cut's source generation
		// cannot be safely replaced (RemoveAll-ing a live/rollback dir mid-cut
		// violates #1967). Refuse HERE, pre-PREFLIGHT, so no journal is persisted
		// and no .dbsnap is taken — a re-run then starts fresh and re-resolves
		// the source rather than RESUMING a journal that re-refuses forever.
		//
		// "Does not match" covers BOTH a different stamp AND an ABSENT stamp (a
		// pre-#1981 live dir) when this cut pins a generation (srcGen != "").
		// The previous `existingGen != ""` exclusion left the absent-stamp live
		// case to the copyStaged backstop, which runs AFTER PREFLIGHT/.dbsnap and
		// thus re-wedged on resume (Codex r6). A legacy cut (srcGen == "") over
		// an unstamped live dir matches (existingGen == "" == srcGen) and is a
		// true resume — not refused.
		// `prev` was just read authoritatively from readCurrentVersion() above
		// (errors handled), so it IS the live `current` version here (we hold
		// the upgrade lock, so it cannot change under us). Use `prev` for the
		// live/rollback test rather than re-reading via an error-discarding
		// helper — that would return "" on a transient unreadable `current` and
		// SKIP this guard, letting the run persist a journal + take a .dbsnap
		// before refusing in copyStaged (re-introducing the wedge this guard
		// prevents). `prev` is both the rollback target AND the live current
		// here, so a single comparison covers both (Copilot r4).
		if _, statErr := os.Stat(r.versionDir(stagedVer)); statErr == nil {
			existingGen, gerr := r.readSrcGen(stagedVer)
			if gerr == nil && existingGen != srcGen && stagedVer == prev {
				if cerr := r.clearJournal(); cerr != nil {
					r.logf("upgrade: WARN clear stale journal on live-dir-replace refuse: %v", cerr)
				}
				return fmt.Errorf("refuse-before-PREFLIGHT: cannot replace the live/rollback "+
					"version dir %s (its bytes come from source generation %q but this cut pins "+
					"%q); re-stage under a DISTINCT version tag, or `dpkg-reconfigure xpf` to "+
					"realign the generation", r.versionDir(stagedVer), existingGen, srcGen)
			}
		}
		j.TargetVersion = stagedVer
		j.PreviousVersion = prev
		j.StartedAtUnixNano = r.cfg.Sys.Now().UnixNano()
		// Pin the source generation NOW (#1981 Option B, B-P3): the cut copies
		// from staged-gen/<SourceGeneration>/ — the resolved DIRECTORY, never
		// re-reading current-gen — so a concurrent publish that advances
		// current-gen cannot redirect this in-flight cut. srcGen is "" only on
		// the pre-#1981 legacy-staged fallback (no published generation exists
		// yet on a freshly-seeded host whose seed predates B); in that case the
		// copy reads live staged/, the documented one-hop bootstrap window.
		j.SourceGeneration = srcGen
		// Record the sanctioned-first-cut decision NOW (#1964 mechanism C,
		// Codex r1): a no-previous cut is sanctioned only when the caller
		// passes AllowNoRollbackFirstCut. Persisting it means a crash-resume
		// PAST the STOP step (where the refuse guard no longer re-runs) still
		// honors the original sanction, and recoverFromFlipFailure can prove
		// the empty-previous flip-failure restart is legitimate.
		if prev == "" && opts.AllowNoRollbackFirstCut {
			j.FirstCutSanctioned = true
		}
		if err := r.transition(j, StateStaged); err != nil {
			return err
		}
	}

	// Idempotent no-op: target already live and committed.
	if j.State == StateCommitted {
		r.logf("upgrade: version %s already committed; nothing to do", j.TargetVersion)
		return r.clearJournal()
	}

	// ---- PREFLIGHT (pure) ----
	if !j.State.atLeast(StatePreflight) {
		if err := r.preflight(j); err != nil {
			return fmt.Errorf("preflight: %w", err)
		}
		if err := r.transition(j, StatePreflight); err != nil {
			return err
		}
	}

	// ---- COPY (pure) ----
	if !j.State.atLeast(StateCopied) {
		if err := r.copyStaged(j); err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		if err := r.transition(j, StateCopied); err != nil {
			return err
		}
	}

	// ---- VERIFY (pure) ----
	if !j.State.atLeast(StateVerified) {
		if err := r.verify(j); err != nil {
			// A REJECT or verify failure leaves live state untouched. Clean up
			// the just-copied versions/<ver> so a same-version retry recopies
			// a corrected staged binary instead of re-verifying the stale
			// failing copy (#1967 verify-fail cleanup).
			r.cleanupFailedVerifyCopy(j)
			return fmt.Errorf("verify-dataplane: %w", err)
		}
		if err := r.transition(j, StateVerified); err != nil {
			return err
		}
	}

	// ---- REFUSE-BEFORE-STOP (mechanism C, plan §8 inv. C) ----
	// The UNCONDITIONAL pre-STOP invariant: never proceed into a STOP/FLIP/
	// START path for a cut with no restorable target (PreviousVersion=="")
	// unless it is an explicitly sanctioned no-rollback first cut.
	//
	// This check is NOT gated on the cut not-yet-having-stopped (Copilot r2):
	// a corrupted / hand-edited / older-version journal that resumes at
	// StateStopped (or later) with PreviousVersion=="" AND
	// FirstCutSanctioned==false would otherwise sail past STOP straight into
	// FLIP/START, silently completing an UNSANCTIONED no-rollback cut. By
	// evaluating it on every Run — even a post-STOP resume — an unsanctioned
	// empty-previous cut is always refused, while a legitimately sanctioned
	// resume passes (its FirstCutSanctioned was persisted at INIT). With the
	// #1964 seed/migration PreviousVersion is non-empty on every field host,
	// so this fires only on an unexpected loss of the rollback target.
	//
	// Sanctioned either by THIS invocation's flag or by the persisted journal
	// decision from the original run (so a crash-resume re-entering without
	// the flag is still honored).
	sanctioned := opts.AllowNoRollbackFirstCut || j.FirstCutSanctioned
	if j.State.atLeast(StateStaged) && j.PreviousVersion == "" && !sanctioned {
		return fmt.Errorf("refuse-before-STOP: no previous version to roll back to "+
			"(versions/current is absent or unreadable) and this is not a sanctioned "+
			"first cut; refusing to proceed past STOP for the %s cut because a "+
			"flip/start failure would leave the daemon offline with no recovery "+
			"target. Re-seed the versioned runtime (xpfd seed-runtime), then re-run "+
			"the upgrade", j.TargetVersion)
	}

	// ---- STOP (live mutation #1) ----
	if !j.State.atLeast(StateStopped) {
		if !opts.UnitAlreadyStopped {
			r.logf("upgrade: stopping %s before flip", r.cfg.Unit)
			if err := r.cfg.Sys.StopUnit(r.cfg.Unit); err != nil {
				return fmt.Errorf("stop unit: %w", err)
			}
		}
		if err := r.transition(j, StateStopped); err != nil {
			return err
		}
	}

	// ---- FLIP (live mutation #2; three journaled-idempotent substeps) ----
	// A flip failure leaves the unit STOPPED (the STOP step above already
	// ran). The daemon must not be left offline (AGY-5): recover by rolling
	// back to the previous version, or — for a sanctioned first cut with no
	// previous version — by restarting the first-install binary already
	// present in versions/current (the flip's 6a current-repoint is the only
	// substep that could have run; current still resolves to a launchable
	// version either way).
	if !j.State.atLeast(StateFlipped) {
		if err := r.flip(j.TargetVersion); err != nil {
			return r.recoverFromFlipFailure(j, opts, err)
		}
		if err := r.transition(j, StateFlipped); err != nil {
			return err
		}
	}

	// ---- START ----
	if !j.State.atLeast(StateStarted) {
		// C3 (diagnostic): confirm the flipped-in version dir is still
		// complete before StartUnit (#1967). A concurrent GC or disk event in
		// the FLIP->START window could remove versions/<ver>/xpfd, making
		// systemd exec a missing binary. The outcome is ALREADY covered by the
		// START-failure auto-rollback below (a missing ExecStart fails the
		// start), so this is not a new correctness path — it only converts an
		// opaque systemd "exec format/no such file" into a clear, actionable
		// error and lets the rollback fire from a known cause. Routed through
		// the SAME firstNonNil/rollback machinery so HA semantics are
		// unchanged.
		preStartErr := r.versionDirComplete(j.TargetVersion)
		// A StartUnit exec failure is treated the SAME as an unhealthy
		// start (AGY r3 Medium): the binary is already flipped-in, so a
		// failure to start leaves the daemon OFFLINE unless we roll back.
		// Both the start-exec error and the health error route through the
		// standalone auto-rollback (or surface for operator-driven HA
		// rollback when SkipStartHealthRollback is set).
		var startErr error
		if preStartErr != nil {
			// Skip the doomed StartUnit; surface the concrete missing-binary
			// cause and let the shared failure path roll back.
			startErr = preStartErr
		} else {
			startErr = r.cfg.Sys.StartUnit(r.cfg.Unit)
		}
		var healthErr error
		if startErr == nil {
			healthErr = r.cfg.Sys.HelperHealthy(j.TargetVersion, r.cfg.StartHealthDeadline)
		}
		if failErr := firstNonNil(startErr, healthErr); failErr != nil {
			if opts.SkipStartHealthRollback {
				return fmt.Errorf("new version %s failed to come up after flip (HA: "+
					"rollback is operator-driven): %w", j.TargetVersion, failErr)
			}
			r.logf("upgrade: new version %s failed to come up after start (%v); AUTO-ROLLBACK",
				j.TargetVersion, failErr)
			if rbErr := r.rollback(j); rbErr != nil {
				return fmt.Errorf("new version failed (%v) AND rollback failed: %w", failErr, rbErr)
			}
			return fmt.Errorf("new version %s failed to come up; rolled back to %s: %w",
				j.TargetVersion, j.PreviousVersion, failErr)
		}
		if err := r.transition(j, StateStarted); err != nil {
			return err
		}
	}

	// ---- COMMIT (GC) ----
	if err := r.gc(j); err != nil {
		// GC failure is non-fatal to the cut-over (the new version is live
		// and healthy); log and proceed.
		r.logf("upgrade: WARN gc failed: %v", err)
	}
	if err := r.transition(j, StateCommitted); err != nil {
		return err
	}
	r.logf("upgrade: committed version %s", j.TargetVersion)
	return r.clearJournal()
}

// versionDirComplete reports a diagnostic error if the flipped-in version
// dir is missing a managed lockstep binary just before StartUnit (#1967 C3).
// A concurrent GC or disk event in the FLIP->START window could remove
// versions/<ver>/{xpfd,xpf-userspace-dp}, making systemd exec a missing
// binary. Returning a clear cause here (rather than relying on an opaque
// systemd exec failure) lets the caller's existing START-failure rollback
// fire from a known cause. The outcome was already covered by that rollback,
// so this is diagnostic-only — it never changes which recovery path runs.
// Returns nil when the dir is complete.
func (r *Runner) versionDirComplete(ver string) error {
	// The lockstep set (xpfd, xpf-userspace-dp) comes from the manifest SSOT
	// (#1982) rather than a hardcoded list, so it cannot silently drift from
	// the managed-binary declaration.
	for _, b := range manifest.LockstepNames() {
		p := filepath.Join(r.versionDir(ver), b)
		if _, serr := os.Stat(p); serr != nil {
			return fmt.Errorf("flipped-in version dir incomplete before start: "+
				"%s: %w (versions/%s vanished in the FLIP->START window?)", p, serr, ver)
		}
	}
	return nil
}

// firstNonNil returns the first non-nil error.
func firstNonNil(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// preflight checks disk space (incl. the rollback DB snapshot), GCs
// eligible versions if short, and takes the pre-upgrade DB snapshot. Pure:
// no live mutation.
func (r *Runner) preflight(j *Journal) error {
	if err := fsatomic.MkdirAllDurable(r.cfg.VersionsDir, 0755); err != nil {
		return fmt.Errorf("create versions dir: %w", err)
	}
	r.removeAllPartials()

	// Size the ACTUAL copy source (the pinned generation, #1981), not live
	// staged/ — the cut copies the pinned generation into versions/<ver>
	// (Codex r5-#4b).
	stagedSize, err := dirSize(r.sourceDir(j))
	if err != nil {
		return fmt.Errorf("size staged: %w", err)
	}
	dbSize, _ := dirSize(r.cfg.ConfigDBDir) // best-effort; 0 if absent

	need := stagedSize + dbSize + r.cfg.DiskMarginBytes

	free, err := r.cfg.Sys.FreeBytes(r.cfg.VersionsDir)
	if err != nil {
		return fmt.Errorf("statfs versions dir: %w", err)
	}
	if free < need {
		r.logf("upgrade: preflight short on space (free=%d need=%d); GC-before-copy", free, need)
		if err := r.gc(j); err != nil {
			r.logf("upgrade: WARN gc-before-copy failed: %v", err)
		}
		free, err = r.cfg.Sys.FreeBytes(r.cfg.VersionsDir)
		if err != nil {
			return fmt.Errorf("statfs versions dir (post-gc): %w", err)
		}
		if free < need {
			return fmt.Errorf("insufficient space on %s: free=%d bytes, need=%d "+
				"(staged=%d + dbsnap=%d + margin=%d); aborting before any live "+
				"mutation", r.cfg.VersionsDir, free, need, stagedSize, dbSize, r.cfg.DiskMarginBytes)
		}
	}

	// Take the pre-upgrade config-DB snapshot for binary+DB-atomic
	// rollback. Snapshot the whole .configdb dir into a .partial then
	// atomically rename so a crash never yields a torn snapshot.
	snapDir := filepath.Join(r.cfg.VersionsDir, "."+j.TargetVersion+".dbsnap")
	snapPartial := snapDir + partialSuffix
	_ = os.RemoveAll(snapPartial)
	_ = os.RemoveAll(snapDir)
	if _, err := os.Stat(r.cfg.ConfigDBDir); err == nil {
		if _, cerr := copyTree(r.cfg.ConfigDBDir, snapPartial); cerr != nil {
			return fmt.Errorf("snapshot config DB: %w", cerr)
		}
		if err := fsatomic.SyncDir(snapPartial); err != nil {
			return fmt.Errorf("fsync db snapshot: %w", err)
		}
		if err := os.Rename(snapPartial, snapDir); err != nil {
			return fmt.Errorf("commit db snapshot: %w", err)
		}
		if err := fsatomic.SyncDir(r.cfg.VersionsDir); err != nil {
			return fmt.Errorf("fsync versions dir after snapshot: %w", err)
		}
		j.DBSnapshotPath = snapDir
	} else {
		r.logf("upgrade: no config DB at %s; skipping DB snapshot", r.cfg.ConfigDBDir)
	}

	// Determine whether the new version raises the state-format floor.
	// Conservative default: assume it may (the rollback restores the DB
	// unconditionally when a snapshot exists, which is always safe).
	j.AdvancedStateFloor = j.DBSnapshotPath != ""
	return nil
}

// copyStaged copies the PINNED source generation
// (staged-gen/<SourceGeneration>/, never live staged/) -> .<ver>.partial/ then
// atomic-renames it to versions/<ver>/ and stamps the source generation into
// versions/<ver>/.srcgen. Pure: leaves live untouched.
//
// Source resolution (#1981 Option B): the cut reads from the generation pinned
// at INIT — a directory dpkg is NOT rewriting — so the copy is internally a
// single generation by construction. j.SourceGeneration == "" is the
// documented pre-B legacy/bootstrap fallback (copy from live staged/).
//
// Same-version destination identity + SAFE replacement (B-P3b OPT1): the
// version-keyed skip is GENERATION-AWARE.
//
//   - An existing versions/<ver> whose .srcgen MATCHES this cut's source
//     generation (or both are empty on the legacy same-cut resume) is a true
//     resume — skip the copy.
//   - Otherwise the existing dir's bytes may NOT match this cut's source —
//     whether it carries a different .srcgen stamp OR no stamp at all (a stale
//     pre-#1981 dir, or a legacy cut over a now-stamped dir). It must be
//     REPLACED. If it is the live `current` or rollback (PreviousVersion)
//     target, REFUSE (cannot safely RemoveAll a live version dir mid-cut,
//     #1967) — though the primary refusal for a stamped-different live dir is
//     pre-PREFLIGHT at INIT; this is the backstop for a resume and for the
//     unstamped-live case. Otherwise it is a stale non-live dir and is safe to
//     RemoveAll + recopy via the proven guarded-delete shape (Codex r5-#1: an
//     unstamped STALE dir must be replaced, NOT reused — a pre-fix torn
//     versions/<ver> must not be committed under a fresh generation).
//
// sourceDir returns the directory the cut copies FROM for journal j: the
// pinned staged-gen/<SourceGeneration>/ (#1981 Option B) or, on the pre-B
// legacy path (empty SourceGeneration), live staged/. It does NOT validate
// existence; copyStaged stats it.
func (r *Runner) sourceDir(j *Journal) string {
	if j.SourceGeneration != "" {
		return r.stagedGenConfig().GenDir(j.SourceGeneration)
	}
	return r.cfg.StagedDir
}

func (r *Runner) copyStaged(j *Journal) error {
	ver := j.TargetVersion
	dst := r.versionDir(ver)
	partial := r.partialDir(ver)

	srcDir := r.cfg.StagedDir
	if j.SourceGeneration != "" {
		if !stagedgen.ValidGenID(j.SourceGeneration) {
			return fmt.Errorf("journal source generation %q is not a safe path segment",
				j.SourceGeneration)
		}
		srcDir = r.stagedGenConfig().GenDir(j.SourceGeneration)
		fi, serr := os.Stat(srcDir)
		if serr != nil {
			return fmt.Errorf("pinned source generation %s missing at %s: %w "+
				"(it may have been GC'd — re-run after re-publishing)", j.SourceGeneration, srcDir, serr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("pinned source generation %s at %s is not a directory",
				j.SourceGeneration, srcDir)
		}
	}

	// Resume / same-version replacement decision (B-P3b OPT1).
	if _, err := os.Stat(dst); err == nil {
		existingGen, gerr := r.readSrcGen(ver)
		if gerr != nil {
			return fmt.Errorf("read source-generation stamp of %s: %w", dst, gerr)
		}
		if existingGen == j.SourceGeneration {
			// True resume (same generation, or both empty on the legacy path):
			// the copy already landed; skip.
			r.logf("upgrade: version dir %s already present (same source generation); skipping copy", dst)
			return nil
		}
		// The existing dir does NOT match this cut's source (different stamp, or
		// an unstamped pre-#1981 dir vs a stamped cut, or vice-versa). Replace
		// it — unless it is live/rollback, in which case refuse (backstop; the
		// stamped-different live case is already refused at INIT).
		//
		// FAIL-SAFE on an unreadable `current` (Copilot): if we cannot determine
		// the live version, REFUSE rather than risk RemoveAll-ing a dir that may
		// be live — an ignored read error here could destroy the running
		// daemon's binaries.
		cur, curErr := r.readCurrentVersion()
		if curErr != nil {
			return fmt.Errorf("refuse: cannot determine the live `current` version while "+
				"deciding whether to replace %s (its source generation %q differs from this "+
				"cut's %q); refusing to risk deleting a live version dir: %w",
				dst, existingGen, j.SourceGeneration, curErr)
		}
		if ver == cur || ver == j.PreviousVersion {
			return fmt.Errorf("refuse: cannot replace the live/rollback version dir %s "+
				"(its bytes come from source generation %q but this cut pins %q); re-stage "+
				"under a DISTINCT version tag, or `dpkg-reconfigure xpf` to realign the "+
				"generation", dst, existingGen, j.SourceGeneration)
		}
		// Stale non-live: reuse the proven guarded delete, then recopy.
		r.logf("upgrade: replacing stale version dir %s (source generation %q -> %q)",
			dst, existingGen, j.SourceGeneration)
		if rerr := r.removeStaleVersionDir(ver); rerr != nil {
			return rerr
		}
	}

	_ = os.RemoveAll(partial)
	sum, err := copyTree(srcDir, partial)
	if err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("copy source -> partial: %w", err)
	}
	// Re-checksum the partial to confirm the copy is intact.
	verifySum, err := copyTreeChecksum(partial)
	if err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("checksum partial: %w", err)
	}
	if verifySum != sum {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("partial checksum mismatch (copy corrupted)")
	}
	// Stamp the source generation INSIDE the partial (B-P3b OPT1) so it lands
	// atomically with the version dir and GC removes it with the dir. Skip the
	// stamp on the legacy path (empty SourceGeneration) so a pre-B dir stays
	// stamp-free and is recognized as legacy on a later resume.
	if j.SourceGeneration != "" {
		stampPath := filepath.Join(partial, stagedgen.SrcGenFile)
		if werr := fsatomic.WriteFileDurable(stampPath, []byte(j.SourceGeneration+"\n"), 0o644); werr != nil {
			_ = os.RemoveAll(partial)
			return fmt.Errorf("stamp source generation into partial: %w", werr)
		}
	}
	if err := fsatomic.SyncDir(partial); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("fsync partial: %w", err)
	}
	if err := os.Rename(partial, dst); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("atomic rename partial -> version dir: %w", err)
	}
	if err := fsatomic.SyncDir(r.cfg.VersionsDir); err != nil {
		return fmt.Errorf("fsync versions dir after rename: %w", err)
	}
	return nil
}

// removeStaleVersionDir removes a NON-live versions/<ver> (B-P3b OPT1
// guarded-replace) so a same-version-different-generation cut can recopy. The
// caller has ALREADY proven ver is neither `current` nor PreviousVersion; this
// mirrors the durable-unlink shape of cleanupFailedVerifyCopy.
func (r *Runner) removeStaleVersionDir(ver string) error {
	if err := os.RemoveAll(r.versionDir(ver)); err != nil {
		return fmt.Errorf("remove stale version dir %s: %w", r.versionDir(ver), err)
	}
	if serr := partialSweepSyncDir(r.cfg.VersionsDir); serr != nil {
		r.logf("upgrade: WARN fsync versions dir after stale-version removal: %v", serr)
	}
	return nil
}

// verify runs the kernel verify-dataplane gate against the COPIED binary
// with throwaway socket/state/pin paths (plan §8 inv. 10). Pure.
func (r *Runner) verify(j *Journal) error {
	bin := filepath.Join(r.versionDir(j.TargetVersion), "xpfd")
	tmp, err := os.MkdirTemp("", "xpf-verify-*")
	if err != nil {
		return fmt.Errorf("mktemp for verify isolation: %w", err)
	}
	defer os.RemoveAll(tmp)
	// Throwaway paths so verify never touches a live socket/state/pin.
	env := []string{
		"XPF_CONTROL_SOCKET=" + filepath.Join(tmp, "verify.sock"),
		"XPF_STATE_FILE=" + filepath.Join(tmp, "verify.state"),
		"XPF_BPF_PIN_DIR=" + filepath.Join(tmp, "pins"),
	}
	pass, err := r.cfg.Sys.VerifyDataplane(bin, env)
	if err != nil {
		return err
	}
	if !pass {
		return fmt.Errorf("REJECT: kernel verifier rejected the staged dataplane; "+
			"refusing to cut over to %s (live dataplane untouched)", j.TargetVersion)
	}
	return nil
}

// cleanupFailedVerifyCopy removes the just-copied versions/<TargetVersion>
// after a VERIFY failure so a subsequent run keyed by the SAME version string
// recopies the (presumably corrected) staged tree rather than re-verifying the
// stale failing copy (#1967 verify-fail cleanup). copyStaged skips the copy
// when versions/<ver> already exists, so without this a dev/test/reinstall
// retry under the same version would re-verify the bad copy forever.
//
// Two MANDATORY guards (plan §6 AGY-r4-2/3):
//
//   - NEVER delete the active version. Removing it would destroy the RUNNING
//     daemon's binaries. We only remove versions/<TargetVersion> when it is
//     neither the previous (rollback) version NOR the live `current` target.
//     VERIFY is a pure pre-STOP step, so the only way TargetVersion could be
//     active is a degenerate same-version re-stage; the guard makes that safe.
//   - RESET the journal so the next run re-runs copyStaged. After a successful
//     COPY the journal is at StateCopied; if we delete the dir but leave the
//     journal there, the next run SKIPS copyStaged (state already >= Copied)
//     and VERIFY then fails file-not-found. We rewind to INIT and clear the
//     DB-snapshot fields AND the pinned SourceGeneration so the retry re-runs
//     INIT (re-resolving staged-gen/current-gen), preflight (FRESH config-DB
//     snapshot), and copyStaged. Rewinding only to PREFLIGHT would reuse the
//     snapshot taken at the original preflight; but the daemon stays LIVE
//     across a verify failure (verify is pure), so an operator may change the
//     config DB before the retry — a later rollback would then restore the
//     stale pre-failure snapshot and silently lose those changes (Codex r1
//     High). Clearing SourceGeneration is the #1981 addition: an operator who
//     re-stages CORRECTED bytes publishes a NEW generation, so the retry must
//     re-resolve current-gen rather than re-cutting the failed generation.
//     The orphan snapshot is removed here; GC also sweeps orphan .dbsnap
//     dotfiles defensively.
//
// Best-effort: a cleanup failure is logged, never masking the verify error
// the caller is about to return. If the dir was protected (active), we still
// reset the journal so a retry re-enters cleanly.
func (r *Runner) cleanupFailedVerifyCopy(j *Journal) {
	ver := j.TargetVersion
	if ver == "" {
		return
	}
	cur, _ := r.readCurrentVersion()
	if ver == j.PreviousVersion || ver == cur {
		// Guard (a): the target version is the rollback target or the live
		// `current` — its dir backs a runnable daemon. NEVER delete it. A
		// same-version re-stage that fails verify against the active version
		// is a no-op for the running daemon; nothing to clean.
		r.logf("upgrade: verify-fail cleanup SKIPPED for %s (it is the active/"+
			"rollback version; refusing to delete a live version dir)", ver)
	} else if err := os.RemoveAll(r.versionDir(ver)); err != nil {
		r.logf("upgrade: WARN verify-fail cleanup of %s failed: %v", r.versionDir(ver), err)
	} else {
		// Make the unlink durable so a crash cannot resurrect the failing copy
		// and re-trip the copyStaged-skip on a retry.
		if serr := partialSweepSyncDir(r.cfg.VersionsDir); serr != nil {
			r.logf("upgrade: WARN fsync versions dir after verify-fail cleanup: %v", serr)
		}
		r.logf("upgrade: removed copied version dir %s after verify failure "+
			"(a retry will recopy from staged)", r.versionDir(ver))
	}
	// Guard (b): rewind the journal to INIT so the retry re-runs INIT
	// (re-resolving current-gen), preflight (fresh DB snapshot), AND
	// copyStaged, and PERSIST it FIRST (Codex r2): the journal rewrite is the
	// durable source of truth. If we instead removed the snapshot before
	// persisting, a crash (or a saveJournal failure) in between would leave the
	// persisted journal at StateCopied / AdvancedStateFloor=true pointing at an
	// already-removed snapshot — exactly the stale-snapshot bug this fix
	// targets. By clearing the fields and persisting first, the on-disk journal
	// never references a snapshot we are about to delete. SourceGeneration is
	// cleared too (#1981): a corrected re-stage publishes a new generation, so
	// the retry must re-resolve current-gen, not re-cut the failed generation.
	j.State = StateInit
	j.SourceGeneration = ""
	j.DBSnapshotPath = ""
	j.AdvancedStateFloor = false
	if err := r.saveJournal(j); err != nil {
		// The journal rewrite did NOT persist (Codex r3): the on-disk record
		// may still be StateCopied with DBSnapshotPath set. Do NOT delete the
		// snapshot now — that would leave the persisted journal referencing a
		// removed snapshot (the exact bug the persist-before-remove ordering
		// closes). Leave the snapshot in place; the next run re-runs cleanup
		// (verify will fail again), and gc() also sweeps orphan .dbsnap
		// dotfiles defensively.
		r.logf("upgrade: WARN reset journal after verify-fail cleanup failed (%v); "+
			"leaving the DB snapshot in place to avoid a journal->removed-snapshot "+
			"reference", err)
		return
	}
	// Drop the now-orphan DB snapshot taken at the original preflight (the
	// retry re-snapshots from the possibly-changed live DB). Best-effort, and
	// done AFTER the journal is durably rewound so it no longer references the
	// snapshot. Derive the path from the validated TargetVersion rather than
	// trusting the persisted DBSnapshotPath as an os.RemoveAll target (Codex
	// r2): ver is validated as a safe path segment in Run() before any cut, so
	// this is the same path preflight wrote. gc() also sweeps orphan .dbsnap
	// dotfiles defensively.
	_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, "."+ver+".dbsnap"))
}
