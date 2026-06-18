package upgrade

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
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

	// Identify the staged version. It keys versions/<ver> et al. on a fresh
	// cut, so validate it as a safe single path segment BEFORE any path use
	// (#1964 C1) — `git describe`-derived versions can carry a `/` (a
	// branch-named tag), which would otherwise escape VersionsDir.
	stagedXpfd := filepath.Join(r.cfg.StagedDir, "xpfd")
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
		j.TargetVersion = stagedVer
		j.PreviousVersion = prev
		j.StartedAtUnixNano = r.cfg.Sys.Now().UnixNano()
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
	for _, b := range []string{"xpfd", "xpf-userspace-dp"} {
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

	stagedSize, err := dirSize(r.cfg.StagedDir)
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

// copyStaged copies staged/ -> .<ver>.partial/ then atomic-renames to
// versions/<ver>/. Pure: leaves live untouched.
func (r *Runner) copyStaged(j *Journal) error {
	ver := j.TargetVersion
	dst := r.versionDir(ver)
	partial := r.partialDir(ver)

	// If the final dir already exists (resume after a crash post-rename),
	// nothing to copy.
	if _, err := os.Stat(dst); err == nil {
		r.logf("upgrade: version dir %s already present; skipping copy", dst)
		return nil
	}

	_ = os.RemoveAll(partial)
	sum, err := copyTree(r.cfg.StagedDir, partial)
	if err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("copy staged -> partial: %w", err)
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
//     and VERIFY then fails file-not-found. We rewind BELOW PREFLIGHT (to
//     StateStaged) and clear the DB-snapshot fields so the retry re-runs
//     preflight and takes a FRESH config-DB snapshot. Rewinding only to
//     PREFLIGHT would reuse the snapshot taken at the original preflight; but
//     the daemon stays LIVE across a verify failure (verify is pure), so an
//     operator may change the config DB before the retry — a later rollback
//     would then restore the stale pre-failure snapshot and silently lose
//     those changes (Codex r1 High). The orphan snapshot is removed here; GC
//     also sweeps orphan .dbsnap dotfiles defensively.
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
	// Drop the now-stale DB snapshot taken at the original preflight (the
	// retry re-snapshots from the possibly-changed live DB). Best-effort.
	if j.DBSnapshotPath != "" {
		_ = os.RemoveAll(j.DBSnapshotPath)
	}
	// Guard (b): rewind the journal BELOW PREFLIGHT so the retry re-runs BOTH
	// preflight (fresh DB snapshot) AND copyStaged. Clear the snapshot fields
	// so a crash between here and the retry's preflight cannot leave a journal
	// pointing at a removed snapshot.
	j.State = StateStaged
	j.DBSnapshotPath = ""
	j.AdvancedStateFloor = false
	if err := r.saveJournal(j); err != nil {
		r.logf("upgrade: WARN reset journal after verify-fail cleanup: %v", err)
	}
}
