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

	// StopUnitBeforeFlip controls whether Run performs the STOP step. The
	// HA driver drains the node to its peer and stops the unit itself
	// (so the cluster keeps forwarding); it then calls Run with the unit
	// already stopped. Standalone always stops here. Default false =
	// Run owns the stop.
	UnitAlreadyStopped bool
}

// Run executes (or resumes) the cut-over to the staged version. It is
// idempotent: a crashed run re-invokes Run and resumes from the journal.
//
// The standalone single-node flow. The HA rolling driver wraps this with
// a controlled drain (rolling.go).
func (r *Runner) Run(opts Options) (err error) {
	j, err := r.loadJournal()
	if err != nil {
		return err
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

	// Identify the staged version.
	stagedXpfd := filepath.Join(r.cfg.StagedDir, "xpfd")
	stagedVer, err := r.cfg.Sys.BinaryVersion(stagedXpfd)
	if err != nil {
		return fmt.Errorf("read staged version (%s): %w", stagedXpfd, err)
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
			if err := r.cfg.Sys.StartUnit(r.cfg.Unit); err != nil {
				return fmt.Errorf("finish stale half-cut: start unit: %w", err)
			}
			if healthErr := r.cfg.Sys.HelperHealthy(j.TargetVersion, r.cfg.StartHealthDeadline); healthErr != nil {
				r.logf("upgrade: stale half-cut %s unhealthy (%v); AUTO-ROLLBACK before the new cut",
					j.TargetVersion, healthErr)
				if rbErr := r.rollback(j); rbErr != nil {
					return fmt.Errorf("stale half-cut unhealthy (%v) AND rollback failed: %w", healthErr, rbErr)
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
		j.TargetVersion = stagedVer
		j.PreviousVersion = prev
		j.StartedAtUnixNano = r.cfg.Sys.Now().UnixNano()
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
			// A REJECT or verify failure leaves live state untouched.
			return fmt.Errorf("verify-dataplane: %w", err)
		}
		if err := r.transition(j, StateVerified); err != nil {
			return err
		}
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
	if !j.State.atLeast(StateFlipped) {
		if err := r.flip(j.TargetVersion); err != nil {
			return fmt.Errorf("flip: %w", err)
		}
		if err := r.transition(j, StateFlipped); err != nil {
			return err
		}
	}

	// ---- START ----
	if !j.State.atLeast(StateStarted) {
		// A StartUnit exec failure is treated the SAME as an unhealthy
		// start (AGY r3 Medium): the binary is already flipped-in, so a
		// failure to start leaves the daemon OFFLINE unless we roll back.
		// Both the start-exec error and the health error route through the
		// standalone auto-rollback (or surface for operator-driven HA
		// rollback when SkipStartHealthRollback is set).
		startErr := r.cfg.Sys.StartUnit(r.cfg.Unit)
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
