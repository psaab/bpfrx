package logging

import (
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// #9118: the recovery leg #3478 deliberately did not ship.
//
// THE WEDGE. rotate() closes the active file and sets lw.file = nil BEFORE
// reopening. If openHardenedAuditLog then fails -- EMFILE, ENFILE, ENOSPC,
// EROFS, EACCES -- it bumps failedRotations and returns with the handle still
// nil. Every subsequent Send / SendBinary / WriteRecord takes the `file == nil`
// arm and drops.
//
// AND NOTHING RE-FIRES. rotate() is called only from `if lw.written >=
// lw.maxSize`, i.e. after a SUCCESSFUL write. Once wedged, `written` never
// advances, so the only caller of the only reopen in the file can never run
// again. One transient error at a rotation boundary silences the local audit
// and trace channel -- the channel an operator uses to reconstruct an incident
// -- until the next config commit or a daemon restart.
//
// #3478 made this state OBSERVABLE (counters, a rate-limited WARN, rotate
// returning an error) and said so; pkg/logging/README.md names the state in as
// many words. Observability is not recovery, and on an unattended appliance in
// steady state "until the next commit" is unbounded.
//
// WHY A `closed` FLAG IS REQUIRED AND NOT DEFENSIVE CLUTTER. Close() also sets
// lw.file = nil, so a nil handle means EITHER "wedged" OR "shut down on
// purpose". Reopening on the second reading is worse than the bug: it would
// recreate an audit file after the writer was deliberately closed, and on the
// ReplaceLocalWriters path it would resurrect a writer the daemon has just
// retired. The two states are indistinguishable from the handle alone, so they
// are distinguished explicitly.
//
// RATE-LIMITED, because the failure is usually not transient in the instant.
// Under ENOSPC every write would otherwise issue an openat, turning a full disk
// into a syscall storm on the logging path. One attempt per interval bounds
// that, and the interval is short enough that recovery is measured in seconds.

// reopenBackoff9118 is the minimum spacing between reopen attempts on a wedged
// writer. A var only so a test can shorten it; production never writes it.
var reopenBackoff9118 = time.Second

// wedgeState9118 carries the recovery bookkeeping. Embedded rather than added
// as loose fields so the whole mechanism is greppable from one name.
type wedgeState9118 struct {
	closed      bool      // Close() was called: never reopen
	lastAttempt time.Time // last reopen attempt, for the backoff
	recovered   atomic.Uint64
}

// ensureOpenLocked attempts to recover a wedged writer, and reports whether the
// handle is usable afterwards. The caller must hold lw.mu.
//
// Returns false without touching the filesystem when the writer was closed
// deliberately, or when the last attempt was too recent -- so a caller can use
// the result directly as "may I write?" and the existing drop-and-count arm
// stays exactly where it was for the cases that genuinely cannot write.
func (lw *LocalLogWriter) ensureOpenLocked() bool {
	if lw.file != nil {
		return true
	}
	if lw.wedge.closed {
		return false
	}
	now := time.Now()
	if !lw.wedge.lastAttempt.IsZero() && now.Sub(lw.wedge.lastAttempt) < reopenBackoff9118 {
		return false
	}
	lw.wedge.lastAttempt = now

	f, err := openHardenedAuditLog(lw.path, os.O_APPEND)
	if err != nil {
		// Deliberately NOT counted as a failed rotation: no rotation was
		// attempted. It is counted by the caller's existing drop path, which is
		// the honest accounting -- one dropped line, one drop.
		return false
	}
	lw.file = f
	// Re-sync the byte count to the file that actually exists. The wedge may
	// have begun mid-rotation, so `written` describes a file that was already
	// renamed aside; carrying it forward would make the next rotation fire
	// against the wrong size.
	if info, statErr := f.Stat(); statErr == nil {
		lw.written = info.Size()
	} else {
		lw.written = 0
	}
	lw.wedge.recovered.Add(1)
	slog.Warn("local security-log writer recovered after a failed rotation reopen (#9118)",
		"path", lw.path,
		"dropped_writes", lw.droppedWrites.Load(),
		"failed_rotations", lw.failedRotations.Load(),
		"recoveries", lw.wedge.recovered.Load())
	return true
}

// RecoveredWrites reports how many times a wedged writer was reopened (#9118).
// Exported for the same reason DroppedWrites is: an operator must be able to
// distinguish "the audit channel never broke" from "it broke and healed", and
// those two look identical if only the drop counter is visible.
func (lw *LocalLogWriter) RecoveredWrites() uint64 { return lw.wedge.recovered.Load() }

// ensureOpenLocked is the TraceWriter twin, and it exists separately for the
// same reason the two writers are separate types: they open different paths
// (openTraceFile resolves under traceLogDir and sanitizes the basename, which
// openHardenedAuditLog on a raw path would not). The RECOVERY LOGIC is
// identical, and the wedge is identical -- trace.go's own rotate() nils the
// handle before reopening and WriteRecord drops forever after -- so the
// bookkeeping type is shared rather than duplicated.
func (tw *TraceWriter) ensureOpenLocked() bool {
	if tw.file != nil {
		return true
	}
	if tw.wedge.closed {
		return false
	}
	now := time.Now()
	if !tw.wedge.lastAttempt.IsZero() && now.Sub(tw.wedge.lastAttempt) < reopenBackoff9118 {
		return false
	}
	tw.wedge.lastAttempt = now

	f, err := openTraceFile(tw.name)
	if err != nil {
		return false
	}
	tw.file = f
	if info, statErr := f.Stat(); statErr == nil {
		tw.written = info.Size()
	} else {
		tw.written = 0
	}
	tw.wedge.recovered.Add(1)
	slog.Warn("flow-trace writer recovered after a failed rotation reopen (#9118)",
		"path", tw.path,
		"dropped_writes", tw.droppedWrites.Load(),
		"failed_rotations", tw.failedRotations.Load(),
		"recoveries", tw.wedge.recovered.Load())
	return true
}

// RecoveredWrites reports how many times a wedged trace writer was reopened.
func (tw *TraceWriter) RecoveredWrites() uint64 { return tw.wedge.recovered.Load() }

// wedgeAttemptForTest9118 exposes the last reopen attempt time so a cell can
// assert the backoff actually suppresses a retry, rather than asserting it by
// counting syscalls it cannot see.
func (lw *LocalLogWriter) wedgeAttemptForTest9118() time.Time {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.wedge.lastAttempt
}
