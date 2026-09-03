package fwdstatus

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// helperCrashRecordFor7967 builds a crash record in the shape the surface reads
// during an episode: a crash observed, retries armed, and the given attempt time.
func helperCrashRecordFor7967(attempt time.Time) userspace.HelperCrashRecord {
	return userspace.HelperCrashRecord{
		LastExitWasCrash:   true,
		RestartPending:     true,
		ExitCode:           101,
		Detail:             "exit status 101",
		PID:                4242,
		At:                 attempt.Add(-time.Minute),
		Restarts:           3,
		NextRestart:        attempt.Add(30 * time.Second),
		LastRestartAttempt: attempt,
	}
}

// #7967: the last-restart-attempt timestamp must reach the rendered surface.
//
// These bind the two joins the supervisor-side cells cannot see: the builder
// copying the record field onto the status, and the formatter emitting a row
// for it. Written after a mutation sweep found the builder assignment could be
// DELETED with `pkg/fwdstatus` still green — the record carried the value, the
// renderer would have printed it, and nothing connected them.
func TestLastRestartAttemptReachesTheRenderedSurface7967(t *testing.T) {
	at := time.Date(2026, 9, 3, 4, 5, 6, 0, time.UTC)
	dp := &fakeCrashDP{
		known: true,
		rec:   helperCrashRecordFor7967(at),
	}

	fs := crashBuild(t, dp)

	// Join 1: the builder copied it off the record.
	if !fs.HelperLastRestartAttempt.Equal(at) {
		t.Fatalf("builder did not surface the attempt time: got %v, want %v",
			fs.HelperLastRestartAttempt, at)
	}

	// Join 2: the formatter emitted a row carrying it.
	out := Format(fs)
	if !strings.Contains(out, "Helper last restart attempt") {
		t.Fatalf("no last-restart row in the rendered surface:\n%s", out)
	}
	if !strings.Contains(out, at.Format(time.RFC3339)) {
		t.Fatalf("the row does not carry the timestamp %s:\n%s",
			at.Format(time.RFC3339), out)
	}
}

// A zero attempt time renders NO row — an episode where no restart has been
// attempted yet must not print a zero-valued timestamp, which reads as
// "restarted at year 1" rather than as "not yet attempted".
//
// This is the control for the cell above: without it, a formatter that printed
// the row unconditionally would satisfy that one.
func TestNoLastRestartRowBeforeAnyAttempt7967(t *testing.T) {
	dp := &fakeCrashDP{
		known: true,
		rec:   helperCrashRecordFor7967(time.Time{}),
	}

	out := Format(crashBuild(t, dp))
	if strings.Contains(out, "Helper last restart attempt") {
		t.Fatalf("a last-restart row was rendered before any attempt:\n%s", out)
	}
	// Control on the control: the surrounding crash rows ARE present, so the
	// absence above is the guard working rather than the crash block being
	// skipped entirely.
	if !strings.Contains(out, "Helper restart attempts") {
		t.Fatalf("the crash block did not render at all, so the assertion above "+
			"proves nothing:\n%s", out)
	}
}
