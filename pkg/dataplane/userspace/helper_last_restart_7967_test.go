package userspace

import (
	"path/filepath"
	"testing"
	"time"
)

// #7967 / #5838: the crash surface must state when a restart was last
// ATTEMPTED, not only how many attempts there have been and when the next is
// due.
//
// The issue that filed this argued the field could not exist, because the
// successful-restart wipe would clear it — "wiped by the very event it is meant
// to record". That objection applies verbatim to `Restarts`, `NextRestart`,
// `ExitCode`, `Detail` and `LastExitWasCrash`, which are all shipped and
// rendered. These cells pin the property the objection would have removed, and
// pin the wipe itself so the episode contract stays explicit.

// The attempt time is recorded even when the restart FAILS — that is the case
// where the record survives to be read, and the one an operator is looking at
// during a crash loop.
func TestLastRestartAttemptRecordedOnFailedRestart7967(t *testing.T) {
	rec := HelperCrashRecord{
		LastExitWasCrash: true,
		Restarts:         3,
		NextRestart:      time.Now().Add(30 * time.Second),
	}
	if !rec.LastRestartAttempt.IsZero() {
		t.Fatal("a fresh record must carry no attempt time")
	}

	// What restartHelperAfterCrash does before calling ensureProcessLocked.
	at := time.Now()
	rec.LastRestartAttempt = at

	if rec.LastRestartAttempt != at {
		t.Fatalf("attempt time = %v, want %v", rec.LastRestartAttempt, at)
	}
	// The other episode fields are untouched by recording an attempt — the new
	// field must not disturb the contract the surface already renders.
	if rec.Restarts != 3 || !rec.LastExitWasCrash {
		t.Fatalf("recording the attempt disturbed the episode record: %+v", rec)
	}
}

// The field is episode-scoped: the successful-restart wipe clears it along with
// everything else. Pinned deliberately — this IS the behaviour the issue called
// disqualifying, and it is the same behaviour the five shipped fields have.
func TestLastRestartAttemptIsEpisodeScoped7967(t *testing.T) {
	rec := HelperCrashRecord{
		LastExitWasCrash:   true,
		Restarts:           2,
		ExitCode:           101,
		Detail:             "exit status 101",
		NextRestart:        time.Now().Add(time.Minute),
		LastRestartAttempt: time.Now(),
	}

	// The wipe restartHelperAfterCrash performs on success.
	rec = HelperCrashRecord{}

	if !rec.LastRestartAttempt.IsZero() {
		t.Fatal("attempt time survived the episode wipe")
	}
	// Control: it is cleared the SAME way as the fields already shipped, which
	// is the whole answer to "it would be wiped by the event it records".
	if rec.Restarts != 0 || rec.ExitCode != 0 || rec.LastExitWasCrash ||
		!rec.NextRestart.IsZero() || rec.Detail != "" {
		t.Fatalf("the wipe is not total, so the new field is not scoped like the rest: %+v", rec)
	}
}

// The backoff is a pure function of the attempt count, which is what makes the
// scheduling time DERIVABLE from the surface today — and therefore what makes
// this field an ergonomics fix rather than an impossibility fix.
//
// Pinned because the honest justification for the field depends on it: if
// `helperRestartDelay` ever took another input, the derivation would break and
// the argument for the field would become stronger, not weaker. Either way the
// commit message should not be left claiming the wrong one.
func TestRestartDelayIsAPureFunctionOfAttempts7967(t *testing.T) {
	for _, attempt := range []int{1, 2, 3, 5, 10, 50} {
		a := helperRestartDelay(attempt)
		b := helperRestartDelay(attempt)
		if a != b {
			t.Fatalf("helperRestartDelay(%d) is not deterministic: %v vs %v", attempt, a, b)
		}
	}
	// It grows then saturates; both halves matter for the derivation.
	if helperRestartDelay(1) >= helperRestartDelay(3) {
		t.Fatal("backoff does not grow with attempts")
	}
	if helperRestartDelay(50) != helperRestartDelay(51) {
		t.Fatal("backoff does not saturate; the derivation's upper end is unstable")
	}
}

// THE WIRING CELL: `restartHelperAfterCrash` actually sets the field.
//
// The cells above build a `HelperCrashRecord` by hand, so they prove the struct
// carries the value and the wipe clears it — NOT that anything ever writes it.
// That distinction cost a round on #7497 blocker 4, where a guard asserted a
// renderer while the capture feeding it was unbound and could be emptied with
// the whole suite still green.
//
// Driven through the real supervisor with a binary that cannot exist, so
// `ensureProcessLocked` fails at `findBinary` without spawning: the record
// SURVIVES, which is exactly the state an operator reads during a crash loop.
func TestRestartAttemptTimeIsActuallyRecorded7967(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)
	m.mu.Lock()
	m.cfg.Binary = filepath.Join(t.TempDir(), "no-such-helper")
	gen := m.procGen
	exited := m.procSup.exited
	m.mu.Unlock()

	_ = cmd.Process.Kill()
	awaitSupervisor(t, m, exited)

	m.mu.Lock()
	before := m.helperCrash.LastRestartAttempt
	m.mu.Unlock()
	if !before.IsZero() {
		t.Fatalf("an attempt time was set before any restart was attempted: %v", before)
	}

	start := time.Now()
	m.restartHelperAfterCrash(gen)

	m.mu.Lock()
	got := m.helperCrash.LastRestartAttempt
	crash := m.helperCrash.LastExitWasCrash
	m.mu.Unlock()

	if got.IsZero() {
		t.Fatal("restartHelperAfterCrash did not record the attempt time; the " +
			"field is carried and cleared correctly but nothing writes it")
	}
	if got.Before(start.Add(-time.Second)) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("attempt time %v is not from this restart (start %v)", got, start)
	}
	// The record must have survived: a FAILED restart keeps the episode, which
	// is what makes the timestamp readable at all.
	if !crash {
		t.Fatal("the failed restart cleared the episode; the attempt time would " +
			"never be observable")
	}
}
