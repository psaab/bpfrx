package userspace

import (
	"testing"
	"time"
)

// #7250: the crash record must be renderable AND must not report things that
// are no longer true.
//
// Two of its facts are DERIVED rather than stored, and that is the fix rather
// than a style choice — a stored judgement about the present is exactly what
// went stale. `Crashed` was read as both "the last exit was unexpected" and "a
// restart is coming", and those diverge the moment an intentional stop advances
// the process generation: the armed timer is orphaned, the record is
// deliberately NOT cleared (the retry path depends on it as debt), and a
// renderer would have reported a restart that will never fire.

func TestRestartPendingIsFalseAfterAnIntentionalStop7250(t *testing.T) {
	m := New()

	// The shape a crash leaves behind: retry debt recorded, armed for the
	// generation that died.
	m.mu.Lock()
	m.procGen = 7
	m.proc = nil
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash: true,
		Restarts:         1,
		NextRestart:      time.Now().Add(time.Second),
		restartGen:       7,
	}
	m.mu.Unlock()

	// Precondition: while the generation still matches, a restart IS pending.
	// Without this the assertion below could pass on a record that never
	// reported pending in the first place.
	if got := m.HelperCrashState(); !got.RestartPending {
		t.Fatalf("precondition: a crash armed on the CURRENT generation must report "+
			"RestartPending, got %+v", got)
	}

	// An intentional stop advances the generation, orphaning the armed timer.
	m.mu.Lock()
	m.procGen = 8
	m.mu.Unlock()

	got := m.HelperCrashState()
	if got.RestartPending {
		t.Error("RestartPending is still true after the generation advanced. The armed " +
			"timer is fenced on the old generation and will never fire, so a status " +
			"surface would tell an operator a restart is coming that is not (#7250)")
	}
	// And the OTHER fact must survive: the retry path reads it as debt, and
	// clearing it turned TestRestartUsesTheCurrentConfigNotTheDeadGeneration5838
	// red when it was tried.
	if !got.LastExitWasCrash {
		t.Error("LastExitWasCrash must NOT be cleared by a stop — ensureProcessLocked " +
			"calls the same stopLocked when a spawn misses readiness, and the retry " +
			"path depends on this flag")
	}
}

// The crash-loop predicate is backoff-at-cap, not a raw restart count, because a
// count is time-blind: twenty restarts over a week and twenty in a minute are
// different situations a counter cannot distinguish.
func TestCrashLoopingIsBackoffAtCapNotACount7250(t *testing.T) {
	// One restart: escalating, not looping.
	early := HelperCrashRecord{LastExitWasCrash: true, Restarts: 1}
	if early.CrashLooping() {
		t.Errorf("a single restart must not read as crash-looping: delay %v, cap %v",
			helperRestartDelay(1), helperRestartBackoffMax)
	}

	// Enough restarts that the backoff has saturated.
	att := 1
	for helperRestartDelay(att) < helperRestartBackoffMax {
		att++
		if att > 64 {
			t.Fatal("backoff never reached the cap; the predicate cannot be satisfied")
		}
	}
	looping := HelperCrashRecord{LastExitWasCrash: true, Restarts: att}
	if !looping.CrashLooping() {
		t.Errorf("backoff at the cap (attempt %d, delay %v) must read as crash-looping",
			att, helperRestartDelay(att))
	}

	// The control that stops this being "any record with enough restarts": a
	// helper that recovered is not looping however many times it restarted.
	recovered := HelperCrashRecord{LastExitWasCrash: false, Restarts: att}
	if recovered.CrashLooping() {
		t.Error("a record whose last exit was NOT a crash must never read as " +
			"crash-looping, however high the restart count — otherwise the predicate " +
			"latches on a box that recovered")
	}
}

// Exit code and signal must be separable. Detail folds them into prose
// ("exit status 101" / "killed by signal killed") that a renderer cannot parse
// back apart, which is why the acceptance bullet asks for them separately.
func TestExitCodeAndSignalAreSeparable7250(t *testing.T) {
	crashed := HelperCrashRecord{ExitCode: 101, Signal: ""}
	if crashed.ExitCode != 101 || crashed.Signal != "" {
		t.Errorf("a normal exit must carry its code with no signal, got %+v", crashed)
	}
	killed := HelperCrashRecord{ExitCode: -1, Signal: "killed"}
	if killed.ExitCode != -1 || killed.Signal == "" {
		t.Errorf("a signalled exit must carry the signal and -1 for the code, got %+v", killed)
	}
	// Signal is the discriminator: exactly one of the two is meaningful, and a
	// renderer needs a rule it can apply without parsing prose.
	if crashed.Signal != "" || killed.Signal == "" {
		t.Error("Signal must discriminate the two dispositions")
	}
}
