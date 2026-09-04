package userspace

import (
	"testing"
	"time"
)

// #8397: crash HISTORY must survive the recovery that wipes the episode record.
//
// The defect is a disappearance, not a wrong value, and that is what makes it
// hard to see: `restartHelperAfterCrash` sets `m.helperCrash =
// HelperCrashRecord{}` on success, so a helper that crashed four times in the
// last hour and is healthy now presents a COMPLETELY CLEAN crash surface. A
// clean surface is also exactly what a healthy helper is supposed to look like,
// so no assertion about the current record can distinguish the two.

func crashedManagerFor8397(at time.Time, pid, code, restarts int, detail string) *Manager {
	m := &Manager{}
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash: true,
		At:               at,
		PID:              pid,
		ExitCode:         code,
		Detail:           detail,
		Restarts:         restarts,
	}
	return m
}

func TestCrashHistorySurvivesTheRecoveryWipe8397(t *testing.T) {
	at := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	m := crashedManagerFor8397(at, 4242, 101, 3, "exit status 101")

	m.recordRecoveredCrashEpisodeLocked(at.Add(2 * time.Second))
	// The wipe the production path performs immediately after.
	m.helperCrash = HelperCrashRecord{}

	// CONTROL on the premise. If the record still carried the crash, this test
	// would pass without the history doing anything, and the whole file would
	// be measuring the wipe not happening.
	if m.helperCrash.LastExitWasCrash || m.helperCrash.Restarts != 0 {
		t.Fatalf("the episode record must be wiped by recovery — that is the "+
			"premise of #8397; got %+v", m.helperCrash)
	}

	eps, total := m.HelperCrashHistory()
	if total != 1 {
		t.Fatalf("history total = %d, want 1 — the episode did not survive the wipe", total)
	}
	if len(eps) != 1 {
		t.Fatalf("retained %d episodes, want 1", len(eps))
	}
	got := eps[0]
	if !got.At.Equal(at) {
		t.Errorf("At = %v, want %v", got.At, at)
	}
	if got.PID != 4242 || got.ExitCode != 101 || got.Detail != "exit status 101" {
		t.Errorf("disposition not carried: %+v", got)
	}
	if got.Restarts != 3 {
		t.Errorf("Restarts = %d, want 3 — the attempt count is the recurrence signal", got.Restarts)
	}
	if got.RecoveredAt.IsZero() {
		t.Error("RecoveredAt must be set; an episode enters the ring only on recovery")
	}
}

func TestCrashHistoryIsBoundedButTheTotalIsNot8397(t *testing.T) {
	m := &Manager{}
	const n = helperCrashHistoryDepth + 5
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		m.helperCrash = HelperCrashRecord{At: base.Add(time.Duration(i) * time.Minute), PID: 1000 + i}
		m.recordRecoveredCrashEpisodeLocked(base.Add(time.Duration(i) * time.Minute))
		m.helperCrash = HelperCrashRecord{}
	}

	eps, total := m.HelperCrashHistory()
	if len(eps) != helperCrashHistoryDepth {
		t.Fatalf("retained %d episodes, want the ring depth %d — a flapping helper "+
			"must not grow this without limit", len(eps), helperCrashHistoryDepth)
	}
	// THE LOAD-BEARING ASSERTION. Returning only the slice would make a wrapped
	// ring indistinguishable from a full one — "8 crashes" versus "at least 8
	// crashes" — and this surface exists to answer "is this recurring?", where
	// that is the whole answer.
	if total != n {
		t.Errorf("total = %d, want %d — the total must NOT be capped by the ring", total, n)
	}
	// Oldest-first, and the OLDEST entries are the ones dropped.
	if eps[0].PID != 1000+(n-helperCrashHistoryDepth) {
		t.Errorf("oldest retained PID = %d, want %d — the ring must drop the "+
			"OLDEST, not the newest", eps[0].PID, 1000+(n-helperCrashHistoryDepth))
	}
	if eps[len(eps)-1].PID != 1000+n-1 {
		t.Errorf("newest retained PID = %d, want %d", eps[len(eps)-1].PID, 1000+n-1)
	}
}

func TestCrashHistoryIsACopyNotTheLiveSlice8397(t *testing.T) {
	m := &Manager{}
	m.helperCrash = HelperCrashRecord{PID: 7}
	m.recordRecoveredCrashEpisodeLocked(time.Now())

	eps, _ := m.HelperCrashHistory()
	eps[0].PID = 999

	again, _ := m.HelperCrashHistory()
	if again[0].PID != 7 {
		t.Errorf("a caller mutated the manager's own history through the returned "+
			"slice: PID = %d, want 7", again[0].PID)
	}
}

func TestNoHistoryUntilAnEpisodeRecovers8397(t *testing.T) {
	// A manager that has never recovered from anything reports an empty
	// history and a zero total — not a phantom episode. Without this, a ring
	// that appended on the CRASH rather than the recovery would satisfy every
	// other cell here while reporting an episode that may still be looping.
	m := &Manager{}
	eps, total := m.HelperCrashHistory()
	if len(eps) != 0 || total != 0 {
		t.Errorf("a manager with no recovered episode must report none; got %d/%d",
			len(eps), total)
	}
}
