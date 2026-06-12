// manager_reload_test.go — #1880 degraded-reload state machine tests:
// retry scheduling/convergence, success-cancels-episode, Stop() leak
// gate, the stale-success/confGen invariant, pythontools-missing
// classification, and one-shot (cleanup) behavior.
package frr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newRetryTestManager builds a retry-enabled Manager with compressed
// backoff delays, a t.TempDir frr.conf, and Stop() wired into test
// cleanup (no goroutine leaks across cases — AGY plan-r3 f1).
func newRetryTestManager(t *testing.T, fake *fakeExecutor, delays []time.Duration, slow time.Duration) *Manager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		frrConf:      filepath.Join(t.TempDir(), "frr.conf"),
		exec:         fake,
		retryEnabled: true,
		retryDelays:  delays,
		retrySlow:    slow,
		mgrCtx:       ctx,
		mgrCancel:    cancel,
	}
	t.Cleanup(m.Stop)
	return m
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestDegradedRetrySchedulesAndConverges: a commit whose primary reload
// fails goes degraded (sentinel + gauge), the single-flight retry
// re-runs the primary, and convergence clears the gauge.
func TestDegradedRetrySchedulesAndConverges(t *testing.T) {
	fake := &fakeExecutor{}
	fake.frrReloadPyHook = func(call int) error {
		if call == 1 {
			return errors.New("transient: vtysh socket refused")
		}
		return nil
	}
	m := newRetryTestManager(t, fake,
		[]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
		2*time.Millisecond)

	err := m.Clear()
	if !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	if !m.ReloadDegraded() {
		t.Fatalf("ReloadDegraded() = false right after degraded commit")
	}
	waitFor(t, "degraded retry convergence", 2*time.Second, func() bool {
		return !m.ReloadDegraded()
	})
	if calls := fake.reloadPyCalls(); calls < 2 {
		t.Errorf("FrrReloadPy calls = %d, want >= 2 (commit + retry)", calls)
	}
}

// TestSuccessCancelsRetryEpisode: a newer fully-converging apply clears
// the degraded state AND cancels the pending retry episode — the woken
// retry must exit without exec'ing (AGY plan-r3 f2).
func TestSuccessCancelsRetryEpisode(t *testing.T) {
	fake := &fakeExecutor{}
	fake.frrReloadPyHook = func(call int) error {
		if call == 1 {
			return errors.New("transient failure")
		}
		return nil
	}
	// Hour-long delays: the episode can only end via cancellation.
	m := newRetryTestManager(t, fake, []time.Duration{time.Hour}, time.Hour)

	if err := m.Clear(); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	m.retryMu.Lock()
	done := m.retryDone
	m.retryMu.Unlock()
	if done == nil {
		t.Fatalf("no retry episode scheduled after degraded commit")
	}

	// Second commit: primary succeeds (full convergence).
	if err := m.Clear(); err != nil {
		t.Fatalf("second Clear = %v, want nil", err)
	}
	if m.ReloadDegraded() {
		t.Errorf("ReloadDegraded() = true after full convergence")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("retry episode did not exit after success-cancel")
	}
	if calls := fake.reloadPyCalls(); calls != 2 {
		t.Errorf("FrrReloadPy calls = %d, want exactly 2 (no retry exec after cancel)", calls)
	}
}

// TestStopTerminatesPendingRetry: Stop() cancels the manager lifetime
// and reaps the retry goroutine promptly even when the next attempt is
// an hour away (Codex plan-r3 H / AGY plan-r3 f1).
func TestStopTerminatesPendingRetry(t *testing.T) {
	fake := &fakeExecutor{frrReloadPyErr: errors.New("always failing")}
	m := newRetryTestManager(t, fake, []time.Duration{time.Hour}, time.Hour)

	if err := m.Clear(); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	doneCh := make(chan struct{})
	go func() {
		m.Stop()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop() did not return — retry goroutine leaked")
	}
	if calls := fake.reloadPyCalls(); calls != 1 {
		t.Errorf("FrrReloadPy calls = %d, want 1 (no retry exec after Stop)", calls)
	}
}

// TestStaleSuccessDoesNotClearDegraded pins the §7 gate-1 stale-success
// edge (Codex plan-r3 M): a retry that succeeds against an OLDER config
// generation must NOT clear the degraded state. confGen cannot actually
// change while retryReloadOnce holds reloadMu — the hook simulates the
// refactor-bug (exec moved outside the lock) by bumping confGen from
// inside the exec, which runs under the same lock.
func TestStaleSuccessDoesNotClearDegraded(t *testing.T) {
	fake := &fakeExecutor{}
	var m *Manager
	sawDegradedAfterStaleSuccess := false
	fake.frrReloadPyHook = func(call int) error {
		switch call {
		case 1:
			return errors.New("transient failure") // commit goes degraded
		case 2:
			m.confGen++ // simulate a concurrent write landing mid-exec
			return nil  // stale success — must NOT clear degraded
		default:
			// Reached only because the stale success at call 2 kept the
			// loop alive; record that degraded survived it.
			sawDegradedAfterStaleSuccess = m.degraded.Load()
			return nil
		}
	}
	m = newRetryTestManager(t, fake,
		[]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
		2*time.Millisecond)

	if err := m.Clear(); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	waitFor(t, "convergence after the stale-success detour", 2*time.Second, func() bool {
		return !m.ReloadDegraded()
	})
	if calls := fake.reloadPyCalls(); calls < 3 {
		t.Fatalf("FrrReloadPy calls = %d, want >= 3 (stale success must not end the episode)", calls)
	}
	if !sawDegradedAfterStaleSuccess {
		t.Errorf("degraded state was cleared by a stale-generation success")
	}
}

// TestPytoolsMissingClassification: a primary failure caused by a
// missing frr-reload.py (frr-pythontools absent) still degrades via the
// sentinel, the cause stays errors.Is-visible through the wrap, and the
// retry starts directly at the slow cadence (skipping the fast rungs).
func TestPytoolsMissingClassification(t *testing.T) {
	notFound := fmt.Errorf("/usr/lib/frr/frr-reload.py: %w", os.ErrNotExist)
	fake := &fakeExecutor{}
	fake.frrReloadPyHook = func(call int) error {
		if call == 1 {
			return notFound
		}
		return nil
	}
	// Hour-long fast rungs + millisecond slow cadence: convergence is
	// only reachable if slowStart skipped the fast rungs.
	m := newRetryTestManager(t, fake,
		[]time.Duration{time.Hour, time.Hour, time.Hour},
		time.Millisecond)

	err := m.Clear()
	if !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("degraded sentinel does not preserve the ENOENT cause: %v", err)
	}
	waitFor(t, "slow-cadence retry convergence", 2*time.Second, func() bool {
		return !m.ReloadDegraded()
	})
}

// TestDisableDegradedRetryNeverSchedules: the one-shot (`xpfd cleanup`)
// configuration reports degraded to the caller but never spawns the
// background retry.
func TestDisableDegradedRetryNeverSchedules(t *testing.T) {
	fake := &fakeExecutor{frrReloadPyErr: errors.New("always failing")}
	m := newRetryTestManager(t, fake,
		[]time.Duration{time.Millisecond}, time.Millisecond)
	m.DisableDegradedRetry()

	if err := m.Clear(); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("Clear = %v, want ErrFRRReloadDegraded", err)
	}
	m.retryMu.Lock()
	done := m.retryDone
	m.retryMu.Unlock()
	if done != nil {
		t.Fatalf("retry episode scheduled despite DisableDegradedRetry")
	}
	time.Sleep(20 * time.Millisecond)
	if calls := fake.reloadPyCalls(); calls != 1 {
		t.Errorf("FrrReloadPy calls = %d, want 1 (no background retries)", calls)
	}
}

// TestApplyFullPropagatesDegraded: the sentinel surfaces through the
// public ApplyFull (content path), not just Clear.
func TestApplyFullPropagatesDegraded(t *testing.T) {
	fake := &fakeExecutor{frrReloadPyErr: errors.New("primary down")}
	m := newRetryTestManager(t, fake, []time.Duration{time.Hour}, time.Hour)

	err := m.ApplyFull(&FullConfig{ClusterMode: true})
	if !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("ApplyFull = %v, want ErrFRRReloadDegraded", err)
	}
	if !m.ReloadDegraded() {
		t.Errorf("ReloadDegraded() = false after degraded ApplyFull")
	}
}
