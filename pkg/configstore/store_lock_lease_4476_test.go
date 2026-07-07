package configstore

import (
	"errors"
	"testing"
	"time"
)

// backdateConfigLock rewinds the current config lock's acquire/refresh time by
// `by`, simulating the passage of idle time deterministically (no sleeps, so
// the tests stay -race clean). Callers must already hold the lock via an
// EnterConfigure* method.
func backdateConfigLock(t *testing.T, s *Store, by time.Duration) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		t.Fatal("backdateConfigLock: not in config mode")
	}
	s.configLockAt = s.configLockAt.Add(-by)
}

// TestConfigLockStaleLeaseReclaimed is the RED-on-revert guard for #4476.
//
// A REST client takes the config lock (POST /api/v1/config/enter ->
// EnterConfigure, empty holder) and never calls /config/exit. The stateless
// REST path has NO disconnect hook — unlike the gRPC configLockInterceptor —
// so before this fix the lock was stuck forever and every subsequent
// CLI/gRPC/REST config edit returned ErrConfigLocked (a management-plane DoS),
// recoverable only via `clear system config-lock` or a daemon restart.
//
// On revert this test goes RED: after the idle lease expires the second
// session's EnterConfigureSession still returns ErrConfigLocked because no
// reaper exists.
func TestConfigLockStaleLeaseReclaimed(t *testing.T) {
	s := newTestStore(t)

	// A REST client takes the lock and wanders off.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if !s.InConfigMode() {
		t.Fatal("expected config mode after EnterConfigure")
	}

	// While the lease is fresh, a second session is correctly rejected —
	// the reaper must not steal a live lock.
	if err := s.EnterConfigureSession("cli-peer"); !errors.Is(err, ErrConfigLocked) {
		t.Fatalf("EnterConfigureSession while lease fresh = %v, want ErrConfigLocked", err)
	}

	// Age the lease past the idle TTL (the wedged REST lock, no edits).
	backdateConfigLock(t, s, configLockLeaseTTL+time.Minute)

	// The second session must now reclaim the stale lease and enter. RED on
	// revert: without the reaper this returns ErrConfigLocked forever.
	if err := s.EnterConfigureSession("cli-peer"); err != nil {
		t.Fatalf("EnterConfigureSession after stale lease = %v, want reclaim+success", err)
	}
	if holder, locked := s.ConfigHolder(); !locked || holder != "cli-peer" {
		t.Fatalf("ConfigHolder() = (%q, %v), want (%q, true)", holder, locked, "cli-peer")
	}
	s.ExitConfigureSession("cli-peer")
}

// TestConfigLockActiveHolderNotReclaimed proves the reaper never steals a lock
// from a holder that is actively editing. A config mutation refreshes the idle
// lease (touchConfigLockLocked), so even after the lease was aged past the TTL,
// a single edit makes the lock live again and a competing entrant is rejected.
func TestConfigLockActiveHolderNotReclaimed(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureSession("editor"); err != nil {
		t.Fatalf("EnterConfigureSession(editor): %v", err)
	}

	// Age the lease, then make an edit — the edit must refresh it.
	backdateConfigLock(t, s, configLockLeaseTTL+time.Minute)
	if err := s.SetFromInput("system host-name testfw"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}

	// A competing session must be rejected: the edit refreshed the lease, so
	// the reaper must NOT reclaim it.
	if err := s.EnterConfigureSession("intruder"); !errors.Is(err, ErrConfigLocked) {
		t.Fatalf("EnterConfigureSession against active holder = %v, want ErrConfigLocked", err)
	}
	if holder, _ := s.ConfigHolder(); holder != "editor" {
		t.Fatalf("ConfigHolder() = %q, want %q (lease should not have been reclaimed)", holder, "editor")
	}
	s.ExitConfigureSession("editor")
}

// TestConfigLockExclusiveStaleLeaseReclaimed confirms the reaper also reclaims
// a stale EXCLUSIVE lock and fully clears the exclusive-holder bookkeeping, so
// the reclaiming session enters cleanly in shared mode.
func TestConfigLockExclusiveStaleLeaseReclaimed(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureExclusive("ghost"); err != nil {
		t.Fatalf("EnterConfigureExclusive(ghost): %v", err)
	}
	backdateConfigLock(t, s, configLockLeaseTTL+time.Minute)

	if err := s.EnterConfigureSession("newpeer"); err != nil {
		t.Fatalf("EnterConfigureSession reclaim of stale exclusive = %v", err)
	}
	if s.IsExclusiveLocked() {
		t.Fatal("exclusiveHolder not cleared after reclaiming a stale exclusive lock")
	}
	if holder, locked := s.ConfigHolder(); !locked || holder != "newpeer" {
		t.Fatalf("ConfigHolder() = (%q, %v), want (%q, true)", holder, locked, "newpeer")
	}
	s.ExitConfigureSession("newpeer")
}

// TestConfigLockReentryRefreshesLease confirms a same-session re-entry counts
// as activity and refreshes the lease, so an interactive session that keeps
// re-entering is never reclaimed.
func TestConfigLockReentryRefreshesLease(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureSession("editor"); err != nil {
		t.Fatalf("EnterConfigureSession(editor): %v", err)
	}
	backdateConfigLock(t, s, configLockLeaseTTL+time.Minute)

	// Re-entry by the holder refreshes the lease.
	if err := s.EnterConfigureSession("editor"); err != nil {
		t.Fatalf("re-entry by holder = %v, want success", err)
	}
	// A different session must still be rejected.
	if err := s.EnterConfigureSession("intruder"); !errors.Is(err, ErrConfigLocked) {
		t.Fatalf("EnterConfigureSession after holder re-entry = %v, want ErrConfigLocked", err)
	}
	s.ExitConfigureSession("editor")
}
