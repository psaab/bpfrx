package configstore

import (
	"errors"
	"testing"
)

// TestExclusiveLockReleasedOnSessionExit is the RED-on-revert guard for #3979.
//
// `configure exclusive` records the holder in exclusiveHolder (configHolder
// stays empty). The pre-fix ExitConfigureSession guard compared only
// configHolder, so an exclusive holder could never release its own lock: the
// guard saw configHolder("") != sessionID and returned false without clearing
// anything. The exclusive lock then persisted with no live holder and every
// subsequent configure was rejected until daemon restart.
//
// On revert this test goes RED: sessionA's ExitConfigureSession returns false
// (lock stuck) and sessionB's EnterConfigureSession returns ErrConfigLocked.
func TestExclusiveLockReleasedOnSessionExit(t *testing.T) {
	s := newTestStore(t)

	// Session A takes the exclusive lock.
	if err := s.EnterConfigureExclusive("sessionA"); err != nil {
		t.Fatalf("EnterConfigureExclusive(sessionA): %v", err)
	}
	if !s.InConfigMode() {
		t.Fatal("expected config mode after EnterConfigureExclusive")
	}
	if !s.IsExclusiveLocked() {
		t.Fatal("expected IsExclusiveLocked true after EnterConfigureExclusive")
	}
	// #3979: ConfigHolder must attribute the lock to its real holder, not "".
	if holder, locked := s.ConfigHolder(); !locked || holder != "sessionA" {
		t.Fatalf("ConfigHolder() = (%q, %v), want (\"sessionA\", true)", holder, locked)
	}

	// Session A exits / disconnects. This is the exact call the gRPC
	// configLockInterceptor makes on client disconnect.
	if released := s.ExitConfigureSession("sessionA"); !released {
		t.Fatal("ExitConfigureSession(sessionA) returned false — exclusive lock stuck (the #3979 bug)")
	}
	if s.InConfigMode() {
		t.Fatal("still in config mode after the exclusive holder exited")
	}
	if s.IsExclusiveLocked() {
		t.Fatal("still exclusive-locked after the exclusive holder exited")
	}

	// Session B must now be able to enter — the lock was released.
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatalf("EnterConfigureSession(sessionB) after A released: %v", err)
	}
	s.ExitConfigureSession("sessionB")
}

// TestExclusiveLockReacquireCycle exercises the full acquire -> release ->
// reacquire cycle across simulated sessions in both modes.
func TestExclusiveLockReacquireCycle(t *testing.T) {
	s := newTestStore(t)

	// exclusive -> release -> exclusive (different session) -> release
	if err := s.EnterConfigureExclusive("A"); err != nil {
		t.Fatalf("EnterConfigureExclusive(A): %v", err)
	}
	if !s.ExitConfigureSession("A") {
		t.Fatal("ExitConfigureSession(A) failed to release exclusive lock")
	}
	if err := s.EnterConfigureExclusive("B"); err != nil {
		t.Fatalf("EnterConfigureExclusive(B) after release: %v", err)
	}
	if !s.ExitConfigureSession("B") {
		t.Fatal("ExitConfigureSession(B) failed to release exclusive lock")
	}

	// shared -> release -> exclusive -> release (modes interleave cleanly)
	if err := s.EnterConfigureSession("C"); err != nil {
		t.Fatalf("EnterConfigureSession(C): %v", err)
	}
	if s.IsExclusiveLocked() {
		t.Fatal("shared/private session must not report exclusive lock")
	}
	if !s.ExitConfigureSession("C") {
		t.Fatal("ExitConfigureSession(C) failed to release shared lock")
	}
	if err := s.EnterConfigureExclusive("D"); err != nil {
		t.Fatalf("EnterConfigureExclusive(D) after shared release: %v", err)
	}
	if !s.ExitConfigureSession("D") {
		t.Fatal("ExitConfigureSession(D) failed to release exclusive lock")
	}
}

// TestLiveExclusiveHolderBlocksOthers verifies that a genuinely-active
// exclusive holder still blocks other sessions and cannot have its lock stolen
// by a non-holder's exit — the live-holder-blocks-others behavior must survive
// the #3979 fix.
func TestLiveExclusiveHolderBlocksOthers(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureExclusive("owner"); err != nil {
		t.Fatalf("EnterConfigureExclusive(owner): %v", err)
	}

	// Another session must be rejected (both plain and exclusive entry).
	if err := s.EnterConfigureSession("intruder"); !errors.Is(err, ErrConfigLocked) {
		t.Fatalf("EnterConfigureSession(intruder) = %v, want ErrConfigLocked", err)
	}
	if err := s.EnterConfigureExclusive("intruder"); !errors.Is(err, ErrConfigLocked) {
		t.Fatalf("EnterConfigureExclusive(intruder) = %v, want ErrConfigLocked", err)
	}

	// A non-holder's exit must NOT steal the live owner's lock.
	if s.ExitConfigureSession("intruder") {
		t.Fatal("ExitConfigureSession(intruder) stole the live owner's exclusive lock")
	}
	if !s.InConfigMode() || !s.IsExclusiveLocked() {
		t.Fatal("owner's exclusive lock was disturbed by a non-holder exit")
	}

	// The real owner still holds it and can release.
	if !s.ExitConfigureSession("owner") {
		t.Fatal("ExitConfigureSession(owner) failed to release the live lock")
	}
}

// TestSharedLockUnaffected confirms the shared/private-mode release path is
// unchanged by the #3979 fix.
func TestSharedLockUnaffected(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigureSession("A"); err != nil {
		t.Fatalf("EnterConfigureSession(A): %v", err)
	}
	if holder, locked := s.ConfigHolder(); !locked || holder != "A" {
		t.Fatalf("ConfigHolder() = (%q, %v), want (\"A\", true)", holder, locked)
	}
	// Same-session re-entry is a no-op success.
	if err := s.EnterConfigureSession("A"); err != nil {
		t.Fatalf("EnterConfigureSession(A) re-entry: %v", err)
	}
	// A non-holder cannot release it.
	if s.ExitConfigureSession("B") {
		t.Fatal("ExitConfigureSession(B) released A's shared lock")
	}
	// The holder releases it.
	if !s.ExitConfigureSession("A") {
		t.Fatal("ExitConfigureSession(A) failed to release shared lock")
	}
	if s.InConfigMode() {
		t.Fatal("still in config mode after shared holder exited")
	}
}
