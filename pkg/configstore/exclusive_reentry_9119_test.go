package configstore

import (
	"errors"
	"testing"
	"time"
)

func exclusiveStore9119(t *testing.T) *Store {
	t.Helper()
	return newTestStore(t)
}

// stageAnEdit9119 puts a real staged change in the candidate, so IsDirty()
// below reports on something an operator would actually lose.
func stageAnEdit9119(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.LoadSet("set system host-name reentry-9119\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if !s.IsDirty() {
		t.Fatal("the fixture staged nothing; IsDirty() below would assert nothing")
	}
}

// #9119: EnterConfigureExclusive had no self-reentry arm, while its shared-mode
// sibling has had one since #4476. Two consequences, and the second destroys
// work:
//
//	fresh lease, same holder -> ErrConfigLocked (cannot idempotently re-assert)
//	stale lease, same holder -> nil, and the holder's own staged edits are GONE
//
// The wipe is reclaimStaleLockLocked doing exactly what #4476 designed it to do
// — discard the candidate for any entrant past the idle lease — with the
// entrant being the holder itself.
func TestExclusiveSelfReentryIsIdempotent9119(t *testing.T) {
	s := exclusiveStore9119(t)
	if err := s.EnterConfigureExclusive("admin-session"); err != nil {
		t.Fatalf("EnterConfigureExclusive: %v", err)
	}
	stageAnEdit9119(t, s)

	if err := s.EnterConfigureExclusive("admin-session"); err != nil {
		t.Fatalf("re-entry by the SAME holder on a fresh lease was refused: %v. An "+
			"automation client cannot idempotently re-assert the lock it already "+
			"holds, while the shared-mode sibling allows exactly that", err)
	}
	if !s.IsDirty() {
		t.Error("self-reentry discarded the holder's own staged edits")
	}
}

func TestExclusiveSelfReentryPastTheLeaseKeepsTheCandidate9119(t *testing.T) {
	s := exclusiveStore9119(t)
	if err := s.EnterConfigureExclusive("admin-session"); err != nil {
		t.Fatalf("EnterConfigureExclusive: %v", err)
	}
	stageAnEdit9119(t, s)
	backdateConfigLock(t, s, configLockLeaseTTL+time.Minute)

	if err := s.EnterConfigureExclusive("admin-session"); err != nil {
		t.Fatalf("stale-lease self-reentry: %v", err)
	}
	if !s.IsDirty() {
		t.Error("re-asserting the exclusive lock after an idle stall SILENTLY " +
			"destroyed the holder's own staged candidate. The self-check must sit " +
			"BEFORE reclaimStaleLockLocked, or the reclaim wipes before the check " +
			"can spare it")
	}
}

// NARROWNESS 1: a DIFFERENT holder must still be refused on a fresh lease. This
// is what stops the fix from becoming a lock bypass.
func TestExclusiveLockStillRefusesAnotherHolder9119(t *testing.T) {
	s := exclusiveStore9119(t)
	if err := s.EnterConfigureExclusive("admin-session"); err != nil {
		t.Fatalf("EnterConfigureExclusive: %v", err)
	}
	err := s.EnterConfigureExclusive("someone-else")
	if err == nil {
		t.Fatal("a DIFFERENT holder took the exclusive lock; the self-reentry arm " +
			"has become a lock bypass")
	}
	if !errors.Is(err, ErrConfigLocked) {
		t.Errorf("refusal must carry ErrConfigLocked so deferrable callers can "+
			"retry rather than string-match: %v", err)
	}
}

// NARROWNESS 3: an EMPTY holder must never match.
//
// The precondition matters and my first version of this got it wrong: asserting
// it against an EXCLUSIVE lock proves nothing, because "" != "admin-session"
// refuses on the string compare alone and the `holder != ""` guard is never
// consulted. Dropping that guard killed zero cells until this case was written
// with the right precondition.
//
// The guard only bites when exclusiveHolder is ALSO empty — which is exactly a
// lock held in SHARED mode. There, `"" == ""` would match, and an anonymous
// caller would get nil back, refresh someone else's lease, and believe it held
// an exclusive lock nobody had granted it.
func TestEmptyHolderCannotMatchAnEmptyExclusiveHolder9119(t *testing.T) {
	s := exclusiveStore9119(t)
	// Shared mode: configHolder is set, exclusiveHolder stays "".
	if err := s.EnterConfigureSession("sessA"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	s.mu.Lock()
	excl := s.exclusiveHolder
	s.mu.Unlock()
	if excl != "" {
		t.Fatalf("fixture precondition failed: exclusiveHolder = %q, want empty — "+
			"this case is only meaningful when both sides of the compare are empty", excl)
	}

	if err := s.EnterConfigureExclusive(""); err == nil {
		s.mu.Lock()
		got := s.exclusiveHolder
		s.mu.Unlock()
		if got == "" {
			t.Fatal("an ANONYMOUS caller matched the empty exclusiveHolder of a " +
				"shared lock: it got nil back, refreshed another session's lease, " +
				"and now believes it holds an exclusive lock it never took")
		}
	}
}

// NARROWNESS 2, and it is the one the issue's own prose would have got wrong.
//
// The self-check matches on exclusiveHolder, NOT on the effective holder. If it
// used the effective holder, a SHARED-mode holder calling EnterConfigureExclusive
// would get nil back while the lock stayed SHARED — the caller would believe it
// had upgraded to exclusive and would not have. A silent failure to acquire the
// stronger lock is worse than a refusal, so this must still be refused.
func TestSharedHolderCannotSilentlyClaimExclusive9119(t *testing.T) {
	s := exclusiveStore9119(t)
	if err := s.EnterConfigureSession("sessA"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := s.EnterConfigureExclusive("sessA"); err == nil {
		s.mu.Lock()
		excl := s.exclusiveHolder
		s.mu.Unlock()
		if excl != "sessA" {
			t.Fatal("a shared holder's call to EnterConfigureExclusive returned nil " +
				"WITHOUT taking the exclusive lock: the caller now believes it holds " +
				"an exclusive lock it does not hold")
		}
	}
}
