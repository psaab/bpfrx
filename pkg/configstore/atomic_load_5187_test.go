package configstore

import (
	"testing"
	"time"
)

// #5187: LoadSet / LoadMerge must import the whole batch or nothing. Before the
// fix both replayed each flat line directly onto the LIVE candidate and returned
// on the first error, leaving every EARLIER set/delete line committed to the
// candidate while the RPC/CLI reported the load FAILED — a non-atomic import. A
// partial delete was fail-open: replacement deny lines placed AFTER the failing
// line were dropped, yet the candidate had already advanced. The fix mirrors
// LoadOverride: replay into a deep clone and swap it in only on complete
// success, so a mid-body error leaves the candidate byte-identical to before the
// request with dirty/lease state untouched.
//
// Both tests below are RED on revert: the pre-fix line-by-line-on-live-candidate
// behavior mutates the candidate (host-name changed + eth0 deleted) before the
// trailing bad line fails, so the byte-identity assertion trips.

// seedForAtomicLoad enters config mode, seeds a baseline candidate the failing
// batch will attempt to mutate, and resets dirty so a failed load's effect on
// dirty is observable. It returns the pre-request candidate serialization, dirty
// flag, and config-lock lease so the caller can assert none of them changed.
func seedForAtomicLoad(t *testing.T) (s *Store, before string, beforeDirty bool, beforeLease time.Time) {
	t.Helper()
	s = newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name original"); err != nil {
		t.Fatalf("seed host-name: %v", err)
	}
	if err := s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24"); err != nil {
		t.Fatalf("seed interface: %v", err)
	}
	before = s.ShowCandidateSet()
	// Clean baseline: a failed load must not dirty the candidate nor refresh the
	// idle lease. Reading/writing the unexported fields is fine — the test is
	// in-package and single-goroutine.
	s.dirty = false
	beforeDirty = s.dirty
	beforeLease = s.configLockAt
	return s, before, beforeDirty, beforeLease
}

// atomicBadBatch has two valid mutating lines (change the host-name, delete the
// seeded eth0) followed by a line that errors — a delete of an interface that
// does not exist (ErrPathNotFound). The trailing verb IS recognized, so it flows
// through applyEditLine and fails at apply time rather than the fail-closed verb
// gate, exercising the partial-apply path.
const atomicBadBatch = "set system host-name changed\n" +
	"delete interfaces eth0\n" +
	"delete interfaces eth9"

func assertCandidateUnchanged(t *testing.T, s *Store, before string, beforeDirty bool, beforeLease time.Time) {
	t.Helper()
	if after := s.ShowCandidateSet(); after != before {
		t.Errorf("candidate mutated by a FAILED load (non-atomic import)\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
	if s.dirty != beforeDirty {
		t.Errorf("dirty flag changed by a FAILED load: before=%v after=%v", beforeDirty, s.dirty)
	}
	if s.configLockAt != beforeLease {
		t.Errorf("config-lock idle lease refreshed by a FAILED load: before=%v after=%v", beforeLease, s.configLockAt)
	}
}

func TestLoadSet_AtomicOnMidBodyError_5187(t *testing.T) {
	s, before, beforeDirty, beforeLease := seedForAtomicLoad(t)

	count, err := s.LoadSet(atomicBadBatch)
	if err == nil {
		t.Fatalf("LoadSet: expected an error on the delete of a non-existent node, got nil (count=%d)", count)
	}
	assertCandidateUnchanged(t, s, before, beforeDirty, beforeLease)
}

func TestLoadMerge_AtomicOnMidBodyError_5187(t *testing.T) {
	s, before, beforeDirty, beforeLease := seedForAtomicLoad(t)

	// The batch begins with "set ..." lines, so LoadMerge selects the flat
	// set-format branch (the branch that carries the fail-open partial-delete
	// risk).
	if err := s.LoadMerge(atomicBadBatch); err == nil {
		t.Fatalf("LoadMerge: expected an error on the delete of a non-existent node, got nil")
	}
	assertCandidateUnchanged(t, s, before, beforeDirty, beforeLease)
}
