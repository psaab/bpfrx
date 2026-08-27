package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

// #6741 Increment 1 — make an obsolete-generation registry access OBSERVABLE.
//
// Teardown's Cleanup destroys the pinned kernel objects but deliberately does
// NOT clear m.maps / m.programs, and the #2114 A3 rule deliberately lets a
// retained-state method PROCEED. So between a Teardown-retain and the next
// publish, a lookup hands back a handle to an obsolete forwarding generation
// and the caller mutates it — a mutation that succeeds and reaches nothing.
//
// These tests pin the counter's SEMANTICS, including what it deliberately does
// not do. The "does not" cases matter more than the "does": a counter that
// silently over-reports would make the deferred redesign chase noise, and one
// that implies a guard it lacks is worse than no counter at all.

func regTestManager6741() *Manager {
	return &Manager{
		maps:     make(map[string]*ebpf.Map),
		programs: make(map[string]*ebpf.Program),
	}
}

// TestObsoleteRegistryAccessCounted_6741 is the core case: a Teardown-retained
// registry, then a lookup that serves a handle from it.
func TestObsoleteRegistryAccessCounted_6741(t *testing.T) {
	m := regTestManager6741()

	// A published generation, then a lookup: nothing obsolete yet.
	m.mu.Lock()
	m.registryGeneration = 1
	m.maps["sessions"] = &ebpf.Map{}
	m.mu.Unlock()

	if _, present, _ := m.lookupMapLocked("sessions"); !present {
		t.Fatalf("premise broken: the seeded handle must be present")
	}
	if got := m.ObsoleteRegistryAccesses(); got != 0 {
		t.Fatalf("a lookup against the CURRENT generation must not count as obsolete, got %d", got)
	}

	// Teardown supersedes generation 1 without clearing the registry.
	m.mu.Lock()
	m.registryObsoleteFrom = m.registryGeneration
	m.mu.Unlock()

	// #6741 AC1 INVERTS this assertion, deliberately. It used to require that
	// the retained registry still SERVE the handle. It must now REFUSE: the
	// handle is an orphan of a generation Cleanup already unpinned, and serving
	// it lets a mutation succeed against an object nothing forwards through.
	//
	// The acceptance criterion offered "fails loudly OR is a verified no-op with
	// a metric". The no-op branch is unavailable and that is measured, not
	// assumed: `Close` closes only the XDP/TC link handles and `Cleanup` unpins
	// without closing, so `m.maps` / `m.programs` FDs are never closed and the
	// orphaned map stays alive and WRITABLE.
	if h, present, _ := m.lookupMapLocked("sessions"); present || h != nil {
		t.Errorf("a Teardown-superseded generation must be REFUSED, got present=%v handle=%v — "+
			"serving it is the #6741 hazard: the mutation succeeds and reaches nothing",
			present, h != nil)
	}
	if got := m.ObsoleteRegistryAccesses(); got != 1 {
		t.Errorf("obsolete access count = %d, want 1 — the counter is now the observability "+
			"half of a real guard: it counts REFUSALS, not served-obsolete accesses", got)
	}
}

// TestCloseRetainedRegistryStillProceeds_6741 is the SCOPE half of AC1, and the
// reason the guard above is safe to add at all.
//
// #6741 AC1 refuses to serve a superseded generation. That revokes the #2114 A3
// proceed-on-retained rule — but ONLY on the Teardown path, and by construction
// rather than by care: `registryObsoleteFrom` is set by `Teardown` and
// explicitly NOT by `Close`. Close keeps its pinned handles live for hitless
// restart, which is the case A3 was argued for.
//
// Without this cell the change is indistinguishable from one that revoked
// proceed-on-retained everywhere, and the guard's scope would live only in
// prose.
//
// FAIL-ON-REVERT, measured rather than asserted: make `Close` set
// `registryObsoleteFrom` and this goes RED while
// TestObsoleteRegistryAccessCounted_6741 stays green.
//
// What it does NOT bind, stated because an unverified fail-on-revert claim is
// worse than none: dropping the `registryObsoleteFrom != 0` conjunct from
// registryObsoleteLocked leaves this cell GREEN. Its fixture has
// generation=1 and obsoleteFrom=0, so `1 <= 0` is false either way. (That
// conjunct is not unguarded — removing it hangs the package suite, because
// every lookup then refuses — but this cell is not what catches it.)
//
// And it is not the only guard for the Close boundary:
// TestCloseDoesNotStartAnObsoleteEpoch_6741 pre-existed and reds on the same
// mutation. That one pins the COUNTER not starting; this one pins the handle
// still being SERVED, which is the half AC1 could have broken.
func TestCloseRetainedRegistryStillProceeds_6741(t *testing.T) {
	m := regTestManager6741()

	m.mu.Lock()
	m.registryGeneration = 1
	m.maps["sessions"] = &ebpf.Map{}
	m.mu.Unlock()

	// The hitless-restart shape: Close unarms and closes link handles, and
	// deliberately leaves the pinned map registry intact for reuse. It does not
	// mark the generation superseded.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Guard the fixture: if Close ever DID mark the generation obsolete, the
	// assertion below would be testing the refusal path by accident.
	m.mu.Lock()
	obsoleteFrom := m.registryObsoleteFrom
	m.mu.Unlock()
	if obsoleteFrom != 0 {
		t.Fatalf("fixture broken: Close set registryObsoleteFrom=%d — Close must NOT mark a "+
			"generation superseded, or hitless restart loses its retained handles", obsoleteFrom)
	}

	if _, present, _ := m.lookupMapLocked("sessions"); !present {
		t.Error("a CLOSE-retained registry must still SERVE its handle — proceed-on-retained " +
			"(#2114 A3) is preserved exactly where it was argued for. AC1 declines a " +
			"generation TEARDOWN superseded; it does not weaken the rule")
	}
	if got := m.ObsoleteRegistryAccesses(); got != 0 {
		t.Errorf("refusal count = %d, want 0 — nothing was superseded, so nothing is refused", got)
	}
}

// TestRepublishEndsTheObsoleteEpoch_6741 pins the other half: a new publish
// makes the registry current again, so the counter must STOP moving. Without
// this the counter would latch on forever after the first Teardown and every
// later reading would be noise.
func TestRepublishEndsTheObsoleteEpoch_6741(t *testing.T) {
	m := regTestManager6741()
	m.mu.Lock()
	m.registryGeneration = 1
	m.registryObsoleteFrom = 1
	m.maps["sessions"] = &ebpf.Map{}
	m.mu.Unlock()

	m.lookupMapLocked("sessions")
	before := m.ObsoleteRegistryAccesses()
	if before != 1 {
		t.Fatalf("premise broken: expected the obsolete epoch to count 1, got %d", before)
	}

	// A re-Start publishes a fresh generation above the obsolete boundary.
	m.mu.Lock()
	m.registryGeneration++
	m.mu.Unlock()

	m.lookupMapLocked("sessions")
	m.lookupMapLocked("sessions")
	if got := m.ObsoleteRegistryAccesses(); got != before {
		t.Errorf("count moved from %d to %d after a republish — the epoch ended, so these "+
			"lookups serve the CURRENT generation and must not be counted", before, got)
	}
}

// TestCloseDoesNotStartAnObsoleteEpoch_6741 is the precision case, and it is the
// one most likely to regress. Close() keeps its pinned handles LIVE on purpose
// for hitless restart, so a Close-retained registry is not obsolete — only
// Teardown, whose Cleanup destroys the pinned objects, supersedes a generation.
//
// A counter that fired on Close would report on every ordinary daemon restart
// and be dismissed as noise within a day.
func TestCloseDoesNotStartAnObsoleteEpoch_6741(t *testing.T) {
	m := regTestManager6741()
	m.mu.Lock()
	m.registryGeneration = 3
	m.maps["sessions"] = &ebpf.Map{}
	m.mu.Unlock()
	m.loaded.Store(true)

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.lookupMapLocked("sessions")
	if got := m.ObsoleteRegistryAccesses(); got != 0 {
		t.Errorf("Close started an obsolete epoch (count=%d). Close deliberately keeps its "+
			"pinned handles live for hitless-restart reuse; only Teardown's Cleanup "+
			"destroys them", got)
	}
}

// TestAbsentLookupIsNotCounted_6741 keeps the counter honest about what it
// measures. A miss serves no handle, so there is nothing obsolete to mutate; a
// counter that included misses would inflate exactly during the fresh/retained
// windows where lookups miss most often.
func TestAbsentLookupIsNotCounted_6741(t *testing.T) {
	m := regTestManager6741()
	m.mu.Lock()
	m.registryGeneration = 1
	m.registryObsoleteFrom = 1
	m.mu.Unlock()

	m.lookupMapLocked("no_such_map")
	m.lookupProgramLocked("no_such_program")
	if got := m.ObsoleteRegistryAccesses(); got != 0 {
		t.Errorf("a lookup that found NOTHING was counted as an obsolete access (%d) — it "+
			"served no handle, so no obsolete mutation is possible through it", got)
	}
}

// TestProgramLookupCountedToo_6741 covers the second choke point. The two
// helpers are separate functions with the same rule, which is exactly the shape
// where one gets updated and the other does not.
func TestProgramLookupCountedToo_6741(t *testing.T) {
	m := regTestManager6741()
	m.mu.Lock()
	m.registryGeneration = 1
	m.registryObsoleteFrom = 1
	m.programs["xdp_entry"] = &ebpf.Program{}
	m.mu.Unlock()

	m.lookupProgramLocked("xdp_entry")
	if got := m.ObsoleteRegistryAccesses(); got != 1 {
		t.Errorf("program-registry lookup was not counted (%d) — lookupProgramLocked is the "+
			"sibling choke point and carries the identical rule", got)
	}
}

// TestPublishBumpsTheGeneration_6741 binds the producer side. Without the bump
// the obsolete epoch could never end, so every test above would still pass while
// the counter latched permanently after the first Teardown.
func TestPublishBumpsTheGeneration_6741(t *testing.T) {
	m := regTestManager6741()
	m.mu.Lock()
	before := m.registryGeneration
	m.mu.Unlock()

	m.publishShimRegistryLocked(&ebpf.Program{}, map[string]*ebpf.Map{"sessions": {}}, nil)

	m.mu.Lock()
	after := m.registryGeneration
	m.mu.Unlock()
	if after != before+1 {
		t.Errorf("registryGeneration %d -> %d, want +1: the publisher is what ends an "+
			"obsolete epoch, so a missing bump latches the counter on forever", before, after)
	}
}
