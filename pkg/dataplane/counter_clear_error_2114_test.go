package dataplane

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// #2114 (Codex PR #6743 r4-F2): the blind-write counter-clear loops used
// to discard every Update error and return nil, so `clear security
// policies statistics` and `clear firewall counters` reported success
// unconditionally — including against a dataplane whose state the
// commit-confirmed rollback had already detached.
//
// These bind the propagation through the counterMapUpdater seam. A real
// *ebpf.Map cannot be used: map creation returns EPERM in the
// unprivileged unit lane (verified), and a test that SKIPS leaves the
// mutation cell unknown rather than green.

// fakeCounterUpdater records every Update and fails at one chosen index.
type fakeCounterUpdater struct {
	failAt   uint32
	fail     bool
	calls    int
	maxKey   uint32
	sawFirst bool
}

func (f *fakeCounterUpdater) Update(key, _ any, _ ebpf.MapUpdateFlags) error {
	f.calls++
	k, ok := key.(uint32)
	if !ok {
		return errors.New("clear loop passed a non-uint32 key")
	}
	if !f.sawFirst || k > f.maxKey {
		f.maxKey = k
		f.sawFirst = true
	}
	if f.fail && k == f.failAt {
		return errors.New("synthetic map update failure (#2114 r4 test)")
	}
	return nil
}

// TestClearPolicyCountersIn_PropagatesUpdateError is the binder.
//
// Fail-on-revert: drop the `if err := ...; err != nil { return ... }`
// wrapper in clearPolicyCountersIn (pkg/dataplane/maps_policy.go) back to
// a bare `zm.Update(i, zero, ebpf.UpdateAny)` and this reports a nil
// error for a map that rejected the write.
func TestClearPolicyCountersIn_PropagatesUpdateError(t *testing.T) {
	t.Parallel()

	up := &fakeCounterUpdater{failAt: 7, fail: true}
	err := clearPolicyCountersIn(up)
	if err == nil {
		t.Fatal("clearPolicyCountersIn reported SUCCESS after the map rejected the write at index 7; " +
			"the operator's clear silently did nothing")
	}
	if !strings.Contains(err.Error(), "policy_counters") {
		t.Fatalf("error %q does not name the map", err)
	}
}

// TestClearFilterCountersIn_PropagatesUpdateError is the filter twin.
//
// Fail-on-revert: the same wrapper in clearFilterCountersIn
// (pkg/dataplane/maps_filter.go).
func TestClearFilterCountersIn_PropagatesUpdateError(t *testing.T) {
	t.Parallel()

	up := &fakeCounterUpdater{failAt: 3, fail: true}
	err := clearFilterCountersIn(up)
	if err == nil {
		t.Fatal("clearFilterCountersIn reported SUCCESS after the map rejected the write at index 3; " +
			"the operator's clear silently did nothing")
	}
	if !strings.Contains(err.Error(), "filter_counters") {
		t.Fatalf("error %q does not name the map", err)
	}
}

// TestClearCountersIn_HealthyMapStillClearsEveryEntry is the OVER-REACH
// guard: propagating an error must not change what a HEALTHY clear does.
// Both loops must still succeed and still cover every slot the map holds
// (MAX_POLICIES 4096 / MAX_FILTER_RULES 512 — the maps' max_entries), so
// the fix cannot have narrowed the sweep or stopped it early. GREEN under
// both reverts above.
func TestClearCountersIn_HealthyMapStillClearsEveryEntry(t *testing.T) {
	t.Parallel()

	policy := &fakeCounterUpdater{}
	if err := clearPolicyCountersIn(policy); err != nil {
		t.Fatalf("healthy policy clear returned %v, want nil", err)
	}
	if policy.calls != 4096 || policy.maxKey != 4095 {
		t.Fatalf("policy clear wrote %d entries up to index %d, want 4096 up to 4095 (MAX_POLICIES)",
			policy.calls, policy.maxKey)
	}

	filter := &fakeCounterUpdater{}
	if err := clearFilterCountersIn(filter); err != nil {
		t.Fatalf("healthy filter clear returned %v, want nil", err)
	}
	if filter.calls != MaxFilterRules || filter.maxKey != MaxFilterRules-1 {
		t.Fatalf("filter clear wrote %d entries up to index %d, want %d up to %d (MAX_FILTER_RULES)",
			filter.calls, filter.maxKey, MaxFilterRules, MaxFilterRules-1)
	}
}

// TestCounterMapUpdaterIsSatisfiedByEBPFMap keeps the seam honest: the
// interface the clear loops take must be exactly what *ebpf.Map already
// provides, so the production call sites pass the real map unchanged and
// the fake above cannot drift into a shape production never uses.
func TestCounterMapUpdaterIsSatisfiedByEBPFMap(t *testing.T) {
	t.Parallel()

	var _ counterMapUpdater = (*ebpf.Map)(nil)
}
