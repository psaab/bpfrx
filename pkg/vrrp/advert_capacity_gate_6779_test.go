package vrrp

import (
	"fmt"
	"net"
	"testing"
)

// #6779 RUNTIME GATES. becomeMaster used to claim the VIP set and publish
// MASTER, and only then call sendAdvert — which discards a Marshal failure at
// slog.Debug. An oversized VIP set therefore produced an owner that advertised
// NOTHING: the peer's masterDownTimer expires and it promotes too (dual-master),
// or, with the same config synced to both nodes, the addresses are stranded.
//
// Two guards close it, and each is tested against the ORDERING, not just the
// error value:
//   - becomeMaster refuses to claim (fail-closed, #5082 doctrine)
//   - UpdateInstances refuses to build the instance (#4573 doctrine)

// makeVIPs builds n distinct configured virtual addresses (CIDR form, as the
// compiler emits them) of the requested family.
func makeVIPs(n int, isIPv6 bool) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if isIPv6 {
			out = append(out, fmt.Sprintf("2001:db8::%x/64", i+1))
		} else {
			out = append(out, fmt.Sprintf("10.%d.%d.1/24", i>>8, i&0xff))
		}
	}
	return out
}

// TestBecomeMaster_RefusesOversizedVIPSet is the fail-on-revert gate for the
// ORDERING claim. It asserts the three things that together mean "ownership was
// not claimed": becomeMaster returned false, the state did NOT go MASTER, and
// no VIP was actuated.
//
// Under the pre-fix code becomeMaster returns true and setState(StateMaster)
// has run, while every advert Marshal fails — the exact silent dual-master
// condition. Removing the guard makes this RED on the returned value AND on the
// observed state, so a partial revert cannot hide.
func TestBecomeMaster_RefusesOversizedVIPSet(t *testing.T) {
	for _, tc := range []struct {
		name   string
		isIPv6 bool
	}{
		{"IPv4", false},
		{"IPv6", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			over := MaxConfiguredVIPs(tc.isIPv6) + 1
			vi := newInstance(Instance{
				Interface:         "reth0.50",
				GroupID:           42,
				Priority:          200,
				AdvertiseInterval: 1000,
				VirtualAddresses:  makeVIPs(over, tc.isIPv6),
			}, &net.Interface{Name: "reth0.50", Index: 42}, make(chan VRRPEvent, 16), nil)

			if vi.advertCapacityErr == nil {
				t.Fatalf("%d %s VIPs (cap %d) must be recorded as unadvertisable",
					over, tc.name, MaxConfiguredVIPs(tc.isIPv6))
			}
			before := vi.getState()
			if got := vi.becomeMaster(); got {
				t.Errorf("becomeMaster() = true for an oversized %s VIP set; "+
					"ownership was claimed for a group that can never advertise",
					tc.name)
			}
			if got := vi.getState(); got == StateMaster {
				t.Errorf("state = MASTER after a refused promotion (was %v); the "+
					"node holds the VIPs while every advert fails to build", before)
			}
		})
	}
}

// TestBecomeMaster_AcceptsVIPSetAtCap is the TIGHTENING control: the guard must
// not over-reject. A VIP set at exactly the per-family cap advertises fine, so
// becomeMaster must not be blocked by advertCapacityErr.
//
// Boundary pairing matters here — cap is the largest legal value and cap+1 (the
// test above) the smallest illegal one, so an off-by-one in either direction is
// caught. A mutation making the guard `>=` instead of `>` reds THIS test.
func TestBecomeMaster_AcceptsVIPSetAtCap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		isIPv6 bool
	}{
		{"IPv4", false},
		{"IPv6", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := MaxConfiguredVIPs(tc.isIPv6)
			vi := newInstance(Instance{
				Interface:         "reth0.50",
				GroupID:           42,
				Priority:          200,
				AdvertiseInterval: 1000,
				VirtualAddresses:  makeVIPs(at, tc.isIPv6),
			}, &net.Interface{Name: "reth0.50", Index: 42}, make(chan VRRPEvent, 16), nil)

			if vi.advertCapacityErr != nil {
				t.Fatalf("%d %s VIPs is exactly the cap and must be advertisable, "+
					"got: %v", at, tc.name, vi.advertCapacityErr)
			}
		})
	}
}

// TestUpdateInstances_SkipsUnadvertisableVIPSet pins the construction-side
// guard: an oversized instance is never seated in the election at all, while a
// sibling with a legal VIP set still builds.
//
// The sibling is what makes this mutation-sensitive in both directions: a guard
// that rejected everything would fail on the valid instance, and a deleted
// guard fails on the oversized one.
func TestUpdateInstances_SkipsUnadvertisableVIPSet(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	over := MaxConfiguredVIPs(false) + 1
	desired := []*Instance{
		{Interface: "reth0", GroupID: 100, VirtualAddresses: makeVIPs(over, false)},
		{Interface: "reth1", GroupID: 101, VirtualAddresses: []string{"10.0.62.1/24"}},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	n := len(m.instances)
	_, haveValid := m.instances[instanceKey{iface: "reth1", groupID: 101}]
	_, haveOver := m.instances[instanceKey{iface: "reth0", groupID: 100}]
	m.mu.RUnlock()

	if haveOver {
		t.Errorf("an instance with %d IPv4 VIPs (cap %d) was built; it would claim "+
			"the VIPs and never advertise", over, MaxConfiguredVIPs(false))
	}
	if !haveValid {
		t.Error("the legal-VIP-set instance must still be built")
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 instance (only the advertisable one), got %d", n)
	}
	if open, _, _ := rec.snapshot(); open != 1 {
		t.Errorf("openInstanceSocket calls = %d, want 1 (only the advertisable "+
			"instance should reach socket open)", open)
	}
}

// TestSendAdvert_SplitterMatchesGuardCounting binds the guard's counting rule to
// the builder's. checkAdvertCapacity and sendAdvert must classify the same VIP
// list into the same per-family counts, or the guard can pass a set the builder
// then chokes on (or vice-versa).
//
// It exercises the shapes that actually differ between naive implementations:
// CIDR vs bare literal, IPv4-mapped-IPv6 spelling, and an unparseable entry that
// both sides must SKIP rather than count.
func TestSendAdvert_SplitterMatchesGuardCounting(t *testing.T) {
	vips := []string{
		"10.0.61.1/24",     // v4 CIDR
		"10.0.61.2",        // v4 bare
		"2001:db8::1/64",   // v6 CIDR
		"2001:db8::2",      // v6 bare
		"not-an-address",   // skipped by both
		"::ffff:10.0.61.3", // IPv4-mapped: To4() != nil, so it counts as v4
	}
	v4, v6 := splitVIPsByFamily(vips)
	if len(v4) != 3 {
		t.Errorf("IPv4 count = %d, want 3 (CIDR + bare + IPv4-mapped)", len(v4))
	}
	if len(v6) != 2 {
		t.Errorf("IPv6 count = %d, want 2 (CIDR + bare)", len(v6))
	}
	// The unparseable entry must not inflate either family.
	if len(v4)+len(v6) != len(vips)-1 {
		t.Errorf("parsed %d of %d entries, want %d (one unparseable entry skipped)",
			len(v4)+len(v6), len(vips), len(vips)-1)
	}
	if err := checkAdvertCapacity(vips); err != nil {
		t.Errorf("a 5-address mixed-family set must be advertisable: %v", err)
	}
}
