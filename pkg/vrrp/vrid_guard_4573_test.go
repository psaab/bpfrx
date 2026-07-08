package vrrp

import "testing"

// #4573 defensive runtime VRID guard: UpdateInstances must refuse to build a
// VRRP instance whose GroupID falls outside the RFC 5798 VRID range 1..255. The
// config-layer commit gate (validateVRRPGroupIDStrict) rejects an out-of-range
// id, but the tolerant load / HA-sync path downgrades that gate to a warning
// (#1960 no-brick), so a bad id could reach the manager and would otherwise be
// truncated onto the single VRID wire byte — advertising the reserved VRID 0
// (256→0) or an aliased VRID (257→1). The guard drops such an instance instead.
//
// FAIL-ON-REVERT: remove the range guard at the top of the UpdateInstances
// desired loop and the out-of-range ids get instances built (openInstanceSocket
// called, m.instances populated) — the wrong-VRID advert this guard prevents.
func TestUpdateInstances_SkipsOutOfRangeVRID(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	desired := []*Instance{
		{Interface: "reth0", GroupID: 0, VirtualAddresses: []string{"10.0.61.1/24"}},   // reserved VRID 0
		{Interface: "reth0", GroupID: 256, VirtualAddresses: []string{"10.0.61.2/24"}}, // wraps to 0
		{Interface: "reth0", GroupID: -1, VirtualAddresses: []string{"10.0.61.3/24"}},  // below range
		{Interface: "reth1", GroupID: 100, VirtualAddresses: []string{"10.0.62.1/24"}}, // valid
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	n := len(m.instances)
	_, haveValid := m.instances[instanceKey{iface: "reth1", groupID: 100}]
	_, haveZero := m.instances[instanceKey{iface: "reth0", groupID: 0}]
	_, haveWrap := m.instances[instanceKey{iface: "reth0", groupID: 256}]
	_, haveNeg := m.instances[instanceKey{iface: "reth0", groupID: -1}]
	m.mu.RUnlock()

	if !haveValid {
		t.Error("valid VRID 100 instance should have been built")
	}
	if haveZero || haveWrap || haveNeg {
		t.Errorf("out-of-range VRID instances must be skipped (zero=%v wrap=%v neg=%v)",
			haveZero, haveWrap, haveNeg)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 instance (only the valid VRID), got %d", n)
	}

	// Only the single valid instance should have opened a socket.
	open, _, _ := rec.snapshot()
	if open != 1 {
		t.Errorf("openInstanceSocket calls = %d, want 1 (only the valid VRID)", open)
	}
}

// TestUpdateInstances_BoundaryVRIDsBuild pins that the range boundaries (1 and
// 255) are ACCEPTED — the guard must not over-reject a valid id.
func TestUpdateInstances_BoundaryVRIDsBuild(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	desired := []*Instance{
		{Interface: "reth0", GroupID: 1, VirtualAddresses: []string{"10.0.61.1/24"}},
		{Interface: "reth1", GroupID: 255, VirtualAddresses: []string{"10.0.62.1/24"}},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	n := len(m.instances)
	m.mu.RUnlock()
	if n != 2 {
		t.Fatalf("both boundary VRIDs (1 and 255) must build, got %d instances", n)
	}
}
