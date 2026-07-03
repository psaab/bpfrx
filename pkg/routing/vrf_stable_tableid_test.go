package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestReconcileVRFsStableTableIDNoRecreateOnSiblingDelete proves the #3855 fix
// at the VRF-reconcile layer: with STABLE name-hashed kernel table ids, deleting
// one routing-instance does NOT renumber the survivors, so reconcileVRFs never
// deletes+recreates an UNTOUCHED live VRF device (the link down/up + route
// reprogram forwarding outage the positional scheme caused on unrelated VRFs).
func TestReconcileVRFsStableTableIDNoRecreateOnSiblingDelete(t *testing.T) {
	idA := config.StableRoutingInstanceTableID("A")
	idB := config.StableRoutingInstanceTableID("B")
	idC := config.StableRoutingInstanceTableID("C")

	f := newFakeVRFOps()
	// Kernel currently has all three VRFs bound to their stable tables.
	f.seed("vrf-A", uint32(idA))
	f.seed("vrf-B", uint32(idB))
	f.seed("vrf-C", uint32(idC))

	// Operator deletes B. A and C keep their stable ids (invariant under
	// sibling churn) — the compiler still emits idA/idC for them.
	desired := []VRFSpec{
		{Name: "A", TableID: idA},
		{Name: "C", TableID: idC},
	}
	tracked := []string{"vrf-A", "vrf-B", "vrf-C"}
	newTracked, err := reconcileVRFs(f, tracked, desired)
	if err != nil {
		t.Fatalf("reconcileVRFs: %v", err)
	}

	// The whole point: no untouched VRF is recreated. Under the positional
	// scheme C's desired table would have shifted (102 -> 101) and this would be
	// adds=1/dels of the survivor.
	if f.adds != 0 {
		t.Errorf("adds = %d, want 0 (an untouched survivor must not be recreated)", f.adds)
	}
	if f.dels != 1 {
		t.Errorf("dels = %d, want 1 (only the removed vrf-B is deleted)", f.dels)
	}
	if !f.has("vrf-A") || !f.has("vrf-C") {
		t.Errorf("survivor VRF missing: has(vrf-A)=%v has(vrf-C)=%v", f.has("vrf-A"), f.has("vrf-C"))
	}
	if f.has("vrf-B") {
		t.Error("vrf-B was not deleted")
	}
	if len(newTracked) != 2 {
		t.Fatalf("newTracked = %v, want exactly [vrf-A vrf-C]", newTracked)
	}
	want := map[string]bool{"vrf-A": true, "vrf-C": true}
	for _, n := range newTracked {
		if !want[n] {
			t.Errorf("unexpected tracked VRF %q", n)
		}
	}
}

// TestReconcileVRFsRecreatesOnRealTableChange confirms the recreate-on-mismatch
// path is still intact for a GENUINE table-id change (e.g. a rename that folds
// to a different stable id) — the #3855 fix suppresses only spurious positional
// renumbering, never a real reconfig.
func TestReconcileVRFsRecreatesOnRealTableChange(t *testing.T) {
	f := newFakeVRFOps()
	oldTable := config.StableRoutingInstanceTableID("A")
	f.seed("vrf-A", uint32(oldTable))

	// A real change moves vrf-A to a different kernel table.
	newTable := oldTable + 12345
	if _, err := reconcileVRFs(f, []string{"vrf-A"}, []VRFSpec{{Name: "A", TableID: newTable}}); err != nil {
		t.Fatalf("reconcileVRFs: %v", err)
	}
	if f.dels != 1 || f.adds != 1 {
		t.Errorf("a real table change must delete+recreate: dels=%d adds=%d, want 1/1", f.dels, f.adds)
	}
	if got := f.links["vrf-A"].Table; got != uint32(newTable) {
		t.Errorf("vrf-A rebound to table %d, want %d", got, newTable)
	}
}
