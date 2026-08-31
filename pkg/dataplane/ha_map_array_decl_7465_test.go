package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

// #7465 supporting leg: why the PUBLISH path's arm is already safe, so the gate
// added in pkg/dataplane/userspace is guarding the POLL path specifically.
//
// applyCompiledSnapshot runs refreshHAStateFromMapsLocked -> syncHAStateLocked
// -> syncDesiredForwardingStateLocked, each returning on error, so the publish
// path cannot arm before publishing. That argument rests on one property of
// code rather than of ordering: the HA maps are declared as fixed ARRAYS, and a
// BPF array is fully populated at creation — every redundancy-group index exists
// before anything writes to it — so a clustered refresh can never yield an EMPTY
// inventory to publish. Change them to hashes (sparse: an unwritten key does not
// exist) and an all-inactive clustered node could present an empty map, which
// makes the ha.rs `ha_state.is_empty()` fail-open reachable on the publish path
// too.
//
// THE ASSERTION IS ON THE DECLARATION, DELIBERATELY, and this is the part a
// future extender must not "improve". The stronger-looking cell — create the map
// and count what iteration yields — is VACUOUS in this environment: ebpf.NewMap
// fails with "operation not permitted (MEMLOCK may be too low)", the cell SKIPs,
// and `go test` prints `ok`. A skipped cell and a passing cell are
// indistinguishable in aggregate output, so the stronger property would be
// asserted by a test that never ran. The declaration check needs no privileges
// and therefore actually executes.
//
// The map-backed half is kept below as a BONUS that runs only where it can, and
// it is explicitly NOT the thing this cell rests on.
//
// FAIL-ON-REVERT: change either arrayMapSpec("rg_active"/"ha_watchdog", ...) in
// loader_userspace_shim.go to a hash spec, or drop MaxRedundancyGroups, and the
// declaration half reds — on every host, with no privileges.
func TestHAMapsDeclaredAsFullArrays7465(t *testing.T) {
	for _, name := range []string{"rg_active", "ha_watchdog"} {
		spec := sharedShimMapSpecByName(name)
		if spec == nil {
			t.Fatalf("%s absent from userspaceShimSharedMapSpecs. #7465's publish-path "+
				"safety argument rests on this map's declaration, so it must not "+
				"silently disappear", name)
		}
		if spec.Type != ebpf.Array {
			t.Errorf("%s declared as %v, want ebpf.Array. A sparse map means an "+
				"unwritten redundancy-group index does not exist, so a clustered node "+
				"can refresh an EMPTY HA inventory and publish nothing — which makes "+
				"the ha.rs LocalDelivery fail-open reachable on the publish path, not "+
				"just the poll path", name, spec.Type)
		}
		if spec.MaxEntries != MaxRedundancyGroups {
			t.Errorf("%s MaxEntries = %d, want MaxRedundancyGroups (%d); the inventory "+
				"is only 'full by construction' if it is sized to the group space",
				name, spec.MaxEntries, MaxRedundancyGroups)
		}
	}
}

// The map-backed property, where privileges allow it. This SKIPS on a host
// without MEMLOCK headroom, which is exactly why it is not the cell the argument
// rests on — see TestHAMapsDeclaredAsFullArrays7465. It is worth running where
// it can because it checks the kernel's behaviour rather than our reading of it.
func TestHAMapsIterateFullyPopulated7465(t *testing.T) {
	for _, name := range []string{"rg_active", "ha_watchdog"} {
		spec := sharedShimMapSpecByName(name)
		if spec == nil {
			t.Fatalf("%s absent from userspaceShimSharedMapSpecs", name)
		}
		m, err := ebpf.NewMap(spec.Copy())
		if err != nil {
			// Report the skip with its reason. A silent skip here would read as a
			// pass for the property below, which is the #7465 trap this file exists
			// to warn about.
			t.Skipf("SKIP (not a pass): cannot create %s from its production spec: %v", name, err)
		}

		// Nothing is written: a freshly-loaded shim on a clustered node with zero
		// configured redundancy-groups is exactly this state.
		var (
			key   uint32
			val   []byte
			count uint32
		)
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			count++
		}
		err = iter.Err()
		m.Close()
		if err != nil {
			t.Fatalf("iterate %s: %v", name, err)
		}
		if count != MaxRedundancyGroups {
			t.Errorf("%s yields %d entries with nothing written, want %d — the array is "+
				"not fully populated by construction and the publish-path argument fails",
				name, count, MaxRedundancyGroups)
		}
	}
}
