package dataplane

import "testing"

// TestAssignNATCounterIDTypeNamespaceNoCollision is the #2218 fail-on-revert
// guard for the counter-ID collision MINOR. Before the fix the per-rule NAT
// counter map was keyed by "ruleset/rule" only, so the SAME (ruleset, rule)
// name pair reused across source-, destination-, and static-NAT collided on a
// single counter ID and merged their hit counts. The fix prefixes the key with
// the NAT type (dataplane.NATCounterKey → snat/dnat/static).
//
// Reverting the type prefix at the write site (assignNATCounterID) makes the
// three same-named rules return the SAME id and this test fails.
func TestAssignNATCounterIDTypeNamespaceNoCollision(t *testing.T) {
	result := &CompileResult{
		NATCounterIDs: make(map[string]uint32),
	}

	const ruleSet = "rs1"
	const rule = "r1"

	snat := assignNATCounterID(result, NATCounterTypeSource, ruleSet, rule)
	dnat := assignNATCounterID(result, NATCounterTypeDest, ruleSet, rule)
	static := assignNATCounterID(result, NATCounterTypeStatic, ruleSet, rule)

	if snat == 0 || dnat == 0 || static == 0 {
		t.Fatalf("counter IDs must be non-zero: snat=%d dnat=%d static=%d", snat, dnat, static)
	}
	if snat == dnat || snat == static || dnat == static {
		t.Fatalf("same-named SNAT/DNAT/static rules collided on a counter ID: snat=%d dnat=%d static=%d (type prefix reverted?)",
			snat, dnat, static)
	}

	// The map must carry three distinct, type-namespaced keys.
	wantKeys := []string{
		NATCounterKey(NATCounterTypeSource, ruleSet, rule),
		NATCounterKey(NATCounterTypeDest, ruleSet, rule),
		NATCounterKey(NATCounterTypeStatic, ruleSet, rule),
	}
	if len(result.NATCounterIDs) != len(wantKeys) {
		t.Fatalf("NATCounterIDs has %d keys, want %d: %v", len(result.NATCounterIDs), len(wantKeys), result.NATCounterIDs)
	}
	for _, k := range wantKeys {
		if _, ok := result.NATCounterIDs[k]; !ok {
			t.Fatalf("NATCounterIDs missing key %q: %v", k, result.NATCounterIDs)
		}
	}

	// Re-assigning the same (type, ruleset, rule) must REUSE the id (shared
	// across expanded address/port pairs), not allocate a new slot.
	if reuse := assignNATCounterID(result, NATCounterTypeSource, ruleSet, rule); reuse != snat {
		t.Fatalf("re-assign snat id = %d, want reuse of %d", reuse, snat)
	}
	if len(result.NATCounterIDs) != len(wantKeys) {
		t.Fatalf("re-assign allocated a new slot: %v", result.NATCounterIDs)
	}
}
