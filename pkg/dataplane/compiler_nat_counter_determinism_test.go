package dataplane

import (
	"fmt"
	"maps"
	"testing"
)

// assignAndFinalize mirrors the compile pipeline: stream the rule keys through
// assignNATCounterID (as SNAT/DNAT/static compilation does) and then run the
// order-independent finalize pass, returning the AUTHORITATIVE counter-ID map.
func assignAndFinalize(order []string) map[string]uint32 {
	result := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	for _, rule := range order {
		assignNATCounterID(result, NATCounterTypeSource, "rs", rule)
	}
	finalizeNATCounterIDs(result)
	return result.NATCounterIDs
}

// TestFinalizeNATCounterIDsDeterministicUnderReorder is the #5099 fail-on-revert
// guard. Two DISTINCT source-NAT rule keys collide on their FNV-1a base id
// (0xea231588) AND on their "#1" re-hash (487396352) — the exact double
// collision from the issue.
//
// assignNATCounterID alone is compile-order dependent on a collision: whichever
// key compiles FIRST claims the base id and the other is bumped, so swapping the
// rule order swaps their counter ids. finalizeNATCounterIDs re-derives the ids
// in a stable sorted order, so the assignment is identical regardless of compile
// order. Reverting the finalize pass (or emptying its body) makes the forward
// and reverse compiles disagree and this test fails.
func TestFinalizeNATCounterIDsDeterministicUnderReorder(t *testing.T) {
	const (
		ruleSet = "rs"
		ruleA   = "rule-91588"
		ruleB   = "rule-154876"
	)
	kA := NATCounterKey(NATCounterTypeSource, ruleSet, ruleA)
	kB := NATCounterKey(NATCounterTypeSource, ruleSet, ruleB)

	// Precondition: the two keys must actually collide on the base id, otherwise
	// the test would not exercise the collision fallback at all. Guards against a
	// future hash change silently defusing this regression test.
	if natCounterIDForKey(kA) != natCounterIDForKey(kB) {
		t.Fatalf("test precondition broken: %q and %q no longer share a base id "+
			"(%d vs %d) — pick new colliding rule names",
			kA, kB, natCounterIDForKey(kA), natCounterIDForKey(kB))
	}

	fwd := assignAndFinalize([]string{ruleA, ruleB})
	rev := assignAndFinalize([]string{ruleB, ruleA})

	// The whole assignment must be byte-for-byte identical across compile order.
	if !maps.Equal(fwd, rev) {
		t.Fatalf("NAT counter-id assignment is compile-order dependent (#5099 regressed):\n"+
			"  forward (A,B) = %v\n  reverse (B,A) = %v", fwd, rev)
	}

	// Explicitly: each colliding rule keeps its own id across the reorder.
	if fwd[kA] != rev[kA] {
		t.Fatalf("rule %q id swapped on reorder: %d vs %d", kA, fwd[kA], rev[kA])
	}
	if fwd[kB] != rev[kB] {
		t.Fatalf("rule %q id swapped on reorder: %d vs %d", kB, fwd[kB], rev[kB])
	}

	// Collision-avoidance preserved: distinct keys keep distinct, non-zero ids.
	if fwd[kA] == 0 || fwd[kB] == 0 {
		t.Fatalf("colliding rule assigned counter 0: %v", fwd)
	}
	if fwd[kA] == fwd[kB] {
		t.Fatalf("collision not resolved — both rules share id %d: %v", fwd[kA], fwd)
	}
}

// TestFinalizeNATCounterIDsUniqueAndOrderIndependentAtScale assigns ids for the
// full documented cap in two opposite input orders and asserts (a) the finalized
// map is identical regardless of order and (b) every id is unique and non-zero
// (the collision-avoidance guarantee survives the deterministic re-derivation).
func TestFinalizeNATCounterIDsUniqueAndOrderIndependentAtScale(t *testing.T) {
	build := func(reverse bool) map[string]uint32 {
		result := &CompileResult{NATCounterIDs: make(map[string]uint32)}
		for i := 0; i < MaxNATRuleCounters; i++ {
			j := i
			if reverse {
				j = MaxNATRuleCounters - 1 - i
			}
			assignNATCounterID(result, NATCounterTypeSource, "rs", fmt.Sprintf("rule-%04d", j))
		}
		finalizeNATCounterIDs(result)
		return result.NATCounterIDs
	}

	forward := build(false)
	backward := build(true)

	if !maps.Equal(forward, backward) {
		t.Fatalf("finalize is not order-independent at scale (%d keys)", MaxNATRuleCounters)
	}

	seen := make(map[uint32]string, len(forward))
	for k, id := range forward {
		if id == 0 {
			t.Fatalf("id 0 assigned within cap for %q", k)
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("id %d assigned to both %q and %q (collision-avoidance regressed)", id, prev, k)
		}
		seen[id] = k
	}
	if len(seen) != MaxNATRuleCounters {
		t.Fatalf("expected %d distinct ids, got %d", MaxNATRuleCounters, len(seen))
	}
}

// TestFinalizeNATCounterIDsPreservesExhaustionZero confirms the finalize pass
// leaves exhausted keys (id 0, no per-rule attribution) untouched.
func TestFinalizeNATCounterIDsPreservesExhaustionZero(t *testing.T) {
	result := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	for i := 0; i < MaxNATRuleCounters; i++ {
		assignNATCounterID(result, NATCounterTypeSource, "rs", fmt.Sprintf("rule-%04d", i))
	}
	overKey := NATCounterKey(NATCounterTypeSource, "rs", "one-too-many")
	if got := assignNATCounterID(result, NATCounterTypeSource, "rs", "one-too-many"); got != 0 {
		t.Fatalf("rule past the cap got id %d, want 0", got)
	}

	finalizeNATCounterIDs(result)

	if id, ok := result.NATCounterIDs[overKey]; !ok || id != 0 {
		t.Fatalf("exhausted key lost its 0 after finalize: id=%d ok=%v", id, ok)
	}
}
