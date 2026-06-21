package dataplane

import (
	"fmt"
	"testing"
)

// TestAssignNATCounterIDStableAcrossReorder is the #2255 fail-on-revert guard.
//
// The per-rule NAT translation-hit counter_id MUST be a function of the rule's
// IDENTITY (its NATCounterKey), not of its compile-time position. Before the
// fix, ids were assigned sequentially (nextNATCounterID reset to 1 each
// compile), so reordering rules A,B -> B,A reused A's id (1) for B and vice
// versa. Because the Rust helper keeps a CUMULATIVE numeric-keyed counter store
// (reconcile_ids retains, does not reset), the reused id made the new rule
// inherit the old rule's count -> cross-rule mis-attribution.
//
// Reverting assignNATCounterID to a position counter makes this test fail:
// the reordered compile would hand B the id that A got in the first compile.
func TestAssignNATCounterIDStableAcrossReorder(t *testing.T) {
	const ruleSet = "rs1"

	// First compile: rules in order A, B.
	first := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	idA1 := assignNATCounterID(first, NATCounterTypeSource, ruleSet, "rule-a")
	idB1 := assignNATCounterID(first, NATCounterTypeSource, ruleSet, "rule-b")

	if idA1 == 0 || idB1 == 0 {
		t.Fatalf("counter ids must be non-zero: A=%d B=%d", idA1, idB1)
	}
	if idA1 == idB1 {
		t.Fatalf("distinct rules must get distinct ids: A=%d B=%d", idA1, idB1)
	}

	// Second compile: rules REORDERED to B, A. A position counter would now
	// hand B the id A held (and A the id B held). The identity-derived id must
	// be unchanged for each rule.
	reordered := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	idB2 := assignNATCounterID(reordered, NATCounterTypeSource, ruleSet, "rule-b")
	idA2 := assignNATCounterID(reordered, NATCounterTypeSource, ruleSet, "rule-a")

	if idA2 != idA1 {
		t.Fatalf("rule-a id changed across reorder: was %d, now %d (position-based assignment reverted?)", idA1, idA2)
	}
	if idB2 != idB1 {
		t.Fatalf("rule-b id changed across reorder: was %d, now %d (position-based assignment reverted?)", idB1, idB2)
	}
}

// TestAssignNATCounterIDStableAcrossRemoval proves the surviving rule keeps its
// id when an UNRELATED rule that compiled earlier is removed. With a position
// counter, removing rule-a (which compiled first, id 1) would shift rule-b from
// id 2 to id 1 -> rule-b would then read the cumulative store slot 1 that still
// held rule-a's count (until reconcile dropped it) -> mis-attribution. The
// identity-derived id makes rule-b's id independent of rule-a's presence.
func TestAssignNATCounterIDStableAcrossRemoval(t *testing.T) {
	const ruleSet = "rs1"

	withBoth := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	_ = assignNATCounterID(withBoth, NATCounterTypeSource, ruleSet, "rule-a")
	idBWith := assignNATCounterID(withBoth, NATCounterTypeSource, ruleSet, "rule-b")

	// Recompile with rule-a removed.
	withoutA := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	idBWithout := assignNATCounterID(withoutA, NATCounterTypeSource, ruleSet, "rule-b")

	if idBWithout != idBWith {
		t.Fatalf("rule-b id changed when unrelated rule-a was removed: was %d, now %d", idBWith, idBWithout)
	}
}

// TestAssignNATCounterIDDeterministic asserts the same key always derives the
// same id (across independent CompileResults), which is what makes the helper
// store correct across daemon restarts and HA peers.
func TestAssignNATCounterIDDeterministic(t *testing.T) {
	a := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	b := &CompileResult{NATCounterIDs: make(map[string]uint32)}

	id1 := assignNATCounterID(a, NATCounterTypeDest, "dstnat", "web")
	id2 := assignNATCounterID(b, NATCounterTypeDest, "dstnat", "web")
	if id1 != id2 {
		t.Fatalf("same key derived different ids across compiles: %d vs %d", id1, id2)
	}
}

// TestAssignNATCounterIDUniqueAtScale assigns ids for a large set of distinct
// rule keys and asserts every id is unique and non-zero. The deterministic
// in-compile collision resolution in assignNATCounterID must guarantee
// uniqueness even on a (rare) hash collision.
func TestAssignNATCounterIDUniqueAtScale(t *testing.T) {
	result := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	const n = MaxNATRuleCounters // exercise up to the documented cap
	seen := make(map[uint32]string, n)
	for i := 0; i < n; i++ {
		rule := fmt.Sprintf("rule-%04d", i)
		id := assignNATCounterID(result, NATCounterTypeSource, "rs", rule)
		if id == 0 {
			t.Fatalf("id 0 assigned within cap for %q (count=%d)", rule, len(result.NATCounterIDs))
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("id %d assigned to both %q and %q (collision not resolved)", id, prev, rule)
		}
		seen[id] = rule
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct ids, got %d", n, len(seen))
	}
}

// TestAssignNATCounterIDExhaustionFallsBackToZero preserves the historical
// exhaustion contract: once MaxNATRuleCounters distinct counters are assigned,
// further rules fall back to counter 0 (no per-rule attribution).
func TestAssignNATCounterIDExhaustionFallsBackToZero(t *testing.T) {
	result := &CompileResult{NATCounterIDs: make(map[string]uint32)}
	for i := 0; i < MaxNATRuleCounters; i++ {
		assignNATCounterID(result, NATCounterTypeSource, "rs", fmt.Sprintf("rule-%04d", i))
	}
	over := assignNATCounterID(result, NATCounterTypeSource, "rs", "one-too-many")
	if over != 0 {
		t.Fatalf("rule past the cap got id %d, want 0 (exhaustion fallback)", over)
	}
}
