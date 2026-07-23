package userspace

import "testing"

// TestSyntheticLogicalIfindex_ExhaustionReturnsSentinel_5557 pins that
// syntheticLogicalIfindex degrades to the negative sentinel when its entire
// private range is already claimed, instead of panicking and crash-looping the
// daemon. Exhaustion is unreachable in practice (it needs >1<<20 logical-only
// VLAN units on one box), but the snapshot builder must not take down the whole
// daemon on it.
//
// FAIL-ON-REVERT: restore the panic() in syntheticLogicalIfindex and this test
// panics (a test panic is a FAIL) instead of observing the sentinel.
func TestSyntheticLogicalIfindex_ExhaustionReturnsSentinel_5557(t *testing.T) {
	span := syntheticInterfaceIfindexMax - syntheticInterfaceIfindexMin + 1
	used := make(map[int]struct{}, span)
	for v := syntheticInterfaceIfindexMin; v <= syntheticInterfaceIfindexMax; v++ {
		used[v] = struct{}{}
	}

	got := syntheticLogicalIfindex("reth0.80", 80, used)
	if got != syntheticIfindexExhausted {
		t.Fatalf("exhausted range: syntheticLogicalIfindex = %d, want sentinel %d", got, syntheticIfindexExhausted)
	}
}
