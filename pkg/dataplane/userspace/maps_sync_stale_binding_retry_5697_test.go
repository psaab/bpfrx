package userspace

import (
	"slices"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestClearStaleBindingRowsRetainsFailedClearInRetryInventory exercises the
// #5697 (codex-review-182 M20) fix: a stale userspace_bindings row whose
// zeroing Update FAILS must be RETAINED in the retry inventory
// (m.lastBindingIndices) so a later status pass re-attempts the clear, while a
// row whose clear SUCCEEDS is dropped from the inventory.
//
// Before the fix the clear result was discarded (`_ = bindingsMap.Update(...)`)
// and m.lastBindingIndices was unconditionally overwritten with only the live
// bindings, so a failed clear stranded a stale binding in the BPF map that the
// clear loop could never rediscover — the XDP shim kept steering transit to a
// slot no longer backed by a live worker.
func TestClearStaleBindingRowsRetainsFailedClearInRetryInventory(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()

	// A small Array bindings map makes the clear Update fail deterministically
	// for an out-of-bounds index (Array rejects key >= MaxEntries), matching
	// the production userspace_bindings Array without needing a mock.
	bindingsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(userspaceBindingValue{})),
		MaxEntries: 8,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_bindings array map", err)
	}
	t.Cleanup(func() { bindingsMap.Close() })

	const goodIdx = uint32(3) // in bounds — clear succeeds
	const badIdx = uint32(99) // out of bounds — clear fails

	// Seed a live-looking value at goodIdx so we can prove it gets zeroed.
	if err := bindingsMap.Update(goodIdx, userspaceBindingValue{Slot: 5, Flags: userspaceBindingReady}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed goodIdx: %v", err)
	}

	// Both rows were live on the previous pass; neither is live now (empty
	// newBindingIndexSet), so both are candidates for clearing.
	m.lastBindingIndices = []uint32{goodIdx, badIdx}

	retry := m.clearStaleBindingRowsLocked(bindingsMap, nil, map[uint32]struct{}{})

	// The failed clear (badIdx) MUST be retained so the watchdog re-attempts
	// it on a later pass. Dropping it is the M20 defect.
	if !slices.Contains(retry, badIdx) {
		t.Fatalf("retry inventory %v missing failed-clear idx %d; watchdog can never re-attempt the clear (M20 regression)", retry, badIdx)
	}
	// The successful clear (goodIdx) MUST be dropped from the inventory.
	if slices.Contains(retry, goodIdx) {
		t.Fatalf("retry inventory %v retains successfully-cleared idx %d; a cleared row must not be re-scanned", retry, goodIdx)
	}

	// The successful clear must actually have zeroed the BPF map row.
	var val userspaceBindingValue
	if err := bindingsMap.Lookup(goodIdx, &val); err != nil {
		t.Fatalf("lookup goodIdx after clear: %v", err)
	}
	if val.Slot != 0 || val.Flags != 0 {
		t.Fatalf("goodIdx row not zeroed after successful clear: %+v", val)
	}
}

// TestClearStaleBindingRowsKeepsLiveBindings verifies the clear loop leaves
// still-live bindings (present in newBindingIndexSet) untouched and carries
// them forward in the returned inventory.
func TestClearStaleBindingRowsKeepsLiveBindings(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	bindingsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(userspaceBindingValue{})),
		MaxEntries: 8,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_bindings array map", err)
	}
	t.Cleanup(func() { bindingsMap.Close() })

	const liveIdx = uint32(2)
	const staleIdx = uint32(4)
	if err := bindingsMap.Update(liveIdx, userspaceBindingValue{Slot: 1, Flags: userspaceBindingReady}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed liveIdx: %v", err)
	}
	if err := bindingsMap.Update(staleIdx, userspaceBindingValue{Slot: 2, Flags: userspaceBindingReady}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed staleIdx: %v", err)
	}

	m.lastBindingIndices = []uint32{liveIdx, staleIdx}
	newIndices := []uint32{liveIdx}
	newSet := map[uint32]struct{}{liveIdx: {}}

	retry := m.clearStaleBindingRowsLocked(bindingsMap, newIndices, newSet)

	if !slices.Contains(retry, liveIdx) {
		t.Fatalf("retry inventory %v dropped still-live idx %d", retry, liveIdx)
	}
	if slices.Contains(retry, staleIdx) {
		t.Fatalf("retry inventory %v retains cleared stale idx %d", retry, staleIdx)
	}

	// liveIdx must be untouched; staleIdx must be zeroed.
	var live userspaceBindingValue
	if err := bindingsMap.Lookup(liveIdx, &live); err != nil {
		t.Fatalf("lookup liveIdx: %v", err)
	}
	if live.Slot != 1 || live.Flags != userspaceBindingReady {
		t.Fatalf("live binding was modified: %+v", live)
	}
	var stale userspaceBindingValue
	if err := bindingsMap.Lookup(staleIdx, &stale); err != nil {
		t.Fatalf("lookup staleIdx: %v", err)
	}
	if stale.Slot != 0 || stale.Flags != 0 {
		t.Fatalf("stale binding not zeroed: %+v", stale)
	}
}
