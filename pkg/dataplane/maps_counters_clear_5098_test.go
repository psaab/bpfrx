package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

// Test_clear_global_counters_read_equation_zero_5098 pins the #5098 fix against
// the FULL ReadGlobalCounter read equation: the per-CPU BPF array sum PLUS the
// in-memory userspaceCounterOffsets entry. Before #5098 ClearGlobalCounters
// zeroed only the BPF array, so a cleared total snapped back to the surviving
// offset on the next read.
//
// This needs a real PERCPU_ARRAY map, so it skips on an unprivileged host (no
// BPF map creation). The always-on fail-on-revert gate lives in the userspace
// package (Test_clear_global_counters_resets_userspace_offset_5098), which keys
// on the offset half without a map.
func Test_clear_global_counters_read_equation_zero_5098(t *testing.T) {
	gc, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: GlobalCtrMax,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new global_counters map", err)
	}
	t.Cleanup(func() { gc.Close() })

	m := &Manager{maps: map[string]*ebpf.Map{"global_counters": gc}}

	const idx = GlobalCtrRxPackets

	// Seed BOTH halves of the read equation: a per-CPU BPF array value and an
	// in-memory userspace offset.
	numCPUs := ebpf.MustPossibleCPU()
	arr := make([]uint64, numCPUs)
	arr[0] = 7
	// #9337: uint32(idx), not idx. `const idx = GlobalCtrRxPackets` is an
	// UNTYPED constant, so passing it to Update's interface{} key boxes it as
	// `int` and cilium/ebpf refuses with "some values are not fixed-sized in
	// type int" — the map key is 4 bytes. The sibling calls below take a typed
	// parameter and convert implicitly, which is why only this one failed. The
	// cell needs a real BPF map, so it skips unprivileged and this never
	// surfaced under `make test-go`.
	if err := gc.Update(uint32(idx), arr, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed global_counters array: %v", err)
	}
	if err := m.IncrementGlobalCounter(idx, 100); err != nil {
		t.Fatalf("seed offset: %v", err)
	}

	got, err := m.ReadGlobalCounter(idx)
	if err != nil {
		t.Fatalf("ReadGlobalCounter (seed): %v", err)
	}
	if got != 107 {
		t.Fatalf("ReadGlobalCounter (seed) = %d, want 107 (array 7 + offset 100)", got)
	}

	if err := m.ClearGlobalCounters(); err != nil {
		t.Fatalf("ClearGlobalCounters: %v", err)
	}
	got, err = m.ReadGlobalCounter(idx)
	if err != nil {
		t.Fatalf("ReadGlobalCounter (post-clear): %v", err)
	}
	if got != 0 {
		t.Fatalf("ReadGlobalCounter after clear = %d, want 0 "+
			"(cleared total snaps back — #5098 offset reset reverted?)", got)
	}

	// A new offset after the clear accrues from zero (epoch restarted).
	if err := m.IncrementGlobalCounter(idx, 5); err != nil {
		t.Fatalf("post-clear IncrementGlobalCounter: %v", err)
	}
	got, err = m.ReadGlobalCounter(idx)
	if err != nil {
		t.Fatalf("ReadGlobalCounter (post-clear accrual): %v", err)
	}
	if got != 5 {
		t.Fatalf("ReadGlobalCounter after post-clear accrual = %d, want 5", got)
	}
}
