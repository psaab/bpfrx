package userspace

import (
	"net"
	"testing"
	"time"
)

// #5250 (A6-b2 F1). ForEachSnapshotNeighbor held m.mu across the callback
// (`m.mu.Lock(); defer m.mu.Unlock()` around `fn(...)`). m.mu is a plain
// sync.Mutex, so any callback that re-entered a Manager method that also takes
// m.mu — SnapshotHasIfindex here, and the force-probe consumer's own path in
// production — self-deadlocked with no timeout and no error.
//
// This test RUNS the re-entrant callback on a goroutine and fails on a
// deadline. Reverting the walk to invoke fn under the lock makes it hang and
// therefore RED at the deadline. The deadline is generous (5s) because it
// bounds a HANG, not a latency: the fixed path completes in microseconds, so
// the value can never make the test flaky in the passing direction.
func TestForEachSnapshotNeighborDoesNotHoldTheLockAcrossTheCallback(t *testing.T) {
	m := &Manager{
		neighborIndex: map[neighborIndexKey]*NeighborSnapshot{
			{ifindex: 7, ip: "10.0.0.1"}: {Ifindex: 7, IP: "10.0.0.1"},
			{ifindex: 7, ip: "10.0.0.2"}: {Ifindex: 7, IP: "10.0.0.2"},
			{ifindex: 9, ip: "10.0.1.1"}: {Ifindex: 9, IP: "10.0.1.1"},
		},
	}

	type visit struct {
		ifindex int
		ip      string
	}
	done := make(chan []visit, 1)
	go func() {
		var seen []visit
		m.ForEachSnapshotNeighbor(func(ifindex int, ip net.IP) {
			// Re-enter the Manager from inside the callback. Under the old
			// lock-across-callback shape this blocks forever on the FIRST
			// entry, so `seen` never reaches len 3 and `done` never closes.
			if !m.SnapshotHasIfindex(ifindex) {
				t.Errorf("SnapshotHasIfindex(%d) = false inside the callback", ifindex)
			}
			seen = append(seen, visit{ifindex, ip.String()})
		})
		done <- seen
	}()

	select {
	case seen := <-done:
		if len(seen) != 3 {
			t.Fatalf("visited %d neighbors, want 3: %v", len(seen), seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ForEachSnapshotNeighbor DEADLOCKED: a callback that re-enters the " +
			"Manager blocked, so m.mu is being held across fn() again")
	}
}

// An entry whose IP does not parse is skipped, as before — the snapshot copy
// must not change which neighbors are delivered.
func TestForEachSnapshotNeighborSkipsUnparseableIP(t *testing.T) {
	m := &Manager{
		neighborIndex: map[neighborIndexKey]*NeighborSnapshot{
			{ifindex: 1, ip: "10.0.0.1"}:  {Ifindex: 1, IP: "10.0.0.1"},
			{ifindex: 1, ip: "not-an-ip"}: {Ifindex: 1, IP: "not-an-ip"},
		},
	}
	n := 0
	m.ForEachSnapshotNeighbor(func(_ int, ip net.IP) {
		n++
		if ip.String() != "10.0.0.1" {
			t.Errorf("delivered unexpected ip %q", ip)
		}
	})
	if n != 1 {
		t.Fatalf("delivered %d neighbors, want 1 (the unparseable entry must be skipped)", n)
	}
}
