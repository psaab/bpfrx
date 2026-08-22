package daemon

import (
	"errors"
	"io/fs"
	"testing"
)

// #5250 (A7-b2 F2). readQueueCount returned a bare int and yielded 0 on a sysfs
// ReadDir error, so a FAILED enumeration and a NIC that genuinely reports zero
// RX queues arrived at applyRSSIndirectionOne as the same value. The failure was
// then logged at INFO as `queues=0 reason="queue count unknown"`, which reads as
// a decision made about a real NIC, and fell through the `queues > 1` guard so
// the stale-table restore never ran either.
//
// Widening the seam to (int, error) is what makes the two distinguishable. This
// test pins BOTH sides of the distinction, since a guard that only checks the
// error case cannot see a fix that swallowed the genuine-zero case with it.
func TestReadQueueCountErrorIsNotAGenuineZero(t *testing.T) {
	t.Run("enumeration error touches no ethtool", func(t *testing.T) {
		f := &fakeRSSExecutor{
			drivers:   map[string]string{"eth0": "mlx5_core"},
			queueErrs: map[string]error{"eth0": fs.ErrNotExist},
			ethtoolX:  map[string][]byte{"eth0": defaultRSSTable6q},
		}
		applyRSSIndirectionOne("eth0", 4, f)
		if len(f.calls) != 0 {
			t.Fatalf("a failed RX-queue enumeration must not run ethtool at all, got %v", f.calls)
		}
	})

	t.Run("genuine zero still takes the skip path", func(t *testing.T) {
		f := &fakeRSSExecutor{
			drivers:  map[string]string{"eth0": "mlx5_core"},
			queues:   map[string]int{"eth0": 0},
			ethtoolX: map[string][]byte{"eth0": defaultRSSTable6q},
		}
		applyRSSIndirectionOne("eth0", 4, f)
		if len(f.calls) != 0 {
			t.Fatalf("a genuine zero-queue NIC must not run ethtool either, got %v", f.calls)
		}
	})

	t.Run("a real queue count still reshapes", func(t *testing.T) {
		f := &fakeRSSExecutor{
			drivers:  map[string]string{"eth0": "mlx5_core"},
			queues:   map[string]int{"eth0": 6},
			ethtoolX: map[string][]byte{"eth0": defaultRSSTable6q},
		}
		applyRSSIndirectionOne("eth0", 4, f)
		if len(f.calls) != 2 {
			t.Fatalf("workers=4 queues=6 must probe then write, got %v", f.calls)
		}
	})
}

// The seam must actually REPORT the error rather than folding it into the
// count — a (0, nil) return would leave the caller as blind as before.
func TestFakeExecutorSurfacesTheEnumerationError(t *testing.T) {
	f := &fakeRSSExecutor{queueErrs: map[string]error{"eth0": fs.ErrNotExist}}
	n, err := f.readQueueCount("eth0")
	if err == nil {
		t.Fatal("readQueueCount must return the enumeration error, not fold it into the count")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("readQueueCount error = %v, want fs.ErrNotExist", err)
	}
	if n != 0 {
		t.Fatalf("readQueueCount count = %d on error, want 0", n)
	}
}

var defaultRSSTable6q = []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
    8:      0     1     2     3     4     5
   16:      0     1     2     3     4     5
`)
