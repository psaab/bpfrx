package vrrp

import (
	"sync"
	"testing"
	"time"
)

// #6230: advertInterval() read vi.cfg.AdvertiseInterval with NO lock while the
// run loop reset the advert timer, but every other cfg accessor snapshots
// vi.cfg under vi.mu (getState, masterDownInterval, preemptHoldDuration) and
// cfg writers mutate it under vi.mu.Lock(). That unsynchronized read is a data
// race the Go memory model forbids and `go test -race` flags. The fix snapshots
// AdvertiseInterval under vi.mu.RLock() (advertInterval), while the ONE caller
// that already holds the write lock — recordMasterAdvert → masterAdverFloor —
// reads via advertIntervalLocked so it does not self-deadlock on the RLock.
//
// These tests are the fail-on-revert gate. The race detector reports on the
// FIRST unsynchronized concurrent access, so a few thousand tightly interleaved
// iterations suffice and stay fast even under -race.

// TestAdvertIntervalNoRace6230 drives a LOCKED write of cfg.AdvertiseInterval
// (the config-update discipline every cfg writer, e.g. updateConfig, follows)
// concurrently with advertInterval() reads from a second goroutine. Under -race
// it is CLEAN with the RLock fix and DETECTS the race if advertInterval() is
// reverted to the unlocked read of vi.cfg.AdvertiseInterval.
func TestAdvertIntervalNoRace6230(t *testing.T) {
	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1, AdvertiseInterval: 30}}

	const iters = 5000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: a locked config update mutating AdvertiseInterval, mirroring the
	// vi.mu.Lock() discipline every cfg writer uses.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			vi.mu.Lock()
			if i%2 == 0 {
				vi.cfg.AdvertiseInterval = 30
			} else {
				vi.cfg.AdvertiseInterval = 100
			}
			vi.mu.Unlock()
		}
	}()

	// Reader: the run-loop advert-timer reset path. The value is always one of
	// the two writer-set intervals — a torn read would surface as neither.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if d := vi.advertInterval(); d != 30*time.Millisecond && d != 100*time.Millisecond {
				t.Errorf("advertInterval() = %v, want 30ms or 100ms", d)
				return
			}
		}
	}()

	wg.Wait()
}

// TestAdvertIntervalMasterAdverFloorNoDeadlock6230 guards the non-obvious half
// of the #6230 fix. recordMasterAdvert holds vi.mu.Lock() when it reaches
// masterAdverFloor, so masterAdverFloor MUST read the interval via
// advertIntervalLocked. If it were reverted to call the RLock-taking
// advertInterval, the RLock requested under the held write lock would
// self-deadlock and this test would hang until the go-test timeout kills it.
// Running it alongside a concurrent advertInterval() reader also exercises the
// RLock/Lock interleave without a race.
func TestAdvertIntervalMasterAdverFloorNoDeadlock6230(t *testing.T) {
	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1, AdvertiseInterval: 30}}

	// A non-zero-priority advert with a valid Max Adver Int drives
	// recordMasterAdvert down the masterAdverFloor path (MaxAdvertInt > 0).
	pkt := &VRRPPacket{VRID: 1, Priority: 100, MaxAdvertInt: 5}

	const iters = 5000
	var wg sync.WaitGroup
	wg.Add(2)

	// recordMasterAdvert takes vi.mu.Lock() and, still holding it, calls
	// masterAdverFloor → advertIntervalLocked. Deadlocks if that reverts to
	// advertInterval's RLock.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			vi.recordMasterAdvert(pkt)
		}
	}()

	// Concurrent RLock reader of the same interval field.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = vi.advertInterval()
		}
	}()

	wg.Wait()
}
