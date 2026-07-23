package vrrp

import (
	"net"
	"strings"
	"sync"
	"testing"
)

// #5718 (codex-182 C-HA C01c): Manager.Status() formatted vi.cfg.Priority,
// vi.cfg.Preempt, vi.cfg.AdvertiseInterval, and vi.cfg.VirtualAddresses while
// holding only m.mu.RLock. Those cfg fields are mutated under vi.mu.Lock by
// updateConfig, UpdateRGPriority, and suppressPreempt/restorePreempt. A `show`/
// status render concurrent with a failover priority update is therefore an
// unsynchronized concurrent read/write — a diagnostic-only data race the Go
// memory model forbids and go test -race flags. The fix snapshots the cfg
// fields under vi.mu.RLock before formatting, mirroring advertInterval/
// getPriority (#6230).
//
// This is the fail-on-revert gate. The race detector reports on the FIRST
// unsynchronized concurrent access, so a few thousand tightly interleaved
// iterations suffice and stay fast under -race. It is CLEAN with the snapshot
// fix and DETECTS the race if Status() reverts to reading vi.cfg.* directly.
// Must be run with `go test -race`.
func TestStatusConfigNoRace5718(t *testing.T) {
	m := NewManager()
	reth := newInstance(
		Instance{Interface: "reth0", GroupID: 101, Priority: 100, AdvertiseInterval: 30, Preempt: true},
		&net.Interface{Name: "reth0", Index: 8}, m.eventCh, nil)
	m.instances[instanceKey{iface: "reth0", groupID: 101}] = reth

	const iters = 5000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: a locked mutation of cfg.Priority, mirroring the vi.mu.Lock()
	// discipline every cfg writer (updateConfig, UpdateRGPriority) uses.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			reth.mu.Lock()
			if i%2 == 0 {
				reth.cfg.Priority = 100
			} else {
				reth.cfg.Priority = 1
			}
			reth.mu.Unlock()
		}
	}()

	// Reader: the real Status() render path.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if out := m.Status(); !strings.Contains(out, "reth0") {
				t.Errorf("Status() missing instance: %q", out)
				return
			}
		}
	}()

	wg.Wait()
}
