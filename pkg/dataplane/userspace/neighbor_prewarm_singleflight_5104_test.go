package userspace

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestNeighborPrewarmSingleflightCoalescesOverlappingTicks5104 is the #5104
// merge-gate regression. The status loop kicks proactiveNeighborResolveAsyncLocked
// every 1s for the first 60s (then every 10s on HA standby); a single scan can
// outlast its tick under slow netlink or a large RIB. Without the singleflight
// guard, overlapping ticks multiplied concurrent scans (and probe goroutines) —
// self-amplifying control-plane load. This test fires overlapping ticks while a
// scan is artificially in flight (blocked in an injected seam) and asserts that
// only ONE scan runs. Reverting the CAS guard in
// proactiveNeighborResolveAsyncLocked makes this go RED (started/peak > 1).
func TestNeighborPrewarmSingleflightCoalescesOverlappingTicks5104(t *testing.T) {
	var (
		started    atomic.Int32
		concurrent atomic.Int32
		peak       atomic.Int32
	)
	entered := make(chan struct{}, 32)
	release := make(chan struct{})

	m := &Manager{
		lastSnapshot: &ConfigSnapshot{Config: &config.Config{}},
	}
	m.neighborPrewarmScan = func(ctx context.Context, cfg *config.Config) {
		started.Add(1)
		c := concurrent.Add(1)
		for { // record the concurrency peak
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		concurrent.Add(-1)
	}

	tick := func() {
		m.mu.Lock()
		m.proactiveNeighborResolveAsyncLocked()
		m.mu.Unlock()
	}

	// First tick starts a scan that blocks in the seam, holding the guard.
	tick()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first prewarm scan never started")
	}

	// Overlapping ticks while scan 1 is DEFINITIVELY in flight (blocked on
	// release). The singleflight guard must coalesce all of these.
	for i := 0; i < 5; i++ {
		tick()
	}

	// Give any erroneously-spawned scan time to reach the seam and bump the
	// peak. With the guard in place, none spawn and this drains nothing.
	select {
	case <-entered:
		// A second scan reached the seam — the guard failed to coalesce.
	case <-time.After(300 * time.Millisecond):
	}

	if got := peak.Load(); got != 1 {
		t.Fatalf("concurrent prewarm scans peaked at %d, want 1 (#5104 singleflight guard must coalesce overlapping ticks)", got)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("prewarm scans started = %d, want 1 (overlapping ticks must coalesce onto the running scan)", got)
	}
	if !m.neighborPrewarmInFlight.Load() {
		t.Fatal("singleflight guard cleared while a scan is still in flight")
	}

	// Release the in-flight scan; the guard must clear so a later tick runs a
	// fresh scan (coalescing is transient, not permanent).
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for m.neighborPrewarmInFlight.Load() {
		if time.Now().After(deadline) {
			t.Fatal("singleflight guard never cleared after the scan returned")
		}
		time.Sleep(time.Millisecond)
	}

	tick()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("post-release tick did not start a fresh scan")
	}
	if got := started.Load(); got != 2 {
		t.Fatalf("prewarm scans started = %d after release, want 2", got)
	}
	// Let the last scan finish so the goroutine doesn't linger past the test.
	// release is already closed, so its <-release returns immediately.
}

// TestNeighborProbePoolBounded5104 asserts the #5104 bounded probe pool: N
// resolve targets fan out to at most neighborPrewarmProbeWorkers concurrent
// probes (previously ONE goroutine per target, unbounded). Reverting
// runBoundedNeighborProbes to an unbounded goroutine-per-target loop drives the
// concurrency peak well past the worker cap and makes this RED.
func TestNeighborProbePoolBounded5104(t *testing.T) {
	const (
		workers    = 4
		numTargets = 200
	)
	var (
		concurrent atomic.Int32
		peak       atomic.Int32
		total      atomic.Int32
	)
	targets := make([]neighborProbeTarget, 0, numTargets)
	for i := 0; i < numTargets; i++ {
		targets = append(targets, neighborProbeTarget{
			iface: "ge-0-0-0",
			ip:    fmt.Sprintf("10.0.0.%d", i%254+1),
		})
	}
	probe := func(iface string, target net.IP) {
		total.Add(1)
		c := concurrent.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(time.Millisecond) // hold the slot so overlap manifests
		concurrent.Add(-1)
	}

	runBoundedNeighborProbes(context.Background(), targets, workers, probe)

	if got := total.Load(); got != numTargets {
		t.Fatalf("probed %d targets, want %d (all targets must be probed)", got, numTargets)
	}
	if got := peak.Load(); got > workers {
		t.Fatalf("probe concurrency peaked at %d, want <= %d (#5104 bounded pool)", got, workers)
	}
	if got := peak.Load(); got < 1 {
		t.Fatalf("probe concurrency peaked at %d, want >= 1", got)
	}
}

// TestNeighborProbePoolStopsOnCanceledContext5104 locks the ctx cancellation
// wiring: a cancelled/expired scan context stops the probe sweep instead of
// firing every target.
func TestNeighborProbePoolStopsOnCanceledContext5104(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var total atomic.Int32
	targets := []neighborProbeTarget{
		{iface: "ge-0-0-0", ip: "10.0.0.1"},
		{iface: "ge-0-0-0", ip: "10.0.0.2"},
	}
	runBoundedNeighborProbes(ctx, targets, 4, func(string, net.IP) { total.Add(1) })

	if got := total.Load(); got != 0 {
		t.Fatalf("canceled context still fired %d probes, want 0", got)
	}
}
