package lldp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestApplyStopLifecycleRace is the fail-on-revert regression test for #5121:
// Apply (a config commit) and Stop (daemon shutdown) are lifecycle transitions
// that can run concurrently. The shutdown path (pkg/daemon runShutdownSequence)
// calls lldpMgr.Stop() WITHOUT the applySem that Apply runs under, so a SIGTERM
// arriving mid-commit races Stop against the in-flight Apply.
//
// Before the lifecycle mutex that race was real and unsynchronized: Apply writes
// m.cancel and calls m.wg.Add(1) with no lifecycle lock while Stop reads m.cancel
// and calls m.wg.Wait(). Under the race detector that is a data race on m.cancel;
// the wg.Add/wg.Wait interleave is a WaitGroup misuse that can panic ("WaitGroup
// is reused before previous Wait has returned") or drop a goroutine from the
// join; and Stop can snapshot the session set before Apply finishes publishing a
// later interface's session, leaving that RX goroutine parked in recv forever.
//
// This drives two goroutines that hammer Apply and Stop concurrently for many
// iterations, then asserts a coherent final teardown. Run under `go test -race`:
//
//   - WITH lifecycleMu: every Apply/Stop is atomic w.r.t. the other, so the loop
//     is race-free and the final Stop leaves the manager fully torn down.
//   - REVERT the mutex (drop lifecycleMu.Lock in Apply/Stop and restore Apply's
//     internal m.Stop()): `-race` reports a data race on m.cancel and/or the
//     WaitGroup, or a WaitGroup-reuse panic crashes the test. RED on revert.
//
// It stubs the session/interface seams so no CAP_NET_RAW or real device is
// needed; sessions are socketpair-backed so the real cancel/close/wg.Wait
// teardown path executes.
func TestApplyStopLifecycleRace(t *testing.T) {
	var peerMu sync.Mutex
	var peerFDs []int
	prevSess := newIfSessionFn
	newIfSessionFn = func(iface *net.Interface) (*ifSession, error) {
		sess, peerFD := newSocketpairSession(t, iface)
		peerMu.Lock()
		peerFDs = append(peerFDs, peerFD)
		peerMu.Unlock()
		return sess, nil
	}
	// Resolve to synthetic interfaces so each Apply builds several sessions —
	// widening the window between Stop's session snapshot and Apply's later
	// wg.Add/session-publish where the unguarded race lives.
	prevLookup := interfaceByNameFn
	interfaceByNameFn = func(name string) (*net.Interface, error) {
		return &net.Interface{
			Index:        1,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		}, nil
	}
	t.Cleanup(func() {
		newIfSessionFn = prevSess
		interfaceByNameFn = prevLookup
		peerMu.Lock()
		for _, fd := range peerFDs {
			unix.Close(fd)
		}
		peerMu.Unlock()
	})

	cfg := &LLDPConfig{
		Interfaces: []LLDPInterface{
			{Name: "if0"}, {Name: "if1"}, {Name: "if2"}, {Name: "if3"},
		},
		Interval: 30,
	}

	m := New()
	const iterations = 300

	var wg sync.WaitGroup
	wg.Add(2)
	// Goroutine A: config-commit path — each Apply tears down the prior
	// generation and rebuilds a new one.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			m.Apply(context.Background(), cfg)
		}
	}()
	// Goroutine B: shutdown path — hammer Stop concurrently.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			m.Stop()
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Apply/Stop race loop did not finish within 30s — a raced Stop " +
			"missed a published session and its RX goroutine parked forever, " +
			"hanging wg.Wait()")
	}

	// Final coherent state: a last Stop must leave the manager fully torn down.
	// A live generation or a residual session here means the interleaving left an
	// orphaned generation that Stop failed to claim (the "session omitted from
	// teardown" impact).
	m.Stop()
	if m.Running() {
		t.Fatal("manager still Running() after final Stop — a raced Apply leaked a live generation")
	}
	m.mu.RLock()
	nSessions := len(m.sessions)
	m.mu.RUnlock()
	if nSessions != 0 {
		t.Fatalf("residual sessions after final Stop: %d — teardown missed a session "+
			"published by a raced Apply", nSessions)
	}
}
