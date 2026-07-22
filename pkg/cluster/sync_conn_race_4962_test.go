package cluster

import (
	"net"
	"sync"
	"testing"
)

// TestHandleNewConnectionRaceDoesNotAbortWinnerBulk4962 is the #4962
// fail-on-revert test for the async handleNewConnection cold-prime race.
//
// Post-#4370 handleNewConnection runs per-accept in its own goroutine, so two
// same-fabric accepts can race. From a fully-disconnected registry:
//
//   - Accept A observes the empty registry (wasDisconnected), installs connA,
//     and starts cold-priming connA.
//   - Accept B locks AFTER A, observes connA (a NON-empty registry), CLOSES
//     connA (aborting A's in-flight cold-prime bulk), and installs connB as the
//     surviving active connection.
//
// The pre-#4962 code computed the cold-prime decision from wasDisconnected read
// under the lock but USED after unlock. B saw a non-empty registry so its
// wasDisconnected was false and it SKIPPED cold-prime entirely — the surviving
// connection connB never re-pushed the authoritative session table, and the
// peer blackholed every established flow on the next failover to it.
//
// The fix arms a needColdPrime latch on the full-disconnect edge and consumes
// it only when a cold-prime bulk SUCCEEDS, so the surviving accept B INHERITS
// the obligation. installConn commits that decision atomically under s.mu.
//
// RED-on-revert: change installConn's decision back to the after-unlock shape
// (`shouldColdPrime = becameActive && wasDisconnected`, i.e. drop the
// needColdPrime latch) and B — which supersedes A and therefore sees
// wasDisconnected=false — no longer cold-primes, so the survivor assertion
// below fires.
func TestHandleNewConnectionRaceDoesNotAbortWinnerBulk4962(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)

	connA := newPreAuthTestConn("10.0.0.2:5001")
	connB := newPreAuthTestConn("10.0.0.2:5002")

	// Accept A: first connection after a full disconnect. It becomes the active
	// fabric and MUST cold-prime.
	decA := s.installConn(0, connA)
	if !decA.wasDisconnected {
		t.Fatalf("accept A must observe a fully-disconnected registry, got %+v", decA)
	}
	if !decA.shouldColdPrime {
		t.Fatalf("accept A (first after full disconnect) must cold-prime, got %+v", decA)
	}
	if got := s.getActiveConn(); got != net.Conn(connA) {
		t.Fatalf("accept A must be installed as the active connection, got %p", got)
	}
	if !s.needColdPrime.Load() {
		t.Fatal("the cold-prime obligation must be armed after the first connection")
	}

	// Accept B: supersedes A on the SAME fabric while A's cold-prime is still in
	// flight. It closes connA (aborting A's bulk) and becomes the survivor.
	decB := s.installConn(0, connB)
	if got := s.getActiveConn(); got != net.Conn(connB) {
		t.Fatalf("accept B must supersede A as the active connection, got %p", got)
	}
	if !connA.closed.Load() {
		t.Fatal("accept B must close the superseded connection A")
	}
	if decB.wasDisconnected {
		t.Fatal("accept B observes A's connection, so it must NOT see a disconnected registry")
	}
	// The crux: the surviving connection MUST inherit the cold-prime obligation
	// aborted from A. Dropping it is the #4962 blackhole.
	if !decB.shouldColdPrime {
		t.Fatal("#4962: the surviving accept B MUST inherit the cold-prime obligation " +
			"aborted from A; skipping it leaves the peer un-primed and blackholes " +
			"established flows on the next failover")
	}
	if !s.needColdPrime.Load() {
		t.Fatal("#4962: the obligation must remain armed until a cold-prime bulk succeeds")
	}
}

// TestHandleNewConnectionColdPrimeLatchLifecycle4962 pins the latch lifecycle:
// armed on the full-disconnect edge, RETAINED across a same-fabric supersession
// (so the survivor re-drives), consumed only on a successful bulk, and NOT
// re-driven on a routine single-fabric flip once discharged.
//
// RED-on-revert: if installConn armed nothing (no latch) or the survivor's
// decision keyed on wasDisconnected, the "survivor must cold-prime" assertion
// fails; if the discharge were unconditional (cleared regardless of bulk
// outcome), the "steady-state flip does not re-bulk" invariant would be the one
// pinned by the final assertions.
func TestHandleNewConnectionColdPrimeLatchLifecycle4962(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Fresh full-disconnect -> connect on fabric 0 arms the obligation.
	c0 := newPreAuthTestConn("10.0.0.2:6001")
	if d := s.installConn(0, c0); !d.shouldColdPrime {
		t.Fatalf("first connection must cold-prime, got %+v", d)
	}
	if !s.needColdPrime.Load() {
		t.Fatal("obligation must be armed on the full-disconnect edge")
	}

	// Simulate a SUCCESSFUL cold-prime bulk: handleNewConnection consumes the
	// latch on doBulkSync() == nil.
	s.needColdPrime.Store(false)

	// A routine single-fabric flip: fabric 1 comes up while fabric 0 is still
	// active. It becomes active-eligible but the obligation is discharged, so it
	// must NOT re-bulk (matches the pre-#4962 becameActive/else behavior).
	c1 := newPreAuthTestConn("10.0.0.2:6002")
	d1 := s.installConn(1, c1)
	if d1.wasDisconnected {
		t.Fatalf("fabric 1 install with fabric 0 up must not see a disconnected registry, got %+v", d1)
	}
	if d1.shouldColdPrime {
		t.Fatal("a routine fabric flip with the obligation discharged must NOT re-bulk")
	}
}

// TestHandleNewConnectionConcurrentAcceptsRetainObligation4962 drives many
// concurrent same-fabric installs from a disconnected registry under -race. No
// cold-prime bulk runs (installConn never clears the latch), so the obligation
// must survive every supersession — a losing accept can never silently drop it.
// The surviving connection is one of the racers and is the active connection.
func TestHandleNewConnectionConcurrentAcceptsRetainObligation4962(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)

	const n = 16
	conns := make([]*preAuthTestConn, n)
	for i := range conns {
		conns[i] = newPreAuthTestConn("10.0.0.2:7000")
	}

	var wg sync.WaitGroup
	shouldColdPrimeCount := make([]bool, n)
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := s.installConn(0, conns[i])
			shouldColdPrimeCount[i] = d.shouldColdPrime
		}(i)
	}
	wg.Wait()

	// Every install from the (initially) disconnected registry becomes the
	// active fabric-0 connection at the instant it holds the lock, so each sees
	// the armed obligation: shouldColdPrime is true for all of them. Critically,
	// none observed shouldColdPrime=false while the obligation was outstanding.
	for i, v := range shouldColdPrimeCount {
		if !v {
			t.Fatalf("#4962: concurrent accept %d dropped the cold-prime obligation "+
				"while it was outstanding (a losing accept must inherit, not skip)", i)
		}
	}
	if !s.needColdPrime.Load() {
		t.Fatal("#4962: the obligation must remain armed until a bulk succeeds")
	}
	// Exactly one connection survives as the active connection.
	active := s.getActiveConn()
	found := false
	for _, c := range conns {
		if active == net.Conn(c) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("the surviving active connection must be one of the racing accepts")
	}
}
