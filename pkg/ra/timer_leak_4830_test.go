package ra

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestNoTimeAfterInsideSelect is the #4830 RED-on-revert guard for the timer
// leak fix. time.After used directly as a select case's receive expression
// leaks the underlying time.Timer in the runtime's timer heap until it
// fires (up to the full duration) whenever the OTHER case wins the select
// first — which is the common path for both releaseDrain (ra.go) and
// waitConnReady (sender.go). That leak isn't practically time-testable
// (there is no public API to assert "N timers are live in the runtime
// heap"), so this test pins the fix at the source level instead: neither
// file may contain a bare `<-time.After(...)` select case. Both sites now
// use time.NewTimer + a deferred Stop() (the standard Go pattern), which
// reclaims the timer immediately instead of leaving it to fire on its own.
//
// RED on revert: reintroducing `case <-time.After(...)` in either function
// trips this immediately and deterministically — no timing flakiness.
func TestNoTimeAfterInsideSelect(t *testing.T) {
	for _, path := range []string{"ra.go", "sender.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(data), "<-time.After(") {
			t.Errorf("%s contains a bare `<-time.After(...)` select case — "+
				"this leaks the underlying Timer in the runtime's timer heap "+
				"until it fires whenever the OTHER select case wins first "+
				"(#4830); use time.NewTimer + defer Stop() instead", path)
		}
	}
}

// TestWaitConnReadyReturnsPromptlyOnFastPath pins the #4830 fix's behavior:
// converting waitConnReady from time.After to time.NewTimer + defer Stop()
// must not change the fast-path latency — it must still return as soon as
// connReady is signaled, not wait out (any part of) the timeout.
func TestWaitConnReadyReturnsPromptlyOnFastPath(t *testing.T) {
	s := &sender{connReady: make(chan struct{})}
	go func() {
		time.Sleep(5 * time.Millisecond)
		s.signalConnReady(true)
	}()

	start := time.Now()
	ok := s.waitConnReady(2 * time.Second)
	elapsed := time.Since(start)

	if !ok {
		t.Fatal("waitConnReady returned false, want true (conn opened)")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("waitConnReady took %v, want well under the 2s timeout (fast path)", elapsed)
	}
}

// TestWaitConnReadyTimesOut pins the timeout path after the time.NewTimer
// conversion: with connReady never signaled, waitConnReady must still
// return false once the timeout elapses — bounded below by the timeout
// (it must actually wait, not return immediately) and bounded above by a
// generous margin (it must not hang).
func TestWaitConnReadyTimesOut(t *testing.T) {
	s := &sender{connReady: make(chan struct{})}

	start := time.Now()
	ok := s.waitConnReady(50 * time.Millisecond)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("waitConnReady returned true, want false (connReady never signaled)")
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("waitConnReady returned after %v, want >= 50ms (timeout path)", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("waitConnReady took %v, way past its 50ms timeout — looks hung", elapsed)
	}
}
