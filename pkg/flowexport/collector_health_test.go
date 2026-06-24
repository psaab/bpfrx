package flowexport

import (
	"errors"
	"net"
	"sync"
	"testing"
)

// writeFakeConn is a net.Conn fake whose Write returns a programmable
// error, so the per-collector health tests (#2464) can drive a collector
// in and out of the failing state deterministically.
type writeFakeConn struct {
	net.Conn
	mu  sync.Mutex
	err error
}

func (c *writeFakeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	return len(b), nil
}

func (c *writeFakeConn) Close() error { return nil }

func (c *writeFakeConn) setErr(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

// newHealthTestConns builds a collectorConns wrapping the given fake
// connections with the per-collector health state initialized the way
// dialCollectors does (healthy=true).
func newHealthTestConns(addrs []string, fakes []*writeFakeConn) *collectorConns {
	cc := &collectorConns{}
	for i, a := range addrs {
		cc.conns = append(cc.conns, &collectorConn{conn: fakes[i], addr: a, healthy: true})
	}
	return cc
}

// TestCollectorHealth_FailureTracksLastError proves a failed collector
// write bumps WriteAttempts + WriteFailures and records LastError /
// LastErrorTime / LastFailureTime, while a success bumps attempts and
// records LastSuccessTime (#2464).
//
// FAIL-ON-REVERT: on master, collectorConns held a bare []net.Conn with
// no per-collector counters and writeAll only slog.Debug-logged failures
// — there is no WriteFailures field at all, so this test does not even
// compile against the pre-fix code, let alone pass. With the tracking
// removed (revert), the failing-collector branch never records
// WriteFailures>0 / LastError and the assertions below fail.
func TestCollectorHealth_FailureTracksLastError(t *testing.T) {
	sentinel := errors.New("connection refused")
	good := &writeFakeConn{}
	bad := &writeFakeConn{err: sentinel}
	cc := newHealthTestConns([]string{"10.0.0.1:2055", "10.0.0.2:2055"}, []*writeFakeConn{good, bad})

	cc.writeAll([]byte("pkt"), "data send failed")

	h := cc.health()
	if len(h) != 2 {
		t.Fatalf("expected 2 collector health entries, got %d", len(h))
	}

	// Good collector: 1 attempt, 0 failures, healthy, has a success time.
	g := h[0]
	if g.WriteAttempts != 1 || g.WriteFailures != 0 {
		t.Fatalf("good collector attempts/failures = %d/%d, want 1/0", g.WriteAttempts, g.WriteFailures)
	}
	if !g.Healthy {
		t.Fatal("good collector should be healthy")
	}
	if g.LastSuccessTime.IsZero() {
		t.Fatal("good collector LastSuccessTime should be set")
	}
	if g.LastError != "" {
		t.Fatalf("good collector LastError should be empty, got %q", g.LastError)
	}

	// Bad collector: 1 attempt, 1 failure, unhealthy, error recorded.
	b := h[1]
	if b.WriteAttempts != 1 || b.WriteFailures != 1 {
		t.Fatalf("bad collector attempts/failures = %d/%d, want 1/1", b.WriteAttempts, b.WriteFailures)
	}
	if b.Healthy {
		t.Fatal("bad collector should be unhealthy after a failed write")
	}
	if b.LastError != sentinel.Error() {
		t.Fatalf("bad collector LastError = %q, want %q", b.LastError, sentinel.Error())
	}
	if b.LastErrorTime.IsZero() || b.LastFailureTime.IsZero() {
		t.Fatal("bad collector LastErrorTime/LastFailureTime should be set")
	}
	if !b.LastSuccessTime.IsZero() {
		t.Fatal("bad collector never succeeded; LastSuccessTime should be zero")
	}
}

// TestCollectorHealth_StateChangeEdges proves the per-collector edge
// detection: a collector starts healthy, the FIRST failure flips it to
// unhealthy (the unhealthy edge), subsequent consecutive failures keep it
// unhealthy, and a later success flips it back to healthy (the recovery
// edge). The state-change warn/info in writeAll keys off exactly these
// edges, so this verifies the warn fires ONCE per transition rather than
// once per failed write (the project logging rule: no Warn in a per-tick
// loop). #2464.
//
// FAIL-ON-REVERT: master has no Healthy field; the test cannot compile
// against it, and the edge semantics it asserts do not exist pre-fix.
func TestCollectorHealth_StateChangeEdges(t *testing.T) {
	sentinel := errors.New("no route to host")
	fc := &writeFakeConn{}
	cc := newHealthTestConns([]string{"10.0.0.9:4739"}, []*writeFakeConn{fc})

	// Initially healthy after dial.
	if !cc.health()[0].Healthy {
		t.Fatal("collector should start healthy")
	}

	// First failure: unhealthy edge.
	fc.setErr(sentinel)
	cc.writeAll([]byte("a"), "send")
	if cc.health()[0].Healthy {
		t.Fatal("collector should be unhealthy after first failure")
	}
	if got := cc.health()[0].WriteFailures; got != 1 {
		t.Fatalf("WriteFailures = %d, want 1", got)
	}

	// Repeated failures: still unhealthy, failures climb, attempts climb.
	cc.writeAll([]byte("b"), "send")
	cc.writeAll([]byte("c"), "send")
	hs := cc.health()[0]
	if hs.Healthy {
		t.Fatal("collector should remain unhealthy across consecutive failures")
	}
	if hs.WriteFailures != 3 || hs.WriteAttempts != 3 {
		t.Fatalf("after 3 failures attempts/failures = %d/%d, want 3/3", hs.WriteAttempts, hs.WriteFailures)
	}

	// Recovery: success flips back to healthy.
	fc.setErr(nil)
	cc.writeAll([]byte("d"), "send")
	rec := cc.health()[0]
	if !rec.Healthy {
		t.Fatal("collector should be healthy again after a successful write")
	}
	if rec.WriteAttempts != 4 || rec.WriteFailures != 3 {
		t.Fatalf("after recovery attempts/failures = %d/%d, want 4/3", rec.WriteAttempts, rec.WriteFailures)
	}
	if rec.LastSuccessTime.IsZero() {
		t.Fatal("LastSuccessTime should be set after recovery")
	}
}

// TestCollectorHealth_StateChangeCallbackOncePerTransition wraps writeAll
// in a recorder that counts how many times the healthy<->unhealthy edge
// is crossed, proving the transition is detected exactly once per edge
// (not once per failed write). The edge count is derived from the Healthy
// flag observed before/after each writeAll, mirroring exactly what the
// warn/info log in writeAll keys off. #2464.
func TestCollectorHealth_StateChangeCallbackOncePerTransition(t *testing.T) {
	sentinel := errors.New("unreachable")
	fc := &writeFakeConn{}
	cc := newHealthTestConns([]string{"10.0.0.20:2055"}, []*writeFakeConn{fc})

	var unhealthyEdges, recoveryEdges int
	step := func() {
		before := cc.health()[0].Healthy
		cc.writeAll([]byte("x"), "send")
		after := cc.health()[0].Healthy
		if before && !after {
			unhealthyEdges++
		}
		if !before && after {
			recoveryEdges++
		}
	}

	// 3 consecutive failures, then 2 consecutive successes.
	fc.setErr(sentinel)
	step()
	step()
	step()
	fc.setErr(nil)
	step()
	step()

	if unhealthyEdges != 1 {
		t.Fatalf("unhealthy edge crossed %d times, want exactly 1 (warn must not fire per failed write)", unhealthyEdges)
	}
	if recoveryEdges != 1 {
		t.Fatalf("recovery edge crossed %d times, want exactly 1", recoveryEdges)
	}
}
