package logging

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestStreamClient builds a TCP-protocol SyslogClient wired to the supplied
// dial seam, bypassing the real network. The first connection is established
// eagerly (mirroring NewSyslogClientTransport) via the seam.
func newTestStreamClient(t *testing.T, dial func() (net.Conn, error)) *SyslogClient {
	t.Helper()
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.1:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		dialFn:            dial,
	}
	conn, err := dial()
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	c.conn = conn
	return c
}

// deadlineConn is a net.Conn fake that faithfully models stream write-deadline
// semantics: Write blocks until either the caller releases it or the most
// recently set (non-zero) write deadline elapses, in which case it returns a
// timeout error. With NO write deadline set, Write blocks until released —
// which never happens in the hang test, so a reverted (deadline-less) producer
// blocks forever.
type deadlineConn struct {
	mu       sync.Mutex
	deadline time.Time
	release  chan struct{} // closed to unblock all pending writes (healthy path)
	writes   int32         // count of completed writes
}

func newDeadlineConn() *deadlineConn {
	return &deadlineConn{release: make(chan struct{})}
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()

	if dl.IsZero() {
		// No deadline: block until explicitly released. Models a hung
		// server with the (buggy) deadline-less producer.
		<-c.release
		atomic.AddInt32(&c.writes, 1)
		return len(b), nil
	}

	d := time.Until(dl)
	if d <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-c.release:
		atomic.AddInt32(&c.writes, 1)
		return len(b), nil
	case <-timer.C:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *deadlineConn) Read(_ []byte) (int, error)        { return 0, nil }
func (c *deadlineConn) Close() error                      { return nil }
func (c *deadlineConn) LocalAddr() net.Addr               { return dummyAddr{} }
func (c *deadlineConn) RemoteAddr() net.Addr              { return dummyAddr{} }
func (c *deadlineConn) SetDeadline(_ time.Time) error     { return nil }
func (c *deadlineConn) SetReadDeadline(_ time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "203.0.113.1:514" }

// TestStreamWriteDeadlineDoesNotHang asserts that a hung server (Write that
// never completes on its own) cannot stall the caller: with the write deadline
// armed, Send returns a timeout-driven error within roughly writeTimeout and
// counts the drop. Removing the SetWriteDeadline call makes the fake conn's
// Write block forever, so Send never returns and this test deadlocks/fails
// (the fail-on-revert proof for fix #1).
func TestStreamWriteDeadlineDoesNotHang(t *testing.T) {
	conn := newDeadlineConn()
	c := newTestStreamClient(t, func() (net.Conn, error) {
		return conn, nil
	})
	// Short, deterministic deadline. The dial seam never succeeds again, so
	// after the write timeout the reconnect path also fails fast.
	c.writeTimeout = 30 * time.Millisecond
	// Make reconnect dial fail (server still hung) so Send cannot block on a
	// fresh dial either.
	c.dialFn = func() (net.Conn, error) { return nil, errors.New("still down") }

	done := make(chan error, 1)
	go func() {
		done <- c.Send(SyslogInfo, "hung-server message")
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Send to fail on a hung server, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return — write deadline missing (event reader would stall)")
	}

	if got := c.DroppedWrites() + c.DroppedCooldown(); got == 0 {
		t.Errorf("expected a drop to be counted, got writes=%d cooldown=%d",
			c.DroppedWrites(), c.DroppedCooldown())
	}
}

// TestReconnectCooldownRateLimitsDials asserts that with a down target (every
// dial fails), rapid Sends do NOT each drive a fresh dial. The cooldown caps
// dials to roughly one per cooldown window, and intervening Sends fail fast.
// Removing the cooldown gate makes every Send dial → dialCount == sends, which
// trips this test (the fail-on-revert proof for fix #2).
func TestReconnectCooldownRateLimitsDials(t *testing.T) {
	var dialCount int32
	// Use a controllable fake clock so the test is sleep-free and
	// deterministic. Time only advances when the test advances it.
	var nowMu sync.Mutex
	now := time.Unix(0, 0)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}

	dial := func() (net.Conn, error) {
		atomic.AddInt32(&dialCount, 1)
		return nil, errors.New("connection refused")
	}

	// First dial (in the helper) counts as dial #1 and seeds lastDialFailure
	// only on subsequent reconnects; construct the client with a broken conn
	// so the first Send triggers the reconnect path.
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.1:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: time.Second,
		dialFn:            dial,
		nowFn:             clock,
		conn:              &alwaysFailConn{}, // first writeMsg fails → reconnect path
	}

	const sends = 50
	for i := 0; i < sends; i++ {
		_ = c.Send(SyslogInfo, "down-target message")
	}

	// All sends happened at t=0; only the FIRST should have dialed. The rest
	// are inside the cooldown window → fail fast, no dial.
	if d := atomic.LoadInt32(&dialCount); d != 1 {
		t.Fatalf("expected 1 dial within the cooldown window across %d sends, got %d",
			sends, d)
	}
	if c.DroppedCooldown() == 0 {
		t.Errorf("expected cooldown drops to be counted, got %d", c.DroppedCooldown())
	}

	// Advance past the cooldown: exactly one more dial may occur.
	advance(time.Second + time.Millisecond)
	for i := 0; i < sends; i++ {
		_ = c.Send(SyslogInfo, "down-target message round 2")
	}
	if d := atomic.LoadInt32(&dialCount); d != 2 {
		t.Fatalf("expected 2 total dials after one cooldown window, got %d", d)
	}

	// Sanity: dials (2) are far fewer than total sends (2*sends).
	if int(atomic.LoadInt32(&dialCount)) >= 2*sends {
		t.Fatalf("reconnect thrash: dials %d not rate-limited vs %d sends",
			dialCount, 2*sends)
	}
}

// alwaysFailConn is a net.Conn whose Write always fails immediately, forcing
// the reconnect path without blocking.
type alwaysFailConn struct{}

func (alwaysFailConn) Write(_ []byte) (int, error)        { return 0, errors.New("broken pipe") }
func (alwaysFailConn) Read(_ []byte) (int, error)         { return 0, nil }
func (alwaysFailConn) Close() error                       { return nil }
func (alwaysFailConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (alwaysFailConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (alwaysFailConn) SetDeadline(_ time.Time) error      { return nil }
func (alwaysFailConn) SetReadDeadline(_ time.Time) error  { return nil }
func (alwaysFailConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestHealthyStreamNoDeadlineDrops asserts the normal path is unaffected: a
// healthy conn delivers every message with no deadline-induced drop and no
// reconnect. Each Write completes promptly (released immediately).
func TestHealthyStreamNoDeadlineDrops(t *testing.T) {
	conn := newHealthyConn()
	var dialCount int32
	c := newTestStreamClient(t, func() (net.Conn, error) {
		atomic.AddInt32(&dialCount, 1)
		return conn, nil
	})

	const sends = 20
	for i := 0; i < sends; i++ {
		if err := c.Send(SyslogInfo, "healthy message"); err != nil {
			t.Fatalf("send %d failed on healthy conn: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&conn.writes); int(got) != sends {
		t.Errorf("expected %d writes delivered, got %d", sends, got)
	}
	if c.DroppedWrites() != 0 || c.DroppedCooldown() != 0 {
		t.Errorf("healthy path should not drop: writes=%d cooldown=%d",
			c.DroppedWrites(), c.DroppedCooldown())
	}
	// Only the initial dial; no reconnect on a healthy conn.
	if d := atomic.LoadInt32(&dialCount); d != 1 {
		t.Errorf("healthy path should dial once, got %d", d)
	}
	// A write deadline must have been set on the healthy conn (the fix
	// applies to the success path too, just far enough out to never fire).
	if !conn.sawDeadline() {
		t.Error("expected a write deadline to be set on the healthy stream conn")
	}
}

// healthyConn completes every Write immediately and records that a non-zero
// write deadline was set.
type healthyConn struct {
	mu          sync.Mutex
	hadDeadline bool
	writes      int32
}

func newHealthyConn() *healthyConn { return &healthyConn{} }

func (c *healthyConn) Write(b []byte) (int, error) {
	atomic.AddInt32(&c.writes, 1)
	return len(b), nil
}
func (c *healthyConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	if !t.IsZero() {
		c.hadDeadline = true
	}
	c.mu.Unlock()
	return nil
}
func (c *healthyConn) sawDeadline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hadDeadline
}
func (c *healthyConn) Read(_ []byte) (int, error)        { return 0, nil }
func (c *healthyConn) Close() error                      { return nil }
func (c *healthyConn) LocalAddr() net.Addr               { return dummyAddr{} }
func (c *healthyConn) RemoteAddr() net.Addr              { return dummyAddr{} }
func (c *healthyConn) SetDeadline(_ time.Time) error     { return nil }
func (c *healthyConn) SetReadDeadline(_ time.Time) error { return nil }
