package flowexport

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// timeoutError is a net.Error whose Timeout() reports true, matching what a
// real net.Conn write returns once its write deadline elapses.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// blockingConn models a collector whose socket send buffer never drains: its
// Write blocks until either the write deadline set via SetWriteDeadline
// elapses (returning a timeout error, like a real *net.UDPConn) or release is
// closed. Without a deadline the Write blocks forever — which is exactly the
// #4423 H07 stall: one such collector parks the shared export goroutine and
// starves every other collector, the template refresh, the batch flush, and
// the shutdown drain.
type blockingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	release  chan struct{}
}

func (c *blockingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *blockingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	if dl.IsZero() {
		// Pre-fix path: writeAll never set a deadline, so block until the
		// test releases us. Against the fix this branch is never taken.
		<-c.release
		return len(b), nil
	}
	select {
	case <-c.release:
		return len(b), nil
	case <-time.After(time.Until(dl)):
		return 0, timeoutError{}
	}
}

func (c *blockingConn) Close() error { return nil }

// TestWriteAll_SlowCollectorDoesNotStallOthers is the #4423 H07 fail-on-revert
// guard: writeAll must bound each collector write with a deadline so one
// blocked collector cannot stall the shared export goroutine that also drives
// every other collector, the template refresh, the batch flush, and the
// shutdown drain.
//
// Against the pre-fix code (no SetWriteDeadline in writeAll) the blockingConn's
// deadline stays zero, its Write blocks forever, and writeAll never returns —
// the 3s guard below fires. With the fix each write is deadlined, the blocked
// write times out, and delivery to the healthy collector proceeds.
func TestWriteAll_SlowCollectorDoesNotStallOthers(t *testing.T) {
	orig := collectorWriteTimeout
	collectorWriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { collectorWriteTimeout = orig })

	blocked := &blockingConn{release: make(chan struct{})}
	t.Cleanup(func() { close(blocked.release) }) // unblock any parked Write

	good := &writeFakeConn{}
	cc := &collectorConns{conns: []*collectorConn{
		{conn: blocked, addr: "10.0.0.1:2055", healthy: true},
		{conn: good, addr: "10.0.0.2:2055", healthy: true},
	}}

	done := make(chan struct{})
	go func() {
		cc.writeAll([]byte("pkt"), "data send failed")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("writeAll stalled on a blocked collector: one slow collector " +
			"blocked the shared export goroutine (#4423 H07)")
	}

	h := cc.health()
	// The healthy collector after the blocked one still got its write.
	if h[1].WriteAttempts != 1 || !h[1].Healthy {
		t.Fatalf("good collector: attempts=%d healthy=%v, want 1/true "+
			"(starved by the blocked collector)", h[1].WriteAttempts, h[1].Healthy)
	}
	// The blocked collector's deadlined write is recorded as a failure.
	if h[0].WriteFailures != 1 || h[0].Healthy {
		t.Fatalf("blocked collector: failures=%d healthy=%v, want 1/false",
			h[0].WriteFailures, h[0].Healthy)
	}
}

// TestTemplateRefreshInterval_ClampsNonPositive is the #4423 M10 fail-on-revert
// guard for the helper: a non-positive refresh rate must clamp to the default
// so time.NewTicker (which panics on d <= 0) is never handed a zero.
func TestTemplateRefreshInterval_ClampsNonPositive(t *testing.T) {
	if got := templateRefreshInterval(0); got != defaultTemplateRefreshRate {
		t.Fatalf("templateRefreshInterval(0) = %v, want %v", got, defaultTemplateRefreshRate)
	}
	if got := templateRefreshInterval(-5 * time.Second); got != defaultTemplateRefreshRate {
		t.Fatalf("templateRefreshInterval(-5s) = %v, want %v", got, defaultTemplateRefreshRate)
	}
	if got := templateRefreshInterval(30 * time.Second); got != 30*time.Second {
		t.Fatalf("templateRefreshInterval(30s) = %v, want 30s", got)
	}
}

// TestExporterRun_ZeroRefreshRateNoPanic is the #4423 M10 fail-on-revert guard
// at the Run layer: a hand-built ExportConfig with TemplateRefreshRate 0 (which
// the public constructors accept) must not panic the Run goroutine. Against the
// pre-fix code time.NewTicker(0) panics; a panic under `go e.Run(ctx)` is fatal.
func TestExporterRun_ZeroRefreshRateNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Run panicked with zero TemplateRefreshRate: %v (#4423 M10)", r)
		}
	}()

	// Empty Collectors -> dialCollectors opens no sockets and returns no error.
	e, err := NewExporter(&ExportConfig{TemplateRefreshRate: 0})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run builds the tickers then returns on ctx.Done
	e.Run(ctx)

	ie, err := NewIPFIXExporter(&ExportConfig{TemplateRefreshRate: 0})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	ictx, icancel := context.WithCancel(context.Background())
	icancel()
	ie.Run(ictx)
}

// TestExporterBootTimeAnchorsAtDeviceBoot is the #4423 M13 fail-on-revert
// guard: the NetFlow v9 sysUptime reference must anchor at the device boot
// instant (which predates every session), not at exporter-construction time.
// After a daemon restart a session that started before the restart has a
// StartTime earlier than the construction instant, so anchoring there clamps
// its FirstSwitched to 0 (uptimeMs floors a negative delta), truncating the
// flow age to "at boot".
//
// A deterministic 48h-ago boot is injected (well within the ~49.7-day uint32
// millisecond sysUptime window and independent of the host's real uptime).
// Against the pre-fix code (bootTime = time.Now() at construction) a session
// that started an hour ago yields FirstSwitched 0; with the fix it is nonzero.
func TestExporterBootTimeAnchorsAtDeviceBoot(t *testing.T) {
	boot := time.Now().Add(-48 * time.Hour)
	orig := bootTimeFunc
	bootTimeFunc = func() time.Time { return boot }
	t.Cleanup(func() { bootTimeFunc = orig })

	e, err := NewExporter(&ExportConfig{}) // empty collectors: no sockets
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	// A session that started an hour ago — before this exporter was constructed
	// (post-restart) but long after device boot.
	sessionStart := time.Now().Add(-time.Hour)
	if got := uptimeMs(e.bootTime, sessionStart); got == 0 {
		t.Fatal("FirstSwitched truncated to 0 for a pre-exporter session: bootTime " +
			"must anchor at device boot, not exporter-construction time (#4423 M13)")
	}
}
