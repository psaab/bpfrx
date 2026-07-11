package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// blockingListener is a fake net.Listener whose Accept blocks until Close, so a
// fabric-listener supervisor test can hold a "listening" session up without a
// real socket and tear it down deterministically.
type blockingListener struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

func waitFabricUp(t *testing.T, s *Server, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.FabricListenerUp(addr) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fabric listener %q never came up", addr)
}

// TestFabricListenerRecoversFromTransientBindFailure_5047 drives the REAL serve
// path (buildFabricServer + serveUntilDone over a bufconn) after a run of
// transient bind failures. The supervisor must retry past the failures, bring
// the listener up (health down->up), and then stop cleanly on ctx cancel.
//
// RED-on-revert: with the pre-#5047 terminal `return` on a Listen failure, the
// very first transient bind error permanently kills the listener — health never
// goes up and superviseFabricListener does not exist / returns immediately — so
// this test fails.
func TestFabricListenerRecoversFromTransientBindFailure_5047(t *testing.T) {
	s := &Server{}
	const addr = "fab-recover"
	const failFirst = 3
	var attempts atomic.Int32

	cfg := fabricSupervisorConfig{
		backoffBase:  time.Millisecond,
		backoffMax:   5 * time.Millisecond,
		healthyServe: time.Hour,
		listen: func(ctx context.Context) (net.Listener, error) {
			if n := attempts.Add(1); n <= failFirst {
				return nil, fmt.Errorf("transient bind failure %d", n)
			}
			return bufconn.Listen(1 << 20), nil
		},
		serve: func(ctx context.Context, lis net.Listener) error {
			return s.serveUntilDone(ctx, s.buildFabricServer(), lis)
		},
	}

	if s.FabricListenerUp(addr) {
		t.Fatalf("FabricListenerUp(%q) = true before start; want false", addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.superviseFabricListener(ctx, addr, "", cfg); close(done) }()

	waitFabricUp(t, s, addr)
	if got := attempts.Load(); got <= failFirst {
		t.Fatalf("listen attempts = %d; want > %d (supervisor must retry past the transient failures)", got, failFirst)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not return after ctx cancel")
	}
	if s.FabricListenerUp(addr) {
		t.Fatalf("FabricListenerUp(%q) = true after shutdown; want false", addr)
	}
}

// TestFabricListenerStopsOnCtxCancel_5047 proves the supervisor and its serve
// worker both exit promptly on ctx cancel — no spurious retry, no goroutine
// leak — once the listener is up.
func TestFabricListenerStopsOnCtxCancel_5047(t *testing.T) {
	s := &Server{}
	const addr = "fab-cancel"
	var listenCalls atomic.Int32
	serveReturned := make(chan struct{})

	cfg := fabricSupervisorConfig{
		backoffBase:  time.Millisecond,
		backoffMax:   5 * time.Millisecond,
		healthyServe: time.Hour,
		listen: func(ctx context.Context) (net.Listener, error) {
			listenCalls.Add(1)
			return newBlockingListener(), nil
		},
		serve: func(ctx context.Context, lis net.Listener) error {
			defer lis.Close()
			defer close(serveReturned)
			<-ctx.Done()
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.superviseFabricListener(ctx, addr, "", cfg); close(done) }()

	waitFabricUp(t, s, addr)

	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not return promptly after ctx cancel")
	}
	select {
	case <-serveReturned:
	case <-time.After(time.Second):
		t.Fatal("serve worker did not return after ctx cancel — goroutine leak")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown took %v after cancel; want prompt", elapsed)
	}
	// A clean ctx-cancel must not spin the listen loop.
	if got := listenCalls.Load(); got != 1 {
		t.Fatalf("listen called %d times; a clean shutdown must not retry (want exactly 1)", got)
	}
}

// TestFabricListenerErrServerStoppedNotRetried_5047 confirms the expected
// graceful-stop signal (grpc.ErrServerStopped) is treated as a clean exit, NOT
// a fault to retry, even though ctx is still live.
func TestFabricListenerErrServerStoppedNotRetried_5047(t *testing.T) {
	s := &Server{}
	const addr = "fab-stopped"
	var listenCalls atomic.Int32

	cfg := fabricSupervisorConfig{
		backoffBase:  time.Millisecond,
		backoffMax:   5 * time.Millisecond,
		healthyServe: time.Hour,
		listen: func(ctx context.Context) (net.Listener, error) {
			listenCalls.Add(1)
			return newBlockingListener(), nil
		},
		serve: func(ctx context.Context, lis net.Listener) error {
			defer lis.Close()
			// Wrap it to also exercise errors.Is unwrapping.
			return fmt.Errorf("fabric serve: %w", grpc.ErrServerStopped)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.superviseFabricListener(ctx, addr, "", cfg); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not exit on grpc.ErrServerStopped — it retried a graceful stop")
	}
	if got := listenCalls.Load(); got != 1 {
		t.Fatalf("listen called %d times; grpc.ErrServerStopped must NOT be retried (want exactly 1)", got)
	}
	if s.FabricListenerUp(addr) {
		t.Fatalf("FabricListenerUp(%q) = true after graceful stop; want false", addr)
	}
}

// TestFabricListenerPersistentFailureBoundedBackoff_5047 proves a persistent
// bind failure keeps retrying (no permanent give-up) at a BOUNDED interval that
// caps out — it does not spin. The supervisor is run for a fixed window with
// tiny backoff bounds and the retry count is asserted against the cap.
func TestFabricListenerPersistentFailureBoundedBackoff_5047(t *testing.T) {
	s := &Server{}
	const addr = "fab-persistent"
	const base = 10 * time.Millisecond
	const max = 25 * time.Millisecond
	const window = 250 * time.Millisecond
	var listenCalls atomic.Int32

	cfg := fabricSupervisorConfig{
		backoffBase:  base,
		backoffMax:   max,
		healthyServe: time.Hour,
		listen: func(ctx context.Context) (net.Listener, error) {
			listenCalls.Add(1)
			return nil, errors.New("persistent bind failure")
		},
		serve: func(ctx context.Context, lis net.Listener) error { return nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.superviseFabricListener(ctx, addr, "", cfg); close(done) }()

	time.Sleep(window)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not return after ctx cancel")
	}

	got := listenCalls.Load()
	// Steady-state interval caps at `max`, so attempts in `window` are bounded
	// by window/max plus slack for the (shorter) initial ramp. A spinning loop
	// (no backoff) would make hundreds/thousands of calls and blow this bound.
	maxExpected := int32(window/max) + 5
	if got > maxExpected {
		t.Fatalf("listen attempts = %d in %v; want <= %d — backoff is NOT bounded (spinning)", got, window, maxExpected)
	}
	// It must actually keep retrying a persistent failure (no permanent give-up).
	if got < 2 {
		t.Fatalf("listen attempts = %d; a persistent failure must keep retrying (want >= 2)", got)
	}
	if s.FabricListenerUp(addr) {
		t.Fatalf("FabricListenerUp(%q) = true while bind persistently fails; want false", addr)
	}
}
