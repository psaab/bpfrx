// RED-on-revert net for the #6401 round-3 deadlock fix: an UNEXPECTED HTTP
// serve-exit must NOT deadlock a concurrent Server.Wait(). The round-2
// serve-exit->Failed fold marked the leg dead UNDER lifeMu; because the serve
// goroutine still holds its wg count when it does so, and Wait() holds lifeMu
// ACROSS wg.Wait(), a serve-exit racing a shutdown Wait deadlocked (Wait holds
// lifeMu waiting on the goroutine's wg.Done; the goroutine waits on lifeMu
// before it can return -> Done). The fix makes the dead marking atomic (no
// lock), breaking the cycle.
package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// deadlockProbeLn is an in-memory listener whose Accept blocks until either
// Close (a requested shutdown -> net.ErrClosed) or fail is closed (an UNEXPECTED
// self-termination -> a non-net error, so http.Server.Serve returns it). It
// drives the serve-exit path deterministically WITHOUT a real socket.
type deadlockProbeLn struct {
	addr   net.Addr
	fail   chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (l *deadlockProbeLn) Accept() (net.Conn, error) {
	select {
	case <-l.fail:
		return nil, errors.New("simulated unexpected serve failure")
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *deadlockProbeLn) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *deadlockProbeLn) Addr() net.Addr { return l.addr }

func TestServeExitDoesNotDeadlockConcurrentWait_6401(t *testing.T) {
	ln := &deadlockProbeLn{
		addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		fail:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	srv := NewServer(Config{
		Addr:       "127.0.0.1:8080",
		ListenFunc: func(_, _ string) (net.Listener, error) { return ln, nil },
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The leg is serving (parked at Accept).
	if srv.EffectiveHTTPAddr() == "" {
		t.Fatal("HTTP leg not serving after Start")
	}

	// Start Wait() concurrently: it acquires lifeMu and blocks in wg.Wait()
	// while the leg is parked — HOLDING lifeMu the whole time. This is the exact
	// shutdown ordering that made the round-2 lifeMu-guarded dead marking
	// deadlock.
	waitDone := make(chan struct{})
	go func() { srv.Wait(); close(waitDone) }()
	// Let Wait acquire the (uncontended) lifeMu and enter wg.Wait().
	time.Sleep(100 * time.Millisecond)

	// Trigger the UNEXPECTED serve-exit. With the lifeMu-guarded marking the leg
	// goroutine would block on lifeMu (held by Wait) and never wg.Done ->
	// permanent hang. With the atomic marking it stores dead lock-free, returns,
	// wg.Done -> Wait unblocks.
	close(ln.fail)

	select {
	case <-waitDone:
		// No deadlock — the fix holds.
	case <-time.After(3 * time.Second):
		t.Fatal("Server.Wait() deadlocked with a concurrent unexpected serve-exit (#6401 lock-ordering regression)")
	}

	// The leg ended up dead, so the effective-listener snapshot reports it not
	// serving (Failed at the daemon layer).
	if got := srv.EffectiveHTTPAddr(); got != "" {
		t.Errorf("after serve-exit, EffectiveHTTPAddr = %q, want \"\" (leg marked dead)", got)
	}
}
