// RED-on-revert net for the #6401 fold: the HTTP REST listener state the
// `show system services` snapshot reports (managementReconciler.effectiveHTTPListener)
// must DISTINGUISH three states — Disabled (no --api-addr, nil reconciler),
// Failed (configured but the boot bind failed), and Listening (converged). The
// pre-fold accessor returned a bare address ("" for BOTH disabled and failed),
// so a failed bind was misreported as "disabled". These assert the three states
// are distinct, and that a Listening bind reports the ACTUAL bound address (an
// ephemeral :0 resolves to a concrete port).
package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/sysservices"
)

func TestEffectiveHTTPListenerStatesDistinct(t *testing.T) {
	// Disabled: nil reconciler — an empty --api-addr, where Daemon.Run never
	// started the HTTP listener.
	var nilM *managementReconciler
	if got := nilM.effectiveHTTPListener(); got.State != sysservices.StateDisabled {
		t.Errorf("nil reconciler state = %v, want StateDisabled: %+v", got.State, got)
	}

	// Failed: configured but the boot bind failed (fake factory refuses the
	// addr, so startTo returns an error and curSet stays false).
	reg := newFakeReg()
	reg.failAddr["10.0.0.1:8080"] = true
	mFail := newTestMgmt(reg)
	if err := mFail.startTo(context.Background(), cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
		t.Fatal("startTo should fail when the fake factory refuses the bind")
	}
	failLn := mFail.effectiveHTTPListener()
	if failLn.State != sysservices.StateFailed {
		t.Errorf("failed boot bind state = %v, want StateFailed: %+v", failLn.State, failLn)
	}
	if failLn.Addr != "10.0.0.1:8080" {
		t.Errorf("failed listener addr = %q, want the attempted 10.0.0.1:8080", failLn.Addr)
	}

	// Listening: converged bind (fake factory accepts).
	regOK := newFakeReg()
	mOK := newTestMgmt(regOK)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mOK.startTo(ctx, cfgFor(regOK, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("startTo: %v", err)
	}
	if got := mOK.effectiveHTTPListener(); got.State != sysservices.StateListening {
		t.Errorf("converged bind state = %v, want StateListening: %+v", got.State, got)
	}

	// The three states are mutually distinct — the crux of the fold.
	if sysservices.StateDisabled == sysservices.StateFailed ||
		sysservices.StateFailed == sysservices.StateListening {
		t.Fatal("listener states are not distinct")
	}
}

// TestEffectiveHTTPListenerEphemeralPort drives a REAL bind on 127.0.0.1:0 and
// asserts the reported address is the concrete ephemeral port the socket bound,
// not the requested ":0" — the #6401 point-4 fold that sources the address from
// the live listener's Addr (api.Server.EffectiveHTTPAddr) rather than the
// requested endpoint fingerprint.
func TestEffectiveHTTPListenerEphemeralPort(t *testing.T) {
	m := newManagementReconciler(&Daemon{}, api.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.startTo(ctx, api.Config{Addr: "127.0.0.1:0"}); err != nil {
		t.Fatalf("startTo real bind: %v", err)
	}
	got := m.effectiveHTTPListener()
	if got.State != sysservices.StateListening {
		t.Fatalf("real bind state = %v, want StateListening: %+v", got.State, got)
	}
	if got.Addr == "" || strings.HasSuffix(got.Addr, ":0") {
		t.Errorf("ephemeral bind addr not resolved to a concrete port: %q", got.Addr)
	}
}

// serveExitLn is an in-memory listener whose Accept blocks until either Close
// (a requested shutdown → net.ErrClosed) or fail is closed (an UNEXPECTED
// self-termination → a non-net error, so http.Server.Serve returns it). It
// drives the serve-exit path WITHOUT a real socket (the review sandbox blocks
// them).
type serveExitLn struct {
	addr   net.Addr
	fail   chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (l *serveExitLn) Accept() (net.Conn, error) {
	select {
	case <-l.fail:
		return nil, errors.New("simulated unexpected serve failure")
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *serveExitLn) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *serveExitLn) Addr() net.Addr { return l.addr }

// TestEffectiveHTTPListenerServeExitFails pins the #6401 HTTP↔gRPC SYMMETRY
// fold: when a CONVERGED HTTP leg's serve loop exits UNEXPECTEDLY (not a
// requested shutdown), `show system services` must report the listener Failed —
// NOT StateListening on a dead socket. Before the fold the reconciler reported
// Listening on the dead listener's address (curSet stayed true and
// EffectiveHTTPAddr returned the dead leg's Addr), asymmetric with the gRPC
// serve-exit clear.
func TestEffectiveHTTPListenerServeExitFails(t *testing.T) {
	ln := &serveExitLn{
		addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		fail:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	cfg := api.Config{
		Addr:       "127.0.0.1:8080",
		ListenFunc: func(_, _ string) (net.Listener, error) { return ln, nil },
	}
	m := newManagementReconciler(&Daemon{}, api.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.startTo(ctx, cfg); err != nil {
		t.Fatalf("startTo: %v", err)
	}
	// Converged and serving.
	if got := m.effectiveHTTPListener(); got.State != sysservices.StateListening {
		t.Fatalf("initial state = %v, want StateListening: %+v", got.State, got)
	}

	// Trigger an UNEXPECTED serve exit (not a requested shutdown).
	close(ln.fail)

	// The leg's serve goroutine marks the leg dead asynchronously; poll until
	// the reconciler reports Failed (with a generous bound so a GREEN run
	// finishes in a few ms and a RED run trips cleanly, not a hang).
	var got sysservices.Listener
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got = m.effectiveHTTPListener(); got.State == sysservices.StateFailed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got.State != sysservices.StateFailed {
		t.Fatalf("HTTP serve exit not reported Failed (still Listening on a dead leg): %+v", got)
	}
}

// TestEffectiveHTTPListenerReportsTheRETRIED_Address_6401 covers the reconcileTo
// half of the #6401 attempted-address record. Both write sites matter and only
// the startTo one was pinned: deleting `m.lastHTTPAttempt = next.Addr` from
// reconcileTo left build, vet and the whole pkg/daemon suite green.
//
// The state is a boot bind that FAILED (curSet stays false, so
// effectiveHTTPListener reports lastHTTPAttempt rather than cur.addr) followed by
// a day-2 commit that moves the bind and fails too. `show system services` must
// name the address the listener is retrying NOW, not the one it failed at boot —
// the boot address is not being retried by anything and reporting it sends the
// operator to check the wrong interface.
func TestEffectiveHTTPListenerReportsTheRETRIED_Address_6401(t *testing.T) {
	reg := newFakeReg()
	reg.failAddr["10.0.0.1:8080"] = true
	reg.failAddr["10.0.0.2:8080"] = true
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
		t.Fatal("the BOOT bind was expected to fail; the case needs curSet false, which is " +
			"what makes effectiveHTTPListener report the attempted address at all")
	}
	if got := m.effectiveHTTPListener(); got.Addr != "10.0.0.1:8080" || got.State != sysservices.StateFailed {
		t.Fatalf("after the failed boot bind: %+v, want Failed at 10.0.0.1:8080", got)
	}

	// Day 2: the operator moves the bind. It fails too, so the listener is still
	// down — but it is now retrying a DIFFERENT address.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nil)); err == nil {
		t.Fatal("the day-2 rebind was expected to fail as well; if it succeeded the reconciler " +
			"would be Listening and the attempted-address field would not be read")
	}
	got := m.effectiveHTTPListener()
	if got.State != sysservices.StateFailed {
		t.Fatalf("state = %v, want StateFailed: %+v", got.State, got)
	}
	if got.Addr != "10.0.0.2:8080" {
		t.Fatalf("`show system services` reports %q, want the address actually being retried, "+
			"10.0.0.2:8080. The boot address is stale: the operator moved the bind, and every "+
			"later reconcile now attempts 10.0.0.2:8080", got.Addr)
	}
}
