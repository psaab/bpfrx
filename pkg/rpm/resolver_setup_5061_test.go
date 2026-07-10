// resolver_setup_5061_test.go — #5061.
//
// A VRF/path-scoped RPM probe whose target is a HOSTNAME resolves through a
// resolver socket pinned to the probe's SO_BINDTODEVICE / SO_MARK (#2614). A
// SETUP failure on that resolver socket (EPERM/ENODEV, failed RawConn.Control)
// is a control-plane error — the probe never left the box — and MUST NOT count
// as probe loss, advance failure thresholds, flip status, fire a transition, or
// let ip-monitoring actuate routes (the #1843 fail-safe). Before #5061 the
// data-socket Control wrapped such failures with ErrProbeSetup, but the
// resolver-socket Control returned the raw error, and the ErrProbeSetup
// sentinel does not survive the resolver's *net.DNSError (it flattens its cause
// to a string) — so a resolver bind failure reached the probe loop as an
// ordinary resolve error and was recorded as a failed probe. These tests pin
// the fix: one shared Control helper classifies both sockets, and each probe
// type re-tags from the out-of-band sink.
package rpm

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// fakeRawConn is a syscall.RawConn that hands vrfBindControl a caller-chosen fd
// so applyVRFBind runs against it. fd = ^uintptr(0) (i.e. -1) makes
// SO_BINDTODEVICE fail EBADF without a live socket.
type fakeRawConn struct{ fd uintptr }

func (f fakeRawConn) Control(fn func(fd uintptr)) error    { fn(f.fd); return nil }
func (f fakeRawConn) Read(fn func(fd uintptr) bool) error  { return nil }
func (f fakeRawConn) Write(fn func(fd uintptr) bool) error { return nil }

// TestVRFBindControlClassifiesSetupFailureAsProbeSetup is the shared-helper
// gate: the SINGLE Control hook used by BOTH the probe data socket and the
// VRF-bound DNS resolver socket must classify an applyVRFBind failure as
// ErrProbeSetup AND record it in the out-of-band sink. fail-on-revert:
// restoring the resolver's old raw-error Control (return err/cerr unwrapped)
// makes errors.Is(ErrProbeSetup) false and leaves the sink empty.
func TestVRFBindControlClassifiesSetupFailureAsProbeSetup(t *testing.T) {
	sink := &setupErrSink{}
	ctrl := vrfBindControl(probeSockOpts{BindDevice: "vrf-nonexistent-zzz"}, sink)

	err := ctrl("udp", "192.0.2.53:53", fakeRawConn{fd: ^uintptr(0)})
	if err == nil {
		t.Fatal("vrfBindControl returned nil for a failing SO_BINDTODEVICE; want ErrProbeSetup")
	}
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("vrfBindControl err = %v, want it wrapped with ErrProbeSetup", err)
	}
	if se := sink.load(); se == nil || !errors.Is(se, ErrProbeSetup) {
		t.Fatalf("sink = %v, want the ErrProbeSetup captured out-of-band so the "+
			"resolver path (which loses the sentinel through *net.DNSError) can re-tag", se)
	}

	// A no-op bind (no device, no mark) must not fabricate a setup error.
	if e := vrfBindControl(probeSockOpts{}, sink)("udp", "x", fakeRawConn{fd: ^uintptr(0)}); e != nil {
		t.Fatalf("unscoped vrfBindControl err = %v, want nil (no bind attempted)", e)
	}
}

// TestScopedHostnameResolverSetupHoldsProbeStateICMP drives a scoped icmp-ping
// hostname probe whose resolver socket bind fails, and asserts the test HOLDS
// completely: no counter, no status flip, no transition, no event. The
// lookupIPAddr seam simulates the pure-Go resolver — it invokes the bound
// resolver's Dial (which runs the REAL shared vrfBindControl → applyVRFBind
// against the nonexistent VRF device, failing ENODEV/EPERM and recording
// ErrProbeSetup in the sink), then returns a *net.DNSError as the real resolver
// would (sentinel flattened to a string). fail-on-revert: dropping the
// sink.load() re-tag in resolveProbeTarget makes the probe return an ordinary
// resolve error, counted as loss, so SuccFail/TotalSent advance and a fail
// transition fires.
func TestScopedHostnameResolverSetupHoldsProbeStateICMP(t *testing.T) {
	m := New()
	var mu sync.Mutex
	var transitions []Transition
	var events []Event
	m.SetTransitionCallback(func(tr Transition) { mu.Lock(); transitions = append(transitions, tr); mu.Unlock() })
	m.SetEventCallback(func(ev Event) { mu.Lock(); events = append(events, ev); mu.Unlock() })

	key := "WAN/t"
	m.results[key] = &ProbeResult{ProbeName: "WAN", TestName: "t", LastStatus: "pass"}
	test := &config.RPMTest{Name: "t", Target: "wan-a.example.invalid",
		RoutingInstance: "ISP-B", ThresholdSuccessive: 2}

	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	var dials atomic.Int32
	lookupIPAddr = func(ctx context.Context, r *net.Resolver, target string) ([]net.IPAddr, error) {
		if r.Dial == nil {
			t.Fatal("scoped resolver has no Dial hook — VRF bind never applied")
		}
		dials.Add(1)
		if _, derr := r.Dial(ctx, "udp", "192.0.2.53:53"); derr == nil {
			t.Fatal("bound resolver Dial to a nonexistent VRF device unexpectedly succeeded")
		}
		return nil, &net.DNSError{Err: "server misbehaving", Name: target, IsTemporary: true}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		m.runSingleTest(ctx, "WAN", test, key, 3, time.Millisecond, 2)
	}
	if dials.Load() == 0 {
		t.Fatal("resolver Dial seam never exercised — test did not drive the bind failure")
	}
	assertProbeHeld(t, m, key, &mu, &transitions, &events)
}

// TestScopedHostnameResolverSetupHoldsProbeStateTCP / ...HTTP drive the SAME
// invariant end-to-end for tcp-ping and http-get through the REAL dialer: a
// scoped hostname dial resolves through the VRF-bound resolver, whose
// SO_BINDTODEVICE to the nonexistent VRF device fails ENODEV before any packet
// leaves the box. The failure is captured in the sink and re-tagged
// ErrProbeSetup so the test holds. fail-on-revert: dropping the sink.load()
// re-tag in probeTCP/probeHTTP surfaces the *net.DNSError as ordinary loss.
func TestScopedHostnameResolverSetupHoldsProbeStateTCP(t *testing.T) {
	assertScopedHostnameProbeHeld(t, "tcp-ping")
}

func TestScopedHostnameResolverSetupHoldsProbeStateHTTP(t *testing.T) {
	assertScopedHostnameProbeHeld(t, "http-get")
}

func assertScopedHostnameProbeHeld(t *testing.T, probeType string) {
	t.Helper()
	m := New()
	var mu sync.Mutex
	var transitions []Transition
	var events []Event
	m.SetTransitionCallback(func(tr Transition) { mu.Lock(); transitions = append(transitions, tr); mu.Unlock() })
	m.SetEventCallback(func(ev Event) { mu.Lock(); events = append(events, ev); mu.Unlock() })

	key := "WAN/t"
	m.results[key] = &ProbeResult{ProbeName: "WAN", TestName: "t", LastStatus: "pass"}
	test := &config.RPMTest{Name: "t", Target: "wan-a.example.invalid", ProbeType: probeType,
		RoutingInstance: "ISP-B", ThresholdSuccessive: 2}

	// Sanity: the probe classifies the resolver bind failure as setup.
	if _, err := m.runProbe(context.Background(), test, key); !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("%s scoped hostname probe err = %v, want ErrProbeSetup "+
			"(resolver SO_BINDTODEVICE bind failure must not count as loss, #5061)", probeType, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		m.runSingleTest(ctx, "WAN", test, key, 3, time.Millisecond, 2)
	}
	assertProbeHeld(t, m, key, &mu, &transitions, &events)
}

func assertProbeHeld(t *testing.T, m *Manager, key string, mu *sync.Mutex, transitions *[]Transition, events *[]Event) {
	t.Helper()
	m.mu.RLock()
	r := *m.results[key]
	m.mu.RUnlock()
	if r.LastStatus != "pass" {
		t.Fatalf("LastStatus = %q after resolver setup errors, want held at pass", r.LastStatus)
	}
	if r.SuccFail != 0 {
		t.Fatalf("SuccFail = %d after resolver setup errors, want 0 (no loss counting)", r.SuccFail)
	}
	if r.TotalSent != 0 {
		t.Fatalf("TotalSent = %d, want 0 (nothing reached the wire)", r.TotalSent)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*transitions) != 0 {
		t.Fatalf("transitions = %+v, want none for resolver setup errors", *transitions)
	}
	if len(*events) != 0 {
		t.Fatalf("events = %+v, want none for resolver setup errors", *events)
	}
}
