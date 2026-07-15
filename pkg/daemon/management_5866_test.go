// #5866: the managementReconciler must, on a day-2 web-management change,
// atomically replace the live HTTP/HTTPS listener + authentication snapshot
// instead of leaving the boot-time server enforcing the old policy until a
// restart. These tests drive reconcileTo/startTo with a FAKE listener factory
// (no real ports) and cover: a bind/port change (new active, old closed),
// make-before-break coexistence, a TLS-material change (new cert served),
// a same-endpoint auth swap (no rebind), and a failed new-bind (old listener
// RETAINED, error surfaced — fail-closed to the previous working state).
//
// FAIL-ON-REVERT: revert reconcileTo to close-old-before-binding-new and the
// bind-failure test leaves nothing serving (RED); revert it to not swap and the
// bind/port + auth tests do not converge (RED).
package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
)

// fakeLn is an in-memory net.Listener: Accept blocks until Close, so an
// http.Server.Serve loop parks until Shutdown closes it (no real socket).
type fakeLn struct {
	addr   string
	closed chan struct{}
	once   sync.Once
}

func (f *fakeLn) Accept() (net.Conn, error) { <-f.closed; return nil, net.ErrClosed }
func (f *fakeLn) Close() error              { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakeLn) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (f *fakeLn) isOpen() bool {
	select {
	case <-f.closed:
		return false
	default:
		return true
	}
}

// fakeReg is the injected listener factory. It records, at each new listener's
// creation, whether every previously-created listener was still open — the
// make-before-break witness: a new endpoint must bind while the old is still
// serving.
type fakeReg struct {
	mu              sync.Mutex
	byAddr          map[string]*fakeLn
	failAddr        map[string]bool
	priorsOpenAtNew map[string]bool
}

func newFakeReg() *fakeReg {
	return &fakeReg{byAddr: map[string]*fakeLn{}, failAddr: map[string]bool{}, priorsOpenAtNew: map[string]bool{}}
}

func (r *fakeReg) listen(network, addr string) (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failAddr[addr] {
		return nil, fmt.Errorf("fake bind refused: %s", addr)
	}
	priorsOpen := true
	for a, ln := range r.byAddr {
		if a != addr && !ln.isOpen() {
			priorsOpen = false
		}
	}
	r.priorsOpenAtNew[addr] = priorsOpen
	ln := &fakeLn{addr: addr, closed: make(chan struct{})}
	r.byAddr[addr] = ln
	return ln, nil
}

func (r *fakeReg) get(addr string) *fakeLn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byAddr[addr]
}

func cfgFor(reg *fakeReg, addr string, useTLS bool, httpsAddr string, auth *api.AuthConfig) api.Config {
	return api.Config{Addr: addr, TLS: useTLS, HTTPSAddr: httpsAddr, Auth: auth, ListenFunc: reg.listen}
}

func newTestMgmt(reg *fakeReg) *managementReconciler {
	// reconcileTo/startTo do not dereference d (only desired()/start() do), so a
	// bare Daemon is sufficient for these listener-lifecycle tests.
	return newManagementReconciler(&Daemon{}, api.Config{ListenFunc: reg.listen})
}

func waitClosed(t *testing.T, ln *fakeLn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !ln.isOpen() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener %s did not close within the drain window", ln.addr)
}

// Bar 1 + Bar 4: a bind/port change replaces the listener make-before-break —
// the new endpoint is active and the old is closed, and the new endpoint bound
// while the old was still serving (no unreachable window).
func TestMgmtReconcileBindChange_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	old := reg.get("10.0.0.1:8080")
	if old == nil || !old.isOpen() {
		t.Fatal("initial listener not active")
	}

	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nil)); err != nil {
		t.Fatalf("bind-change reconcile: %v", err)
	}
	// New endpoint recorded + active.
	if m.cur.addr != "10.0.0.2:8080" {
		t.Fatalf("current endpoint = %q, want the new bind 10.0.0.2:8080", m.cur.addr)
	}
	newLn := reg.get("10.0.0.2:8080")
	if newLn == nil || !newLn.isOpen() {
		t.Fatal("new listener is not active after the bind change")
	}
	// Make-before-break: the new endpoint bound while the old was still open.
	if !reg.priorsOpenAtNew["10.0.0.2:8080"] {
		t.Fatal("new listener bound only AFTER the old closed — not make-before-break (#5866): " +
			"there was a window with no management listener")
	}
	// Old endpoint is retired.
	waitClosed(t, old)
}

// Bar 2: a TLS-material change replaces the listener and serves a FRESH cert.
func TestMgmtReconcileTLSChange_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start HTTP-only.
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if m.srv.HTTPSCertForTest() != nil {
		t.Fatal("HTTP-only server must not serve a TLS cert")
	}

	// Enable HTTPS -> endpoint changes -> rebuild with a cert.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("enable-TLS reconcile: %v", err)
	}
	cert1 := m.srv.HTTPSCertForTest()
	if cert1 == nil {
		t.Fatal("HTTPS-enabled server must serve a TLS cert after the reconcile")
	}
	if reg.get("10.0.0.1:8443") == nil || !reg.get("10.0.0.1:8443").isOpen() {
		t.Fatal("HTTPS listener not active after enabling TLS")
	}

	// Change the HTTPS bind -> rebuild -> a NEW self-signed cert is served.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.2:8443", nil)); err != nil {
		t.Fatalf("https-rebind reconcile: %v", err)
	}
	cert2 := m.srv.HTTPSCertForTest()
	if cert2 == nil {
		t.Fatal("HTTPS cert missing after the https rebind")
	}
	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("served TLS cert has no leaf certificate")
	}
	if bytesEqual(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("a TLS-material change must serve a NEW certificate, got the same leaf cert bytes (#5866)")
	}
}

// Bar 3: a same-endpoint auth change swaps the LIVE auth snapshot in place — no
// listener rebind (the server instance is unchanged), and the revoked credential
// is rejected on the next request.
func TestMgmtReconcileAuthSwapNoRebind_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auth := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", auth)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	srvBefore := m.srv
	ln := reg.get("10.0.0.1:8080")

	// Revoke admin on the SAME endpoint.
	revoked := &api.AuthConfig{Users: map[string]string{"other": "pw"}}
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", revoked)); err != nil {
		t.Fatalf("auth-swap reconcile: %v", err)
	}
	// No rebind: the SAME server instance and the SAME listener are retained.
	if m.srv != srvBefore {
		t.Fatal("a same-endpoint auth change must NOT rebind the listener (server instance changed)")
	}
	if !ln.isOpen() {
		t.Fatal("the listener was bounced on a same-endpoint auth change (#5866)")
	}
	// The live auth snapshot was swapped IN PLACE to the revoked set (admin gone,
	// other present). The api-level TestServerReplaceAuthLiveSwap_5866 proves such
	// a snapshot rejects the revoked credential on the next request.
	snap := m.srv.AuthSnapshotForTest()
	if snap == nil {
		t.Fatal("live auth snapshot is nil after the revoke reconcile")
	}
	if _, ok := snap.Users["admin"]; ok {
		t.Fatal("revoked credential 'admin' is STILL in the live auth snapshot — the swap did not " +
			"take effect (#5866)")
	}
	if _, ok := snap.Users["other"]; !ok {
		t.Fatal("the new credential 'other' is missing from the live auth snapshot")
	}
}

// Bar 5: a failed new-bind RETAINS the old listener (fail-closed to the previous
// working state, not mgmt-down) and surfaces the error. This is also the sharp
// make-before-break lever: a close-old-first implementation would leave nothing
// serving.
func TestMgmtReconcileBindFailureRetainsOld_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	old := reg.get("10.0.0.1:8080")
	srvBefore := m.srv

	reg.failAddr["10.0.0.2:8080"] = true
	err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nil))
	if err == nil {
		t.Fatal("a failed listener replacement must surface an error")
	}
	// Old listener retained + still serving.
	if m.srv != srvBefore {
		t.Fatal("the live server was swapped despite the new bind failing (#5866)")
	}
	if m.cur.addr != "10.0.0.1:8080" {
		t.Fatalf("endpoint fingerprint = %q, want the retained 10.0.0.1:8080 (retry debt)", m.cur.addr)
	}
	if !old.isOpen() {
		t.Fatal("the OLD listener was closed on a failed replacement — management went DOWN " +
			"(fail-open); make-before-break must retain the previous working listener (#5866)")
	}
	// Give any (incorrect) async close a chance, then re-assert the old is up.
	time.Sleep(50 * time.Millisecond)
	if !old.isOpen() {
		t.Fatal("the OLD listener closed asynchronously after a failed replacement (#5866)")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
