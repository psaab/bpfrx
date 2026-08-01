package daemon

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/api"
)

// management_authpublish_5561_test.go is the fail-on-revert gate for the #5561
// round-9 finding-3 ORDERING property: no listener may be bound — and therefore
// begin serving — before the authentication snapshot it must enforce is live.
//
// api.Server.ReconcileHTTP binds AND STARTS SERVING the new listener before it
// returns (listener.go, serveLegLocked). reconcileTo used to publish auth at the
// END of the function, so a freshly-bound socket enforced the PREVIOUS snapshot
// until the publish landed — with an entire ReconcileHTTPS call, which generates
// or loads a TLS keypair and performs a bind, sitting inside that window.
//
// These cases observe the live snapshot AT THE MOMENT each listener is created,
// through the injected listener factory. That is the earliest point the new
// socket can exist, and it precedes serving, so a snapshot that is already
// correct there is correct for every request the listener will ever answer.

// authAtBind is a listener factory that records the server's LIVE auth snapshot
// at the instant each address is bound, then delegates to a fakeReg.
type authAtBind struct {
	reg *fakeReg

	mu   sync.Mutex
	srv  *api.Server
	seen map[string]*api.AuthConfig
	hit  map[string]int
}

func newAuthAtBind(reg *fakeReg) *authAtBind {
	return &authAtBind{reg: reg, seen: map[string]*api.AuthConfig{}, hit: map[string]int{}}
}

func (a *authAtBind) listen(network, addr string) (net.Listener, error) {
	a.mu.Lock()
	if a.srv != nil {
		a.seen[addr] = a.srv.AuthSnapshotForTest()
		a.hit[addr]++
	}
	a.mu.Unlock()
	return a.reg.listen(network, addr)
}

// watch starts recording once the server exists (startTo constructs it).
func (a *authAtBind) watch(srv *api.Server) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.srv = srv
}

// snapshotAt returns the auth snapshot live when addr was bound, and whether
// addr was bound at all while watching.
func (a *authAtBind) snapshotAt(addr string) (*api.AuthConfig, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen[addr], a.hit[addr] > 0
}

// TestMgmtNewListenerNeverServesUnderTheOldAuth_5561 drives the worst case the
// ordering allowed: a commit that moves the HTTP bind from loopback to an
// OFF-BOX address and, in the same commit, adds the api-auth credential the
// #4047/#5127 clamp requires for that address — while also enabling TLS, so an
// entire HTTPS reconcile runs between the new HTTP socket serving and the
// credential being published.
//
// The previous snapshot there is legitimately nil: a loopback bind needs no
// credential. So for the duration of the TLS reconcile, the new off-box listener
// answered every caller through dynamicAuthMiddleware's nil-snapshot
// pass-through — an unauthenticated management plane on a routable address, with
// a window as wide as a keypair generation plus a bind.
func TestMgmtNewListenerNeverServesUnderTheOldAuth_5561(t *testing.T) {
	reg := newFakeReg()
	fac := newAuthAtBind(reg)
	m := newManagementReconciler(&Daemon{}, api.Config{ListenFunc: fac.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Boot: loopback, no api-auth — the legitimate nil-on-loopback posture.
	boot := api.Config{Addr: "127.0.0.1:8080", ListenFunc: fac.listen}
	if err := m.startTo(ctx, boot); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if snap := m.srv.AuthSnapshotForTest(); snap != nil {
		t.Fatalf("boot snapshot = %+v, want nil (a loopback bind carries no api-auth)", snap)
	}
	fac.watch(m.srv)

	// The commit: off-box HTTP bind + the credential it requires + TLS on.
	creds := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	next := api.Config{
		Addr:       "10.0.0.1:8080",
		TLS:        true,
		HTTPSAddr:  "10.0.0.1:8443",
		Auth:       creds,
		ListenFunc: fac.listen,
	}
	if err := m.reconcileTo(next); err != nil {
		t.Fatalf("reconcileTo: %v", err)
	}

	// The property. Both legs, because both begin serving on creation and both
	// read the same shared snapshot.
	for _, leg := range []struct{ what, addr string }{
		{"HTTP", "10.0.0.1:8080"},
		{"HTTPS", "10.0.0.1:8443"},
	} {
		snap, bound := fac.snapshotAt(leg.addr)
		if !bound {
			t.Fatalf("the %s leg was never bound at %s, so the case observed nothing", leg.what, leg.addr)
		}
		if snap == nil {
			t.Fatalf("the new OFF-BOX %s listener at %s was bound while the live auth snapshot "+
				"was still nil. It starts serving on creation, so between that moment and the "+
				"eventual ReplaceAuth every request to a routable management address was passed "+
				"through unauthenticated — a window as wide as the TLS reconcile that runs "+
				"inside it", leg.what, leg.addr)
		}
		if _, ok := snap.Users["admin"]; !ok {
			t.Fatalf("the new %s listener at %s was bound under auth snapshot %+v, which is not "+
				"the credential this commit published", leg.what, leg.addr, snap)
		}
	}

	// Control: the reconcile actually converged, so the assertions above are
	// about the ORDER of two things that both happened.
	if snap := m.srv.AuthSnapshotForTest(); snap == nil || snap.Users["admin"] != "secret" {
		t.Fatalf("post-reconcile snapshot = %+v, want the published credential", snap)
	}
	if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("the new HTTP listener is not serving after the reconcile")
	}
}

// TestMgmtCredentialRotationPrecedesTheRebind_5561 is the same ordering at the
// other edge of its scope: a ROTATION (secret A -> secret B) on a bind that also
// moves. Publishing after the HTTP rebind but before the HTTPS one would satisfy
// nothing here either — the new listener would serve secret A for as long as the
// bind takes.
//
// It also pins the direction that must NOT move: the tightening publish is
// hoisted, and the case still converges to B rather than being overwritten by a
// later publish.
func TestMgmtCredentialRotationPrecedesTheRebind_5561(t *testing.T) {
	reg := newFakeReg()
	fac := newAuthAtBind(reg)
	m := newManagementReconciler(&Daemon{}, api.Config{ListenFunc: fac.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	old := &api.AuthConfig{Users: map[string]string{"admin": "secret-a"}}
	if err := m.startTo(ctx, api.Config{Addr: "10.0.0.1:8080", Auth: old, ListenFunc: fac.listen}); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	fac.watch(m.srv)

	rotated := &api.AuthConfig{Users: map[string]string{"admin": "secret-b"}}
	if err := m.reconcileTo(api.Config{Addr: "10.0.0.2:8080", Auth: rotated, ListenFunc: fac.listen}); err != nil {
		t.Fatalf("reconcileTo: %v", err)
	}

	snap, bound := fac.snapshotAt("10.0.0.2:8080")
	if !bound {
		t.Fatal("the HTTP leg was never rebound, so the case observed nothing")
	}
	if snap == nil || snap.Users["admin"] != "secret-b" {
		t.Fatalf("the rebound HTTP listener was bound under auth snapshot %+v, want the ROTATED "+
			"secret. It serves from the moment it is created, so the superseded secret was live "+
			"on the new socket", snap)
	}
	if live := m.srv.AuthSnapshotForTest(); live == nil || live.Users["admin"] != "secret-b" {
		t.Fatalf("post-reconcile snapshot = %+v, want the rotated secret", live)
	}
}
