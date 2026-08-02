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
		// COPY, do not alias. The recorded value must be what was live at THIS
		// instant; keeping the pointer would let a snapshot published later — or
		// an in-place edit of the AuthConfig the caller still holds — rewrite
		// history and turn a failing ordering assertion green.
		a.seen[addr] = copyAuth(a.srv.LiveAuth())
		a.hit[addr]++
	}
	a.mu.Unlock()
	return a.reg.listen(network, addr)
}

// copyAuth deep-copies an auth snapshot (nil stays nil).
func copyAuth(a *api.AuthConfig) *api.AuthConfig {
	if a == nil {
		return nil
	}
	out := &api.AuthConfig{Users: map[string]string{}, APIKeys: map[string]bool{}}
	for k, v := range a.Users {
		out.Users[k] = v
	}
	for k, v := range a.APIKeys {
		out.APIKeys[k] = v
	}
	return out
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
	if snap := m.srv.LiveAuth(); snap != nil {
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
		// The VALUE, not just the key: a snapshot naming admin under some other
		// secret is a different credential set, and the property is that the one
		// this commit published was live before the socket existed.
		if snap.Users["admin"] != "secret" {
			t.Fatalf("the new %s listener at %s was bound under auth snapshot %+v, which is not "+
				"the credential this commit published", leg.what, leg.addr, snap)
		}
	}

	// Control: the reconcile actually converged, so the assertions above are
	// about the ORDER of two things that both happened.
	if snap := m.srv.LiveAuth(); snap == nil || snap.Users["admin"] != "secret" {
		t.Fatalf("post-reconcile snapshot = %+v, want the published credential", snap)
	}
	if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("the new HTTP listener is not serving after the reconcile")
	}
}

// TestMgmtCredentialRotationPrecedesTheRebind_5561 is the same ordering at the
// other edge of its scope: a ROTATION (secret A -> secret B) on a bind that also
// moves. The property is about secret A: it must already be gone from the live
// snapshot when the new socket is created, because that socket serves from the
// moment it exists. Publishing after the HTTP rebind — or after the HTTPS one —
// would leave the superseded secret live on the new listener for as long as the
// bind takes.
//
// What the new socket is bound UNDER is the restricted set (#5561 round 12):
// while the rebind is in flight the OLD listener is still serving, and secret B
// was committed for the address being bound, not for that one. The rotation
// therefore converges to B only after the rebind succeeds, which the final
// assertion pins — so the case still proves the hoisted publish is not
// overwritten by a later one.
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
	if snap == nil {
		t.Fatal("the rebound HTTP listener was bound under a nil snapshot — it serves from the " +
			"moment it is created, so every caller was passed through unauthenticated")
	}
	if snap.Users["admin"] == "secret-a" {
		t.Fatalf("the rebound HTTP listener was bound under auth snapshot %+v — the SUPERSEDED "+
			"secret. It serves from the moment it is created, so the secret the operator "+
			"replaced was live on the new socket for as long as the bind took", snap)
	}
	// "not the old secret" is satisfied by publishing the NEW one early, which is
	// the grant this rotation must withhold until the rebind converges — the old
	// listener is still serving at 10.0.0.1:8080 while this bind is in flight, and
	// secret-b was committed for 10.0.0.2:8080. So assert the VALUE the socket is
	// created under, not merely what it is not (#5561 round 14).
	if api.CredentialCount(snap) != 0 {
		t.Fatalf("the rebound HTTP listener was bound under auth snapshot %+v, want the EMPTY "+
			"(deny-all) intersection. A disjoint rotation intersects to nothing, and publishing "+
			"secret-b before this bind converges would hand it to the listener still serving "+
			"10.0.0.1:8080 — the address this commit is moving away from", snap)
	}
	if live := m.srv.LiveAuth(); live == nil || live.Users["admin"] != "secret-b" {
		t.Fatalf("post-reconcile snapshot = %+v, want the rotated secret — the rebind converged, "+
			"so the full committed set must be live", live)
	}
}

// TestMgmtRetainedListenerNeverGainsACredential_5561 is the fail-on-revert gate
// for the #5561 round-12 GRANT property: a listener RETAINED by a failed rebind
// must never start accepting a credential it did not already accept.
//
// The comment that licensed the unconditional publish argued that a non-nil auth
// "only ADDS a requirement, so applying it to whatever is currently live is
// strictly more restrictive". That is true only against a NIL live snapshot.
// Credential sets are not monotonic: they expand and rotate, and every value
// they gain is a value that was not accepted a moment ago.
//
// The operator's commit is a pair — this credential set, at this endpoint. When
// the endpoint fails to bind, the fail-safe keeps the OLD listener serving, and
// publishing the whole set hands the new credentials to an address the commit
// asked to stop serving. The sharp version is a commit that moves management
// off a routable address (or onto loopback) while introducing an automation
// credential: the credential was scoped to the endpoint the operator was moving
// to, and a failed rebind would otherwise expose it exactly where the operator
// was trying to withdraw it.
//
// FAIL-ON-REVERT: publish next.Auth whole before the rebind and the retained
// listener accepts both the new principal and the new api-key.
func TestMgmtRetainedListenerNeverGainsACredential_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Live: an off-box listener accepting exactly one credential.
	live := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", live)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// The commit: keep webadmin, ADD an automation principal and an api-key, and
	// move the bind. The move fails, so 10.0.0.1:8080 keeps serving.
	expanded := &api.AuthConfig{
		Users:   map[string]string{"webadmin": "secret-a", "autobot": "secret-c"},
		APIKeys: map[string]bool{"key-new": true},
	}
	reg.failAddr["10.0.0.2:8080"] = true
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", expanded)); err == nil {
		t.Fatal("the rebind was expected to FAIL, so the case never reached the state it tests " +
			"(a retained listener under a widened credential set)")
	}

	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live snapshot went nil on a failed rebind — that drops api-auth entirely " +
			"on an off-box listener")
	}
	if _, ok := snap.Users["autobot"]; ok {
		t.Fatalf("the listener at %q now accepts principal autobot. The committed config "+
			"authorized autobot at 10.0.0.2:8080, an endpoint that FAILED to bind; this "+
			"listener is the one the commit asked to leave, and it never accepted autobot "+
			"before", m.cur.addr)
	}
	if snap.APIKeys["key-new"] {
		t.Fatalf("the listener at %q now accepts api-key key-new, which it never accepted "+
			"before and which was committed for an endpoint that failed to bind", m.cur.addr)
	}
	// The withholding is an intersection, not a lockout: a credential that was
	// already accepted here AND is still committed keeps working.
	if got := snap.Users["webadmin"]; got != "secret-a" {
		t.Fatalf("the retained listener lost webadmin (snapshot %+v). The commit did not revoke "+
			"it and this listener already accepted it, so withholding it is over-restriction "+
			"with no property behind it", snap)
	}

	// Control: the withholding is scoped to the FAILURE. When the rebind
	// converges, every live listener is at an address this config names and the
	// full set lands — otherwise the assertions above would also be satisfied by
	// an implementation that never grants a credential after any endpoint change.
	delete(reg.failAddr, "10.0.0.2:8080")
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", expanded)); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	snap = m.srv.LiveAuth()
	if snap == nil || snap.Users["autobot"] != "secret-c" || !snap.APIKeys["key-new"] {
		t.Fatalf("post-convergence snapshot = %+v, want the full committed set — the listener is "+
			"now at the endpoint the credentials were committed for", snap)
	}
}
