package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// listener_retiredauth_5561_test.go is the fail-on-revert gate for the #5561
// round-14 MAJOR-2 property: a credential the committed config authorized for a
// NEW management address must never become valid on the address that same commit
// RETIRED.
//
// Retirement is asynchronous. stopLegLocked only closes a channel; the leg's
// serve goroutine wakes up later, and only then does Shutdown close the socket
// and drain. ReconcileHTTP/ReconcileHTTPS return as soon as that channel is
// closed, and the management reconciler then publishes the committed credential
// set. So there is a real interval — bounded by scheduling for new connections
// and by the 5s graceful drain for accepted ones — in which the retired listener
// is still answering requests. While every leg read one shared snapshot, the
// grant went out on that listener too.
//
// The fix is a per-leg snapshot pinned at retirement (authSlot), which can only
// tighten afterwards. These cases drive the leg handlers directly rather than
// over TCP: the property is which POLICY a leg enforces, and going through a
// real socket would make the assertion depend on winning a scheduling race
// against the drain, which is the opposite of a deterministic guard.

// legProbe runs a Basic-auth request against a leg's handler and reports whether
// it was admitted.
func legProbe(t *testing.T, leg *listenerLeg, user, pass string) bool {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/thing", nil)
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	leg.srv.Handler.ServeHTTP(w, r)
	return w.Code != http.StatusUnauthorized
}

// retireTestServer builds a Server whose legs serve a trivial 200 handler over
// the real per-leg auth middleware, with a listener factory that hands out
// closed-on-cleanup local sockets.
func retireTestServer(t *testing.T, boot *AuthConfig) *Server {
	t.Helper()
	s := &Server{}
	s.sharedBase = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	s.auth.Store(boot)
	var mu sync.Mutex
	var lns []net.Listener
	s.listen = func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		lns = append(lns, ln)
		mu.Unlock()
		return ln, nil
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.rootCtx = ctx
	return s
}

// A commit that MOVES the management bind and ROTATES the credential must not
// make the new secret usable at the old address. The old leg is retired but is
// still serving while it drains, and the reconciler publishes the full committed
// set as soon as ReconcileHTTP returns.
//
// FAIL-ON-REVERT: drop the pin in stopLegLocked (let the retired leg keep
// following s.auth) and secret-b authenticates on the retired listener.
func TestRetiredLegNeverGainsARotatedCredential_5561(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "secret-a"}})

	// Boot the first leg at some address, then rebind (which retires it).
	s.lifeMu.Lock()
	s.httpSlot = s.newAuthSlot()
	s.httpServer = s.buildHTTPServer("10.0.0.1:8080", s.httpSlot)
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.httpLeg = s.serveLegLocked(s.httpServer, ln, false, s.httpSlot)
	retired := s.httpLeg
	s.lifeMu.Unlock()

	if !legProbe(t, retired, "admin", "secret-a") {
		t.Fatal("the live listener rejects its own configured credential; the case starts wrong")
	}

	if err := s.ReconcileHTTP("10.0.0.2:8080"); err != nil {
		t.Fatalf("ReconcileHTTP: %v", err)
	}
	live := s.httpLeg
	if live == retired {
		t.Fatal("the rebind did not create a new leg, so nothing was retired")
	}

	// This is exactly what managementReconciler does once every live leg sits at
	// an address the committed config names.
	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"admin": "secret-b"}})

	if legProbe(t, retired, "admin", "secret-b") {
		t.Fatal("secret-b authenticates on the RETIRED listener at 10.0.0.1:8080. That " +
			"credential was committed for 10.0.0.2:8080; the same commit retired this " +
			"address, and retirement is asynchronous — the socket is still accepting and " +
			"the connections it already took are served for the whole drain. A grant must " +
			"never reach an address the commit moved away from (#5561 round 14, MAJOR 2)")
	}
	// The revocation half still lands there: round 7's property is not traded away.
	if legProbe(t, retired, "admin", "secret-a") {
		t.Fatal("secret-a still authenticates on the retired listener — a retiring leg must " +
			"still honour a revocation immediately (#5561 round 7)")
	}
	// The live leg gets the whole committed set, as before.
	if !legProbe(t, live, "admin", "secret-b") {
		t.Fatal("the LIVE listener rejects the committed credential — the pin must not leak " +
			"onto the leg the commit actually named")
	}
}

// The same ordering in the direction that fails OPEN: a commit that removes all
// api-auth and converges to loopback publishes nil, and nil is
// dynamicAuthMiddleware's pass-through. The retired off-loopback leg must not
// see it — the #4047/#5127 clamp that licenses the nil was evaluated against the
// loopback address the commit BOUND, never against the one it retired.
//
// FAIL-ON-REVERT: let authSlot.tighten apply a nil `next` (or drop the pin) and
// the retired off-loopback listener answers an unauthenticated request.
func TestRetiredLegIsNeverDroppedToNoAuth_5561(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "secret"}})

	s.lifeMu.Lock()
	s.httpSlot = s.newAuthSlot()
	s.httpServer = s.buildHTTPServer("10.0.0.1:8080", s.httpSlot)
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.httpLeg = s.serveLegLocked(s.httpServer, ln, false, s.httpSlot)
	retired := s.httpLeg
	s.lifeMu.Unlock()

	if err := s.ReconcileHTTP("127.0.0.1:8080"); err != nil {
		t.Fatalf("ReconcileHTTP: %v", err)
	}
	live := s.httpLeg

	// The nil publishes once every LIVE leg is loopback — which is true here.
	s.ReplaceAuth(nil)

	r := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	retired.srv.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an UNAUTHENTICATED request to the retired off-loopback listener got %d. The "+
			"committed nil disables authentication entirely, and it is justified by the "+
			"loopback clamp on the address this commit BOUND — not on 10.0.0.1:8080, which "+
			"it retired and which is still serving while it drains (#5561 round 14, MAJOR 2)",
			w.Code)
	}
	// The live loopback leg does get the nil: the suppression is scoped to the
	// retired address, not a blanket refusal to ever remove api-auth.
	r = httptest.NewRequest("GET", "/api/v1/config", nil)
	w = httptest.NewRecorder()
	live.srv.Handler.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("the LIVE loopback listener still demands a credential after api-auth was " +
			"removed — the pin must not spread to the leg the commit named")
	}
}

// A live leg FOLLOWS the server-wide snapshot: the plain day-2 credential swap
// on an unchanged bind must still take effect on the very next request, with no
// rebind. This is the control that keeps the pin from being implemented as
// "every leg is pinned at creation", which would break #5866's whole premise.
func TestLiveLegFollowsTheServerSnapshot_5561(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "secret-a"}})

	s.lifeMu.Lock()
	s.httpSlot = s.newAuthSlot()
	s.httpServer = s.buildHTTPServer("10.0.0.1:8080", s.httpSlot)
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.httpLeg = s.serveLegLocked(s.httpServer, ln, false, s.httpSlot)
	live := s.httpLeg
	s.lifeMu.Unlock()

	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"admin": "secret-b"}})
	if legProbe(t, live, "admin", "secret-a") {
		t.Fatal("the revoked secret still authenticates on the LIVE listener — a day-2 " +
			"revocation must land on the next request without a rebind (#5866)")
	}
	if !legProbe(t, live, "admin", "secret-b") {
		t.Fatal("the newly committed secret does not authenticate on the LIVE listener")
	}
}
