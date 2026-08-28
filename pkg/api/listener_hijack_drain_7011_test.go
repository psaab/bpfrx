package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// listener_hijack_drain_7011_test.go — #7011.
//
// drainLeg's guarantee — "nothing this leg accepted is still being served" —
// used to exclude hijacked connections, and the exclusion was defended by a
// tripwire enumerating hijacking types. That enumeration was defeated three
// times, most recently by `net/rpc`, a STANDARD LIBRARY hijacker: the set of
// hijackers is a function of the toolchain rather than of go.mod, so the corpus
// the map was derived over moved with nothing in the repository changing.
//
// These cases prove the caveat is gone, which is what makes the tripwire's job
// disappear. They install a REAL hijacking handler — the thing the enumeration
// was trying to prove absent — because a test that only asserted "no hijacker
// is reachable" would be the same unmaintainable claim in a different file.

// hijackEcho is a handler that hijacks and then holds the connection open,
// which is exactly the shape drainLeg could not previously reach.
func hijackEcho7011(t *testing.T, taken chan<- net.Conn) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter is not a Hijacker; this fixture cannot create the case")
			return
		}
		c, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		taken <- c
		// Deliberately does NOT close: the connection outliving the handler is
		// the case under test.
	}
}

// serveHijackLeg7011 stands up one leg whose only route hijacks, and returns its
// server, base URL and the channel the hijacked conn arrives on.
func serveHijackLeg7011(t *testing.T) (*http.Server, string, chan net.Conn) {
	t.Helper()
	taken := make(chan net.Conn, 1)
	mux := http.NewServeMux()
	mux.Handle("/hijack", hijackEcho7011(t, taken))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// trackHijackedConns is the production wrapper both leg constructors use.
	// Driving it here rather than a bare &http.Server is the point: a test that
	// wired its own hook would prove the tracker works and say nothing about
	// whether production installs it.
	srv := trackHijackedConns(&http.Server{Handler: mux})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	return srv, "http://" + ln.Addr().String(), taken
}

// hijackOne7011 drives one request through the hijacking route and returns the
// server-side conn the handler took over.
func hijackOne7011(t *testing.T, base string, taken chan net.Conn) net.Conn {
	t.Helper()
	go func() {
		c, err := net.Dial("tcp", base[len("http://"):])
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		fmt.Fprintf(c, "GET /hijack HTTP/1.1\r\nHost: x\r\n\r\n")
	}()
	select {
	case c := <-taken:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("the handler never hijacked; the fixture did not create the case")
		return nil
	}
}

// TestDrainSeversHijackedConnections_7011 is the property the caveat used to
// exclude.
func TestDrainSeversHijackedConnections_7011(t *testing.T) {
	srv, base, taken := serveHijackLeg7011(t)
	conn := hijackOne7011(t, base, taken)

	// PREMISE, measured rather than assumed: the server itself no longer knows
	// about this connection, which is why Shutdown and Close cannot reach it.
	// Shutdown returns promptly here precisely because the hijacked conn is not
	// among the ones it waits for.
	if n := hijackTrackerFor(srv).len(); n != 1 {
		t.Fatalf("the tracker recorded %d hijacked connections, want 1 — the ConnState hook "+
			"did not fire, so everything below would be measuring a connection the drain "+
			"never had to reach", n)
	}
	// The connection is genuinely usable before the drain, so "closed
	// afterwards" is a change rather than a starting condition.
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline on the hijacked conn: %v", err)
	}
	if _, err := conn.Write([]byte("still alive\n")); err != nil {
		t.Fatalf("the hijacked connection was already unusable before the drain (%v); this "+
			"case cannot show the drain severed it", err)
	}

	_ = drainLeg(srv)

	// AFTER: the conn is closed. Writing to a closed net.Conn returns an error
	// on the first call — no deadline needed, and no dependence on the peer.
	if _, err := conn.Write([]byte("after drain\n")); err == nil {
		t.Fatal("a HIJACKED connection was still writable after drainLeg returned. " +
			"drainLeg's guarantee is that nothing the leg accepted is still being served; " +
			"Shutdown does not attempt hijacked connections and Close does not know about " +
			"them, so the drain has to close them itself or the guarantee needs the " +
			"'modulo hijacked connections' caveat back — and that caveat is what forced a " +
			"hand-maintained list of hijacking types nobody can keep complete (#7011)")
	}
}

// TestDrainClearsTheHijackRegistry_7011 keeps the mechanism from becoming a
// leak. A registry entry per leg, never released, would grow for the life of
// the process across rebinds.
func TestDrainClearsTheHijackRegistry_7011(t *testing.T) {
	srv, base, taken := serveHijackLeg7011(t)
	_ = hijackOne7011(t, base, taken)
	if n := hijackTrackerFor(srv).len(); n != 1 {
		t.Fatalf("tracker holds %d, want 1 before the drain", n)
	}

	_ = drainLeg(srv)

	if _, ok := legHijacks.Load(srv); ok {
		t.Fatal("the drained leg's tracker is still in the registry. Every rebind builds a " +
			"new *http.Server, so an entry that is never released grows the registry for " +
			"the life of the process (#7011)")
	}
	// And a fresh lookup must not resurrect the old contents.
	if n := hijackTrackerFor(srv).len(); n != 0 {
		t.Fatalf("a tracker recreated after the drain reports %d connections, want 0", n)
	}
	releaseHijackTracker(srv)
}

// TestEveryLegConstructorTracksHijacks_7011 binds the WIRING.
//
// Both cases above drive trackHijackedConns directly, so they would pass
// against a production leg that never installed the hook — which is precisely
// how the previous approach failed: the mechanism was fine and the coverage of
// it was the thing that could not be maintained.
func TestEveryLegConstructorTracksHijacks_7011(t *testing.T) {
	s := NewServer(Config{Addr: "127.0.0.1:0", Store: newConfigStore(t, t.TempDir()+"/xpf.conf")})

	httpSrv := s.buildHTTPServer("127.0.0.1:0", s.newAuthSlot())
	if httpSrv.ConnState == nil {
		t.Fatal("buildHTTPServer produced a leg with no ConnState hook, so a hijacked " +
			"connection on the HTTP leg is invisible to its drain (#7011)")
	}
	httpsSrv, err := s.buildHTTPSServer("127.0.0.1:0", s.newAuthSlot())
	if err != nil {
		t.Skipf("buildHTTPSServer: %v (cert generation unavailable in this environment)", err)
	}
	if httpsSrv.ConnState == nil {
		t.Fatal("buildHTTPSServer produced a leg with no ConnState hook, so a hijacked " +
			"connection on the HTTPS leg is invisible to its drain (#7011)")
	}

	// The hook must actually feed THIS server's tracker, not merely exist.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	httpSrv.ConnState(c1, http.StateHijacked)
	if n := hijackTrackerFor(httpSrv).len(); n != 1 {
		t.Fatalf("the HTTP leg's ConnState hook did not record a StateHijacked connection "+
			"(tracker holds %d). A hook that fires and records nothing is the same as no "+
			"hook (#7011)", n)
	}
	// A non-hijack transition must NOT be recorded, or the tracker would close
	// live connections at drain time that Shutdown was already handling.
	httpSrv.ConnState(c2, http.StateActive)
	if n := hijackTrackerFor(httpSrv).len(); n != 1 {
		t.Fatalf("a StateActive transition was recorded as a hijack (tracker holds %d, "+
			"want 1). The drain closes what this tracker holds, so recording ordinary "+
			"connections would sever them out from under Shutdown", n)
	}
	releaseHijackTracker(httpSrv)
	releaseHijackTracker(httpsSrv)
	_ = context.Background()
}
