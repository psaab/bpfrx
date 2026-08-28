package api

import (
	"net"
	"net/http"
	"sync"
)

// listener_hijack_drain.go — #7011.
//
// drainLeg's guarantee used to carry a "modulo hijacked connections" caveat,
// and the caveat was defended by a tripwire that ENUMERATED hijacking types and
// asserted none was reachable from this package. That enumeration was defeated
// three times: `golang.org/x/net/websocket` (round 8), `http2/h2c` (round 9),
// and `net/rpc` — a STANDARD LIBRARY hijacker, on a corpus three reviewers did
// not think to search.
//
// The last one is the argument for retiring the exception rather than re-keying
// the guard. The set of hijackers is a function of the TOOLCHAIN, not of
// go.mod: this module declares one Go version and the suite runs under another,
// so the corpus a hand-maintained map is derived over moves with nothing in the
// repository changing. A `go list -deps` closure fallback would have missed
// `net/rpc` too unless it were written to include the standard library.
//
// So this stops caring what hijacks. http.Server's ConnState hook fires with
// StateHijacked and hands over the net.Conn at the moment the server loses
// track of it; recording it there and closing it in the drain makes `drained`
// true outright, with no qualifier for drainLeg, listenerLeg.drained or
// pkg/api/README.md to carry.
//
// WHAT THIS DOES NOT CLAIM. It closes the connection; it does not join whatever
// goroutine the hijacking handler started. Nothing can — the handler owns that
// goroutine and there is no handle to it. The drain's guarantee is about what
// is still being SERVED on connections this leg accepted, and a closed conn
// cannot serve anything, which is the same standard Close already meets for the
// non-hijacked in-flight case.
//
// COST, stated because it is real: a hijacked connection is recorded and is not
// removed until the leg drains. ConnState is never called again for a hijacked
// connection — that is the definition of the state — so a handler that hijacks
// and then closes leaves an entry behind, and the map grows with the number of
// hijacks a leg serves rather than with the number live at any moment. Today
// this package has no hijacker, so the map stays empty; if one is added and
// serves at volume, the tracker needs a liveness signal from that handler and
// this comment is where the next author should start.

// hijackTracker records the connections an http.Server has handed to a
// hijacking handler, so a drain can close what the server itself can no longer
// reach.
type hijackTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newHijackTracker() *hijackTracker {
	return &hijackTracker{conns: make(map[net.Conn]struct{})}
}

// note records c as hijacked. Called from the ConnState hook, which http.Server
// invokes from the connection's own goroutine, so it must be safe under
// concurrency with itself and with closeAll.
func (h *hijackTracker) note(c net.Conn) {
	if h == nil || c == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns[c] = struct{}{}
}

// closeAll severs every recorded connection and forgets them. It returns how
// many it closed so a caller can report the number rather than infer it.
func (h *hijackTracker) closeAll() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	conns := h.conns
	h.conns = make(map[net.Conn]struct{})
	h.mu.Unlock()
	for c := range conns {
		// The error is deliberately discarded: a conn the peer already closed
		// returns one, and that is the outcome this call wants anyway.
		_ = c.Close()
	}
	return len(conns)
}

// len reports how many connections are recorded. Test-only in practice.
func (h *hijackTracker) len() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// legHijacks maps each leg's *http.Server to its tracker.
//
// Keyed by the server rather than carried on listenerLeg because drainLeg is
// reached from four places, two of which hold only the *http.Server
// (Server.serveBound). A registry keeps ONE drain path for every caller instead
// of a covered path and an uncovered one — which is the shape that let the
// original exception survive as long as it did.
var legHijacks sync.Map // *http.Server -> *hijackTracker

// hijackTrackerFor returns srv's tracker, creating it on first use.
func hijackTrackerFor(srv *http.Server) *hijackTracker {
	if srv == nil {
		return nil
	}
	if v, ok := legHijacks.Load(srv); ok {
		return v.(*hijackTracker)
	}
	v, _ := legHijacks.LoadOrStore(srv, newHijackTracker())
	return v.(*hijackTracker)
}

// trackHijackedConns installs the ConnState hook that feeds srv's tracker, and
// returns srv so it can be used inline in a struct literal's construction.
//
// It must be installed by every leg constructor. A leg without it is a leg
// whose hijacked connections outlive its drain — silently, since nothing else
// observes the difference.
func trackHijackedConns(srv *http.Server) *http.Server {
	if srv == nil {
		return nil
	}
	tracker := hijackTrackerFor(srv)
	prev := srv.ConnState
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			tracker.note(c)
		}
		if prev != nil {
			prev(c, state)
		}
	}
	return srv
}

// releaseHijackTracker drops srv's tracker after its final drain, so the
// registry does not grow one entry per leg for the life of the process. Rebinds
// create a new *http.Server each time.
func releaseHijackTracker(srv *http.Server) {
	if srv != nil {
		legHijacks.Delete(srv)
	}
}
