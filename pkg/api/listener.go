package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// listenerLeg is one independently-managed listening socket + its serve
// goroutine (#5866). The HTTP and HTTPS listeners each run in their own leg so a
// day-2 change to one (TLS enable/disable, an HTTPS-bind change, or an HTTP-bind
// change) rebinds ONLY that leg — the sibling keeps serving without a bounce and
// without the EADDRINUSE that a whole-server rebuild hit when the two legs
// shared no socket but the rebuild still re-bound the unchanged one.
type listenerLeg struct {
	srv      *http.Server
	ln       net.Listener
	stopCh   chan struct{}
	stopOnce sync.Once
	// dead is set when the leg's serve loop exits UNEXPECTEDLY — the listener
	// terminated on its own, not via a requested shutdown (stopLegLocked /
	// rootCtx). EffectiveHTTPAddr treats a dead leg as not-serving so `show
	// system services` reports the HTTP listener Failed rather than Listening on
	// a dead socket, symmetric with the gRPC serve-exit clear (#6401).
	//
	// It is an atomic (NOT lifeMu-guarded): the serve goroutine still holds its
	// wg count when it sets this on exit, and Server.Wait holds lifeMu ACROSS
	// wg.Wait — so if the marker needed lifeMu, an exit racing a shutdown Wait
	// would deadlock (Wait holds lifeMu waiting on the goroutine's wg.Done; the
	// goroutine waits on lifeMu before it can return -> Done). Storing atomically
	// with no lock breaks that lock-ordering cycle (#6401 round-3 fix).
	dead atomic.Bool
	// stopping is set the moment a graceful drain BEGINS — before Shutdown, not
	// after the goroutine returns. Between those two points the listener is
	// already closed (Shutdown closes it) so no new client can reach the
	// certificate, yet a flag stored only when the goroutine RETURNS would stay
	// false for up to the 5s drain window (#6827 round 5). For "is a certificate
	// in front of clients right now?" the answer during a drain is NO: the
	// process is on its way down and a staleness warning is noise. Callers that
	// want "what address is this leg finishing on" (EffectiveHTTPAddr)
	// deliberately do not consult this.
	stopping atomic.Bool
}

// serving reports whether this leg is actually carrying traffic right now: it
// exists, holds a listener, and its serve goroutine has neither self-terminated
// (`dead`) nor begun a graceful drain (`stopping`).
//
// A non-nil leg pointer is NOT that question (#6827). An unexpected serve exit
// sets `dead` and leaves the leg INSTALLED in s.httpsLeg; a root-context
// shutdown sets `stopping` (never `dead`) and also leaves it installed. In both
// states the pointer is live and the socket is not. A caller that reads the leg
// to answer "what is this box serving?" must test the state, not the pointer.
//
// It tests `stopping` rather than `stopCh` on purpose. A requested retirement
// (stopLegLocked) is not observable through s.httpsLeg by construction: the
// disable arm clears s.httpsLeg under lifeMu before retiring, and the rebind
// arm installs the replacement before retiring the old one. So a stopCh test
// would be an arm for a state that cannot occur — while the state that DOES
// occur, root-context shutdown, closes no stopCh and would slip past it.
// `stopping` is set at the TOP of both drain arms — requested retirement and
// root-context shutdown — before Shutdown runs, so it covers that path from the
// moment the listener closes through the goroutine's return. Together with
// `dead` (self-termination) every exit is covered, which is why there is no
// third defer-set flag: it would be unbindable, and an arm no test can drive is
// the thing that made the previous round's predicate look complete.
//
// Deliberately stricter than EffectiveHTTPAddr's inline check, which tests nil
// / ln / dead only: that one answers `show system services`, where a leg
// finishing a graceful drain should still report the address it is on. This one
// answers "is there a certificate in front of clients right now?" The two
// questions differ, so they are not folded into one predicate.
func (l *listenerLeg) serving() bool {
	return l != nil && l.ln != nil && !l.dead.Load() && !l.stopping.Load()
}

// serveLegLocked launches srv on ln in a background goroutine registered on the
// server wait group, and returns the leg. The goroutine serves until (a) the
// listener terminates on its own, (b) the leg is explicitly retired
// (stopLegLocked), or (c) the daemon root context is cancelled — then it runs a
// bounded 5s graceful drain (Shutdown closes ln + unblocks Serve) and joins.
// Caller holds lifeMu (so rootCtx is set and reads are consistent).
func (s *Server) serveLegLocked(srv *http.Server, ln net.Listener, isTLS bool) *listenerLeg {
	leg := &listenerLeg{srv: srv, ln: ln, stopCh: make(chan struct{})}
	rootCtx := s.rootCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		serveErr := make(chan error, 1)
		go func() {
			if isTLS {
				// TLSConfig.Certificates is populated, so ServeTLS with empty
				// file paths uses those in-memory certs.
				serveErr <- srv.ServeTLS(ln, "", "")
			} else {
				serveErr <- srv.Serve(ln)
			}
		}()

		var rootDone <-chan struct{}
		if rootCtx != nil {
			rootDone = rootCtx.Done()
		}
		select {
		case err := <-serveErr:
			// The listener terminated on its own (not a requested shutdown); the
			// socket is already closed, nothing left to drain.
			if err != nil && err != http.ErrServerClosed {
				slog.Error("API listener terminated unexpectedly", "addr", srv.Addr, "tls", isTLS, "err", err)
			}
			// #6401: an UNEXPECTED serve exit means this leg is no longer
			// serving. Mark it dead ATOMICALLY — NOT under lifeMu: the goroutine
			// still holds its wg count here, and Server.Wait holds lifeMu across
			// wg.Wait, so acquiring lifeMu here would deadlock a shutdown that
			// raced this exit (round-3 fix). EffectiveHTTPAddr then stops
			// reporting the dead listener's address and `show system services`
			// renders the HTTP listener Failed, mirroring the gRPC serve-exit
			// clear. A leg already retired/replaced by a reconcile takes the
			// stopCh path below instead, so this only fires on a genuine
			// self-termination.
			leg.dead.Store(true)
			return
		case <-leg.stopCh:
		case <-rootDone:
		}
		leg.stopping.Store(true)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-serveErr // join the Serve goroutine before the leg is considered drained
	}()
	return leg
}

// stopLegLocked idempotently requests a leg's graceful retirement. The leg's
// goroutine drains + joins in the background; wg.Wait (Server.Wait) joins it on
// daemon shutdown. Caller holds lifeMu.
func (s *Server) stopLegLocked(leg *listenerLeg) {
	if leg == nil {
		return
	}
	leg.stopOnce.Do(func() { close(leg.stopCh) })
}

// Start binds the configured listeners and serves each in its own leg (#5866),
// returning once they are live. HTTP is the primary listener: a bind failure
// returns an error with nothing serving (the caller logs it non-fatally and the
// next commit retries via ReconcileHTTP). HTTPS is best-effort at boot — a bind
// failure leaves the HTTP plane up (fail-safe, management not down) and the next
// reconcile retries the HTTPS leg. Wait blocks until every leg (live + retiring)
// has drained.
func (s *Server) Start(ctx context.Context) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	s.rootCtx = ctx

	if s.httpServer != nil {
		ln, err := s.listen("tcp", s.httpServer.Addr)
		if err != nil {
			return fmt.Errorf("api: bind HTTP listener %q: %w", s.httpServer.Addr, err)
		}
		s.httpLeg = s.serveLegLocked(s.httpServer, ln, false)
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
	}
	if s.httpsServer != nil {
		ln, err := s.listen("tcp", s.httpsServer.Addr)
		if err != nil {
			slog.Error("api: HTTPS listener bind failed at start; HTTPS disabled until the next reconcile",
				"addr", s.httpsServer.Addr, "err", err)
		} else {
			s.httpsLeg = s.serveLegLocked(s.httpsServer, ln, true)
			slog.Info("HTTPS API server listening", "addr", s.httpsServer.Addr)
		}
	}
	return nil
}

// Wait blocks until every serve goroutine (live + retiring legs) has fully
// exited. It takes lifeMu so no concurrent reconcile can register a new leg
// (WaitGroup Add) once the join has begun; leg drains do not need lifeMu, so
// they complete while Wait holds it. Call after the root context is cancelled.
func (s *Server) Wait() {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	s.wg.Wait()
}

// EffectiveHTTPAddr returns the ACTUAL bound address of the live HTTP leg, or ""
// when no HTTP leg is serving. It reads the listener's own Addr, so an ephemeral
// `:0` request resolves to its concrete port and a wildcard/hostname bind is
// normalized — the address the socket is truly on, not the requested one. The
// #6385/#6401 `show system services` effective-listener snapshot reads it (via
// managementReconciler.effectiveHTTPListener), mirroring the grpcapi.Server
// EffectiveListener pattern.
func (s *Server) EffectiveHTTPAddr() string {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	// httpLeg / ln are swapped only under lifeMu, so read them here; dead is
	// atomic (set without lifeMu by the serve goroutine to avoid a shutdown
	// lock-ordering deadlock — see listenerLeg.dead).
	if s.httpLeg == nil || s.httpLeg.ln == nil || s.httpLeg.dead.Load() {
		return ""
	}
	return s.httpLeg.ln.Addr().String()
}

// HTTPSServing reports whether an HTTPS leg is bound and serving right now
// (#6827 round 5). Start() deliberately returns SUCCESS when the HTTPS bind
// fails — HTTPS is best-effort at boot so a failure leaves the HTTP plane up —
// which means a caller cannot infer from Start's error that HTTPS came up. A
// caller that records a converged HTTPS fingerprint on that assumption pins
// itself to a listener that does not exist and never retries.
func (s *Server) HTTPSServing() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.httpsLeg.serving()
}

// ReconcileHTTP make-before-break rebinds ONLY the HTTP listener to addr (#5866),
// leaving the HTTPS leg untouched. A same-addr call is a no-op. The new listener
// is bound and serving BEFORE the old is retired (no unreachable HTTP window). A
// bind failure retains the previous HTTP listener (fail-closed) and returns the
// error so the caller records retry debt.
func (s *Server) ReconcileHTTP(addr string) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if addr == "" {
		return fmt.Errorf("api: refusing to reconcile the HTTP listener to an empty bind address")
	}
	if s.httpLeg != nil && s.httpLeg.srv.Addr == addr {
		return nil
	}
	srv := s.buildHTTPServer(addr)
	ln, err := s.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: bind HTTP listener %q: %w", addr, err)
	}
	old := s.httpLeg
	s.httpLeg = s.serveLegLocked(srv, ln, false)
	s.stopLegLocked(old) // retire the previous HTTP listener only after the new one is serving
	return nil
}

// ReconcileHTTPS enables, disables, or make-before-break rebinds ONLY the HTTPS
// listener (#5866), leaving the live HTTP listener untouched — this is the fix
// for the whole-server rebuild that re-bound the still-held HTTP socket on a
// TLS-enable (EADDRINUSE). useTLS=false or addr=="" disables HTTPS. A same-addr
// enabled call is a no-op. On enable/rebind the new HTTPS listener (with its
// durable self-signed cert — loaded AS-IS from disk on a rebind, freshly minted
// only when no on-disk pair exists, #1916 D6) is bound and serving BEFORE any
// old one is retired. A cert or bind failure retains the previous HTTPS state
// (fail-closed) and returns the error for retry debt.
func (s *Server) ReconcileHTTPS(useTLS bool, addr string) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	want := useTLS && addr != ""
	switch {
	case !want:
		if s.httpsLeg != nil {
			s.stopLegLocked(s.httpsLeg)
			s.httpsLeg = nil
		}
		return nil
	case s.httpsLeg != nil && s.httpsLeg.srv.Addr == addr:
		return nil
	default:
		srv, err := s.buildHTTPSServer(addr)
		if err != nil {
			return fmt.Errorf("api: generate HTTPS certificate for %q: %w", addr, err)
		}
		ln, err := s.listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("api: bind HTTPS listener %q: %w", addr, err)
		}
		old := s.httpsLeg
		s.httpsLeg = s.serveLegLocked(srv, ln, true)
		s.stopLegLocked(old)
		return nil
	}
}
