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
	// slot is THIS leg's view of the credential policy (#5561 round 14). While
	// the leg is live it FOLLOWS the server-wide snapshot, so a ReplaceAuth is
	// enforced on the very next request exactly as before. When the leg is
	// RETIRED (stopLegLocked) the slot is PINNED to what this address was
	// serving at that instant, and from then on only ever tightens — see
	// authSlot and Server.ReplaceAuth.
	slot *authSlot
	// drained is set by the serve goroutine as its LAST act, so a retired leg can
	// be reaped from Server.retiring without joining it. Atomic for the same
	// lock-ordering reason as dead.
	drained atomic.Bool
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
}

// serveLegLocked launches srv on ln in a background goroutine registered on the
// server wait group, and returns the leg. The goroutine serves until (a) the
// listener terminates on its own, (b) the leg is explicitly retired
// (stopLegLocked), or (c) the daemon root context is cancelled — then it runs a
// bounded 5s graceful drain (Shutdown closes ln + unblocks Serve) and joins.
// Caller holds lifeMu (so rootCtx is set and reads are consistent).
// slot is the credential slot srv's handler was built with (buildHTTPServer /
// buildHTTPSServer); every production call site supplies the same one, so the
// leg's pin and the handler's reads are the same object. A nil is substituted
// rather than stored, so ReplaceAuth's walk over retiring legs can never meet
// one.
func (s *Server) serveLegLocked(srv *http.Server, ln net.Listener, isTLS bool, slot *authSlot) *listenerLeg {
	if slot == nil {
		slot = s.newAuthSlot()
	}
	leg := &listenerLeg{srv: srv, ln: ln, stopCh: make(chan struct{}), slot: slot}
	rootCtx := s.rootCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer leg.drained.Store(true)

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
//
// Retirement is ASYNCHRONOUS and that is the point of the auth pin (#5561 round
// 14). Closing stopCh only WAKES the serve goroutine; the socket keeps accepting
// until that goroutine reaches Shutdown, and connections it already accepted are
// served for the whole bounded drain. ReconcileHTTP/ReconcileHTTPS return as soon
// as this call does, and the management reconciler then publishes the committed
// credential set — so without the pin a credential the commit authorized for the
// NEW address became valid on the address that same commit retired. Pinning the
// leg here to what it was already serving makes that impossible: from this
// moment the retiring listener's policy can only tighten (Server.ReplaceAuth
// intersects it), never gain a value it did not already accept.
func (s *Server) stopLegLocked(leg *listenerLeg) {
	if leg == nil {
		return
	}
	leg.stopOnce.Do(func() {
		// Pin BEFORE the wake-up so there is no interval in which the leg is
		// retired but still following the server-wide snapshot.
		s.trackRetiring(leg)
		close(leg.stopCh)
	})
}

// trackRetiring pins a retired leg's policy and registers it so ReplaceAuth can
// keep tightening it while it drains, reaping the ones that have finished.
//
// The pin and the registration happen under ONE hold of retireMu so no
// revocation can slip between them: a ReplaceAuth that lands before this pins at
// the value it published, and one that lands after finds the leg on the list and
// intersects it. The bookkeeping takes its own mutex rather than lifeMu because
// Server.Wait holds lifeMu across wg.Wait — a ReplaceAuth racing daemon
// shutdown would otherwise block for the whole drain. Callers hold lifeMu, so
// the order is always lifeMu -> retireMu.
func (s *Server) trackRetiring(leg *listenerLeg) {
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	leg.slot.pin(s.auth.Load())
	s.retiring = append(s.pruneRetiredLocked(), leg)
}

// pruneRetiredLocked compacts s.retiring down to the legs that are still
// draining and returns it. Caller holds retireMu.
func (s *Server) pruneRetiredLocked() []*listenerLeg {
	live := s.retiring[:0]
	for _, leg := range s.retiring {
		if !leg.drained.Load() {
			live = append(live, leg)
		}
	}
	s.retiring = live
	return live
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
		s.httpLeg = s.serveLegLocked(s.httpServer, ln, false, s.httpSlot)
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
	}
	if s.httpsServer != nil {
		ln, err := s.listen("tcp", s.httpsServer.Addr)
		if err != nil {
			slog.Error("api: HTTPS listener bind failed at start; HTTPS disabled until the next reconcile",
				"addr", s.httpsServer.Addr, "err", err)
		} else {
			s.httpsLeg = s.serveLegLocked(s.httpsServer, ln, true, s.httpsSlot)
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
	slot := s.newAuthSlot()
	srv := s.buildHTTPServer(addr, slot)
	ln, err := s.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: bind HTTP listener %q: %w", addr, err)
	}
	old := s.httpLeg
	s.httpLeg = s.serveLegLocked(srv, ln, false, slot)
	s.stopLegLocked(old) // retire the previous HTTP listener only after the new one is serving
	return nil
}

// HTTPSServing reports whether an HTTPS leg is CURRENTLY serving (#5561 round
// 14). Start treats an HTTPS bind failure as non-fatal — the HTTP plane stays up
// and the leg is simply absent — so the management reconciler must ask this
// rather than infer convergence from Start's nil error, or it records a desired
// HTTPS fingerprint that no listener implements and never retries the bind.
func (s *Server) HTTPSServing() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.httpsLeg != nil && !s.httpsLeg.dead.Load()
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
		slot := s.newAuthSlot()
		srv, err := s.buildHTTPSServer(addr, slot)
		if err != nil {
			return fmt.Errorf("api: generate HTTPS certificate for %q: %w", addr, err)
		}
		ln, err := s.listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("api: bind HTTPS listener %q: %w", addr, err)
		}
		old := s.httpsLeg
		s.httpsLeg = s.serveLegLocked(srv, ln, true, slot)
		s.stopLegLocked(old)
		return nil
	}
}
