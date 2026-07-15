package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// managementReconciler owns the HTTP/HTTPS management-listener lifecycle so a
// day-2 web-management commit actually replaces the live listener and the
// authentication snapshot instead of sitting inert until a daemon restart
// (#5866). Before this owner the api.Server was constructed ONCE at startup: a
// committed bind-address, port, TLS, or api-auth change reported success while
// the process kept enforcing the old policy — revoked/tightened credentials
// stayed usable, an interface/bind removal left the API on the old address.
//
// Reconcile discipline (the listener lifecycle lives in api.Server; #5866):
//   - AUTH change on an UNCHANGED endpoint: swap the live auth snapshot in place
//     (api.Server.ReplaceAuth) — the middleware reads it per request, so a
//     revoked credential is rejected on the NEXT request, no listener bounce, no
//     restart, no unreachable window.
//   - ENDPOINT change: reconcile ONLY the listener leg that changed, PER LEG.
//     An HTTP-bind change make-before-break rebinds only the HTTP leg
//     (ReconcileHTTP); a TLS enable/disable or HTTPS-bind change rebinds only the
//     HTTPS leg (ReconcileHTTPS) and NEVER touches the live HTTP listener. This
//     is the fix for the old whole-server rebuild: enabling TLS keeps the HTTP
//     bind, so re-binding the whole server re-bound the still-held HTTP socket
//     (EADDRINUSE) and the change could never converge without a restart. Each
//     leg is make-before-break within api.Server: the new socket is bound and
//     serving before the old is retired — no unreachable window, no double-bind
//     of an unchanged socket.
//   - FAIL-SAFE: if a leg fails to (re)bind, that leg's PREVIOUS listener is
//     RETAINED (fail-closed, not mgmt-down), its fingerprint field is left
//     unrecorded so the next commit RETRIES the bind (retry debt), and the error
//     is surfaced.
//   - AUTH ORDERING on a combined change: the auth snapshot is published only
//     once every leg is at its desired bind, so the live auth policy always
//     matches the live binds. An auth-only change publishes immediately. A
//     combined endpoint+auth change whose bind FAILED defers the auth swap to
//     the retry — applying next.Auth (which the #4047/#5127 clamp may leave nil
//     because the DESIRED bind is loopback) to a RETAINED non-loopback listener
//     would fail OPEN.
//
// The reconcile is serialized by mu; the apply path (applyConfigLocked under the
// apply semaphore) already runs commits one at a time, so a newer generation can
// never race or complete out of order behind an older one.
type managementReconciler struct {
	d *Daemon
	// baseCfg carries only the runtime dependencies (store, dataplane probe,
	// managers, callbacks); the bind/port/TLS/auth fields are re-derived from the
	// active config on every reconcile via desired, so a removed web-management
	// stanza correctly reverts to the flag defaults.
	baseCfg api.Config

	mu     sync.Mutex
	srv    *api.Server  // single long-lived server; its HTTP/HTTPS legs reconcile in place (nil until started)
	cur    mgmtEndpoint // last-CONVERGED per-leg fingerprint (a leg field advances only on that leg's successful reconcile)
	curSet bool
}

// mgmtEndpoint fingerprints the listener-defining fields. An auth change does
// NOT change the endpoint (auth is swapped live); only these fields force a
// make-before-break rebind.
type mgmtEndpoint struct {
	addr      string
	httpsAddr string
	tls       bool
}

func (e mgmtEndpoint) summary() string {
	if e.tls {
		return fmt.Sprintf("http=%s https=%s", e.addr, e.httpsAddr)
	}
	return fmt.Sprintf("http=%s (no TLS)", e.addr)
}

func endpointOf(cfg api.Config) mgmtEndpoint {
	return mgmtEndpoint{addr: cfg.Addr, httpsAddr: cfg.HTTPSAddr, tls: cfg.TLS}
}

// newManagementReconciler builds the owner around the runtime-dependency base
// apiCfg. It does not start anything; call start.
func newManagementReconciler(d *Daemon, baseCfg api.Config) *managementReconciler {
	return &managementReconciler{d: d, baseCfg: baseCfg}
}

// desired re-derives the desired api.Config for cfg: it resets the endpoint/auth
// fields to the flag defaults (so a removed web-management or api-auth stanza
// reverts cleanly) and then applies resolveAPIBinds (interface bind, TLS,
// api-auth, and the #4047/#5127 loopback clamp). It reads only set-once state
// (baseCfg, d.opts), so it needs no lock.
func (m *managementReconciler) desired(cfg *config.Config) api.Config {
	next := m.baseCfg
	next.Addr = m.d.opts.APIAddr
	next.HTTPSAddr = ""
	next.TLS = false
	next.Auth = nil
	m.d.resolveAPIBinds(&next, cfg)
	return next
}

// start builds and starts the initial listener from the active config. A bind
// failure is returned (the caller logs it non-fatally); the next commit retries.
func (m *managementReconciler) start(ctx context.Context) error {
	return m.startTo(ctx, m.desired(m.d.store.ActiveConfig()))
}

// startTo starts the initial listener for an explicit desired config. Split from
// start so a test can seed the live server without a configstore (#5866). The
// server owns its HTTP/HTTPS leg lifecycles keyed to ctx; day-2 changes go
// through reconcileTo's per-leg calls, not a new server.
func (m *managementReconciler) startTo(ctx context.Context, next api.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	srv := api.NewServer(next)
	if err := srv.Start(ctx); err != nil {
		return err
	}
	m.srv, m.cur, m.curSet = srv, endpointOf(next), true
	return nil
}

// reconcile matches the live listener + auth snapshot to cfg. It returns a
// non-nil error ONLY when an endpoint replacement could not bind — in that case
// the OLD listener is retained (fail-safe) and the next commit retries. An
// auth-only change (or an unchanged config) always returns nil.
func (m *managementReconciler) reconcile(cfg *config.Config) error {
	return m.reconcileTo(m.desired(cfg))
}

// reconcileTo drives the reconcile against an explicit desired config. Split
// from reconcile so a test exercises the make-before-break / live-auth-swap /
// fail-safe logic with hand-built endpoints, without a configstore or
// resolveAPIBinds (#5866).
func (m *managementReconciler) reconcileTo(next api.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srv == nil {
		// API disabled (--api-addr empty) or a boot bind never succeeded: nothing
		// live to reconcile.
		return nil
	}

	var errs []error

	// HTTP leg: make-before-break rebind ONLY if the HTTP bind changed. Advance
	// the converged fingerprint only on success (retry debt on failure).
	if next.Addr != m.cur.addr {
		if err := m.srv.ReconcileHTTP(next.Addr); err != nil {
			errs = append(errs, err)
		} else {
			m.cur.addr = next.Addr
		}
	}

	// HTTPS leg: enable / disable / rebind ONLY if the HTTPS bind or TLS flag
	// changed. api.Server.ReconcileHTTPS never touches the live HTTP listener, so
	// a TLS enable can no longer collide with the retained HTTP socket.
	if next.TLS != m.cur.tls || next.HTTPSAddr != m.cur.httpsAddr {
		if err := m.srv.ReconcileHTTPS(next.TLS, next.HTTPSAddr); err != nil {
			errs = append(errs, err)
		} else {
			m.cur.tls, m.cur.httpsAddr = next.TLS, next.HTTPSAddr
		}
	}

	// Auth: publish only once every leg is at its desired bind (see the type
	// doc). An auth-only change (no leg change) publishes immediately with no
	// rebind; a combined change whose bind failed defers the swap to retry.
	if len(errs) == 0 {
		m.srv.ReplaceAuth(next.Auth)
		return nil
	}
	joined := errors.Join(errs...)
	slog.Warn("web-management listener reconcile incomplete; retaining previous listener(s), deferring auth swap",
		"desired", endpointOf(next).summary(), "err", joined)
	return fmt.Errorf("web-management reconcile to %s incomplete; retaining previous listener(s): %w",
		endpointOf(next).summary(), joined)
}

// wait blocks until every serve goroutine (live + retiring legs) has drained.
// Called on daemon shutdown after the root ctx is cancelled (which triggers each
// leg's bounded graceful drain inside api.Server).
func (m *managementReconciler) wait() {
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv != nil {
		srv.Wait()
	}
}

// reconcileWebManagement is the applyConfigLocked entry point (#5866). It
// mirrors reconcileSNMP: it runs EARLY in the apply — before the dataplane apply
// that can abort on a protocol-gate error — so a committed authentication
// tightening/revocation or bind change is live even on an apply that returns
// early. store.Commit has already promoted+persisted this config, so the
// committed policy is authoritative regardless of the later dataplane outcome.
//
// A nil reconciler (API disabled) is a no-op. A non-nil error means an endpoint
// replacement could not bind; the OLD listener is retained and the failure is
// logged (retry debt), mirroring reconcileSNMP's warn-and-retry posture rather
// than bricking an otherwise-successful commit.
func (d *Daemon) reconcileWebManagement(cfg *config.Config) error {
	if d.mgmt == nil {
		return nil
	}
	return d.mgmt.reconcile(cfg)
}
