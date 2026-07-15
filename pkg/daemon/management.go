package daemon

import (
	"context"
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
// Reconcile discipline:
//   - AUTH change on an UNCHANGED endpoint: swap the live auth snapshot in place
//     (api.Server.ReplaceAuth) — the middleware reads it per request, so a
//     revoked credential is rejected on the NEXT request, no listener bounce, no
//     restart, no unreachable window.
//   - ENDPOINT change (bind address / port / TLS on/off / HTTPS bind):
//     MAKE-BEFORE-BREAK — build+bind the NEW listener FIRST, and only once it is
//     confirmed serving cancel the OLD server's context (bounded graceful
//     drain). There is never a window where management is unreachable, and never
//     a double-bind.
//   - FAIL-SAFE: if the new listener fails to bind, the OLD listener is RETAINED
//     (the previous working state — fail-closed, not mgmt-down), the endpoint
//     fingerprint is left unrecorded so the next commit RETRIES the bind (retry
//     debt), and the error is surfaced. The auth snapshot swap is applied to the
//     live listener regardless of any endpoint-rebind outcome, so a credential
//     revocation is never blocked by an unrelated bind failure.
//
// The reconcile is serialized by mu; the apply path (applyConfigLocked under the
// apply semaphore) already runs commits one at a time, so a newer generation can
// never race or complete out of order behind an older one.
type managementReconciler struct {
	d *Daemon
	// baseCfg carries only the runtime dependencies (store, dataplane probe,
	// managers, callbacks); the bind/port/TLS/auth fields are re-derived from the
	// active config on every reconcile via desiredLocked, so a removed
	// web-management stanza correctly reverts to the flag defaults.
	baseCfg api.Config
	rootCtx context.Context // daemon lifetime; parent of every generation's ctx

	mu     sync.Mutex
	wg     sync.WaitGroup     // joins every serve goroutine (live + retiring)
	srv    *api.Server        // current live server (nil until started)
	cancel context.CancelFunc // cancels the current server's ctx (retires it)
	cur    mgmtEndpoint       // current endpoint fingerprint
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
// start so a test can seed the live server without a configstore (#5866).
func (m *managementReconciler) startTo(ctx context.Context, next api.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rootCtx = ctx

	srv := api.NewServer(next)
	cctx, cancel := context.WithCancel(ctx)
	if err := srv.Start(cctx); err != nil {
		cancel()
		return err
	}
	m.launchLocked(srv)
	m.srv, m.cancel, m.cur, m.curSet = srv, cancel, endpointOf(next), true
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

	ep := endpointOf(next)

	// Same endpoint -> swap the live auth snapshot in place. A credential
	// revocation takes effect on the next request with NO listener bounce and NO
	// unreachable window. Safe on the current endpoint: the per-listener /metrics
	// gate is derived from the (unchanged) bind address, and dropping auth to nil
	// is only reachable on a loopback bind (the clamp forces a non-loopback
	// no-auth bind to change its address, which takes the rebind path instead).
	if m.curSet && ep == m.cur {
		m.srv.ReplaceAuth(next.Auth)
		return nil
	}

	// Endpoint changed -> make-before-break: bind the NEW listener before
	// retiring the old.
	newSrv := api.NewServer(next)
	cctx, cancel := context.WithCancel(m.rootCtx)
	if err := newSrv.Start(cctx); err != nil {
		cancel()
		// Fail-safe: the new endpoint did not bind. Keep the OLD listener serving
		// the previous working state (fail-closed, NOT mgmt-down). Leave m.srv /
		// m.cur unchanged so the NEXT commit retries the bind (retry debt).
		slog.Warn("web-management listener replacement failed; retaining previous listener",
			"desired", ep.summary(), "retained", m.cur.summary(), "err", err)
		return fmt.Errorf("web-management listener replacement to %s failed; retaining %s: %w",
			ep.summary(), m.cur.summary(), err)
	}

	// The new listener is bound and serving. ONLY NOW retire the old one (its
	// context cancel triggers the api.Server bounded graceful drain) and swap.
	m.launchLocked(newSrv)
	oldCancel, oldEP := m.cancel, m.cur
	m.srv, m.cancel, m.cur = newSrv, cancel, ep
	oldCancel()
	slog.Info("web-management listener replaced (make-before-break)",
		"from", oldEP.summary(), "to", ep.summary())
	return nil
}

// launchLocked registers srv's background serve goroutine on the reconciler's
// wait group so daemon shutdown joins every live and retiring listener.
func (m *managementReconciler) launchLocked(srv *api.Server) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		srv.Wait()
	}()
}

// wait blocks until every serve goroutine (live + retiring) has drained. Called
// on daemon shutdown after the root ctx is cancelled.
func (m *managementReconciler) wait() {
	m.wg.Wait()
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
