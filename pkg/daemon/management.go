package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
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
//   - AUTH ORDERING: the two directions are not symmetric, and a non-nil set is
//     itself split. Its REVOCATION half publishes BEFORE either leg is (re)bound
//     and regardless of the outcome, so a committed revocation is never blocked
//     by a bind failure (#5866 Finding A, #5561 round 7: deferring it left the
//     RETAINED listener honouring the old secret permanently) and a freshly-bound
//     listener never serves under a superseded snapshot (#5561 round 9:
//     ReconcileHTTP serves before it returns, so publishing afterwards left the
//     new socket on the old policy for the width of the intervening
//     ReconcileHTTPS). Its GRANT half waits for every leg to converge, because a
//     credential set is committed together with the endpoint it is meant for:
//     while a leg is retained at an address this config asked to leave, only the
//     intersection with what that listener already accepted may be enforced
//     (#5561 round 12, api.AuthForRetainedListener). An endpoint-only-unchanged
//     commit has nothing to converge and publishes whole. Removing ALL api-auth
//     (nil) publishes AFTER the rebinds and is gated on both LIVE bind addresses
//     being loopback: it REMOVES a requirement, so the #4047/#5127 clamp that
//     justified the nil must be proven against the listeners that are actually
//     serving.
//   - AUTH FRESHNESS: the publish is only safe while the credential policy it
//     came from is the newest COMMITTED one, so reconcile replaces the credential
//     half with the store's active config before handing it to reconcileTo — see
//     withCommittedAuth. Without that, a stale-snapshot apply replay could
//     resurrect a superseded credential on a listener the operator had already
//     moved past.
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
	// lastHTTPAttempt is the most-recent HTTP bind address the reconciler tried
	// (desired.Addr), recorded BEFORE the bind attempt so a boot bind FAILURE
	// (curSet stays false) can report the address it could not bind as
	// `(bind failed)` in `show system services` (#6401). Distinct from cur.addr,
	// which advances only on a successful bind.
	lastHTTPAttempt string
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
	// Record the attempted HTTP bind BEFORE Start so a bind failure (curSet stays
	// false) can report it as `(bind failed)` in `show system services` (#6401).
	m.lastHTTPAttempt = next.Addr
	srv := api.NewServer(next)
	if err := srv.Start(ctx); err != nil {
		return err
	}
	m.srv, m.cur, m.curSet = srv, endpointOf(next), true
	return nil
}

// effectiveHTTPListener returns the effective STATE of the HTTP REST listener
// for `show system services` (#6385/#6401):
//
//   - nil reconciler → StateDisabled: --api-addr was empty, so Daemon.Run never
//     started the HTTP listener. A genuinely-off listener, distinct from a
//     failed one.
//   - configured but never converged (curSet false) → StateFailed: the boot
//     bind failed. Reports lastHTTPAttempt (the address it could not bind).
//   - converged but the live HTTP leg is no longer serving (an UNEXPECTED serve
//     exit — EffectiveHTTPAddr returns "") → StateFailed, symmetric with the
//     gRPC serve-exit clear. Reports m.cur.addr (or lastHTTPAttempt). A day-2
//     rebind FAILURE is NOT this case: it RETAINS the old serving leg (its
//     socket stays live → EffectiveHTTPAddr non-empty), so it correctly stays
//     Listening.
//   - converged and serving → StateListening: reports the ACTUAL bound address
//     from the live server (EffectiveHTTPAddr — so an ephemeral :0 resolves to
//     its concrete port).
func (m *managementReconciler) effectiveHTTPListener() sysservices.Listener {
	if m == nil {
		return sysservices.Listener{State: sysservices.StateDisabled}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.curSet {
		return sysservices.Listener{Addr: m.lastHTTPAttempt, State: sysservices.StateFailed}
	}
	var bound string
	if m.srv != nil {
		bound = m.srv.EffectiveHTTPAddr()
	}
	if bound == "" {
		// The converged HTTP leg died (an unexpected serve exit): report Failed,
		// not a stale Listening on a dead socket.
		addr := m.cur.addr
		if addr == "" {
			addr = m.lastHTTPAttempt
		}
		return sysservices.Listener{Addr: addr, State: sysservices.StateFailed}
	}
	return sysservices.Listener{Addr: bound, State: sysservices.StateListening}
}

// reconcile matches the live listener + auth snapshot to cfg. It returns a
// non-nil error ONLY when an endpoint replacement could not bind — in that case
// the OLD listener is retained (fail-safe) and the next commit retries. An
// auth-only change (or an unchanged config) always returns nil.
func (m *managementReconciler) reconcile(cfg *config.Config) error {
	return m.reconcileTo(m.withCommittedAuth(m.desired(cfg)))
}

// withCommittedAuth replaces next's api-auth policy with the one the store's
// ACTIVE config carries — INCLUDING when that policy is nil (#5561 round 10
// finding 3; the nil direction added in round 12).
//
// The credential set published here governs the LIVE listener, and reconcileTo
// publishes its REVOCATION half before the rebind and regardless of whether the
// rebind succeeds, because a committed revocation must not be blocked by a bind
// failure (#5561 round 7). That is right only while `cfg` is
// the newest committed policy, and on one path it is not: applyConfig callers
// that snapshot store.ActiveConfig() and THEN wait on the apply semaphore (the
// DHCP lease-change callback is the live example) can be overtaken by a commit
// and re-enter the apply carrying a superseded config. Without this, such a
// replay published the SUPERSEDED credential over the committed one and — when
// its own rebind then failed, leaving the newer endpoint serving — left a
// credential the operator had already replaced accepting full-power requests on
// it. Gating the publish on the rebind outcome instead (the pre-round-7 shape)
// does not fix that: the two cases are the same shape from inside reconcileTo
// and differ only in WHICH config is newer, so the only sound discriminator is
// to ask the store.
//
// Scope, stated precisely: this pins the CREDENTIAL half only. A stale replay
// still drives the listener toward the stale ENDPOINT — that is the general
// stale-snapshot apply defect (#6716), which lives in the apply path and is not
// repaired here. The credential is separated out because it is the security
// control: a stale bind is a reachability bug the next commit corrects, while a
// resurrected credential is an authentication bypass that persists.
//
// Direction of the override: BOTH. Round 10 pinned only the non-nil direction,
// on the argument that a stale replay could then over-restrict but never
// under-restrict, "because a resurrected credential over-restricts a management
// API that is clamped to loopback regardless". That premise is false, and the
// #4047/#5127 clamp is exactly why: the clamp is evaluated by resolveAPIBinds
// against the config being applied, using THAT config's own api-auth, and it is
// never re-evaluated against the listener that is actually serving. A config
// that carries a credential therefore binds off-loopback legitimately — and when
// a LATER commit removes api-auth, its own bind is clamped to loopback while the
// off-loopback listener the previous commit bound is RETAINED if that loopback
// bind fails. The live listener is then non-loopback with a nil-auth active
// config, and a stale replay carrying the credential the operator deleted
// published it there: a revoked secret authorizing `POST /api/v1/system/action`
// from off-box. That is under-restriction, and it is the interleaving round 10
// left open (#5561 round 12).
//
// So the credential half is taken from the ACTIVE config unconditionally. The
// nil direction is safe to propagate ONLY because reconcileTo's nil publish is
// gated on the addresses the LIVE listeners are actually bound to rather than on
// the rebind outcome: a stale replay whose own (stale, possibly off-loopback)
// endpoint binds SUCCESSFULLY must not be read as "the live bind is the one
// whose clamp justified the nil". See the nil gate in reconcileTo.
func (m *managementReconciler) withCommittedAuth(next api.Config) api.Config {
	if m.d == nil || m.d.store == nil {
		return next
	}
	active := m.d.store.ActiveConfig()
	if active == nil {
		return next
	}
	next.Auth = m.desired(active).Auth
	return next
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

	// Which legs this reconcile will move. While ANY leg is moving, some live
	// listener is (or may end up) at an address `next` does not name, which is
	// what makes the credential publish below conditional.
	rebinding := next.Addr != m.cur.addr ||
		next.TLS != m.cur.tls || next.HTTPSAddr != m.cur.httpsAddr

	// The REVOCATION half of a non-nil credential set is published BEFORE any
	// listener is bound (#5561 round 9 finding 3; the grant half split off in
	// round 12).
	//
	// api.Server.ReconcileHTTP binds the new listener AND STARTS SERVING IT
	// (listener.go, serveLegLocked) before it returns. Publishing auth at the end
	// of this function therefore left a window in which a freshly-serving socket
	// enforced the PREVIOUS snapshot, and the window is not instantaneous: the
	// ReconcileHTTPS call below sits inside it, and that call generates or loads a
	// TLS keypair and performs a bind, either of which can block for as long as
	// the filesystem or the network stack takes. The worst case is the one that
	// matters — a commit that moves the bind from loopback to an off-box address
	// AND adds the api-auth credential the #4047/#5127 clamp requires for it. The
	// old snapshot there is legitimately nil (loopback needs no credential), so
	// for the duration of the TLS reconcile the new off-box listener answered
	// every caller with dynamicAuthMiddleware's nil-snapshot pass-through.
	//
	// What is hoisted is NOT the whole committed set. Round 9 justified the hoist
	// on the claim that a non-nil Auth "only ADDS a requirement", so applying it
	// to whatever is live is strictly more restrictive. That is true only when
	// the live snapshot is nil (the pass-through case the hoist was written for).
	// Credential sets are not monotonic: {A} -> {A,B} and {A} -> {B} both make a
	// value acceptable that was not acceptable before, and the listener it
	// becomes acceptable on may be one this config never asked to keep serving —
	// the endpoint it did ask for is still unbound at this point, and may fail to
	// bind at all. So while any leg is moving, only the intersection with the
	// live snapshot goes out (#5561 round 12): every revocation lands
	// immediately, no grant does. A nil live snapshot is the universal set, so
	// the round-9 case still publishes the full credential set before the new
	// off-box socket serves.
	//
	// The full set follows below, once every leg has converged onto an address
	// THIS config names. When the endpoint is unchanged there is nothing to
	// converge and no retained listener to protect, so the full set goes out
	// here — the plain day-2 credential change, which must not be degraded to an
	// intersection (that would revoke without granting, i.e. lock the operator
	// out of an endpoint the commit never touched).
	//
	// The nil (remove-all-api-auth) direction stays BELOW the rebinds, because it
	// REMOVES a requirement and its safety gate reads m.cur, which the rebinds
	// update.
	if next.Auth != nil {
		publish := next.Auth
		if rebinding {
			publish = api.AuthForRetainedListener(m.srv.LiveAuth(), next.Auth)
			if withheld := api.CredentialCount(next.Auth) - api.CredentialCount(publish); withheld > 0 {
				slog.Warn("web-management endpoint is moving; withholding committed credentials from the listener that is still serving until the rebind converges",
					"withheld", withheld, "live_http", m.cur.addr, "desired", endpointOf(next).summary())
			}
		}
		m.srv.ReplaceAuth(publish)
	}

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

	// Auth is published DECOUPLED from the HTTPS leg (#5866 Finding A): a
	// committed credential revocation must not be blocked by an HTTPS bind
	// failure. That is why the REVOCATION half of a non-nil set goes out EARLY,
	// above, before any rebind and regardless of its outcome — it covers the case
	// where the HTTP leg's OWN rebind then FAILS and the old listener is retained
	// (#5561 round 7, MAJOR-2), and the case where a freshly-bound listener would
	// otherwise serve under the old snapshot for the duration of the HTTPS
	// reconcile (#5561 round 9, finding 3).
	//
	// Round 7 established the first half: gating the non-nil publish on the
	// rebind outcome was a fail-open for credential ROTATION and REVOCATION,
	// which is the common case — replacing secret A with secret B means A must
	// stop working, and skipping ReplaceAuth left the RETAINED listener honouring
	// A indefinitely, until some later reconcile happened to succeed. Not a race
	// window; a permanent one. Publishing the intersection early keeps that
	// property exactly: A is not in it, so A stops working the moment the commit
	// lands, whatever the rebind does.
	//
	// What the rebind outcome DOES gate is the grant half. Once every leg has
	// converged, every live listener is at an address this config names, so the
	// credential set it committed for those addresses can go out whole. If any
	// leg failed, some listener is still serving an address the config asked to
	// leave, and the restricted set published above stays in force until a later
	// reconcile converges (each commit retries; the error and the Warn above make
	// the state visible).
	if next.Auth != nil && rebinding && len(errs) == 0 {
		m.srv.ReplaceAuth(next.Auth)
	}

	// Dropping to NO auth stays HERE, after the rebinds, because that direction
	// REMOVES a requirement and is the one that can fail open. It requires the
	// LIVE listeners — both legs, read from m.cur, which the rebinds above have
	// just advanced — to be loopback.
	//
	// The gate is on the live ADDRESSES, not on the rebind outcome. A nil auth is
	// justified by the #4047/#5127 clamp, and that clamp is evaluated against the
	// bind of the config that carried the nil; a listener retained by a failed
	// rebind, or moved by a STALE apply replay whose own endpoint bound fine, is
	// not that bind and its address must be proven loopback directly. Testing
	// "the HTTP rebind succeeded" instead is a proxy that holds only while the
	// config being applied is the newest one — withCommittedAuth now propagates a
	// committed nil through stale replays, so the proxy would license dropping an
	// off-loopback listener to no-auth (#5561 round 12).
	if next.Auth == nil && mgmtAddrIsLoopback(m.cur.addr) &&
		(!m.cur.tls || mgmtAddrIsLoopback(m.cur.httpsAddr)) {
		m.srv.ReplaceAuth(nil)
	}

	if len(errs) == 0 {
		return nil
	}
	joined := errors.Join(errs...)
	slog.Warn("web-management listener reconcile incomplete; retaining previous listener(s)",
		"desired", endpointOf(next).summary(), "err", joined)
	return fmt.Errorf("web-management reconcile to %s incomplete; retaining previous listener(s): %w",
		endpointOf(next).summary(), joined)
}

// mgmtAddrIsLoopback reports whether a "host:port" bind is loopback, treating an
// empty addr (no listener on that leg) as loopback and an unparseable host as
// NON-loopback (fail-closed). Used to gate a nil-auth (remove-all-api-auth)
// publish so a non-loopback listener is never dropped to no-auth (#5866).
func mgmtAddrIsLoopback(addr string) bool {
	if addr == "" {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return hostIsLoopback(host)
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
