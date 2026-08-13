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
//     is surfaced. That holds at BOOT too, where there is no previous listener to
//     retain: startTo keeps the server after a failed HTTP bind (so reconcileTo
//     can retry rather than short-circuit on a nil srv) and records only the
//     HTTPS leg that is actually serving (#5561 round 14). Every "over-restrict
//     now, converge on the next commit" argument below rests on that being true.
//   - RETIRED LEGS: a leg replaced by a rebind keeps serving while it drains, so
//     it carries its OWN credential snapshot, pinned at retirement and only ever
//     intersected afterwards (api.authSlot, #5561 round 14). A revocation still
//     reaches it; a grant committed for the NEW address never does.
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
//     (#5561 round 12, api.AuthForRetainedListener). The gate for that is the
//     property itself — every listener that is actually SERVING sits at an
//     address `next` names (mgmtEndpoint.everyLiveLegNamedBy, #5561 round 13) —
//     not "some leg moved and every rebind succeeded", which was a strictly
//     wider proxy. A commit with nothing to converge, and one whose only failure
//     was to ENABLE a leg that therefore does not exist, both publish whole.
//     Removing ALL api-auth is a revocation too and lands
//     immediately, but WHAT lands depends on where the live legs are
//     (publishNilDirectionLocked, #5561 round 14): the nil itself REMOVES a
//     requirement, so the #4047/#5127 clamp that justified it must be proven
//     against the listeners that are actually serving, and while any of them is
//     off-loopback what publishes is the DENY-ALL set instead — never the
//     credential the commit deleted.
//   - AUTH FRESHNESS: the whole desired state — endpoint AND credentials — is
//     re-derived from the newest COMMITTED configuration rather than from the
//     config this apply happens to carry. See committedDesired.
//
// The reconcile is serialized by mu, and so is the apply path (applyConfigLocked
// under the apply semaphore) — but SERIALIZING the applies does not order their
// CONTENT, and the difference is the whole reason committedDesired exists. An
// applyConfig caller that snapshots store.ActiveConfig() and THEN waits on the
// apply semaphore (the DHCP lease-change callback, daemon_dhcp.go, is the live
// example) can be overtaken by one or more commits while it waits and then run,
// alone and in order, carrying a generation the store has already superseded.
// The applies never interleave; an OLDER generation can still be the LAST one
// applied. Every management-listener defect this file has chased across #5561
// rounds 7-13 was a consequence of feeding that stale generation into the
// reconcile, so it is fenced at the entry point instead of being patched
// predicate by predicate.
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

// allLoopback reports whether every listener CURRENTLY SERVING under this
// fingerprint is bound to a loopback address. It gates the remove-all-api-auth
// (nil) publish: nil disables authentication outright, so it may only be
// published once no listener is reachable from off the box. Same per-leg
// reasoning as everyLiveLegNamedBy — an empty addr, or a cleared tls flag, means
// that leg is not serving and imposes no requirement.
func (e mgmtEndpoint) allLoopback() bool {
	return mgmtAddrIsLoopback(e.addr) && (!e.tls || mgmtAddrIsLoopback(e.httpsAddr))
}

// everyLiveLegNamedBy reports whether every listener CURRENTLY SERVING under
// this fingerprint sits at an address `next` names. It is the question the
// grant-half gate means to ask (#5561 round 13); `rebinding && len(errs) == 0`
// was a proxy for it, and the proxy is wider than the property in a reachable
// direction — see reconcileTo.
//
// Per leg:
//
//   - The HTTP leg is serving at e.addr unless e.addr is EMPTY, which means no
//     HTTP listener has ever bound: m.cur starts zeroed and startTo re-zeroes it
//     on a boot bind failure, while every successful bind records a non-empty
//     address (api.Server.ReconcileHTTP refuses an empty one outright). An absent
//     leg has no credential to hand out and imposes no requirement — the same
//     reading mgmtAddrIsLoopback gives an empty bind, and the same reasoning the
//     HTTPS arm below uses for a cleared tls flag. Otherwise `next` names it iff
//     next.Addr == e.addr.
//   - The HTTPS leg is serving only when e.tls is set. api.Server.ReconcileHTTPS
//     assigns s.httpsLeg only after BOTH the keypair and the bind succeed, so a
//     failed ENABLE leaves nothing behind; a disable stops the leg outright. So
//     when e.tls is clear there is no HTTPS listener to hand a credential to and
//     that leg imposes no requirement. When it is set, `next` names the serving
//     listener iff next still wants TLS at exactly e.httpsAddr.
//
// The same predicate answers two different questions depending on WHEN it runs,
// because each field advances only on its own leg's successful reconcile: read
// BEFORE the rebinds it says whether anything is about to move off what `next`
// names; read AFTER, whether everything landed on it.
func (e mgmtEndpoint) everyLiveLegNamedBy(next api.Config) bool {
	if e.addr != "" && e.addr != next.Addr {
		return false
	}
	if !e.tls {
		return true
	}
	return next.TLS && next.HTTPSAddr == e.httpsAddr
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
	err := srv.Start(ctx)
	// Adopt the server WHETHER OR NOT the boot bind succeeded (#5561 round 14,
	// MAJOR 5). Returning early left m.srv nil, and reconcileTo's `m.srv == nil`
	// short-circuit then made EVERY later reconcile a no-op: the "the next commit
	// retries via ReconcileHTTP" contract this file and api.Server.Start both
	// state was never true for a boot bind failure, so the management API stayed
	// down for the life of the process no matter what the operator committed.
	// The server object holds no socket on this path — only the mux, the shared
	// pre-auth base and the root context — so keeping it is exactly what lets
	// ReconcileHTTP/ReconcileHTTPS bind later.
	m.srv = srv
	if err != nil {
		// NOTHING converged: leave the fingerprint empty so the next reconcile
		// sees both legs as changed and retries both binds.
		m.cur, m.curSet = mgmtEndpoint{}, false
		return err
	}
	m.cur, m.curSet = endpointOf(next), true
	// An HTTPS bind failure at boot is deliberately NON-fatal (Start logs it and
	// keeps the HTTP plane up), so a nil error does not mean the HTTPS leg is
	// serving. Recording the desired HTTPS fingerprint as CONVERGED anyway meant
	// the leg-changed test below (`next.TLS != m.cur.tls || ...`) was false on
	// every subsequent unchanged commit and ReconcileHTTPS was never called —
	// the boot HTTPS failure was permanent and silent. Ask the server what is
	// actually serving instead (#5561 round 14, MAJOR 5).
	if next.TLS && !srv.HTTPSServing() {
		m.cur.tls, m.cur.httpsAddr = false, ""
	}
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
	return m.reconcileTo(m.committedDesired(cfg))
}

// committedDesired derives the desired management state from the newest
// COMMITTED configuration, falling back to the caller's cfg only when there is
// no store to ask (unit tests, very early boot). It is the generation fence
// (#5561 round 14).
//
// Every caller that reaches reconcile does so from applyConfigLocked, and
// store.Commit / PromoteRollback have ALREADY promoted the config being applied
// before the apply runs — so on the ordinary commit path ActiveConfig() IS cfg
// and this is the identity. The one path where it is not is a STALE REPLAY: an
// applyConfig caller that snapshots store.ActiveConfig() and then waits on the
// apply semaphore (daemon_dhcp.go's lease-change callback) resumes carrying a
// generation later commits have superseded. There, cfg is the wrong answer and
// ActiveConfig() is the right one — that caller's intent is "re-apply what is
// live", not "re-apply what was live when I started waiting".
//
// Why the WHOLE state and not just the credential half. Rounds 10 and 12 pinned
// only next.Auth, which left the listener being driven toward the STALE endpoint
// under the COMMITTED credentials — a hybrid desired state that belongs to no
// committed generation at all, and that is not a state any gate downstream can
// reason about:
//
//   - It can bind an endpoint the operator has already moved past, under the
//     newest policy. When that newest policy is nil (api-auth removed, so the
//     committed bind is loopback-clamped) the hybrid is an OFF-LOOPBACK endpoint
//     with NO authentication — and reconcileTo cannot repair it, because its nil
//     gate only declines to publish ANOTHER nil. The nil is already live; there
//     is no credential left to restore. That is a permanent unauthenticated
//     routable management API (#5561 round 14, MAJOR 1).
//   - It defeats the grant gate rather than passing it. everyLiveLegNamedBy asks
//     whether every serving listener sits at an address `next` NAMES — and the
//     hybrid's `next` names the stale address the listener is already on. The
//     gate reads TRUE and publishes the whole committed credential set at an
//     endpoint the committed config never authorized it for (MAJOR 3). Round 13
//     did not close this: it sharpened WHICH question is asked, and the hybrid
//     corrupts the `next` the question is asked ABOUT.
//
// Both disappear once endpoint and credentials come from one generation: a stale
// replay then computes exactly the newest commit's desired state, which is
// either already converged (a no-op) or a retry of a bind that failed. It can no
// longer construct a state the operator never committed.
//
// This fences the MANAGEMENT LISTENER only. The general stale-snapshot apply
// defect (#6716) — the rest of the pipeline still reconciling toward a
// superseded generation — lives in the apply path and is not repaired here.
func (m *managementReconciler) committedDesired(cfg *config.Config) api.Config {
	if m.d != nil && m.d.store != nil {
		if active := m.d.store.ActiveConfig(); active != nil {
			cfg = active
		}
	}
	return m.desired(cfg)
}

// reconcileTo drives the reconcile against an explicit desired config. Split
// from reconcile so a test exercises the make-before-break / live-auth-swap /
// fail-safe logic with hand-built endpoints, without a configstore or
// resolveAPIBinds (#5866).
func (m *managementReconciler) reconcileTo(next api.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srv == nil {
		// API disabled (--api-addr empty), or start was never called: nothing to
		// reconcile. A boot bind FAILURE no longer lands here — startTo adopts the
		// server regardless so this path can retry the bind (#5561 round 14).
		return nil
	}

	var errs []error

	// Whether every listener that is CURRENTLY serving sits at an address `next`
	// names. Read here, before any rebind, it says whether some live listener is
	// about to move off (or is already off) what this config named — which is
	// what makes the credential publish below conditional. It is read AGAIN
	// after the rebinds, where it says whether everything landed.
	sanctioned := m.cur.everyLiveLegNamedBy(next)

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
	// bind at all. So while some LIVE listener sits at an address this config
	// does not name, only the intersection with the live snapshot goes out (#5561
	// round 12): every revocation lands immediately, no grant does. A nil live
	// snapshot is the universal set, so the round-9 case still publishes the full
	// credential set before the new off-box socket serves.
	//
	// The full set follows below, once every leg has converged onto an address
	// THIS config names. When every live leg ALREADY sits at an address this
	// config names there is nothing to converge and no retained listener to
	// protect, so the full set goes out here — the plain day-2 credential change,
	// which must not be degraded to an intersection (that would revoke without
	// granting, i.e. lock the operator out of an endpoint the commit never
	// touched).
	//
	// The nil (remove-all-api-auth) direction is resolved at BOTH points against
	// the live addresses in m.cur: here it can only revoke (deny-all) while a
	// listener is still serving off-loopback, and below — after the rebinds have
	// advanced m.cur — it converges to the nil the operator actually committed.
	if next.Auth != nil {
		publish := next.Auth
		if !sanctioned {
			publish = api.AuthForRetainedListener(m.srv.LiveAuth(), next.Auth)
			if withheld := api.CredentialCount(next.Auth) - api.CredentialCount(publish); withheld > 0 {
				slog.Warn("web-management endpoint is moving; withholding committed credentials from the listener that is still serving until the rebind converges",
					"withheld", withheld, "live_http", m.cur.addr, "desired", endpointOf(next).summary())
			}
		}
		m.srv.ReplaceAuth(publish)
	} else {
		// REMOVING all api-auth is a revocation too, and it lands with the same
		// immediacy as any other (#5561 round 7). Resolved here against the
		// PRE-rebind live addresses, and again below against the post-rebind ones
		// — see publishNilDirectionLocked.
		m.publishNilDirectionLocked()
	}

	// HTTP leg: make-before-break rebind ONLY if the HTTP bind changed. Advance
	// the converged fingerprint only on success (retry debt on failure).
	if next.Addr != m.cur.addr {
		// Record the attempted bind so `show system services` reports the address
		// a boot-failed listener is retrying, not the one it failed at boot (#6401).
		m.lastHTTPAttempt = next.Addr
		if err := m.srv.ReconcileHTTP(next.Addr); err != nil {
			errs = append(errs, err)
		} else {
			// curSet advances here too: a boot bind failure leaves it false, and
			// this is the reconcile that pays that retry debt off (#5561 round 14).
			m.cur.addr, m.curSet = next.Addr, true
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
	// What the rebinds DO gate is the grant half — but on where the live legs
	// ended up, not on whether every call returned nil. Once every SERVING
	// listener is at an address this config names, the credential set it
	// committed for those addresses goes out whole. If some listener is still
	// serving an address the config asked to leave, the restricted set published
	// above stays in force until a later reconcile converges (each commit
	// retries; the error and the Warn above make the state visible).
	//
	// `len(errs) == 0` was the proxy for that, and it is strictly wider than the
	// property in one reachable direction: failing to ENABLE a leg leaves NO
	// listener at an unnamed address (ReconcileHTTPS creates the leg only after
	// the bind succeeds), yet it withheld anyway (#5561 round 13). The concrete
	// shape is an ordinary one — one commit rotates the web-management password
	// and enables TLS; the HTTPS bind fails; the HTTP listener never moved off
	// the address the same commit named. Under the proxy the single-account
	// rotation intersected to the EMPTY set, which rejects every non-exempt
	// request, so the management API 401'd every caller on the committed address
	// while the commit reported success. And that state had no exit: the empty
	// set is absorbing under the intersection (∅ ∩ X = ∅), and the endpoint
	// fingerprint could not converge while the port stayed held, so neither
	// re-committing nor rotating again recovered — only backing the TLS enable
	// out did. Asking where the live legs ARE never enters it, because nothing
	// was ever retained anywhere.
	//
	// The empty set stays representable. Refusing it would mean keeping a
	// credential the committed config no longer carries alive on a listener the
	// operator asked to leave, which is the round-7 fail-open. What matters is
	// that every ∅ this gate can now enter has an EXIT a later commit can reach:
	// it is entered only while some listener really is retained at an unnamed
	// address, so converging that bind, or committing the address that is
	// actually serving, publishes the full set
	// (TestMgmtWithheldGrantIsExitableByASubsequentCommit_5561).
	if next.Auth != nil && !sanctioned && m.cur.everyLiveLegNamedBy(next) {
		m.srv.ReplaceAuth(next.Auth)
	}

	// The remove-all-api-auth direction is resolved AGAIN here, against the
	// post-rebind live addresses. This is the call that converges: the pre-rebind
	// one runs while the off-loopback listener is still the one serving and can
	// therefore only publish deny-all, and the whole point of the commit is that
	// once the loopback bind lands, authentication is genuinely off.
	if next.Auth == nil {
		m.publishNilDirectionLocked()
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

// noteStaleMgmtCertHostName records that the kernel host name just moved and
// immediately attempts to deliver the management-TLS staleness diagnostic
// (#6827). Marking and attempting are ONE path: the previous shape branched on
// `d.mgmt == nil` outside staleCertMu while startHTTPServer published d.mgmt
// and drained separately, so a rename landing in that window neither refreshed
// the parked state nor got diagnosed.
//
// This is deliberately NOT part of reconcile(): reconcile runs early in the
// apply, before applyHostname, so it can only ever observe the OLD kernel name.
func (d *Daemon) noteStaleMgmtCertHostName() {
	if d == nil {
		return
	}
	d.staleCertMu.Lock()
	d.staleCertPending = true
	d.staleCertGen++
	d.staleCertMu.Unlock()
	d.deliverStaleMgmtCertDiagnosis()
}

// deliverStaleMgmtCertDiagnosis delivers a pending host-name staleness
// diagnosis if one is owed and a management certificate is actually being
// served, clearing the debt ONLY on success (#6827).
//
// Called from three places, all of them retry points rather than one-shot
// drains: the rename itself, the boot management start, and every
// web-management reconcile (so a later `web-management https` enable settles a
// debt incurred while HTTPS was down).
//
// The host name is read from the kernel HERE, not stored at rename time. That
// removes the "replayed a rename from arbitrarily far back" hazard at its
// root: whenever this speaks, it describes the name the box has right now.
func (d *Daemon) deliverStaleMgmtCertDiagnosis() {
	if d == nil {
		return
	}
	d.staleCertMu.Lock()
	pending, gen, mgmt := d.staleCertPending, d.staleCertGen, d.mgmt
	d.staleCertMu.Unlock()
	if !pending || mgmt == nil {
		return
	}
	hostName, err := osHostname()
	if err != nil || hostName == "" {
		return // cannot describe the current identity; stay in debt
	}
	if !mgmt.warnStaleCertForHostName(hostName) {
		return // nothing serving a certificate yet; the debt stands
	}
	// Clear ONLY the generation this delivery claimed (#6827 round 5). The
	// hostname read and certificate inspection above run UNLOCKED, so a rename
	// committed while they were in flight bumps the generation; an unconditional
	// clear would settle that newer debt with an older delivery's evidence and
	// lose it permanently.
	d.staleCertMu.Lock()
	if d.staleCertGen == gen {
		d.staleCertPending = false
	}
	d.staleCertMu.Unlock()
}

// warnStaleCertForHostName forwards to the live api.Server under mu so it cannot
// race a concurrent startTo/reconcileTo swapping the server pointer. It reports
// whether a served certificate was actually reached.
func (m *managementReconciler) warnStaleCertForHostName(hostName string) bool {
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil {
		return false
	}
	return srv.WarnStaleMgmtCertForHostName(hostName)
}

// publishNilDirectionLocked publishes the remove-all-api-auth (nil) direction
// against the addresses the LIVE listeners are on RIGHT NOW (m.cur). Caller
// holds mu.
//
// The committed policy authorizes no credential at all, and there are exactly
// two ways to say that to a listener:
//
//   - nil, which is dynamicAuthMiddleware's pass-through. It is justified by the
//     #4047/#5127 clamp, and that clamp was evaluated against the bind the
//     COMMITTED config asked for — so it may go out only once every live leg is
//     actually at a loopback address. A listener retained by a failed rebind is
//     not that bind, and publishing nil there is a routable, unauthenticated,
//     MUTATING management API.
//   - the DENY-ALL set: non-nil and empty, which rejects every non-exempt
//     request.
//
// Pre-round-14 there was no second arm: while any live leg was off-loopback the
// live snapshot was left ALONE, so the credential the operator had just deleted
// went on authenticating there — for as long as the loopback bind kept failing,
// which is indefinitely, not for a window. That inverts the instruction. Under
// this file's own immediate-revocation rule (#5561 round 7) the removal must
// land at once, and deny-all is the expression of it that does not fail open: it
// over-restricts and waits for the next commit, exactly as the intersection does
// on the non-nil path (#5561 round 14, MAJOR 4).
//
// Both call sites matter, for DIFFERENT reasons, and the pre-rebind one's reason
// is not the obvious one (#5561 round 16). Read naively it is "the revocation
// lands immediately" — but on a rebind that FAILS the off-loopback leg is
// RETAINED, keeps following the server-wide snapshot, and the post-rebind call
// publishes the same deny-all against the same unchanged m.cur. On that path the
// pre-rebind call is genuinely redundant, which is why deleting it was silent
// through round 15.
//
// It is load-bearing on the rebind that SUCCEEDS, because there the old leg is
// RETIRED rather than retained, and a retired leg stops following the
// server-wide snapshot at the instant of retirement: api.Server.trackRetiring
// PINS it to whatever s.auth holds then. The post-rebind call cannot repair that
// pin — m.cur is loopback by then, so what publishes is the committed nil, and
// api.authSlot.tighten drops a nil next by design (a nil REMOVES a requirement).
// Without this publish the pin captures the credential the operator DELETED, and
// retirement is asynchronous: the socket keeps accepting until the serve
// goroutine reaches Shutdown, and connections already accepted are served for the
// whole bounded drain. Guarded by
// TestMgmtRemovedCredentialNeverSurvivesOnTheRetiredLeg_5561 — the only case in
// the package whose nil-direction rebind converges.
//
// After the rebinds it is what CONVERGES: the loopback bind has landed, so the
// nil the operator committed genuinely takes effect and deny-all is not a
// lockout.
func (m *managementReconciler) publishNilDirectionLocked() {
	if m.cur.allLoopback() {
		m.srv.ReplaceAuth(nil)
		return
	}
	m.srv.ReplaceAuth(&api.AuthConfig{})
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
	err := d.mgmt.reconcile(cfg)
	// #6827: a reconcile may have just brought HTTPS up (enable, or a retried
	// bind). If a host-name staleness diagnosis is still owed from a window
	// when nothing was serving, settle it now rather than losing it.
	d.deliverStaleMgmtCertDiagnosis()
	return err
}
