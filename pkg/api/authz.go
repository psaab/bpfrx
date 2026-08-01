package api

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// authz.go enforces per-principal authorization on the REST mutation surface
// (#5561).
//
// Before this, every state-changing endpoint on 127.0.0.1:8080 — including
// `POST /api/v1/config/set`, `/config/load` and the commit family — ran with no
// per-caller identity at all. The only gates were the #4047/#5127 loopback
// clamp (a location, not an identity), the optional api-auth credential (off by
// default on a loopback bind: dynamicAuthMiddleware passes every request
// through when the snapshot is nil) and the #5055 cross-site guard (a browser
// CSRF defense that a non-browser client passes trivially, by design). Since
// the daemon provisions every `system login user` a real shell account, a
// `read-only` class holder could `curl` a commit and the CLI's client-side RBAC
// never ran. The gRPC surface has the same hole and is tracked separately as
// #5278; the authorization decision itself lives in pkg/authz so both surfaces
// reach the same verdict.
//
// # Shape of the gate
//
// The table below is an ALLOW-list keyed by the exact "METHOD /path" a route
// was registered under. A non-safe method that is not in the table is denied.
// That is the property the issue's scope note asks for — no mutating route
// defaults open — and it holds for routes that do not exist yet: adding a
// `mux.HandleFunc("POST ...")` without a table entry produces a route that
// denies, not a route that is unguarded. TestEveryMutatingRouteHasAPermission_5561
// turns that from a runtime surprise into a test failure by reading the route
// registrations out of server.go and requiring table coverage in both
// directions.
//
// Safe methods (GET/HEAD/OPTIONS/TRACE — isSafeHTTPMethod, shared with the
// cross-site guard) are not gated here at all: read-only endpoints, /health and
// /metrics keep exactly their previous access rules, which the #4162 metrics
// gate and the api-auth middleware continue to enforce.

// restMutationPermissions is the fail-closed route -> required-permission table
// for every state-changing REST route.
//
// Permissions mirror pkg/cli/permissions.go requiredPermission so an operator
// gets the same answer from `curl` as from the CLI: the clear family is
// PermClear, ping/traceroute are PermView (they are `show`-tier operational
// verbs on Junos), and everything under /config is PermConfig — including
// commit-check, which reads the candidate a caller must already hold the
// configure permission to have staged.
//
// `POST /api/v1/system/action` is gated at PermMaint, the permission `request
// system reboot`/`halt` require and that no non-super class holds (#4108 F21).
// The route multiplexes on a body field, and one of its verbs
// (`clear-config-lock`) is a non-destructive recovery action the CLI would gate
// at PermControl — but the middleware deliberately does not consume the request
// body to find out, so the route is gated at the highest permission any of its
// verbs needs. The effect is that an `operator`-class principal cannot clear a
// wedged config lock over REST; it over-restricts rather than under-restricts,
// and splitting enforcement between the middleware and the handler to recover
// that one verb would put half the authorization decision somewhere a future
// route could forget to make.
var restMutationPermissions = map[string]config.LoginClassPermission{
	// Operational clear verbs.
	"POST /api/v1/security/sessions/clear": config.PermClear,
	"POST /api/v1/security/counters/clear": config.PermClear,
	"POST /api/v1/dhcp/identifiers/clear":  config.PermClear,

	// Diagnostics. POST-shaped, but `ping`/`traceroute` are view-tier verbs on
	// Junos and in the CLI's own table.
	"POST /api/v1/diagnostics/ping":       config.PermView,
	"POST /api/v1/diagnostics/traceroute": config.PermView,

	// Configuration: candidate lifecycle, mutation, and commit.
	"POST /api/v1/config/enter":            config.PermConfig,
	"POST /api/v1/config/exit":             config.PermConfig,
	"POST /api/v1/config/set":              config.PermConfig,
	"POST /api/v1/config/delete":           config.PermConfig,
	"POST /api/v1/config/deactivate":       config.PermConfig,
	"POST /api/v1/config/activate":         config.PermConfig,
	"POST /api/v1/config/load":             config.PermConfig,
	"POST /api/v1/config/commit":           config.PermConfig,
	"POST /api/v1/config/commit-check":     config.PermConfig,
	"POST /api/v1/config/commit-confirmed": config.PermConfig,
	"POST /api/v1/config/confirm":          config.PermConfig,
	"POST /api/v1/config/rollback":         config.PermConfig,
	"POST /api/v1/config/annotate":         config.PermConfig,

	// Destructive maintenance (reboot / halt) plus the config-lock recovery
	// verb, folded up to the destructive floor — see the doc comment.
	"POST /api/v1/system/action": config.PermMaint,
}

type peerIdentityKey struct{}

// peerLookupTimeout bounds how long a request waits for its connection's peer
// lookup. It only elapses if the socket-table read is wedged; a timeout yields
// no identity, which denies.
const peerLookupTimeout = 5 * time.Second

// pendingPeer is a connection's peer identity, resolved once, asynchronously,
// starting at accept.
type pendingPeer struct {
	done chan struct{}
	id   authz.PeerIdentity
}

// wait blocks until the lookup finishes, the request context is cancelled, or
// peerLookupTimeout elapses. ok=false means no identity is available and the
// caller must deny.
func (p *pendingPeer) wait(ctx context.Context) (authz.PeerIdentity, bool) {
	select {
	case <-p.done:
		return p.id, true
	default:
	}
	t := time.NewTimer(peerLookupTimeout)
	defer t.Stop()
	select {
	case <-p.done:
		return p.id, true
	case <-ctx.Done():
		return authz.PeerIdentity{}, false
	case <-t.C:
		return authz.PeerIdentity{}, false
	}
}

// connContext is the http.Server ConnContext hook (wired by buildHTTPServer /
// buildHTTPSServer). It STARTS the peer lookup for this connection, at accept,
// and hands every request on the connection the same pending result.
//
// Why it is started at accept rather than at the authorization check: the first
// version deferred it, reasoning that the client is blocked awaiting a response
// and so its socket is established for exactly the window that matters. That
// assumed a COOPERATIVE client and was wrong — `shutdown(fd, SHUT_WR)` leaves
// ESTABLISHED while still letting the caller read the response, so the caller
// could choose the moment of the lookup and choose to make it fail. Starting it
// at accept takes that choice away: the inputs are fixed when the connection is
// established, which is the SO_PEERCRED semantic this stands in for.
//
// Why it runs in a goroutine rather than inline: ConnContext executes SERIALLY
// in http.Server's accept loop, and a peer whose socket is not found costs a
// full walk of the socket table. Connection churn would then serialize those
// walks behind Accept and fill the listen backlog — locking out remote
// administrators before api-auth is even evaluated. Off the accept path, the
// listener keeps accepting; a request that arrives before its lookup finishes
// simply waits for it, and a wedged lookup denies rather than hangs. The
// ESTABLISHED guarantee is unaffected: the lookup is started at accept, not at
// request time, so its timing is still outside the caller's control.
//
// authz.LookupPeer additionally does NO socket-table work at all for a peer that
// cannot be local, so the churn that motivates this is cheap on both counts.
func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	client, server := c.RemoteAddr(), c.LocalAddr()
	p := &pendingPeer{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		p.id = s.lookupPeer(client, server)
	}()
	return context.WithValue(ctx, peerIdentityKey{}, p)
}

// lookupPeer resolves the peer identity through the injected resolver
// (Config.PeerLookupFn) or pkg/authz's kernel lookup, normalizing the result.
//
// The normalization exists because an injected resolver is not bound by
// LookupPeer's invariants and could report the nonsensical (OK, !Local): an
// attributed peer is local by construction — we read its UID out of THIS host's
// socket table. Left unnormalized, that state would reach the precedence rule as
// "attributed but off-box", a combination the policy has no row for.
func (s *Server) lookupPeer(client, server net.Addr) authz.PeerIdentity {
	fn := s.peerLookupFn
	if fn == nil {
		fn = authz.LookupPeer
	}
	id := fn(client, server)
	if id.OK {
		id.Local = true
	}
	return id
}

func peerIdentityFrom(ctx context.Context) (*pendingPeer, bool) {
	p, ok := ctx.Value(peerIdentityKey{}).(*pendingPeer)
	return p, ok
}

// activeConfig returns the active config snapshot the login model is read from,
// or nil when the store is unwired or no config is active yet (early boot).
//
// A nil snapshot does not fail the box open: pkg/authz resolves UID 0 without
// consulting it, and every other principal resolves to "not a configured login
// user", which denies.
func (s *Server) activeConfig() *config.Config {
	if s.store == nil {
		return nil
	}
	return s.store.ActiveConfig()
}

// principal derives the caller's server-side identity for one request (#5561).
//
// The precedence rule is: IF THE CALLER IS ON THIS HOST, THE LOGIN MODEL IS THE
// ONLY AUTHORITY. An api-auth credential may speak only for a caller that is not
// local.
//
// This has been narrowed twice, each time because a weaker version had a hole
// the claim above did not admit to:
//
//   - v1 used the peer UID when the lookup SUCCEEDED and fell back to the
//     credential otherwise. The caller controlled whether it succeeded
//     (half-close), so a `read-only` account holding the shared secret reached
//     full power.
//   - v2 denied an UNATTRIBUTABLE local caller but still let the credential
//     speak for an ATTRIBUTED one that was not a configured `system login user`.
//     That is the population #5561 exists to constrain, and it made the
//     per-principal gate optional for anyone holding the password. The operator
//     doc already said such a caller is denied; the code did not.
//
// So the four outcomes are:
//
//  1. Local, attributed to a configured `system login user` — that class decides.
//  2. Local, attributed to an account the login model does not cover — DENIED.
//     Grant it a class if it needs access; that is the one place access is
//     supposed to be written down.
//  3. Local, not attributable — DENIED.
//  4. Not on this host — a remote administrator, which is exactly what the
//     api-auth credential exists to identify (#4047 requires one for any
//     off-loopback bind).
//
// Rows 1-3 collapse to: a local caller never reaches s.credential.
func (s *Server) principal(r *http.Request) authz.Principal {
	pending, ok := peerIdentityFrom(r.Context())
	if !ok {
		// No ConnContext ran for this connection, so we cannot even tell whether
		// the caller is local — and therefore cannot tell whether a credential
		// is allowed to speak for it. Refuse rather than guess.
		return authz.Unauthenticated("connection identity was not captured at accept")
	}
	id, resolved := pending.wait(r.Context())
	if !resolved {
		return authz.Unauthenticated("peer identity lookup did not complete for this connection")
	}

	if id.OK {
		// (1) and (2). PrincipalForUID yields an unresolved principal for an
		// account outside the login model, which Authorize denies — and no
		// credential is consulted on the way there.
		return authz.PrincipalForUID(s.activeConfig(), id.UID)
	}
	if id.Local {
		return authz.Unauthenticated("caller is local but could not be identified: " + id.Detail)
	}
	if cp, ok := s.credential(r); ok {
		return cp // (4)
	}
	return authz.Unauthenticated(id.Detail)
}

// credential returns the principal for a valid api-auth credential on r, if the
// listener has an auth policy and the request satisfies it.
func (s *Server) credential(r *http.Request) (authz.Principal, bool) {
	a := s.auth.Load()
	if a == nil {
		return authz.Principal{}, false
	}
	user, ok := credentialPrincipalUser(*a, r)
	if !ok {
		return authz.Principal{}, false
	}
	return authz.CredentialPrincipal(user), true
}

// credentialPrincipalUser reports whether r presented a VALID configured
// api-auth credential, and the Basic username it authenticated as ("" for a
// Bearer / X-API-Key token, which names no user).
//
// It routes through the same checkAuthorization / constantTimeAPIKeyMatch
// helpers the auth middleware uses, so the #4157 constant-time and #5636
// empty-secret properties are the middleware's, not a second implementation of
// them. The username is read back only AFTER the credential validated, so a
// wrong password never yields a name.
func credentialPrincipalUser(cfg AuthConfig, r *http.Request) (string, bool) {
	if auth := r.Header.Get("Authorization"); auth != "" && checkAuthorization(auth, cfg) {
		if !strings.HasPrefix(auth, "Basic ") {
			return "", true // Bearer token — authenticated, names no user
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			// Unreachable: checkAuthorization already decoded it.
			return "", true
		}
		user, _, _ := strings.Cut(string(payload), ":")
		return user, true
	}
	if key := r.Header.Get("X-API-Key"); key != "" && constantTimeAPIKeyMatch(cfg, key) {
		return "", true
	}
	return "", false
}

// mutationAuthzGuard rejects a state-changing request whose caller the server
// cannot authorize (#5561). Safe methods pass through untouched.
func (s *Server) mutationAuthzGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeHTTPMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// Exact match on the registered pattern. The path is NOT cleaned or
		// normalized first: cleaning can only widen what matches, and a
		// non-canonical spelling of a guarded route must fail closed here
		// rather than reach the mux's redirect.
		required, known := restMutationPermissions[r.Method+" "+r.URL.Path]
		if !known {
			slog.Warn("api: refused unguarded mutating request",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			writeError(w, http.StatusForbidden,
				"permission denied: no authorization policy is defined for this mutating endpoint")
			return
		}

		p := s.principal(r)
		if err := authz.Authorize(s.activeConfig(), p, required); err != nil {
			slog.Warn("api: denied mutating request",
				"method", r.Method, "path", r.URL.Path,
				"principal", p.String(), "source", p.Source.String(),
				"required", authz.PermissionName(required), "err", err)
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		slog.Debug("api: authorized mutating request",
			"method", r.Method, "path", r.URL.Path,
			"principal", p.String(), "required", authz.PermissionName(required))
		next.ServeHTTP(w, r)
	})
}
