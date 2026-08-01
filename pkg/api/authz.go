package api

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"

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

// connContext is the http.Server ConnContext hook (wired by buildHTTPServer /
// buildHTTPSServer). It resolves the peer's identity ONCE, at accept, and caches
// it on the connection.
//
// The first version deferred this to the authorization check, reasoning that the
// client is blocked awaiting a response and so its socket is established for
// exactly the window that matters. That reasoning assumed a COOPERATIVE client
// and was wrong: `shutdown(fd, SHUT_WR)` takes the socket out of ESTABLISHED
// while still letting the caller read the response, so a caller could choose the
// moment of the lookup and choose to make it fail. Resolving at accept takes that
// choice away — the identity is fixed when the connection is established, which
// is the SO_PEERCRED semantic this is standing in for.
//
// The lookup runs in http.Server's accept loop, so it is on the path of every
// accepted connection. It is one bounded read of the kernel socket table on a
// control-plane listener that answers a handful of operator actions per second,
// which is the right trade for an identity a caller cannot influence. Note that
// correctness does NOT depend on the timing: authz.LookupPeer reports a caller
// whose socket has vanished as LOCAL-but-unattributable (by address), which
// denies. Eager resolution removes the attack; the address rule removes the
// reliance on winning a race.
func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerIdentityKey{}, s.lookupPeer(c.RemoteAddr(), c.LocalAddr()))
}

// lookupPeer resolves the peer identity through the injected resolver
// (Config.PeerLookupFn) or pkg/authz's kernel lookup.
func (s *Server) lookupPeer(client, server net.Addr) authz.PeerIdentity {
	if s.peerLookupFn != nil {
		return s.peerLookupFn(client, server)
	}
	return authz.LookupPeer(client, server)
}

func peerIdentityFrom(ctx context.Context) (authz.PeerIdentity, bool) {
	id, ok := ctx.Value(peerIdentityKey{}).(authz.PeerIdentity)
	return id, ok
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
// The precedence rule is: WHEN THE CALLER IS LOCAL, THE PEER IDENTITY IS
// AUTHORITATIVE. A credential may speak only for a caller the login model does
// not describe, or for one that is not on this host at all.
//
// The first version stated the same intent — "a peer UID outranks a credential"
// — but implemented it as "use the peer UID when the lookup SUCCEEDS, otherwise
// fall back to the credential". The caller controlled whether the lookup
// succeeded (half-close before the request was authorized), so a `read-only`
// account holding the api-auth secret escalated to full power just by calling
// `shutdown(SHUT_WR)` first. A guard scoped to the success case is not a
// precedence rule; the failure case is where precedence matters. The four
// outcomes are now explicit:
//
//  1. Local and attributed to a configured `system login user` — that class is
//     the answer. A credential CANNOT upgrade it. This is the property the
//     issue is about: a restricted account stays restricted even if it also
//     knows a shared secret.
//  2. Local and attributed to an account the login model does not cover — the
//     operator has assigned it no class, so a credential (an explicit operator
//     grant) may speak for it.
//  3. Local but NOT attributable — DENIED. No credential fallthrough. This is
//     the row that used to escalate; a caller that can make its own identity
//     unreadable must not thereby become anonymous-with-a-password.
//  4. Not on this host — a remote administrator, which is exactly what the
//     api-auth credential exists to identify (#4047 requires one for any
//     off-loopback bind).
func (s *Server) principal(r *http.Request) authz.Principal {
	cfg := s.activeConfig()

	id, ok := peerIdentityFrom(r.Context())
	if !ok {
		// No ConnContext ran for this connection, so we cannot even tell whether
		// the caller is local — and therefore cannot tell whether a credential
		// is allowed to speak for it. Refuse rather than guess.
		return authz.Unauthenticated("connection identity was not captured at accept")
	}

	if id.OK {
		p := authz.PrincipalForUID(cfg, id.UID)
		if p.Resolved() {
			return p // (1) authoritative — no credential may override it
		}
		if cp, ok := s.credential(r); ok {
			return cp // (2) outside the login model; the credential may grant it
		}
		return p
	}

	if id.Local {
		// (3) A caller on this host that could not be attributed.
		return authz.Unauthenticated("caller is local but could not be identified: " + id.Detail)
	}

	if cp, ok := s.credential(r); ok {
		return cp // (4) remote administrator
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
