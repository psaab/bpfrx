package api

import (
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
)

// AuthConfig holds authentication credentials for the API middleware.
type AuthConfig struct {
	Users   map[string]string // username -> password
	APIKeys map[string]bool   // valid API key tokens
}

// authMiddleware wraps an http.Handler with Basic Auth / Bearer / X-API-Key
// checks. /health always bypasses authentication (it exposes no sensitive data
// and is a liveness probe). /metrics bypasses authentication only when
// metricsRequireAuth is false for a literal loopback bind, the standard
// Prometheus posture. NewServer derives it independently from the configured
// address of each enabled HTTP or HTTPS listener. A routable, wildcard,
// hostname, malformed, or otherwise unprovable bind requires credentials for
// /metrics like every other endpoint (#4162).
func authMiddleware(cfg AuthConfig, metricsRequireAuth bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /health is always exempt; /metrics is exempt only when this listener
		// has a literal loopback bind.
		if r.URL.Path == "/health" || (r.URL.Path == "/metrics" && !metricsRequireAuth) {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		if auth := r.Header.Get("Authorization"); auth != "" {
			if checkAuthorization(auth, cfg) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check X-API-Key header
		if key := r.Header.Get("X-API-Key"); key != "" {
			if constantTimeAPIKeyMatch(cfg, key) {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="xpf API"`)
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "authentication required",
		})
	})
}

// checkAuthorization validates an Authorization header value.
func checkAuthorization(auth string, cfg AuthConfig) bool {
	// Bearer token
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return constantTimeAPIKeyMatch(cfg, token)
	}

	// Basic auth
	if strings.HasPrefix(auth, "Basic ") {
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return false
		}
		user, pass, ok := strings.Cut(string(payload), ":")
		if !ok {
			return false
		}
		// Look up the expected password, but ALWAYS run the constant-time
		// compare — even for an unknown user — so response timing does not
		// reveal whether the username exists (#4157). Early-returning on
		// !exists would skip the compare entirely, a large and measurable
		// timing gap between a known and an unknown username.
		expected, exists := cfg.Users[user]
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
		// #5636: an EMPTY configured password is not a valid credential —
		// reject it regardless of what the request presents. A quoted-empty
		// api-auth secret can slip through a lenient config load; without this
		// guard `username:` (empty password) matches an empty stored secret and
		// authenticates, an auth bypass on an off-loopback bind. The
		// constant-time compare above still runs unconditionally, so the
		// known/unknown-user timing profile from #4157 is preserved. The added
		// `expected != ""` check is an O(1) length test whose cost does not
		// vary with the secret's content or length; the attacker-supplied
		// username does select WHICH configured `expected` is tested, but the
		// branch reveals only whether that (already `exists`-gated) user has a
		// non-empty configured secret — never any secret content — so it adds
		// no request-content-dependent timing signal.
		return exists && expected != "" && passMatch
	}

	return false
}

// constantTimeAPIKeyMatch reports whether presented equals any configured API
// key. It compares presented against EVERY configured key with
// crypto/subtle.ConstantTimeCompare and OR-s the per-key results, never
// short-circuiting on the first match. This closes the timing side channel of
// the previous plain map lookup (`cfg.APIKeys[presented]`), whose latency
// varied with hash-bucket collisions and key presence and could leak whether a
// submitted token/prefix was valid to a network-timing attacker on an
// interface-bound API (#4157).
//
// ConstantTimeCompare returns 0 immediately when the two byte slices differ in
// length; that reveals only length, not content, which is acceptable here. The
// loop count is the number of configured keys — a deployment constant, not
// attacker-controllable per request — so it does not leak the secret. Not
// short-circuiting means WHICH key matched is not leaked by timing either.
func constantTimeAPIKeyMatch(cfg AuthConfig, presented string) bool {
	presentedBytes := []byte(presented)
	match := 0
	for key, valid := range cfg.APIKeys {
		// #5636: never match an EMPTY configured api-key. An empty api-key is
		// not a valid credential — matching it would authenticate a request
		// presenting an empty Bearer / X-API-Key token. The skip is keyed only
		// on the configured key set (a deployment constant), so it does not add
		// a request-dependent timing signal (#4157).
		if !valid || key == "" {
			continue
		}
		match |= subtle.ConstantTimeCompare(presentedBytes, []byte(key))
	}
	return match == 1
}

// isLoopbackBindAddr reports whether the API listen address binds only the
// loopback interface (#4162). It parses host:port and returns true only for a
// literal loopback IP (127.0.0.0/8 or ::1). Anything else — a routable IP, the
// wildcard bind (":8080" / "0.0.0.0" / "::"), an empty/unparseable host, or a
// hostname — is treated as NON-loopback (returns false), the conservative
// default: when in doubt, gate /metrics behind auth rather than expose it.
func isLoopbackBindAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port (e.g. a bare host). Try the whole string as an IP.
		host = addr
	}
	if host == "" {
		// Wildcard bind (":8080") — listens on all interfaces.
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname or malformed address — cannot prove it is loopback.
		return false
	}
	return ip.IsLoopback()
}
