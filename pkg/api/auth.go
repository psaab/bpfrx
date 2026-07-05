package api

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// AuthConfig holds authentication credentials for the API middleware.
type AuthConfig struct {
	Users   map[string]string // username -> password
	APIKeys map[string]bool   // valid API key tokens
}

// authMiddleware wraps an http.Handler with Basic Auth / Bearer / X-API-Key checks.
// Requests to /health and /metrics bypass authentication.
func authMiddleware(cfg AuthConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
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
		return exists && passMatch
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
		if !valid {
			continue
		}
		match |= subtle.ConstantTimeCompare(presentedBytes, []byte(key))
	}
	return match == 1
}
