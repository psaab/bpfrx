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
			if cfg.APIKeys[key] {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="bpfrx API"`)
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
		return cfg.APIKeys[token]
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
		expected, exists := cfg.Users[user]
		if !exists {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
	}

	return false
}
