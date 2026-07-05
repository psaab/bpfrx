package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsLoopbackBindAddr covers the bind classification that decides whether
// /metrics is auth-gated (#4162).
func TestIsLoopbackBindAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.1", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"192.168.1.5:8080", false},
		{"10.0.0.1:8080", false},
		{":8080", false},        // wildcard
		{"0.0.0.0:8080", false}, // all v4
		{"[::]:8080", false},    // all v6
		{"example.com:8080", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLoopbackBindAddr(tc.addr); got != tc.want {
			t.Errorf("isLoopbackBindAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestMetricsAuthGateNonLoopback asserts the #4162 auth posture: on a
// non-loopback bind (metricsRequireAuth=true) /metrics demands credentials,
// while /health stays exempt; on loopback (false) /metrics stays open.
//
// FAIL-ON-REVERT: restoring the unconditional `path == "/metrics"` bypass makes
// the no-credential non-loopback case return 200 instead of 401.
func TestMetricsAuthGateNonLoopback(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))

	cases := []struct {
		name        string
		requireAuth bool
		path        string
		header      map[string]string
		want        int
	}{
		{"loopback metrics open", false, "/metrics", nil, http.StatusOK},
		{"non-loopback metrics no-key blocked", true, "/metrics", nil, http.StatusUnauthorized},
		{"non-loopback metrics with basic ok", true, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK},
		{"non-loopback metrics with api key ok", true, "/metrics", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK},
		{"non-loopback health still open", true, "/health", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := authMiddleware(cfg, tc.requireAuth, next)
			req := httptest.NewRequest("GET", tc.path, nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d", tc.name, w.Code, tc.want)
			}
		})
	}
}
