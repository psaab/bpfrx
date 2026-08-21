// #5866: the management server's authentication snapshot must be swappable on a
// day-2 commit WITHOUT a listener bounce or daemon restart — a revoked or
// tightened credential is rejected on the very NEXT request. The middleware
// reads s.auth atomically per request; ReplaceAuth swaps it.
//
// FAIL-ON-REVERT: if the middleware captured the auth snapshot statically at
// construction (the pre-#5866 closure over cfg.Auth) instead of reading s.auth
// per request, ReplaceAuth would have no effect and the revoked credential would
// still authenticate — this test goes RED.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerReplaceAuthLiveSwap_5866(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	s := &Server{}
	s.auth.Store(&AuthConfig{Users: map[string]string{"admin": "secret"}})
	// metricsRequireAuth=true models a non-loopback listener (the interesting,
	// security-relevant case).
	h := s.dynamicAuthMiddleware(true, s.newAuthSlot(), ok)

	req := func(user, pass string) int {
		r := httptest.NewRequest("GET", "/api/v1/thing", nil)
		r.SetBasicAuth(user, pass)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Baseline: the configured credential authenticates.
	if code := req("admin", "secret"); code != http.StatusOK {
		t.Fatalf("valid credential before swap = %d, want 200", code)
	}

	// Day-2 REVOKE: swap to a snapshot that no longer contains admin.
	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"newadmin": "newpass"}})

	if code := req("admin", "secret"); code != http.StatusUnauthorized {
		t.Fatalf("REVOKED credential after ReplaceAuth = %d, want 401 — the auth snapshot did not "+
			"take effect without a restart (#5866)", code)
	}
	if code := req("newadmin", "newpass"); code != http.StatusOK {
		t.Fatalf("newly-added credential after ReplaceAuth = %d, want 200", code)
	}

	// /health stays exempt across swaps.
	rh := httptest.NewRequest("GET", "/health", nil)
	wh := httptest.NewRecorder()
	h.ServeHTTP(wh, rh)
	if wh.Code != http.StatusOK {
		t.Fatalf("/health must remain auth-exempt, got %d", wh.Code)
	}

	// Disable auth entirely (loopback-only path) -> requests pass through.
	s.ReplaceAuth(nil)
	if code := req("nobody", "nothing"); code != http.StatusOK {
		t.Fatalf("auth disabled after ReplaceAuth(nil) = %d, want 200 (pass through)", code)
	}
}
