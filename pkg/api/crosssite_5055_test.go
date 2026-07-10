package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// guardedOK wraps a 200-returning handler in mutationCrossSiteGuard so a test
// can assert whether a given request is passed through (200) or rejected (403).
func guardedOK() http.Handler {
	return mutationCrossSiteGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeOK(w, "mutated")
	}))
}

// TestMutationCrossSiteGuard is the #5055 fail-on-revert guard: a state-changing
// request with cross-site provenance (Sec-Fetch-Site / Origin / form
// content-type) must be rejected 403, while a same-origin browser request and a
// programmatic (curl/CLI) client are passed through. Reverting
// mutationCrossSiteGuard to a pass-through makes the reject cases return 200 →
// RED.
func TestMutationCrossSiteGuard(t *testing.T) {
	const target = "http://127.0.0.1:8080/api/v1/config/set"
	h := guardedOK()

	type hdr struct{ k, v string }
	cases := []struct {
		name    string
		method  string
		headers []hdr
		want    int
	}{
		{
			name:    "cross-site fetch is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Sec-Fetch-Site", "cross-site"}, {"Content-Type", "application/json"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "same-site fetch is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Sec-Fetch-Site", "same-site"}, {"Content-Type", "application/json"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "cross-origin Origin is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Origin", "http://evil.example"}, {"Content-Type", "application/json"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "cross-host Referer is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Referer", "http://evil.example/x"}, {"Content-Type", "application/json"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "urlencoded form content-type is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Content-Type", "application/x-www-form-urlencoded"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "multipart form content-type is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Content-Type", "multipart/form-data; boundary=x"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "text/plain content-type is rejected",
			method:  http.MethodPost,
			headers: []hdr{{"Content-Type", "text/plain"}},
			want:    http.StatusForbidden,
		},
		{
			name:    "same-origin browser request passes",
			method:  http.MethodPost,
			headers: []hdr{{"Sec-Fetch-Site", "same-origin"}, {"Origin", "http://127.0.0.1:8080"}, {"Content-Type", "application/json"}},
			want:    http.StatusOK,
		},
		{
			name:    "user-initiated (Sec-Fetch-Site none) passes",
			method:  http.MethodPost,
			headers: []hdr{{"Sec-Fetch-Site", "none"}, {"Content-Type", "application/json"}},
			want:    http.StatusOK,
		},
		{
			name:    "programmatic json client passes",
			method:  http.MethodPost,
			headers: []hdr{{"Content-Type", "application/json"}},
			want:    http.StatusOK,
		},
		{
			name:    "programmatic empty-body mutation passes",
			method:  http.MethodPost,
			headers: nil,
			want:    http.StatusOK,
		},
		{
			// A GET is a safe method: cross-site headers must NOT cause a reject
			// (read endpoints are not state-changing).
			name:    "safe GET with cross-site headers passes",
			method:  http.MethodGet,
			headers: []hdr{{"Sec-Fetch-Site", "cross-site"}, {"Origin", "http://evil.example"}},
			want:    http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, target, strings.NewReader(`{"input":"x"}`))
			for _, hh := range tc.headers {
				req.Header.Set(hh.k, hh.v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d (body=%s)", tc.name, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestSameHostAs checks the host:port comparison used by the Origin/Referer
// signals, including the fail-closed parse-error case.
func TestSameHostAs(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		want bool
	}{
		{"http://127.0.0.1:8080", "127.0.0.1:8080", true},
		{"https://127.0.0.1:8080", "127.0.0.1:8080", true}, // scheme ignored
		{"http://evil.example", "127.0.0.1:8080", false},
		{"http://127.0.0.1:9090", "127.0.0.1:8080", false}, // port differs
		{"::::not-a-url", "127.0.0.1:8080", false},         // parse/empty-host -> mismatch
		{"", "127.0.0.1:8080", false},
	}
	for _, tc := range cases {
		if got := sameHostAs(tc.raw, tc.host); got != tc.want {
			t.Errorf("sameHostAs(%q,%q) = %v, want %v", tc.raw, tc.host, got, tc.want)
		}
	}
}
