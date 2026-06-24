package rpm

import (
	"strings"
	"testing"
)

// TestCanonicalizeHTTPTarget pins the #2495 fix: the http-get target
// canonicalizer must prepend "http://" to every schemeless target —
// including a bare hostname that STARTS WITH 'h' (host.example.com,
// h2.lan), which the old first-char heuristic (`url[0] != 'h'`) wrongly
// assumed was already schemed, leaving a schemeless URL that
// http.NewRequestWithContext rejects before any packet is sent. An
// already-schemed http://... / https://... target is returned unchanged;
// any other scheme (ftp://, gopher://) is rejected.
//
// The "host.example.com" / "h2.lan" cases FAIL against master: the old
// heuristic skips the "http://" prefix for any 'h'-leading target, so
// canonicalization returns the bare host and the probe errors out.
func TestCanonicalizeHTTPTarget(t *testing.T) {
	ok := []struct {
		target string
		want   string
	}{
		// bare host NOT starting with 'h' — worked before and after
		{"server.example.com", "http://server.example.com"},
		// bare host STARTING with 'h' — THE BUG (#2495)
		{"host.example.com", "http://host.example.com"},
		{"h2.lan", "http://h2.lan"},
		// bare host:port — must NOT be mistaken for a scheme
		{"host.example.com:8080", "http://host.example.com:8080"},
		{"server.example.com:443", "http://server.example.com:443"},
		// bare IP literal
		{"203.0.113.5", "http://203.0.113.5"},
		// already schemed — returned unchanged
		{"http://host.example.com", "http://host.example.com"},
		{"https://h.example.com/health", "https://h.example.com/health"},
		{"http://server.example.com:8080/x", "http://server.example.com:8080/x"},
	}
	for _, tc := range ok {
		t.Run("ok/"+tc.target, func(t *testing.T) {
			got, err := canonicalizeHTTPTarget(tc.target)
			if err != nil {
				t.Fatalf("canonicalizeHTTPTarget(%q) unexpected error: %v", tc.target, err)
			}
			if got != tc.want {
				t.Fatalf("canonicalizeHTTPTarget(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}

	bad := []struct {
		target string
		substr string
	}{
		{"", "no target"},
		{"ftp://host.example.com", "unsupported"},
		{"gopher://h.example.com", "unsupported"},
	}
	for _, tc := range bad {
		t.Run("bad/"+tc.target, func(t *testing.T) {
			_, err := canonicalizeHTTPTarget(tc.target)
			if err == nil {
				t.Fatalf("canonicalizeHTTPTarget(%q) = nil error, want rejection", tc.target)
			}
			if !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("canonicalizeHTTPTarget(%q) err = %v, want substring %q", tc.target, err, tc.substr)
			}
		})
	}
}
