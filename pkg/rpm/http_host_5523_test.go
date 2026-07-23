package rpm

import (
	"strings"
	"testing"
)

// C179-042 (codex-179): canonicalizeHTTPTarget must reject a hostless target
// ("http://", "https://", a schemeless ":8080") as a probe SETUP failure so a
// dead probe HOLDS the test state, rather than http.NewRequestWithContext
// failing per attempt and the permanent no-run being counted as path loss.
//
// FAIL-ON-REVERT: dropping the u.Hostname()=="" guards makes these accepted.
func TestCanonicalizeHTTPTarget_HostlessRejected_5523(t *testing.T) {
	for _, target := range []string{"http://", "https://", ":8080", "http://:80/health"} {
		t.Run("reject/"+target, func(t *testing.T) {
			if _, err := canonicalizeHTTPTarget(target); err == nil {
				t.Fatalf("hostless target %q accepted; want no-host rejection", target)
			} else if !strings.Contains(err.Error(), "no host") {
				t.Fatalf("target %q err = %v, want substring %q", target, err, "no host")
			}
		})
	}
}

// No scope-creep: valid hosts (bare, host:port, IPv4, scheme'd, bracketed
// IPv6) are accepted, and a bare unbracketed IPv6 — a malformed schemeless
// target url.Parse cannot parse — stays lenient and passes through unchanged
// (handled downstream exactly as before, NOT newly rejected). The fix ADDS
// only the empty-host rejection.
func TestCanonicalizeHTTPTarget_HostAcceptedNoScopeCreep_5523(t *testing.T) {
	ok := map[string]string{
		"server.example.com":       "http://server.example.com",
		"host.example.com:8080":    "http://host.example.com:8080",
		"203.0.113.5":              "http://203.0.113.5",
		"http://host.example.com":  "http://host.example.com",
		"https://h.example.com/hb": "https://h.example.com/hb",
		"[2001:db8::1]:8080":       "http://[2001:db8::1]:8080",
		"http://[2001:db8::1]/h":   "http://[2001:db8::1]/h",
		// bare unbracketed IPv6: url.Parse fails on the canonicalized form, so
		// the schemeless path stays lenient and passes it through unchanged.
		"2001:db8::1": "http://2001:db8::1",
	}
	for target, want := range ok {
		t.Run("ok/"+target, func(t *testing.T) {
			got, err := canonicalizeHTTPTarget(target)
			if err != nil {
				t.Fatalf("target %q must be accepted: %v", target, err)
			}
			if got != want {
				t.Fatalf("canonicalizeHTTPTarget(%q) = %q, want %q", target, got, want)
			}
		})
	}
}
