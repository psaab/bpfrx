package config

import (
	"strings"
	"testing"
)

// TestDDNSProviderStringRedactsURLCredentials is the #2781 fail-on-revert
// guard: DDNSProvider.String() (used by %v/%s/slog) must never leak a
// credential embedded in a URL field. The generic backend supports a token in
// the URL template (userinfo or query string) and a checkip-url can carry an
// API key — both are plain (non-Secret) strings printed verbatim before #2781.
//
// If RedactURL is removed from String() (revert), the secret substrings reappear
// and this test goes RED.
func TestDDNSProviderStringRedactsURLCredentials(t *testing.T) {
	const (
		queryToken = "QUERY-TOKEN-1a2b3c"
		userinfoPw = "USERINFO-PASS-9z8y7x"
		checkipKey = "CHECKIP-APIKEY-deadbeef"
		serverPw   = "SERVER-PASS-c0ffee"
	)
	p := &DDNSProvider{
		Name:    "leaky",
		Backend: "generic",
		// Token in the query string — the canonical #2781 leak.
		URLTemplate: "https://api.example.net/update?token=" + queryToken + "&host=%h&ip=%i",
		// Userinfo credentials in the server URL.
		Server: "https://user:" + serverPw + "@dyndns.example.net",
		// API key in the checkip endpoint.
		CheckIPURL: "https://checkip.example.net/?apikey=" + checkipKey,
	}

	s := p.String()

	for _, secret := range []string{queryToken, userinfoPw, checkipKey, serverPw} {
		if strings.Contains(s, secret) {
			t.Fatalf("DDNSProvider.String() leaked a URL credential %q: %s", secret, s)
		}
	}
	// A redaction marker must be present — proves redaction fired rather than the
	// fields simply being empty.
	if !strings.Contains(s, "<redacted>") {
		t.Fatalf("DDNSProvider.String() produced no redaction marker: %s", s)
	}
	// The non-sensitive scheme/host/path prefix must survive for diagnostics.
	if !strings.Contains(s, "https://api.example.net/update?") {
		t.Fatalf("DDNSProvider.String() dropped the url-template host/path: %s", s)
	}
	if !strings.Contains(s, "@dyndns.example.net") {
		t.Fatalf("DDNSProvider.String() dropped the server host after userinfo redaction: %s", s)
	}
}

// TestRedactURL exercises RedactURL directly across the shapes #2781 cares
// about: userinfo, query token, both, a plain hostname (rfc2136 update-server),
// an inadyn template with %-specifiers (must not be mangled by url.Parse), and
// empty input.
func TestRedactURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// mustContain / mustNotContain are substring assertions on the result.
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "query token",
			in:             "https://api.example/update?token=SECRET&host=%h",
			mustContain:    []string{"https://api.example/update?", "<redacted>"},
			mustNotContain: []string{"SECRET", "token=", "%h"},
		},
		{
			name:           "userinfo password",
			in:             "https://bob:HUNTER2@dyn.example/path",
			mustContain:    []string{"https://<redacted>@dyn.example/path"},
			mustNotContain: []string{"HUNTER2", "bob:"},
		},
		{
			name:           "userinfo and query",
			in:             "http://bob:HUNTER2@dyn.example/p?key=K3Y",
			mustContain:    []string{"http://<redacted>@dyn.example/p?", "<redacted>"},
			mustNotContain: []string{"HUNTER2", "K3Y", "bob:", "key="},
		},
		{
			name:        "plain host:port (rfc2136 update-server)",
			in:          "ns.example.com:53",
			mustContain: []string{"ns.example.com:53"},
		},
		{
			name:           "inadyn template no creds still drops query",
			in:             "https://svc.example/nic/update?hostname=%h&myip=%i",
			mustContain:    []string{"https://svc.example/nic/update?", "<redacted>"},
			mustNotContain: []string{"hostname=", "%h", "%i"},
		},
		{
			name: "empty",
			in:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURL(tc.in)
			if tc.in == "" && got != "" {
				t.Fatalf("RedactURL(%q) = %q, want empty", tc.in, got)
			}
			for _, sub := range tc.mustContain {
				if !strings.Contains(got, sub) {
					t.Errorf("RedactURL(%q) = %q, want to contain %q", tc.in, got, sub)
				}
			}
			for _, sub := range tc.mustNotContain {
				if strings.Contains(got, sub) {
					t.Errorf("RedactURL(%q) = %q, must NOT contain %q", tc.in, got, sub)
				}
			}
		})
	}
}
