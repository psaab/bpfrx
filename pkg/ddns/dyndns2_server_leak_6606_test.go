package ddns

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// sentinel6606 is the credential every case plants. One distinctive token so
// the assertion can be "the error does not contain this", which is the only
// shape a partial redaction cannot satisfy by looking tidy.
const sentinel6606 = "s3cr3t-PASSWORD"

// TestDyndns2ServerNeverLeaksCredential_6606 is the fail-on-revert gate.
//
// resolveDyndns2Endpoint interpolated the raw `server` at FOUR sites — the
// issue named two, and its own review comment warned that fixing only the cited
// ones leaves the other half open, so every site is exercised here.
//
// Two of the four leaked twice over: `%q` on the raw value echoed any credential
// in it, AND `%w` wrapped url.Parse's error, whose (*url.Error).Error()
// re-embeds the entire raw input. Redacting the %q argument alone would not have
// closed those — the wrapped error reintroduces the raw string.
//
// THE SENTINEL SITS IN THE MALFORMED PORTION on the parse-failure cases, which
// is what the issue's follow-up comment demands: a userinfo or query sentinel
// passes even when the typed inner cause leaks, because net/url's own messages
// embed input (`invalid port %q after host`, `invalid URL escape %q`).
func TestDyndns2ServerNeverLeaksCredential_6606(t *testing.T) {
	for _, tc := range []struct {
		name, server, why string
	}{
		{
			name:   "missing @ puts the credential in the port slot",
			server: "https://user:" + sentinel6606 + ".example/nic/update",
			why: "verified: net/url returns `invalid port \":s3cr3t-PASSWORD.example\" after " +
				"host` — an UNBOUNDED quote of the credential. This is the #6609 host:port " +
				"slot, reached here through the typed inner cause rather than a redactor",
		},
		{
			name:   "credential in the port slot of a well-formed host",
			server: "https://host:" + sentinel6606 + "/nic/update",
			why:    "verified: `invalid port \":s3cr3t-PASSWORD\" after host`, unbounded",
		},
		{
			name:   "credential inside a bracketed IP-literal",
			server: "https://[" + sentinel6606 + "]/nic/update",
			why: "verified: `invalid host: ParseAddr(\"s3cr3t-PASSWORD\"): unable to parse IP` " +
				"— a SECOND unbounded inner cause, so a fix that special-cased only the port " +
				"message would still leak here",
		},
		{
			name:   "credentialed userinfo on a non-http scheme",
			server: "ftp://user:" + sentinel6606 + "@host/nic/update",
			why:    "the scheme branch renders the value after a SUCCESSFUL parse",
		},
		{
			name:   "credentialed userinfo with no host",
			server: "https://user:" + sentinel6606 + "@/nic/update",
			why:    "the hostless branch renders the value after a successful parse",
		},
		{
			name:   "credential in the query of a hostless URL",
			server: "https:///nic/update?token=" + sentinel6606,
			why:    "the hostless branch again, with the credential in the query",
		},
		{
			name:   "bare-host branch: malformed composed URL",
			server: "host:" + sentinel6606,
			why: "the bare-host branch composes https://<server>/nic/update and parses THAT; " +
				"the failure quotes the bad port",
		},
		{
			name:   "bare-host branch: hostless composed URL",
			server: ":8080/x?token=" + sentinel6606,
			why:    "the bare-host branch's hostless arm",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveDyndns2Endpoint(&config.DDNSProvider{Name: "p1", Server: tc.server})
			if err == nil {
				t.Fatalf("expected %q to be rejected; if it is now ACCEPTED the case no longer "+
					"exercises an error render and must be re-chosen", tc.server)
			}
			if strings.Contains(err.Error(), sentinel6606) {
				t.Fatalf("the credential reached the error string.\nserver: %q\nerror:  %v\nwhy this slot: %s",
					tc.server, err, tc.why)
			}
		})
	}
}

// TestDyndns2ServerErrorsStayDiagnostic_6606 is the over-reach guard. An error
// that said only "bad server" would satisfy every assertion above, so these pin
// what must survive: the provider name always, and — on the branches where the
// URL actually PARSED, so config.RedactURL is provably sound — the host.
func TestDyndns2ServerErrorsStayDiagnostic_6606(t *testing.T) {
	for _, tc := range []struct {
		name, server string
		want         []string
	}{
		{
			name:   "wrong scheme keeps provider and host",
			server: "ftp://user:pw@updates.example/nic/update",
			want:   []string{"p1", "updates.example", "http(s)"},
		},
		{
			name:   "hostless keeps provider and names the defect",
			server: "https://user:pw@/nic/update",
			want:   []string{"p1", "has no host"},
		},
		{
			name:   "parse failure keeps provider and a usable cause",
			server: "https://host:notaport/nic/update",
			want:   []string{"p1", "invalid port"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveDyndns2Endpoint(&config.DDNSProvider{Name: "p1", Server: tc.server})
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.server)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %v must still contain %q — an unusable diagnostic is not a fix", err, w)
				}
			}
		})
	}
}

// TestDyndns2ValidServersStillAccepted_6606 is the second over-reach guard: a
// redaction change must not start REJECTING servers that worked, including a
// legitimately credentialed one.
func TestDyndns2ValidServersStillAccepted_6606(t *testing.T) {
	for _, tc := range []struct{ name, server, want string }{
		{"full URL", "https://updates.example/nic/update", "https://updates.example/nic/update"},
		{"credentialed full URL", "https://user:pw@updates.example/nic/update", "https://user:pw@updates.example/nic/update"},
		{"uppercase scheme", "HTTPS://updates.example/nic/update", "HTTPS://updates.example/nic/update"},
		{"bare host", "updates.example", "https://updates.example/nic/update"},
		{"bare host with port", "updates.example:8443", "https://updates.example:8443/nic/update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveDyndns2Endpoint(&config.DDNSProvider{Name: "p1", Server: tc.server})
			if err != nil {
				t.Fatalf("a valid server was rejected: %v", err)
			}
			if got != tc.want {
				t.Fatalf("endpoint = %q, want %q — the returned URL must stay the REAL one; "+
					"only the ERROR text is redacted", got, tc.want)
			}
		})
	}
}
