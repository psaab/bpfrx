package config

import (
	"strings"
	"testing"
)

// sentinel6609 is the credential every case below plants. It is deliberately
// one distinctive token so an assertion can be "the output does not contain
// this", which is the only assertion shape that cannot be satisfied by a
// partial redaction that happens to look tidy.
const sentinel6609 = "s3cr3t-PASSWORD"

// TestRedactURLCredentialSlots_6609 is the fail-on-revert gate for the three
// slots RedactURL did not cover.
//
// The sentinel MUST sit in the slot under test. A userinfo sentinel inside a
// scheme'd URL passes even when all three bugs are present, so a corpus that
// only varied the URL while keeping the credential in one place would report
// success against the unfixed function.
func TestRedactURLCredentialSlots_6609(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		why  string
	}{
		{
			name: "missing @ puts the credential in the host:port slot",
			in:   "http://user:" + sentinel6609 + ".example/",
			why: "the commonest credentialed typo. There is no '@' in the authority, so a " +
				"purely userinfo-based redactor returns the input unchanged",
		},
		{
			name: "scheme-relative URL userinfo",
			in:   "//user:" + sentinel6609 + "@host/",
			why: "authority detection started at index 0, where the first character is the " +
				"'/' that terminates the authority scan, so the authority came out EMPTY",
		},
		{
			name: "fragment with no query",
			in:   "https://host/callback#access_token=" + sentinel6609,
			why: "the fragment was never redacted; it was only ever dropped as a side effect " +
				"of the query rule truncating the whole tail",
		},
		{
			name: "credential in BOTH userinfo and host:port slot",
			in:   "http://" + sentinel6609 + ":" + sentinel6609 + ".example/",
			why:  "neither half may survive",
		},
		{
			name: "scheme-relative with a fragment",
			in:   "//host/x#tok=" + sentinel6609,
			why:  "the two fixes must compose",
		},
		{
			name: "unterminated IPv6 literal hiding a credential",
			in:   "http://[" + sentinel6609 + "/",
			why:  "an unterminated bracket cannot be a host, so nothing in it may be printed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURL(tc.in)
			if strings.Contains(got, sentinel6609) {
				t.Fatalf("RedactURL(%q) = %q — the credential survived.\nwhy this slot: %s",
					tc.in, got, tc.why)
			}
		})
	}
}

// TestRedactURLDoesNotOverRedact_6609 is the over-reach guard. A redactor that
// returns "<redacted>" for everything would pass the test above completely, so
// these cases pin what must still be legible — a log line that names no host is
// close to useless for diagnosing a DDNS provider outage.
func TestRedactURLDoesNotOverRedact_6609(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantContains string
	}{
		{"plain host", "https://api.example/update", "api.example"},
		{"host with a real port", "https://api.example:8443/update", "api.example:8443"},
		{"bracketed IPv6 literal", "https://[2001:db8::1]/update", "[2001:db8::1]"},
		{"bracketed IPv6 with port", "https://[2001:db8::1]:8443/update", "[2001:db8::1]:8443"},
		{"empty port is syntactically valid", "https://api.example:/update", "api.example:"},
		{"host survives userinfo redaction", "https://user:pw@api.example/update", "api.example"},
		{"inadyn template specifier host", "https://%h/update", "%h"},
		{"path is preserved", "https://api.example/nic/update", "/nic/update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactURL(tc.in); !strings.Contains(got, tc.wantContains) {
				t.Fatalf("RedactURL(%q) = %q, want it to still contain %q — over-redaction "+
					"destroys the diagnostic value the function exists to preserve",
					tc.in, got, tc.wantContains)
			}
		})
	}
}

// TestRedactURLPreexistingBehaviour_6609 pins the contract that predates this
// change, so the new host:port rule cannot quietly alter it.
func TestRedactURLPreexistingBehaviour_6609(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"empty stays empty", "", ""},
		{"scheme'd userinfo", "https://user:pw@host/?q=1", "https://<redacted>@host/?<redacted>"},
		{"schemeless userinfo (#5458)", "user:pw@host/", "<redacted>@host/"},
		{"query dropped wholesale (#2781)", "https://host/u?token=x&h=%h", "https://host/u?<redacted>"},
		{"@ in the path is not userinfo", "https://host/p@th", "https://host/p@th"},
		{"query redaction swallows a trailing fragment", "https://host/?a=1#t=x", "https://host/?<redacted>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactURL(tc.in); got != tc.want {
				t.Fatalf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestURLHostPortPlausible_6609 covers the predicate directly. The scenario
// tests above cannot distinguish "this host was rejected for the right reason"
// from "the whole authority happened to be redacted", and an over-broad
// predicate silently degrades every well-formed log line.
func TestURLHostPortPlausible_6609(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"", true},                       // empty authority is not a leak
		{"host", true},                   // no port separator
		{"host:8080", true},              // ordinary port
		{"host:", true},                  // empty port — url.Parse accepts it
		{"[::1]", true},                  // bare IPv6 literal
		{"[::1]:8080", true},             // IPv6 literal with port
		{"::1", true},                    // unbracketed v6: last colon suffix is digits
		{"user:PASSWORD.example", false}, // the missing-@ typo
		{"host:notaport", false},         // non-numeric port
		{"[::1", false},                  // unterminated literal
		{"[::1]junk", false},             // junk after the literal
	} {
		if got := urlHostPortPlausible(tc.host); got != tc.want {
			t.Fatalf("urlHostPortPlausible(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestURLAuthorityStart_6609 covers the scheme-separator rule. RFC 3986 forbids
// '/', '?' and '#' in a scheme, so a "://" inside a path or query is not a
// scheme separator — taking it as one pointed the authority window into the
// query.
func TestURLAuthorityStart_6609(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"https://host/x", 8},
		{"//host/x", 2},          // scheme-relative
		{"user:pw@host/x", 0},    // schemeless template (#5458)
		{"/p?u=http://a@b", 0},   // a late "://" is NOT a scheme separator
		{"host/p?u=http://a", 0}, // ditto, with no leading slash
	} {
		if got := urlAuthorityStart(tc.in); got != tc.want {
			t.Fatalf("urlAuthorityStart(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
