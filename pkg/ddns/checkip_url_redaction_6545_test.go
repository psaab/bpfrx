package ddns

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// checkip_url_redaction_6545_test.go: a MALFORMED checkip-url must not put its
// credential in the refusal error (#6545 review, security MINOR).
//
// #6545 made CheckIP/CheckIPBound RETURN the reason a probe failed so a
// permanently misconfigured checkip-url stops masquerading as a transient miss.
// The daemon observer then logs that reason (slog.Warn "err", cerr) AND uses its
// text as the checkIPProbeWarned dedup map key. validateCheckIPURL built those
// errors with the RAW url, so the new operator-visible signal wrote a
// query-string API key into journald in cleartext:
//
//	ddns checkip: url "ftp://checkip.example/?apikey=SECRET" must be http(s)
//
// A checkip endpoint with a per-account API key in its query is ordinary
// (ipify, ip-api, and the whole "what is my IP" API tier all offer one), and the
// key is exactly the kind of credential this package redacts everywhere else —
// backend_generic.go runs url-template through config.RedactURL, doRequest runs
// transport errors through scrubURLError. The checkip validator was the hole.
//
// checkIPCredential is the sentinel every case below plants in the position an
// operator's key actually occupies. It is deliberately not a substring of any
// host or scheme in these URLs, so a hit is unambiguous evidence of a leak.
const checkIPCredential = "CHECKIP-SECRET-MUST-NOT-LOG"

// malformedCredentialedURLs covers ALL THREE validateCheckIPURL refusal
// branches with a credential attached, plus the userinfo shape. A fix that
// redacts only the branch Codex quoted would stay RED on the others.
var malformedCredentialedURLs = []struct {
	name string
	url  string
	// want is a fragment the message must STILL carry, so a "redaction" that
	// simply drops the URL (and the operator's ability to tell which provider
	// leaf is wrong) does not pass this test either.
	want string
}{
	{
		name: "bad scheme, credential in query",
		url:  "ftp://checkip.example/?apikey=" + checkIPCredential,
		want: "checkip.example",
	},
	{
		name: "no host, credential in query",
		url:  "http://?apikey=" + checkIPCredential,
		want: "has no host",
	},
	{
		name: "unparseable, credential in query",
		// An unterminated IPv6 literal: url.Parse FAILS here, so the error is
		// the *url.Error whose Error() re-embeds the whole raw input. This is
		// the case a naive "RedactURL(u) + %w" fix still leaks through.
		url:  "http://[::1/?apikey=" + checkIPCredential,
		want: "is not a valid URL",
	},
	{
		name: "bad scheme, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@checkip.example/",
		want: "checkip.example",
	},
	{
		name: "unparseable, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@[::1/",
		want: "is not a valid URL",
	},
}

// TestValidateCheckIPURLRedactsCredentials is the fail-on-revert gate: restore
// the raw %q/%w in validateCheckIPURL and every case here fails by assertion,
// naming the leaked sentinel.
func TestValidateCheckIPURLRedactsCredentials(t *testing.T) {
	for _, tc := range malformedCredentialedURLs {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCheckIPURL(tc.url)
			if err == nil {
				t.Fatalf("validateCheckIPURL(%q) = nil; this URL is malformed and must be "+
					"refused — the redaction assertions below would be vacuous", tc.url)
			}
			if got := err.Error(); strings.Contains(got, checkIPCredential) {
				t.Fatalf("validateCheckIPURL leaked the checkip-url credential into its error:\n"+
					"  error    = %q\n"+
					"  contains = %q\n"+
					"This error is logged by the Surface A observer (slog.Warn \"err\", cerr) and "+
					"is retained as the checkIPProbeWarned dedup map key, so the operator's API "+
					"key lands in journald in cleartext. Render the URL through config.RedactURL "+
					"and do not %%w-wrap url.Parse's error (it re-embeds the raw input).",
					got, checkIPCredential)
			}
			if got := err.Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("validateCheckIPURL(%q) = %q, want it to still contain %q; the "+
					"redaction must strip the credential, not the diagnostic", tc.url, got, tc.want)
			}
		})
	}
}

// TestCheckIPMalformedURLErrorRedactsCredentials proves the redaction survives
// the path the DAEMON actually takes. validateCheckIPURL is unexported; what
// reaches the log is CheckIP's third return, so assert on that end to end.
func TestCheckIPMalformedURLErrorRedactsCredentials(t *testing.T) {
	// A transport that fails loudly if it is ever reached: every URL here must
	// be refused BEFORE any request is issued.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("a malformed checkip-url reached the transport (%q); the validator must "+
			"fail closed before any request", r.URL.String())
		return nil, nil
	})}

	for _, tc := range malformedCredentialedURLs {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := CheckIP(context.Background(), client, tc.url, true, nil)
			if ok {
				t.Fatalf("CheckIP(%q) ok=true; a malformed checkip-url must fail closed", tc.url)
			}
			if err == nil {
				t.Fatalf("CheckIP(%q) err=nil; #6545 requires the refusal to be reportable", tc.url)
			}
			if got := err.Error(); strings.Contains(got, checkIPCredential) {
				t.Fatalf("CheckIP returned an error carrying the checkip-url credential:\n"+
					"  error    = %q\n"+
					"  contains = %q\n"+
					"The daemon logs this string verbatim and keys its dedup map on it.",
					got, checkIPCredential)
			}
		})
	}
}

// TestCheckIPValidURLStillAccepted is the over-reach guard for the redaction:
// the validator must keep ACCEPTING a well-formed credentialed checkip-url. A
// "fix" that redacted the URL before parsing it (RedactURL turns a query into
// the literal "<redacted>") would refuse every checkip endpoint that carries an
// API key — turning a log-hygiene bug into a total outage of the feature.
func TestCheckIPValidURLStillAccepted(t *testing.T) {
	for _, good := range []string{
		"https://checkip.example/?apikey=" + checkIPCredential,
		"https://user:" + checkIPCredential + "@checkip.example/",
		"HTTPS://checkip.example/?apikey=" + checkIPCredential,
	} {
		if err := validateCheckIPURL(good); err != nil {
			t.Fatalf("validateCheckIPURL(%q) = %v, want nil; a credentialed but VALID "+
				"checkip-url must still be accepted", good, err)
		}
	}
}
