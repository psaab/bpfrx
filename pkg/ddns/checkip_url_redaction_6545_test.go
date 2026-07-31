package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
		want: "missing ']' in host",
	},
	{
		name: "bad scheme, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@checkip.example/",
		want: "checkip.example",
	},
	{
		name: "unparseable, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@[::1/",
		want: "missing ']' in host",
	},
	// The cases below put the sentinel INSIDE the malformed portion itself.
	// Everything above leaves the credential in a well-formed userinfo/query,
	// so a fix that only stopped %w-wrapping would pass those and still leak
	// here. Each `want` is the CLASS-SPECIFIC constant urlParseCause selects,
	// so these also prove the sanitization kept a useful diagnostic instead of
	// collapsing everything to the generic reason.
	{
		name: "unparseable, credential lands in the port (missing @)",
		// The realistic operator typo: a credentialed URL with the '@' left
		// out. net/url reads host "user", port ":<credential>.example", and
		// reports invalid port %q after host — the whole password, unbounded.
		// This case ALSO covers the second surface: RedactURL keys on '@' to
		// find userinfo, so with the '@' missing it returns the string
		// unchanged and the display half leaks even with the cause sanitized.
		url:  "http://user:" + checkIPCredential + ".example/",
		want: "invalid port after host",
	},
	{
		name: "unparseable, credential in an IP-literal host",
		// invalid host: ParseAddr("<raw host>") — also unbounded. RedactURL
		// deliberately preserves hosts, so this too is only safe because the
		// URL is omitted outright from the parse-failure branch.
		url:  "http://user:pass@[" + checkIPCredential + "]/",
		want: "invalid host",
	},
	{
		name: "unparseable, credential begins with a bad percent-escape",
		// url.EscapeError quotes 3 bytes of input; bounded, but still input.
		url:  "http://user:%" + checkIPCredential + "@checkip.example/",
		want: "invalid percent-escape",
	},
}

// TestValidateCheckIPURLOmitsUnparseableURL pins the structural rule the cases
// above rely on: when url.Parse FAILS there is no authority to bound and no
// structure to trust, so NO part of the input may appear in the message —
// RedactURL is only sound on a string that actually parsed. Asserting on a
// benign, highly legible host keeps this independent of any credential
// sentinel: if the host survives, so would a password in the same position.
func TestValidateCheckIPURLOmitsUnparseableURL(t *testing.T) {
	const host = "checkip.example"
	// Parse-FAILING inputs whose host is plainly legible in the raw string.
	for _, bad := range []string{
		"http://user:pw." + host + ":notaport/",
		"http://" + host + ":notaport/",
		"http://[" + host + "]/",
		"http://%zz@" + host + "/",
	} {
		if _, perr := url.Parse(bad); perr == nil {
			t.Fatalf("%q parses cleanly; this case cannot exercise the parse-failure "+
				"branch and the assertion below would be vacuous", bad)
		}
		err := validateCheckIPURL(bad)
		if err == nil {
			t.Fatalf("validateCheckIPURL(%q) = nil, want a refusal", bad)
		}
		if strings.Contains(err.Error(), host) {
			t.Errorf("validateCheckIPURL(%q) = %q: the parse-failure branch echoed part of "+
				"an unparseable input. RedactURL cannot be trusted here — it is "+
				"authority-bounded and keys on '@', so a missing-'@' credential typo passes "+
				"through it verbatim. Omit the URL entirely on a parse failure.", bad, err)
		}
	}
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

// TestURLParseCauseAlwaysReturnsAConstant is the structural gate under the
// case table above: urlParseCause must return one of a CLOSED set of
// compile-time literals, whatever it is handed. That property — not the
// particular net/url causes enumerated today — is what makes the helper safe to
// reuse (the other DDNS URL validators inherit it, #6606), and it is what a
// stdlib rewording or a brand-new cause must not be able to break: an
// unrecognized cause has to fail CLOSED to "malformed URL", never pass through.
//
// The corpus plants the sentinel in every position that can end up inside a
// parse failure, including the ones RedactURL cannot reach.
func TestURLParseCauseAlwaysReturnsAConstant(t *testing.T) {
	allowed := map[string]bool{
		causeMalformedURL: true,
		causeInvalidPort:  true,
		causeInvalidHost:  true,
		causeBadEscape:    true,
		causeBadHostChar:  true,
	}
	for _, c := range urlParseSafeCauses {
		allowed[c] = true
	}

	corpus := []string{
		// Sentinel inside the malformed token.
		"http://user:" + checkIPCredential + ".example/",
		"http://checkip.example:" + checkIPCredential + "/",
		"http://user:pass@[" + checkIPCredential + "]/",
		"http://%" + checkIPCredential + "@h/",
		"http://h/p%" + checkIPCredential,
		"http://h/#%" + checkIPCredential,
		"http://h\x7f" + checkIPCredential + "/",
		"http://[::1/?apikey=" + checkIPCredential,
		"http://user:" + checkIPCredential + "@[::1/",
		// Sentinel elsewhere, still a parse failure.
		"ht tp://x/?apikey=" + checkIPCredential,
		"://nohost/?apikey=" + checkIPCredential,
		// Degenerate inputs.
		"", "%", ":", "//", "http://[", string([]byte{0x00}),
	}
	for _, in := range corpus {
		_, err := url.Parse(in)
		if err == nil {
			continue // parses fine; urlParseCause is never consulted
		}
		got := urlParseCause(err)
		if !allowed[got] {
			t.Errorf("urlParseCause for input %q returned %q, which is NOT one of the "+
				"declared constants; the helper must never return a string derived from "+
				"its input", in, got)
		}
		if strings.Contains(got, checkIPCredential) {
			t.Errorf("urlParseCause leaked the credential for input %q: %q", in, got)
		}
	}

	// A non-*url.Error must fail closed rather than render its own text.
	if got := urlParseCause(errors.New("boom " + checkIPCredential)); got != causeMalformedURL {
		t.Errorf("urlParseCause(non-url.Error) = %q, want %q; an unaudited error must fail "+
			"closed to the fixed reason, not be passed through", got, causeMalformedURL)
	}
}

// TestCheckIPValidURLStillAccepted is the over-reach guard for the redaction:
// the validator must keep ACCEPTING a well-formed credentialed checkip-url. A
// "fix" that redacted the URL before parsing it would refuse every checkip
// endpoint that carries an API key — turning a log-hygiene bug into a total
// outage of the feature.
//
// The USERINFO cases are what make this a real guard: RedactURL renders userinfo
// as "<redacted>@", and url.Parse REJECTS that with "net/url: invalid userinfo"
// (verified against Go 1.26.4), so parsing the redacted value fails loudly. A
// query-only case would be vacuous — RedactURL renders a query as "?<redacted>"
// and url.Parse accepts that as an ordinary raw query — so the query cases below
// are coverage of the accept path, NOT of the redact-before-parse mistake.
func TestCheckIPValidURLStillAccepted(t *testing.T) {
	for _, good := range []string{
		"https://checkip.example/?apikey=" + checkIPCredential,
		"https://user:" + checkIPCredential + "@checkip.example/",
		"HTTPS://checkip.example/?apikey=" + checkIPCredential,
		// Userinfo + query together: the shape a redact-before-parse fix
		// mangles most thoroughly.
		"https://user:" + checkIPCredential + "@checkip.example/?apikey=" + checkIPCredential,
	} {
		if err := validateCheckIPURL(good); err != nil {
			t.Fatalf("validateCheckIPURL(%q) = %v, want nil; a credentialed but VALID "+
				"checkip-url must still be accepted", good, err)
		}
	}
}
