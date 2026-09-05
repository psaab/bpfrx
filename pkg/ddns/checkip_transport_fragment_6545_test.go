package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// checkip_transport_fragment_6545_test.go: a VALID checkip-url must not leak a
// FRAGMENT credential when the probe fails at TRANSPORT (#6545 review, security
// MAJOR).
//
// Everything else in this PR's redaction work guards the VALIDATOR — the paths
// that refuse a malformed checkip-url. Those tests all feed INVALID URLs, which
// are rejected before a request is ever built, so none of them exercises the
// transport path at all. A perfectly VALID checkip-url takes a different route:
// CheckIP accepts it, hands it to doRequest, and doRequest renders any transport
// failure through scrubURLError.
//
// scrubURLError clears RawQuery and User but NOT Fragment, and url.URL.Redacted()
// renders the fragment, so:
//
//	https://checkip.example/path#apikey=SECRET
//	  -> ddns http: request failed: Get "https://checkip.example/path#apikey=SECRET": ...
//
// A fragment carries an auth token exactly as routinely as a query does. The
// daemon then copies that string verbatim into BOTH the process-lifetime
// checkIPProbeWarned dedup key and the journal attribute — the same two
// consumers the validator work was hardened for. This is a SECOND scrubber
// (pkg/ddns.scrubURLError, distinct from config.RedactURL) with the same blind
// spot; the parallel for the other one was FIXED under #6609 (#8942 — this
// line used to defer it as outstanding, which stopped being true once
// config.RedactURL gained its own fragment and scheme-relative handling).

// transportFragmentSentinel sits where an operator's token would, in the
// fragment of an otherwise entirely valid https checkip-url.
const transportFragmentSentinel = "TRANSPORT-FRAGMENT-MUST-NOT-LOG"

// errSyntheticTransport is the injected failure. Its own text is deliberately
// credential-free so any sentinel in the output can only have come from the URL.
var errSyntheticTransport = errors.New("synthetic transport failure")

// TestCheckIPTransportFailureRedactsFragment is the fail-on-revert gate for the
// transport path. Restore the missing Fragment clear in scrubURLError and this
// fails by assertion naming the leaked sentinel.
func TestCheckIPTransportFailureRedactsFragment(t *testing.T) {
	// A URL that is VALID by every validateCheckIPURL rule — https scheme, real
	// host — so it reaches the transport instead of being refused.
	urlStr := "https://checkip.example/path#apikey=" + transportFragmentSentinel
	if err := validateCheckIPURL(urlStr); err != nil {
		t.Fatalf("validateCheckIPURL(%q) = %v; this URL must be ACCEPTED or the test "+
			"never reaches the transport path it exists to cover", urlStr, err)
	}

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSyntheticTransport
	})}

	_, ok, err := CheckIP(context.Background(), client, urlStr, true, nil)
	if ok {
		t.Fatal("a failing transport must not yield an observation")
	}
	if err == nil {
		t.Fatal("a transport failure must be reported (#6545); got err=nil, so the " +
			"assertion below would be vacuous")
	}
	// Not vacuous in the other direction either: the error must really be the
	// transport failure, not something raised earlier.
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("CheckIP err = %q, want the transport-failure error; the test is not "+
			"exercising doRequest/scrubURLError", err)
	}
	if strings.Contains(err.Error(), transportFragmentSentinel) {
		t.Fatalf("a transport failure on a VALID checkip-url leaked the fragment credential:\n"+
			"  error    = %q\n"+
			"  contains = %q\n"+
			"scrubURLError clears RawQuery and User but not Fragment, and Redacted() renders "+
			"it. The daemon copies this string into the checkIPProbeWarned dedup key and the "+
			"journal attribute, so an operator token in the fragment reaches both. Clear "+
			"Fragment alongside RawQuery and User.", err, transportFragmentSentinel)
	}
}

// TestScrubURLErrorClearsFragment pins the fix at the helper doRequest actually
// calls, so every HTTP DDNS backend inherits it — dyndns2, duckdns, cloudflare,
// route53 and generic all route their transport errors through this one
// function, not just the checkip probe.
func TestScrubURLErrorClearsFragment(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"fragment only", "https://prov.example/nic/update#token=" + transportFragmentSentinel},
		{"query and fragment", "https://prov.example/upd?token=" + transportFragmentSentinel +
			"#also=" + transportFragmentSentinel},
		{"userinfo and fragment", "https://user:" + transportFragmentSentinel +
			"@prov.example/upd#t=" + transportFragmentSentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The exact *url.Error shape net/http produces for a transport
			// failure: Op from the method, URL from the request URL (fragment
			// included), Err the transport error.
			got := scrubURLError(&url.Error{Op: "Get", URL: tc.url, Err: errSyntheticTransport})
			if !strings.Contains(got, "prov.example") {
				t.Fatalf("scrubURLError(%q) = %q, want it to still name the host; the scrub "+
					"must remove the credential, not the diagnostic", tc.url, got)
			}
			if strings.Contains(got, transportFragmentSentinel) {
				t.Fatalf("scrubURLError leaked a credential:\n  in  = %q\n  out = %q\n"+
					"userinfo, query AND fragment must all be cleared before rendering.",
					tc.url, got)
			}
		})
	}
}
