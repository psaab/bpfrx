package ddns

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// provider_response_text_6634_test.go: #6634. Four backends rendered text taken
// from the PROVIDER'S HTTP RESPONSE BODY straight into a returned error the
// daemon logs and retains as the provider's lastErr. The provider is the
// untrusted party: no hostile transport is needed, only an API that answers
// "your request was invalid: <the request>" and echoes our own update URL back.
// DuckDNS makes that concrete — its token travels in the QUERY STRING, so the
// echo IS the credential.
//
// EVERY CELL DRIVES THE REAL BACKEND THROUGH A REAL httptest SERVER. That is
// deliberate: a unit test on the scrubber alone would pass whether or not any
// backend called it, and "the credential is absent" is satisfied just as well by
// an input that never reached the function. Each cell therefore asserts the
// request was actually SERVED, that the returned error is non-nil, and that the
// message still carries the provider's ordinary prose — before asserting the
// credential is gone.
//
// WHAT IS ACTUALLY BEING FIXED, since two thirds of this issue's surface turned
// out to be closed already and the tests should not claim otherwise:
//
//   - control-character forgery at the TERMINAL is closed by
//     termsafe.SanitizeForDisplay on both `show services ddns` surfaces (#6468);
//   - control characters in the JOURNAL are closed by slog's TextHandler, which
//     strconv.Quote-s any value carrying a byte outside printable ASCII;
//   - what NEITHER closes is a CREDENTIAL in the bytes, or 64 KiB of them
//     (httpMaxResponseBody), logged on every reconcile tick of a persistent
//     failure and retained in lastErr.
//
// So the assertions here are about the credential and the bound, not escaping.

const (
	// providerEchoURL is the shape a credential arrives in when a provider
	// echoes our own request back. The sentinel is inside the userinfo.
	providerEchoSecret = "S3CR3T-PROVIDER-6634"
	providerEchoURL    = "https://user:" + providerEchoSecret + "@prov.example/update?token=" +
		providerEchoSecret

	// providerProse is ordinary, useful provider text. The negative controls
	// require it to SURVIVE — a fix that withheld everything would pass every
	// leak assertion above and destroy the one diagnostic an operator gets.
	providerProse = "zone not found for this token"
)

// hostileBody is a provider response whose error text echoes our credentialed
// request URL back, wrapped in prose exactly as a real API would.
func hostileBody(shape string) string {
	return strings.Replace(shape, "%ECHO%", providerProse+": "+providerEchoURL, 1)
}

// serveOnce answers every request with the given status + body and records that
// it was reached, so a cell cannot pass because nothing was requested.
type recordingProvider struct {
	served int
	status int
	body   string
	srv    *httptest.Server
}

func newRecordingProvider(t *testing.T, status int, body string) *recordingProvider {
	t.Helper()
	p := &recordingProvider{status: status, body: body}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.served++
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func testRec() LeaseDNSRecord {
	return LeaseDNSRecord{
		FQDN:        "wan.example.net",
		Addr:        netip.MustParseAddr("203.0.113.7"),
		ForwardType: "A",
		TTL:         60,
	}
}

// ---------------------------------------------------------------------------
// The four render sites, each driven end to end.
// ---------------------------------------------------------------------------

func TestProviderResponseTextDoesNotLeakCredential_6634(t *testing.T) {
	echo := providerProse + ": " + providerEchoURL

	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + echo + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "cloudflare_decode_error",
			status: http.StatusOK,
			// Not JSON at all: the decoder quotes the offending input back.
			body: echo,
			run:  runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + echo + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   echo,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   echo,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)

			// NON-VACUITY. The request must actually have been served and the
			// operation must actually have failed; otherwise "the sentinel is
			// absent" is true for the wrong reason.
			if p.served == 0 {
				t.Fatal("the fake provider was never reached; this cell must drive the REAL " +
					"backend through a round trip, not assert on a helper in isolation")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error; got nil, so " +
					"every assertion below would be vacuous")
			}
			msg := err.Error()

			// THE LEAK.
			if strings.Contains(msg, providerEchoSecret) {
				t.Errorf("provider-supplied response text carried the credential into the "+
					"returned error:\n  error = %s\n"+
					"This error is logged by the daemon and retained as the provider's "+
					"lastErr. Render provider-chosen text through scrubProviderText.", msg)
			}
			// WHAT IT BECAME. Absence alone would also be satisfied by an empty
			// error, by a typo in the sentinel, or by a body that never reached
			// the render site.
			if !strings.Contains(msg, providerURLWithheld) &&
				!strings.Contains(msg, string(transportWithheld)) {
				t.Errorf("the URL-shaped token must be REPLACED by a marker (%q), or the whole "+
					"text withheld (%q) on the decode path — not merely absent; got:\n  %s",
					providerURLWithheld, string(transportWithheld), msg)
			}
			// The message must stay attributable.
			if !strings.Contains(msg, "ddns ") {
				t.Errorf("the error must still name the backend; got:\n  %s", msg)
			}
		})
	}
}

// TestProviderResponseTextKeepsOrdinaryProse_6634 is the NEGATIVE CONTROL the
// issue asks for, and it is the half that stops this fix from being blanket
// suppression. "token invalid" / "zone not found" / "rate limited" is the single
// most useful thing an operator gets out of a failing provider; a fix that
// withheld it would satisfy every leak assertion above and be a regression.
func TestProviderResponseTextKeepsOrdinaryProse_6634(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + providerProse + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + providerProse + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   providerProse,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   providerProse,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)
			if p.served == 0 {
				t.Fatal("the fake provider was never reached")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error")
			}
			if msg := err.Error(); !strings.Contains(msg, providerProse) {
				t.Errorf("ordinary provider prose must SURVIVE — it is the diagnostic the "+
					"operator is reading. Withholding it wholesale passes every leak test and "+
					"is a regression.\n  want to contain: %q\n  got: %s", providerProse, msg)
			}
		})
	}
}

// TestProviderResponseTextIsBounded_6634 pins the half of this fix that IS a
// proof. readCappedBody admits httpMaxResponseBody (64 KiB), and every byte of a
// provider-chosen message was reaching a journal line on every reconcile tick of
// a persistent failure, plus the retained lastErr. The bound is on the RENDER,
// so it holds whatever the provider sends.
func TestProviderResponseTextIsBounded_6634(t *testing.T) {
	// A single enormous whitespace-free token, so nothing but the cap can
	// shorten it, and one that is NOT URL-shaped, so it is not withheld for a
	// different reason and the cell keeps testing the bound.
	//
	// SIZED TO FIT UNDER readCappedBody, deliberately. A message at
	// httpMaxResponseBody makes the enclosing JSON/XML document itself exceed
	// the read cap, so the body arrives truncated, the decode fails, and the
	// cell never reaches the render site it exists to test — a green that
	// measures nothing. 8 KiB is 40x the render bound and comfortably inside the
	// 64 KiB read cap, so the ONLY thing that can shorten it is this fix. The
	// read cap is a real second layer, but it bounds the BODY at 64 KiB, which
	// is three orders of magnitude past what belongs in a log line.
	huge := strings.Repeat("A", 8<<10)

	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + huge + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + huge + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   huge,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   huge,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)
			if p.served == 0 {
				t.Fatal("the fake provider was never reached")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error")
			}
			msg := err.Error()
			// A generous ceiling: the bound plus this package's own fixed prefix
			// prose. The point is that it is O(maxProviderTextBytes), not
			// O(httpMaxResponseBody).
			const ceiling = maxProviderTextBytes + 256
			if len(msg) > ceiling {
				t.Errorf("a provider-chosen message reached the error at %d bytes, want at most "+
					"%d. readCappedBody admits %d, and this error is logged every reconcile "+
					"tick of a persistent failure and retained as lastErr.",
					len(msg), ceiling, httpMaxResponseBody)
			}
			if !strings.Contains(msg, providerTextTruncated) {
				t.Errorf("a bounded render must SAY it was truncated (%q), otherwise the "+
					"operator reads a silently-cut message as the whole one; got %d bytes:\n  %s",
					providerTextTruncated, len(msg), msg)
			}
		})
	}
}

// TestCloudflareErrorCountIsBounded_6634 closes the repetition bypass. The
// per-message cap is not a bound when the PROVIDER chooses how many messages the
// envelope carries: ten thousand short errors is still an unbounded log line.
func TestCloudflareErrorCountIsBounded_6634(t *testing.T) {
	var items []string
	const n = 500
	for i := 0; i < n; i++ {
		items = append(items, `{"code":1001,"message":"`+providerProse+`"}`)
	}
	body := `{"success":false,"errors":[` + strings.Join(items, ",") + `],"result":null}`

	p := newRecordingProvider(t, http.StatusOK, body)
	err := runCloudflare(t, p.srv.URL)
	if p.served == 0 {
		t.Fatal("the fake provider was never reached")
	}
	if err == nil {
		t.Fatal("a success:false envelope must produce a non-nil error")
	}
	msg := err.Error()
	const ceiling = maxCFErrors*(maxProviderTextBytes+64) + 256
	if len(msg) > ceiling {
		t.Errorf("a %d-error envelope rendered %d bytes, want at most %d: the per-message cap "+
			"is defeated by repetition when the provider picks the COUNT", n, len(msg), ceiling)
	}
	if !strings.Contains(msg, "more]") {
		t.Errorf("a count-bounded render must say how many errors were dropped; got:\n  %s", msg)
	}
}

// ---------------------------------------------------------------------------
// Backend drivers. Each builds the REAL backend against the fake provider and
// runs the operation whose failure path renders provider text.
// ---------------------------------------------------------------------------

func runCloudflare(t *testing.T, u string) error {
	t.Helper()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", Zone: "example.net",
		APIToken: config.Secret("cf-token"), Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build cloudflare backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runRoute53(t *testing.T, u string) error {
	t.Helper()
	b, err := newRoute53Backend(&config.DDNSProvider{
		Name: "r53", Backend: "route53", HostedZoneID: "Z123",
		AWSAccessKeyID: "AKID", AWSSecretAccessKey: config.Secret("aws-secret"),
		Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build route53 backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runDyndns2(t *testing.T, u string) error {
	t.Helper()
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "dd2", Backend: "dyndns2", Server: u,
		Username: "u", Password: config.Secret("p"),
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build dyndns2 backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runDuckDNS(t *testing.T, u string) error {
	t.Helper()
	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", APIToken: config.Secret("duck-token"),
		Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build duckdns backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

// TestProviderDecodeScopeIsLoadBearing_6634 proves the file scope on
// json.Unmarshal is doing work in BOTH directions, because a scope that is
// vacuous either way is worse than none: one that never excludes anything is
// noise, and one that never includes anything is a gate that passes on nothing.
//
// The second half is the important one. It re-walks state.go while LYING about
// its filename, so the scope does not apply — and asserts the walk finds an
// unscrubbed json.Unmarshal render there. That is the direct evidence the scope
// is load-bearing rather than decorative: without it, adding json.Unmarshal to
// urlErrorProducers would have turned the class gate red on a site that decodes
// a file this daemon wrote itself.
func TestProviderDecodeScopeIsLoadBearing_6634(t *testing.T) {
	if !producerFileScope("json.Unmarshal", "backend_cloudflare.go") {
		t.Error("json.Unmarshal MUST be a producer in a backend file — that is where it " +
			"decodes a provider-chosen response body, which is the whole point of the entry")
	}
	if producerFileScope("json.Unmarshal", "state.go") {
		t.Error("json.Unmarshal must NOT be a producer in state.go, which decodes the " +
			"ownership state file this daemon wrote itself")
	}
	// Every other producer is unscoped.
	if !producerFileScope("url.Parse", "state.go") {
		t.Error("the scope must apply to json.Unmarshal ONLY; url.Parse is unscoped")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "state.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse state.go: %v", err)
	}
	aliases := importAliases(file)
	unscrubbed := 0
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// Pretend state.go is a backend file, which disables the scope.
			for _, site := range urlErrorHandlers(n, "backend_pretend.go", aliases) {
				if site.producer != "json.Unmarshal" {
					continue
				}
				unscrubbed += len(unscrubbedUses(fset, site.stmts, site.errVar, aliases))
			}
			return true
		})
	}
	if unscrubbed == 0 {
		t.Error("state.go no longer has an unscrubbed json.Unmarshal render, so the file scope " +
			"excludes nothing and should be DELETED rather than left standing — a scope that " +
			"covers no site silently exempts whatever moves into it next")
	}
}
