package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_http_test.go: mock-server (#2691 P3) tests for the HTTP DDNS backends.
// Every test drives the REAL backend implementation against an httptest server
// (the P2 lesson: test the real mechanism, not a fake that bypasses the
// protocol). A backend constructed by newDyndns2Backend/newCloudflareBackend/
// etc. is pointed at the test server via the per-instance endpoint override
// (Server / apiBase / endpoint), so the wire request the backend actually emits
// is asserted on the server side.

// hostRecord builds a forward A/AAAA LeaseDNSRecord for the backend under test.
func hostRecord(t *testing.T, fqdn, addr string) LeaseDNSRecord {
	t.Helper()
	rec, err := buildHostRecord(fqdn, netip.MustParseAddr(addr), 300)
	if err != nil {
		t.Fatalf("buildHostRecord: %v", err)
	}
	return rec
}

func TestDyndns2GoodAndNochg(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		// The hostname/myip must be present in the query.
		if r.URL.Query().Get("hostname") == "" || r.URL.Query().Get("myip") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("good 203.0.113.5\n"))
	}))
	defer srv.Close()

	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
		Username: "u1", Password: config.Secret("p1"),
	})
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease good: %v", err)
	}
	if !strings.Contains(gotPath, "hostname=wan.example.net") || !strings.Contains(gotPath, "myip=203.0.113.5") {
		t.Fatalf("dyndns2 request did not carry hostname+myip: %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("dyndns2 must send Basic auth header")
	}
}

func TestDyndns2VerdictMapping(t *testing.T) {
	cases := []struct {
		body    string
		wantErr bool
		wantSub string
	}{
		{"good 1.2.3.4\n", false, ""},
		{"nochg\n", false, ""},
		{"badauth\n", true, "auth"},
		{"abuse\n", true, "auth"},
		{"911\n", true, "rate"},
		{"nohost\n", true, "rejected"},
		{"weird-thing\n", true, "unrecognized"},
	}
	for _, tc := range cases {
		err := parseDyndns2Response(tc.body, "p")
		if tc.wantErr != (err != nil) {
			t.Fatalf("body %q: wantErr=%v got %v", tc.body, tc.wantErr, err)
		}
		if tc.wantErr && tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("body %q: error %q missing %q", tc.body, err.Error(), tc.wantSub)
		}
	}
}

func TestDyndns2NameEndpointResolution(t *testing.T) {
	b, err := newDyndns2Backend(&config.DDNSProvider{Name: "duckdns", Backend: "dyndns2"})
	if err != nil {
		t.Fatalf("newDyndns2Backend(duckdns): %v", err)
	}
	if !strings.Contains(b.endpoint, "duckdns.org") {
		t.Fatalf("duckdns name must resolve to its built-in endpoint, got %q", b.endpoint)
	}
	// No server + unknown name → error (fall back to no-op at the manager).
	if _, err := newDyndns2Backend(&config.DDNSProvider{Name: "weird", Backend: "dyndns2"}); err == nil {
		t.Fatal("unknown provider with no server must error")
	}
}

// TestDyndns2DeleteIssuesOfflineRequest is the #2772 FAIL-ON-REVERT guard for
// the dyndns2 withdraw path. The previous DeleteLease was a no-op that returned
// nil WITHOUT contacting the provider, so the engine dropped ownership while the
// public record kept resolving. This test asserts DeleteLease actually issues
// the dyndns2 offline GET (offline=YES + the hostname) and that a provider
// failure verdict propagates as an error. If DeleteLease is reverted to
// `return nil`, the server handler is never hit (got=="") and the test fails.
func TestDyndns2DeleteIssuesOfflineRequest(t *testing.T) {
	var gotPath, gotAuth string
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("good\n"))
	}))
	defer srv.Close()

	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
		Username: "u1", Password: config.Secret("p1"),
	})
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease good: %v", err)
	}
	// FAIL-ON-REVERT: a no-op DeleteLease never reaches the server.
	if hits == 0 {
		t.Fatal("DeleteLease did not issue any HTTP request — withdraw is a silent no-op (regression #2772)")
	}
	if !strings.Contains(gotPath, "offline=YES") {
		t.Fatalf("dyndns2 withdraw must send offline=YES; got %q", gotPath)
	}
	if !strings.Contains(gotPath, "hostname=wan.example.net") {
		t.Fatalf("dyndns2 withdraw must name the hostname; got %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("dyndns2 withdraw must send Basic auth header")
	}
}

// TestDyndns2DeletePropagatesProviderFailure asserts that a provider error
// verdict on the withdraw GET (not a silent success) propagates as a non-nil
// error so the Surface A engine keeps ownership for retry.
func TestDyndns2DeletePropagatesProviderFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("badauth\n"))
	}))
	defer srv.Close()
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
	})
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err == nil {
		t.Fatal("dyndns2 withdraw with a badauth verdict must return an error, not silent success")
	}
}

// TestGenericDeleteFailsNotSilentSuccess is the #2772 FAIL-ON-REVERT guard for
// the generic backend's withdraw path. The generic templated protocol has no
// portable delete verb, so DeleteLease must FAIL (so the engine keeps ownership
// and the abandoned record stays operator-visible) rather than return nil and
// silently drop ownership while the public record persists. If DeleteLease is
// reverted to `return nil`, this test fails.
func TestGenericDeleteFailsNotSilentSuccess(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("good\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/u?h=%h&i=%i",
	})
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	err = b.DeleteLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7"))
	if err == nil {
		t.Fatal("generic DeleteLease must FAIL (no portable delete verb), not report silent success (regression #2772)")
	}
	if !errors.Is(err, errGenericDeleteUnsupported) {
		t.Fatalf("generic DeleteLease error must wrap errGenericDeleteUnsupported; got %v", err)
	}
}

func TestGenericTemplateRenderAndOK(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		_, _ = w.Write([]byte("OK updated\n"))
	}))
	defer srv.Close()

	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: srv.URL + "/upd?host=%h&ip=%i&u=%u",
		Username:    "user one", // space → must be query-escaped
	})
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if !strings.Contains(gotURL, "host=h.example.net") || !strings.Contains(gotURL, "ip=198.51.100.7") {
		t.Fatalf("generic template did not expand %%h/%%i: %q", gotURL)
	}
	if !strings.Contains(gotURL, "u=user+one") && !strings.Contains(gotURL, "u=user%20one") {
		t.Fatalf("generic template did not query-escape %%u: %q", gotURL)
	}
}

func TestGenericSuccessSubstringMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ERROR something\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/u?h=%h&i=%i", OKResponse: "good",
	})
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err == nil {
		t.Fatal("a body without the success substring must be an error")
	}
}

// TestGenericOKTokenMatch is the #2838 FAIL-ON-REVERT guard for the generic
// backend's success classifier. The old matcher used strings.Contains against a
// default set that included the bare token "ok", so an explicit provider FAILURE
// body that merely CONTAINS "ok"/"good" ("not ok", "error: ok token invalid",
// "update not good") was wrongly classified as a completed update — Surface A
// then recorded ownership and suppressed retry, leaving DNS stale. This test
// pins token-bounded matching: a default-token success is a whole token / the
// leading field of a line; a negative response that only contains a token as a
// substring is a FAILURE. Reverting to the substring match turns the negative
// cases green again, which fails this test.
func TestGenericOKTokenMatch(t *testing.T) {
	cases := []struct {
		name string
		body string
		// okResponse: "" means use the default token set; non-empty pins it.
		okResponse string
		wantOK     bool
	}{
		// Default-token SUCCESS cases must keep passing.
		{name: "bare ok line", body: "ok\n", wantOK: true},
		{name: "uppercase OK line", body: "OK\n", wantOK: true},
		{name: "good with ip (dyndns2 shape)", body: "good 198.51.100.7\n", wantOK: true},
		{name: "nochg with ip", body: "nochg 198.51.100.7\n", wantOK: true},
		{name: "ok updated multiword", body: "OK updated\n", wantOK: true},
		// The #2838 false-success cases: a substring hit that is NOT a success.
		{name: "not ok", body: "not ok\n", wantOK: false},
		{name: "error ok token invalid", body: "error: ok token invalid\n", wantOK: false},
		{name: "update not good", body: "update not good\n", wantOK: false},
		{name: "notok glued", body: "notok\n", wantOK: false},
		{name: "html ok button", body: "<html><body><button>OK</button></body></html>\n", wantOK: false},
		// Explicit ok-response is matched the same whole-token way.
		{name: "explicit good success", body: "good\n", okResponse: "good", wantOK: true},
		{name: "explicit good not matched in noise", body: "this is not good news\n", okResponse: "good", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			b, err := newGenericBackend(&config.DDNSProvider{
				Name: "g", Backend: "generic",
				URLTemplate: srv.URL + "/u?h=%h&i=%i",
				OKResponse:  tc.okResponse,
			})
			if err != nil {
				t.Fatalf("newGenericBackend: %v", err)
			}
			err = b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7"))
			if tc.wantOK && err != nil {
				t.Fatalf("body %q must be SUCCESS, got error: %v", tc.body, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("body %q must be FAILURE, got success (false-success regression #2838)", tc.body)
			}
		})
	}
}

// TestMatchesGenericOKUnit exercises the matcher directly, including the
// dyndns2-shared default tokens (good/nochg) that the generic default set must
// continue to accept, and confirms substring-only hits are rejected.
func TestMatchesGenericOKUnit(t *testing.T) {
	def := defaultGenericOKTokens
	cases := []struct {
		body   string
		tokens []string
		want   bool
	}{
		{"good", def, true},
		{"nochg", def, true},
		{"GOOD 1.2.3.4", def, true},
		{"ok", def, true},
		{"not ok", def, false},
		{"update not good", def, false},
		{"error: ok", def, false},
		{"", def, false},
		{"good", nil, false}, // empty token set never matches
	}
	for _, tc := range cases {
		if got := matchesGenericOK(tc.body, tc.tokens); got != tc.want {
			t.Errorf("matchesGenericOK(%q, %v) = %v, want %v", tc.body, tc.tokens, got, tc.want)
		}
	}
}

// TestGenericURLTemplateValidation is the #2841 fail-on-revert gate for the
// runtime construction path. The generic url-template was validated PREFIX-ONLY
// (a bare HasPrefix http(s):// check), so a host-less or wrong-scheme template
// constructed a backend that then failed at the first publish. newGenericBackend
// must now reject a malformed template (no host / wrong scheme) at construction,
// with the SAME discipline as checkip's validateCheckIPURL, while remaining
// TEMPLATE-AWARE: a valid template carrying inadyn %h/%i/%u/%p specifiers — even
// a credential in the userinfo, which makes net/url.Parse FAIL — must be
// accepted. Goes RED if the validation reverts to prefix-only or switches to a
// naive url.Parse.
func TestGenericURLTemplateValidation(t *testing.T) {
	reject := []string{
		"https://",           // scheme only, no host
		"https:///upd?ip=%i", // host-less but http(s):// prefix
		"ftp://host/upd",     // wrong scheme
		"not a url",          // no scheme
		"http//host/upd",     // missing colon -> no "://"
		"://host/upd",        // empty scheme
	}
	for _, tmpl := range reject {
		if err := validateGenericURLTemplate(tmpl); err == nil {
			t.Errorf("validateGenericURLTemplate(%q) = nil, want error", tmpl)
		}
		if _, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tmpl,
		}); err == nil {
			t.Errorf("newGenericBackend(%q) = nil error, want rejection", tmpl)
		}
	}

	accept := []string{
		"https://api.example.net/update?host=%h&ip=%i", // %-specifiers in query
		"http://api.example.net/upd",                   // plain http
		"HTTPS://api.example.net/upd?ip=%i",            // uppercase scheme (RFC 3986 §3.1)
		"https://user:%p@api.example.net/upd?host=%h",  // credential in userinfo (url.Parse FAILS here)
		"https://api.example.net:8443/upd?ip=%i",       // explicit port
	}
	for _, tmpl := range accept {
		if err := validateGenericURLTemplate(tmpl); err != nil {
			t.Errorf("validateGenericURLTemplate(%q) = %v, want nil", tmpl, err)
		}
		if _, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tmpl,
		}); err != nil {
			t.Errorf("newGenericBackend(%q) = %v, want nil", tmpl, err)
		}
	}

	// #2841 credential-leak fold: a malformed template that carries a secret in
	// the userinfo or query must NOT echo that secret in the construction error
	// (the error is logged via slog.Warn at the surface-A construction site). The
	// template is run through config.RedactURL before embedding. Goes RED if the
	// raw template is embedded again.
	for _, tc := range []struct {
		tmpl, secret string
	}{
		{"ftp://user:SUPERSECRET@host/upd", "SUPERSECRET"}, // wrong scheme + userinfo secret
		{"https:///upd?token=SUPERSECRET", "SUPERSECRET"},  // host-less + query secret
	} {
		_, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tc.tmpl,
		})
		if err == nil {
			t.Fatalf("newGenericBackend(%q) = nil error, want rejection", tc.tmpl)
		}
		if strings.Contains(err.Error(), tc.secret) {
			t.Errorf("construction error leaked the secret %q: %v", tc.secret, err)
		}
	}
}

func TestGenericRenderUnit(t *testing.T) {
	got := renderGenericURL("https://x/u?h=%h&i=%i&p=%p&lit=%%", "host.tld", "1.2.3.4", "", "p@ss")
	if !strings.Contains(got, "h=host.tld") || !strings.Contains(got, "i=1.2.3.4") {
		t.Fatalf("render missing host/ip: %q", got)
	}
	if !strings.Contains(got, "lit=%") {
		t.Fatalf("%%%% must render a literal percent: %q", got)
	}
	if !strings.Contains(got, "p=p%40ss") {
		t.Fatalf("%%p must be query-escaped: %q", got)
	}
}
