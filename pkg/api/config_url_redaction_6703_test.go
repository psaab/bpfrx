package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// #6703 end-to-end leak regression for the config-READ surfaces.
//
// This is the layer the defect actually lived at. RedactURL has stripped
// userinfo since #2781 and DDNSProvider.String() has applied it since then, yet
// GET /api/v1/config still rendered a userinfo credential VERBATIM — because
// that route json-encodes the compiled *config.Config and called neither. The
// export/show routes render the raw AST, whose keyword-based redaction had no
// url/server/url-template entry. So the mechanism was "no redactor is reached",
// not "the redactor has a gap", and a fix aimed at RedactURL would have been
// invisible here.
//
// Each sentinel is unique so a single leaking field is identifiable, and each
// sits in a DIFFERENT credential-bearing component (userinfo / query) so the
// test does not accidentally prove only one rule.
var urlSecretSentinels6703 = []string{
	"LEAK-SERVER-USERINFO",   // DDNSProvider.Server, credential in userinfo
	"LEAK-URLTEMPLATE-QUERY", // DDNSProvider.URLTemplate, token in query
	"LEAK-CHECKIP-QUERY",     // DDNSProvider.CheckIPURL, key in query
	"LEAK-FEED-QUERY",        // FeedServer.URL, subscription token in query
}

// urlCleanValues must render UNCHANGED on every route. Without this half the
// test cannot distinguish working redaction from blanket over-redaction, which
// for these leaves would destroy the diagnosability #6703 requires be kept.
var urlCleanValues6703 = []string{
	"https://checkip-plain.example/",  // credential-free checkip-url
	"https://feeds.example/plain.txt", // credential-free feed url
	"ns1.example.com:53",              // plain host:port update-server
}

func stageURLSecretConfig6703(t *testing.T) *Server {
	t.Helper()
	cmds := []string{
		"set system services dynamic-dns provider p1 backend generic",
		"set system services dynamic-dns provider p1 update-server ns1.example.com:53",
		`set system services dynamic-dns provider p1 server "https://user:LEAK-SERVER-USERINFO@dyn.example/upd"`,
		`set system services dynamic-dns provider p1 url-template "https://tmpl.example/upd?token=LEAK-URLTEMPLATE-QUERY&host=%h"`,
		`set system services dynamic-dns provider p1 checkip-url "https://checkip.example/?k=LEAK-CHECKIP-QUERY"`,
		"set system services dynamic-dns provider p2 backend generic",
		`set system services dynamic-dns provider p2 checkip-url "https://checkip-plain.example/"`,
		`set security dynamic-address feed-server threat url "https://feeds.example/list.txt?key=LEAK-FEED-QUERY"`,
		`set security dynamic-address feed-server clean url "https://feeds.example/plain.txt"`,
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join(cmds, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// TestConfigReadSurfacesRedactURLSecrets_6703 drives the three routes named in
// #6703's acceptance criteria and asserts both halves on each.
func TestConfigReadSurfacesRedactURLSecrets_6703(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{"GET /api/v1/config", "/api/v1/config"},
		{"GET /api/v1/config/export", "/api/v1/config/export?format=set"},
		{"GET /api/v1/config/show", "/api/v1/config/show"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stageURLSecretConfig6703(t)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.target, nil)
			switch {
			case strings.Contains(tc.target, "/export"):
				s.configExportHandler(rr, req)
			case strings.Contains(tc.target, "/show"):
				s.configShowHandler(rr, req)
			default:
				s.configHandler(rr, req)
			}
			if rr.Code != 200 {
				t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
			}
			body := rr.Body.String()

			for _, leak := range urlSecretSentinels6703 {
				if strings.Contains(body, leak) {
					t.Errorf("%s leaked cleartext URL credential %q", tc.target, leak)
				}
			}
			for _, keep := range urlCleanValues6703 {
				if !strings.Contains(body, keep) {
					t.Errorf("%s over-redacted: credential-free value %q must render unchanged\nbody: %s",
						tc.target, keep, body)
				}
			}
			// The host survives on a REDACTED value too — #6703 requires the
			// field stay diagnosable, so redaction must not swallow the authority.
			if !strings.Contains(body, "dyn.example") {
				t.Errorf("%s dropped the host of a redacted URL; the field must stay diagnosable\nbody: %s",
					tc.target, body)
			}
		})
	}
}

// TestRedactedURLExportIsNotRestorable_6703 pins the round-trip guard on its
// REAL production path — Store.Commit -> SchemaValidateWithDefinitions
// (schema_walk.go) -> checkRedactionPlaceholder — rather than by calling the
// guard directly.
//
// This matters more for URLs than for secrets. The secret placeholder
// ("##SECRET-DATA##") is obviously not a password, but a redacted URL still
// LOOKS like a valid URL, so without the guard an operator re-applying a
// redacted export would silently commit a DDNS provider that publishes to
// "https://dyn.example/upd?<redacted>" — a broken endpoint that fails at
// runtime rather than at commit.
func TestRedactedURLExportIsNotRestorable_6703(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(
		`set system services dynamic-dns provider p1 server "https://dyn.example/upd?<redacted>"`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	_, err := store.Commit()
	if err == nil {
		t.Fatal("committing a redacted export must fail — it is a display render, not a restorable config")
	}
	if !strings.Contains(err.Error(), "redacted URL") {
		t.Errorf("the refusal must name the cause, got %v", err)
	}

	// The same commit with a cleartext URL must succeed, so the guard is not a
	// blanket ban on URLs that merely resemble a redacted one.
	ok := newConfigStore(t, filepath.Join(t.TempDir(), "xpf2.conf"))
	if err := ok.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := ok.LoadSet(
		`set system services dynamic-dns provider p1 server "https://dyn.example/upd?token=real"`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := ok.Commit(); err != nil {
		t.Fatalf("a cleartext URL must commit cleanly, got %v", err)
	}
}
