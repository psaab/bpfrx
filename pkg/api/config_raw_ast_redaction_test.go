package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// allSecretLeaks is the full cleartext set staged by stageSecretConfig — the
// secretSentinels plus the four well-formed-hash / key consts — that must not
// appear in ANY raw-AST render endpoint (#4051).
func allSecretLeaks() []string {
	return append(append([]string(nil), secretSentinels...),
		rootCryptSentinel, loginCryptSentinel, tsigSecretSentinel, wgPrivkeySentinel)
}

// assertRedacted fails if any cleartext secret appears in body, and fails if
// the redaction placeholder is absent (redaction not applied at all).
func assertRedacted(t *testing.T, label, body string) {
	t.Helper()
	for _, leak := range allSecretLeaks() {
		if strings.Contains(body, leak) {
			t.Errorf("%s: leaked cleartext secret %q in raw-AST render:\n%s", label, leak, body)
		}
	}
	if !strings.Contains(body, config.SecretDataPlaceholder) {
		t.Errorf("%s: redaction placeholder %q absent — redaction not applied?\n%s",
			label, config.SecretDataPlaceholder, body)
	}
}

// TestConfigShowHandlerRedactsRawAST drives the REST `show config` endpoint
// (configShowHandler → ShowActive*Redacted) across text/set/json/xml and
// asserts secrets are masked. This is the #4051 RED-on-revert net for the
// raw-AST path: it goes RED (cleartext PSK/community/keys) against pre-fix
// code that called the cleartext Show* methods.
func TestConfigShowHandlerRedactsRawAST(t *testing.T) {
	s, _ := stageSecretConfig(t)
	for _, format := range []string{"", "set", "json", "xml"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/config/show?target=active&format="+format, nil)
		s.configShowHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("format %q: status = %d, body: %s", format, rr.Code, rr.Body.String())
		}
		assertRedacted(t, "show active format="+format, rr.Body.String())
	}
}

// TestConfigExportHandlerRedactsRawAST drives the REST `export` endpoint
// across set/text/json/xml.
func TestConfigExportHandlerRedactsRawAST(t *testing.T) {
	s, _ := stageSecretConfig(t)
	for _, format := range []string{"set", "text", "json", "xml"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/config/export?format="+format, nil)
		s.configExportHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("format %q: status = %d, body: %s", format, rr.Code, rr.Body.String())
		}
		assertRedacted(t, "export format="+format, rr.Body.String())
	}
}

// TestConfigSearchHandlerRedactsRawAST drives the REST `search` endpoint —
// a matching line must never carry a cleartext secret in its snippet.
func TestConfigSearchHandlerRedactsRawAST(t *testing.T) {
	s, _ := stageSecretConfig(t)
	rr := httptest.NewRecorder()
	// Search for the IKE PSK keyword so the matching line is a secret leaf.
	req := httptest.NewRequest("GET", "/api/v1/config/search?q=pre-shared-key", nil)
	s.configSearchHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, leak := range allSecretLeaks() {
		if strings.Contains(body, leak) {
			t.Errorf("search leaked cleartext secret %q:\n%s", leak, body)
		}
	}
}
