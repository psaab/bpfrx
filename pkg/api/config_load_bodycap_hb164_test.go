package api

import (
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fable-review-164 H-2: the REST config-load handler (the parse-path entry
// point) must bound its request body so an oversized payload is rejected with
// a clean 413 before it reaches the parser — never buffered whole and fed to
// config.NewParser. This is the load-handler-specific sibling of the M-7
// generic-mutation body-cap test (TestConfigMutationBodyCappedM7, which
// exercises configSetHandler); both route through decodeJSONBody
// (maxRequestBodyBytes). The body is streamed via repeatReader so the test
// never allocates the >16 MiB payload itself.
func TestConfigLoadHandlerRejectsOversizedBody(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}

	// prefix + (maxRequestBodyBytes + slack) filler bytes + suffix => the cap
	// fires inside the JSON string value, before the store sees any content.
	body := io.MultiReader(
		strings.NewReader(`{"mode":"override","content":"`),
		&repeatReader{b: 'a', remaining: int64(maxRequestBodyBytes) + 4096},
		strings.NewReader(`"}`),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/load", body)
	s.configLoadHandler(rr, req)

	if rr.Code != 413 {
		t.Fatalf("status = %d, want 413 (request entity too large); body: %s",
			rr.Code, rr.Body.String())
	}
}

// TestConfigLoadHandlerAcceptsNormalBody confirms the body cap does not disturb
// an ordinary config-load request.
func TestConfigLoadHandlerAcceptsNormalBody(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}

	body := `{"mode":"set","content":"set system host-name fw"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/load", strings.NewReader(body))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configLoadHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}
