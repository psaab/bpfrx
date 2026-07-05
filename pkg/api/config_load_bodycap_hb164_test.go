package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fable-review-164 H-2: the REST config-load handler must bound its request
// body so an oversized payload is rejected before it reaches the parser. This
// posts a body past maxConfigBodyBytes and asserts a clean 413, not an
// unbounded read into the parser.
func TestConfigLoadHandlerRejectsOversizedBody(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}

	// A body comfortably over the cap; the content need not be valid config —
	// the MaxBytesReader trips during decode, before the store sees it.
	huge := strings.Repeat("a", maxConfigBodyBytes+(1<<20))
	body := `{"mode":"override","content":"` + huge + `"}`

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/load", strings.NewReader(body))
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
	s.configLoadHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}
