package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newCompareStore returns a store in configuration mode with one staged
// candidate change so the rollback/compare handlers have a candidate to
// diff against on the success path.
func newCompareStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system host-name compare-fixture"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	return &Server{store: store}
}

func decodeResponse(t *testing.T, body string) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", body, err)
	}
	return resp
}

// TestConfigCompareHandlerRejectsMalformedRollback asserts the REST
// compare endpoint fails closed (HTTP 400) on a malformed or negative
// `rollback` selector instead of silently defaulting to 0
// (candidate-vs-active). #3443 M5. RED-on-revert: switching the handler
// back to queryInt() makes `?rollback=abc`/`-1` return 0 → a 200 success
// candidate-vs-active diff, which fails these assertions.
func TestConfigCompareHandlerRejectsMalformedRollback(t *testing.T) {
	for _, bad := range []string{"abc", "-1", "1.5", "0x3"} {
		s := newCompareStore(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/config/compare?rollback="+bad, nil)
		s.configCompareHandler(rr, req)

		if rr.Code != 400 {
			t.Errorf("rollback=%q: status = %d, want 400; body=%s", bad, rr.Code, rr.Body.String())
			continue
		}
		resp := decodeResponse(t, rr.Body.String())
		if resp.Success {
			t.Errorf("rollback=%q: success=true, want false", bad)
		}
		if !strings.Contains(resp.Error, "invalid rollback parameter") {
			t.Errorf("rollback=%q: error = %q, want substring %q", bad, resp.Error, "invalid rollback parameter")
		}
	}
}

// TestConfigCompareHandlerAbsentRollbackDefaults asserts the documented
// default (candidate-vs-active) is preserved when `rollback` is absent.
func TestConfigCompareHandlerAbsentRollbackDefaults(t *testing.T) {
	s := newCompareStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/compare", nil)
	s.configCompareHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("absent rollback: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeResponse(t, rr.Body.String())
	if !resp.Success {
		t.Fatalf("absent rollback: success=false, body=%s", rr.Body.String())
	}
}

// TestConfigShowRollbackHandlerRejectsMalformedN asserts the REST
// show-rollback endpoint fails closed on a malformed/negative `n`
// instead of silently defaulting to slot 1. #3443 M5.
func TestConfigShowRollbackHandlerRejectsMalformedN(t *testing.T) {
	for _, bad := range []string{"abc", "-1", "1.5", "0x2"} {
		s := newCompareStore(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/config/show-rollback?n="+bad, nil)
		s.configShowRollbackHandler(rr, req)

		if rr.Code != 400 {
			t.Errorf("n=%q: status = %d, want 400; body=%s", bad, rr.Code, rr.Body.String())
			continue
		}
		resp := decodeResponse(t, rr.Body.String())
		if resp.Success {
			t.Errorf("n=%q: success=true, want false", bad)
		}
		if !strings.Contains(resp.Error, "invalid n parameter") {
			t.Errorf("n=%q: error = %q, want substring %q", bad, resp.Error, "invalid n parameter")
		}
	}
}

// TestConfigShowRollbackHandlerRejectsZeroN pins the #4556 M-01 fix: `?n=0`
// is a canonical non-negative uint that clears queryIntStrict, so the old
// code passed it to ShowRollbackRedacted(0) → history.Get(-1) → the opaque
// "history position -1 out of range" error. The handler now rejects n<=0 up
// front with a clear positive-integer message. RED-on-revert: dropping the
// n<=0 guard returns the store's out-of-range error, not this message.
func TestConfigShowRollbackHandlerRejectsZeroN(t *testing.T) {
	s := newCompareStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/show-rollback?n=0", nil)
	s.configShowRollbackHandler(rr, req)

	if rr.Code != 400 {
		t.Fatalf("n=0: status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeResponse(t, rr.Body.String())
	if resp.Success {
		t.Fatalf("n=0: success=true, want false")
	}
	if !strings.Contains(resp.Error, "rollback index must be a positive integer") {
		t.Fatalf("n=0: error = %q, want substring %q", resp.Error, "rollback index must be a positive integer")
	}
	if strings.Contains(resp.Error, "out of range") {
		t.Fatalf("n=0: error leaked the opaque store message %q", resp.Error)
	}
}

// TestConfigShowRollbackHandlerAcceptsSlotOne asserts n=1 is unchanged by the
// M-01 guard: a real committed rollback slot 1 still renders 200. One Commit()
// pushes the prior (empty) active into history slot 1, so ShowRollback n=1
// succeeds.
func TestConfigShowRollbackHandlerAcceptsSlotOne(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system host-name rollback-fixture"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/show-rollback?n=1", nil)
	s.configShowRollbackHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("n=1: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeResponse(t, rr.Body.String())
	if !resp.Success {
		t.Fatalf("n=1: success=false, body=%s", rr.Body.String())
	}
}
