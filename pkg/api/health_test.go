package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestHealthHandler_DegradedWhenCompileNeverSucceeded pins #758: when
// the daemon's dataplane compile has failed and never succeeded, /health
// must return 503 with status="degraded", not 200 with status="ok". A
// probe reading the old 200-and-opaque response alongside a single WARN
// in the journal gave operators no signal that forwarding was broken.
func TestHealthHandler_DegradedWhenCompileNeverSucceeded(t *testing.T) {
	s := &Server{
		compileHealthFn: func() CompileHealthSnapshot {
			return CompileHealthSnapshot{
				EverSucceeded:    false,
				FailureCount:     3,
				LastError:        "compile zones: add tx port fab0: key too big for map",
				LastErrorUnixSec: 1_700_000_000,
			}
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	s.healthHandler(rr, req)

	if rr.Code != 503 {
		t.Errorf("status = %d, want 503", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Success {
		t.Error("success must be false for degraded health")
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %T, want map", resp.Data)
	}
	if s, _ := data["status"].(string); s != "degraded" {
		t.Errorf("status = %q, want \"degraded\"", s)
	}
	if ever, _ := data["compile_ever_succeeded"].(bool); ever {
		t.Error("compile_ever_succeeded should be false")
	}
	if msg, _ := data["compile_last_error"].(string); msg == "" {
		t.Error("compile_last_error should be populated")
	}
}

// TestHealthHandler_OKAfterCompileSucceeds pins the complementary
// half: once compile has succeeded, /health returns 200/ok regardless
// of how many failures happened before. The counter stays visible for
// observability but no longer gates the probe.
func TestHealthHandler_OKAfterCompileSucceeds(t *testing.T) {
	s := &Server{
		compileHealthFn: func() CompileHealthSnapshot {
			return CompileHealthSnapshot{
				EverSucceeded: true,
				FailureCount:  2,
				LastError:     "",
			}
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	s.healthHandler(rr, req)

	if rr.Code != 200 {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, _ := resp.Data.(map[string]any)
	if s, _ := data["status"].(string); s != "ok" {
		t.Errorf("status = %q, want \"ok\"", s)
	}
	// Counter still visible so operators can tell the daemon had
	// transient issues even after recovery.
	if fc, ok := data["compile_failure_count"].(float64); !ok || fc != 2 {
		t.Errorf("compile_failure_count = %v, want 2", data["compile_failure_count"])
	}
}

// TestHealthHandler_NoCompileFnKeepsLegacyBehaviour pins backwards
// compatibility: callers that do not wire CompileHealthFn (tests,
// embeddings) must keep the pre-#758 200/ok behaviour.
func TestHealthHandler_NoCompileFnKeepsLegacyBehaviour(t *testing.T) {
	s := &Server{} // compileHealthFn intentionally nil

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	s.healthHandler(rr, req)

	if rr.Code != 200 {
		t.Errorf("status = %d, want 200 (legacy)", rr.Code)
	}
}
