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

// TestHealthHandler_DegradedWhenConfigPersistFails pins #1799: while
// the configstore reports persist-degraded (the running active config
// failed to write to disk and the background retry has not yet
// succeeded), /health must return 503 with status="degraded" so an
// operator probe surfaces that a restart would load a stale config.
func TestHealthHandler_DegradedWhenConfigPersistFails(t *testing.T) {
	s := &Server{
		configPersistDegradedFn: func() bool { return true },
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
	if st, _ := data["status"].(string); st != "degraded" {
		t.Errorf("status = %q, want \"degraded\"", st)
	}
	if degraded, _ := data["config_persist_degraded"].(bool); !degraded {
		t.Error("config_persist_degraded should be true")
	}
}

// TestHealthHandler_OKWhenConfigPersistHealthy pins the complementary
// half: with the fn wired and reporting healthy, /health stays 200/ok
// and the field stays visible for observability.
func TestHealthHandler_OKWhenConfigPersistHealthy(t *testing.T) {
	s := &Server{
		configPersistDegradedFn: func() bool { return false },
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
	if st, _ := data["status"].(string); st != "ok" {
		t.Errorf("status = %q, want \"ok\"", st)
	}
	if degraded, ok := data["config_persist_degraded"].(bool); !ok || degraded {
		t.Errorf("config_persist_degraded = %v, want false-and-present", data["config_persist_degraded"])
	}
}

// TestHealthHandler_ReportsRollbackHistoryDegraded pins #3441: while the
// configstore reports a degraded rollback history, /health surfaces the
// rollback_history_degraded field as true — but stays 200/ok, because the
// active config is durable and only the best-effort text rollback copies
// failed (a forwarding firewall must not be pulled from rotation over a
// degraded recovery aid).
func TestHealthHandler_ReportsRollbackHistoryDegraded(t *testing.T) {
	s := &Server{
		rollbackHistoryDegradedFn: func() bool { return true },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	s.healthHandler(rr, req)

	if rr.Code != 200 {
		t.Errorf("status = %d, want 200 (rollback-history degradation is non-fatal)", rr.Code)
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %T, want map", resp.Data)
	}
	if degraded, _ := data["rollback_history_degraded"].(bool); !degraded {
		t.Error("rollback_history_degraded should be true and reported in /health")
	}
}

// TestHealthHandler_ReportsBootstrapImportFailed pins #4184 (H-11): a failed
// day-0 / bootstrap config import is surfaced on /health via
// bootstrap_import_status + bootstrap_import_failed + the error detail — so
// "why didn't my config apply" has an in-band answer beyond a boot-time WARN.
// It is NON-fatal (200/ok): the box is in the lifeline-safe bootstrap state,
// so a probe must not pull it from rotation. RED-on-revert: without the
// bootstrap_import_status field, this assertion fails.
func TestHealthHandler_ReportsBootstrapImportFailed(t *testing.T) {
	s := &Server{
		bootstrapImportFn: func() BootstrapImportSnapshot {
			return BootstrapImportSnapshot{
				Status:  "import-failed",
				Error:   "commit: parse error: unexpected token",
				UnixSec: 1_700_000_000,
				Failed:  true,
			}
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	s.healthHandler(rr, req)

	if rr.Code != 200 {
		t.Errorf("status = %d, want 200 (bootstrap import failure is non-fatal)", rr.Code)
	}
	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %T, want map", resp.Data)
	}
	if st, _ := data["bootstrap_import_status"].(string); st != "import-failed" {
		t.Errorf("bootstrap_import_status = %q, want \"import-failed\"", st)
	}
	if failed, _ := data["bootstrap_import_failed"].(bool); !failed {
		t.Error("bootstrap_import_failed should be true")
	}
	if msg, _ := data["bootstrap_import_error"].(string); msg == "" {
		t.Error("bootstrap_import_error should be populated")
	}
}

// TestHealthHandler_BootstrapImportNoConfigNotFailed pins the factory-boot
// half: the expected no-config state reports its status without marking the
// import failed and without degrading /health.
func TestHealthHandler_BootstrapImportNoConfigNotFailed(t *testing.T) {
	s := &Server{
		bootstrapImportFn: func() BootstrapImportSnapshot {
			return BootstrapImportSnapshot{Status: "no-config", UnixSec: 1_700_000_000}
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
	if st, _ := data["bootstrap_import_status"].(string); st != "no-config" {
		t.Errorf("bootstrap_import_status = %q, want \"no-config\"", st)
	}
	if failed, _ := data["bootstrap_import_failed"].(bool); failed {
		t.Error("bootstrap_import_failed should be false for the factory no-config state")
	}
}

// TestHealthHandler_RollbackHistoryHealthy pins the complementary half:
// with the fn wired and reporting healthy, the field is present and false.
func TestHealthHandler_RollbackHistoryHealthy(t *testing.T) {
	s := &Server{
		rollbackHistoryDegradedFn: func() bool { return false },
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
	if degraded, ok := data["rollback_history_degraded"].(bool); !ok || degraded {
		t.Errorf("rollback_history_degraded = %v, want false-and-present", data["rollback_history_degraded"])
	}
}
