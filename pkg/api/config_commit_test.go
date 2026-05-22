package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func newAPICommitWarningStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system dataplane-type ebpf"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	return store
}

func TestConfigCommitCheckHandlerReturnsWarnings(t *testing.T) {
	s := &Server{store: newAPICommitWarningStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit-check", nil)
	s.configCommitCheckHandler(rr, req)

	resp := decodeConfigCommitResponse(t, rr)
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if !containsWarning(resp.Data.Warnings, "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.Data.Warnings)
	}
}

func TestConfigCommitHandlerReturnsWarnings(t *testing.T) {
	store := newAPICommitWarningStore(t)
	s := &Server{
		store: store,
		commitFn: func(context.Context, string) (*config.Config, error) {
			return store.Commit()
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit", nil)
	s.configCommitHandler(rr, req)

	resp := decodeConfigCommitResponse(t, rr)
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if !containsWarning(resp.Data.Warnings, "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.Data.Warnings)
	}
}

func TestConfigCommitConfirmedHandlerReturnsWarnings(t *testing.T) {
	store := newAPICommitWarningStore(t)
	s := &Server{
		store: store,
		commitConfirmedFn: func(context.Context, int) (*config.Config, error) {
			return store.CommitConfirmed(10)
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/commit-confirmed",
		strings.NewReader(`{"minutes":10}`))
	s.configCommitConfirmedHandler(rr, req)

	resp := decodeConfigCommitResponse(t, rr)
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if !containsWarning(resp.Data.Warnings, "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.Data.Warnings)
	}
}

func decodeConfigCommitResponse(t *testing.T, rr *httptest.ResponseRecorder) struct {
	Success bool                 `json:"success"`
	Data    configCommitResponse `json:"data"`
} {
	t.Helper()

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool                 `json:"success"`
		Data    configCommitResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body: %s", err, rr.Body.String())
	}
	return resp
}

func containsWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
