package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// newAPIConfigStore stages an active system/name-server node in config mode for
// the REST activate/deactivate handler tests.
func newAPIConfigStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set system host-name keep",
		"set system name-server 9.9.9.9",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	return store
}

// #2051: the REST deactivate handler must mark the candidate node actually
// inactive. Assertion is on real inactivation (display-set emits the
// `deactivate` line only for an Inactive node), not merely HTTP 200.
func TestConfigDeactivateHandlerMarksInactive(t *testing.T) {
	store := newAPIConfigStore(t)
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/deactivate",
		strings.NewReader(`{"input":"system name-server 9.9.9.9"}`))
	s.configDeactivateHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	out := store.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("REST deactivate did not mark the node inactive:\n%s", out)
	}
	if strings.Contains(out, "set deactivate ") {
		t.Fatalf("REST deactivate mangled input into a junk set path:\n%s", out)
	}
}

func TestConfigActivateHandlerClearsInactive(t *testing.T) {
	store := newAPIConfigStore(t)
	if err := store.DeactivateFromInput("system name-server 9.9.9.9"); err != nil {
		t.Fatalf("setup DeactivateFromInput: %v", err)
	}
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/activate",
		strings.NewReader(`{"input":"system name-server 9.9.9.9"}`))
	s.configActivateHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	if out := store.ShowCandidateSet(); strings.Contains(out, "deactivate ") {
		t.Fatalf("REST activate did not clear the marker:\n%s", out)
	}
}

// #2052: the REST Load handler must accept mode=set and replay flat lines,
// including `deactivate` lines, through LoadSet.
func TestConfigLoadHandlerModeSet(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}

	body := `{"mode":"set","content":"set system host-name keep\nset system name-server 9.9.9.9\ndeactivate system name-server 9.9.9.9"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/load", strings.NewReader(body))
	s.configLoadHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	out := store.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("REST load mode=set did not preserve the deactivate marker:\n%s", out)
	}
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("REST load mode=set dropped an active node:\n%s", out)
	}
}
