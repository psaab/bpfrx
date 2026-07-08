package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSystemActionREST_JournalsRebootHalt pins #4484 L-1: a reboot/halt issued
// over the REST /api/v1/system/action endpoint MUST write a fsynced
// `system_action` audit entry to the configstore journal BEFORE the power
// action runs, exactly as the gRPC SystemAction handler already does (#4108
// F8). The REST path previously called `systemctl` directly with no journal,
// so a REST-issued reboot left no attributable trail.
//
// RED on revert: dropping the s.logSystemAction call in systemActionHandler
// (or making Store.LogSystemAction a no-op) leaves the journal empty and this
// test fails.
func TestSystemActionREST_JournalsRebootHalt(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	srv := &Server{store: store}

	// Neutralize the real `systemctl` shell-out for the duration of the test:
	// the handler must journal without actually taking the host down.
	orig := apiSchedulePowerAction
	t.Cleanup(func() { apiSchedulePowerAction = orig })
	var scheduled []string
	apiSchedulePowerAction = func(arg string) { scheduled = append(scheduled, arg) }

	for _, action := range []string{"reboot", "halt"} {
		body, _ := json.Marshal(SystemActionRequest{Action: action})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/system/action", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.systemActionHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("action %q: status = %d, want 200; body=%s", action, rec.Code, rec.Body.String())
		}
	}

	// The power action seam was invoked for both verbs (no real reboot).
	if len(scheduled) != 2 || scheduled[0] != "reboot" || scheduled[1] != "halt" {
		t.Fatalf("apiSchedulePowerAction calls = %v, want [reboot halt]", scheduled)
	}

	// The journal on disk carries a durable system_action entry per verb.
	journalBytes, err := os.ReadFile(filepath.Join(dir, ".config.journal"))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	got := string(journalBytes)
	if !strings.Contains(got, `"action":"system_action"`) {
		t.Fatalf("journal has no system_action entry; got:\n%s", got)
	}
	for _, action := range []string{"reboot", "halt"} {
		if !strings.Contains(got, `"detail":"`+action+`"`) {
			t.Errorf("journal missing system_action detail %q; got:\n%s", action, got)
		}
	}
}

// TestSystemActionREST_ClearConfigLock pins the #4484 L-1 REST parity for
// clear-config-lock: an operator wedged out of config mode (H-3 / #4476) can
// self-recover over REST without shell access. With no lock held the handler
// reports so; the unknown-action error text advertises the new verb.
func TestSystemActionREST_ClearConfigLock(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	srv := &Server{store: store}

	body, _ := json.Marshal(SystemActionRequest{Action: "clear-config-lock"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/action", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.systemActionHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear-config-lock status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No configuration lock held") {
		t.Errorf("clear-config-lock body = %s, want the no-lock message", rec.Body.String())
	}

	// An unknown action reports the full verb set (now including
	// clear-config-lock).
	body, _ = json.Marshal(SystemActionRequest{Action: "bogus"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/action", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	srv.systemActionHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus action status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "clear-config-lock") {
		t.Errorf("unknown-action error must advertise clear-config-lock; got: %s", rec.Body.String())
	}
}
