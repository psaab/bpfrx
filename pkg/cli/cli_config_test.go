package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func newCLICommitWarningStore(t *testing.T) *configstore.Store {
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

func TestCommitCheckPrintsValidationWarnings(t *testing.T) {
	c := &CLI{store: newCLICommitWarningStore(t)}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleCommit([]string{"check"})
	})
	if callErr != nil {
		t.Fatalf("handleCommit(check) error = %v", callErr)
	}
	if !strings.Contains(out, "warning: system dataplane-type ebpf selects") {
		t.Fatalf("commit check output missing warning: %q", out)
	}
	if !strings.Contains(out, "configuration check succeeds") {
		t.Fatalf("commit check output missing success line: %q", out)
	}
}

func TestCommitPrintsValidationWarnings(t *testing.T) {
	c := &CLI{store: newCLICommitWarningStore(t)}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleCommit(nil)
	})
	if callErr != nil {
		t.Fatalf("handleCommit() error = %v", callErr)
	}
	if !strings.Contains(out, "warning: system dataplane-type ebpf selects") {
		t.Fatalf("commit output missing warning: %q", out)
	}
	if !strings.Contains(out, "commit complete") {
		t.Fatalf("commit output missing success line: %q", out)
	}
}
