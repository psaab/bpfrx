package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// newCLIEBPFRejectStore stages `set system dataplane-type ebpf` so the
// CLI commit/commit-check handlers can exercise the retirement-reject
// path that #1476 introduced. Prior to that, the same shape returned
// a deprecation warning with a success line.
func newCLIEBPFRejectStore(t *testing.T) *configstore.Store {
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

// TestCommitCheckRejectsRetiredEBPF asserts that `commit check`
// against a candidate carrying the retired `dataplane-type ebpf`
// returns the verbatim retirement message and no longer prints the
// "configuration check succeeds" line.
func TestCommitCheckRejectsRetiredEBPF(t *testing.T) {
	c := &CLI{store: newCLIEBPFRejectStore(t)}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleCommit([]string{"check"})
	})
	// The reject is surfaced either via callErr or via stderr-like
	// stdout depending on how the CLI plumbs error reporting; both
	// are accepted as "did not succeed". The verbatim retirement
	// message must appear in one of the two streams.
	if callErr == nil && strings.Contains(out, "configuration check succeeds") {
		t.Fatalf("commit check unexpectedly succeeded on retired ebpf type; out=%q", out)
	}
	combined := out
	if callErr != nil {
		combined = combined + " err=" + callErr.Error()
	}
	if !strings.Contains(combined, "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("expected eBPF retirement message in combined output; got %q (err=%v)", out, callErr)
	}
}

// TestCommitRejectsRetiredEBPF asserts that `commit` against the
// same candidate fails with the retirement-reject message and does
// not print "commit complete".
func TestCommitRejectsRetiredEBPF(t *testing.T) {
	c := &CLI{store: newCLIEBPFRejectStore(t)}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleCommit(nil)
	})
	if callErr == nil && strings.Contains(out, "commit complete") {
		t.Fatalf("commit unexpectedly succeeded on retired ebpf type; out=%q", out)
	}
	combined := out
	if callErr != nil {
		combined = combined + " err=" + callErr.Error()
	}
	if !strings.Contains(combined, "legacy eBPF dataplane backend has been retired") {
		t.Fatalf("expected eBPF retirement message in combined output; got %q (err=%v)", out, callErr)
	}
}
