package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// minimalNetworkdDaemon builds a Daemon wired with a networkd.Manager rooted
// at networkDir and a runtime DP returning the given ApplyResult, sufficient
// to drive applyConfigLocked through the networkd.Apply step (step 2.5).
func minimalNetworkdDaemon(t *testing.T, networkDir string, ar *dataplane.ApplyResult) (*Daemon, *config.Config) {
	t.Helper()
	installFakeNetworkctl(t)
	d := &Daemon{
		networkd: networkd.NewInDir(networkDir),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{applyResult: ar}) // #2114: publish through the cell
	cfg := &config.Config{}
	return d, cfg
}

// TestApplyConfigLocked_EmptyManagedSetSweepsStale is the #2988 caller-reach
// regression: the daemon previously guarded networkd.Apply with
// `len(ManagedInterfaces) > 0`, so removing the last managed interface never
// invoked the sweep and stale 10-xpf-* files survived. With the relaxed guard,
// an empty managed set must still flow into Apply and remove the stale file.
func TestApplyConfigLocked_EmptyManagedSetSweepsStale(t *testing.T) {
	networkDir := t.TempDir()

	// A stale xpf-managed file from a prior config that had an interface.
	stale := filepath.Join(networkDir, "10-xpf-ge-0-0-0.network")
	if err := os.WriteFile(stale, []byte("[Match]\nName=ge-0-0-0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Empty managed set: the last interface was removed.
	d, cfg := minimalNetworkdDaemon(t, networkDir, &dataplane.ApplyResult{
		ManagedInterfaces: nil,
	})

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale 10-xpf-ge-0-0-0.network must be swept on empty managed set (the daemon guard shadowed the sweep)")
	}
}

// TestApplyConfigLocked_EmptyManagedSetPreservesLifeline proves the empty-set
// sweep honors the #1922/#1956 protected lifeline end-to-end through the
// daemon: SetProtectedResolver feeds the mgmt interface (derived from
// ActiveConfig, independent of ManagedInterfaces) so its files survive the
// empty-set sweep — no management lockout.
func TestApplyConfigLocked_EmptyManagedSetPreservesLifeline(t *testing.T) {
	networkDir := t.TempDir()

	// Lifeline mgmt files + a genuinely stale file.
	mgmtNet := filepath.Join(networkDir, "10-xpf-fxp0.network")
	mgmtLink := filepath.Join(networkDir, "10-xpf-fxp0.link")
	stale := filepath.Join(networkDir, "10-xpf-ge-0-0-9.network")
	for _, f := range []struct{ path, body string }{
		{mgmtNet, "[Match]\nName=fxp0\n"},
		{mgmtLink, "[Match]\nOriginalName=enp5s0\n"},
		{stale, "[Match]\nName=ge-0-0-9\n"},
	} {
		if err := os.WriteFile(f.path, []byte(f.body), 0644); err != nil {
			t.Fatal(err)
		}
	}

	d, cfg := minimalNetworkdDaemon(t, networkDir, &dataplane.ApplyResult{})
	// Wire the protected resolver exactly as daemon_run.go does, returning
	// the mgmt leaf so the lifeline files are exempt from the sweep.
	d.networkd.SetProtectedResolver(func() map[string]bool { return map[string]bool{"fxp0": true} })

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	for _, f := range []string{mgmtNet, mgmtLink} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("protected lifeline file %s swept on empty set (lockout!): %v", filepath.Base(f), err)
		}
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("genuinely stale file should have been swept on empty set")
	}
}

// TestApplyConfigLocked_NetworkdWriteErrorFailsCommit is the #2987 caller-reach
// regression: a networkd write failure previously only logged a slog.Warn and
// the commit succeeded. The daemon must now surface the Apply error as the
// applyConfigLocked return so the commit reports failure (fail-closed),
// matching the dataplane-compile-abort contract.
func TestApplyConfigLocked_NetworkdWriteErrorFailsCommit(t *testing.T) {
	networkDir := t.TempDir()

	// Make the .network target unwritable by pre-creating a DIRECTORY where
	// the generated file is expected — WriteFileAtomic cannot replace a dir.
	blocked := filepath.Join(networkDir, "10-xpf-ge-0-0-0.network")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}

	d, cfg := minimalNetworkdDaemon(t, networkDir, &dataplane.ApplyResult{
		ManagedInterfaces: []networkd.InterfaceConfig{{
			Name:      "ge-0-0-0",
			Addresses: []string{"192.0.2.1/24"},
		}},
	})

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must fail when networkd.Apply cannot write a generated file (got nil — error swallowed)")
	}
	if !strings.Contains(err.Error(), "networkd") {
		t.Fatalf("applyConfigLocked error should mention the networkd failure: %v", err)
	}
}
