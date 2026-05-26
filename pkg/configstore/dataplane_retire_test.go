package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRewriteRetiredDataplaneType_EBPF covers the Store.Load() and
// Store.SyncApply() rolling-upgrade tolerance fix from #1476: a tree
// carrying `set system dataplane-type ebpf` is rewritten so the
// retired leaf is dropped, leaving the empty default that
// EffectiveType resolves to userspace.
func TestRewriteRetiredDataplaneType_EBPF(t *testing.T) {
	t.Parallel()

	tree := mustParseTree(t, "set system dataplane-type ebpf")
	got := rewriteRetiredDataplaneType(tree, LoadCaller)
	if got != 1 {
		t.Fatalf("rewriteRetiredDataplaneType = %d; want 1", got)
	}
	if found := findDataplaneType(tree); found != "" {
		t.Fatalf("dataplane-type leaf survived rewrite: %q", found)
	}
	// Compile must now succeed and resolve to userspace.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after rewrite: %v", err)
	}
	if cfg.System.DataplaneType != "" {
		t.Fatalf("post-rewrite DataplaneType = %q; want empty", cfg.System.DataplaneType)
	}
}

// TestRewriteRetiredDataplaneType_DPDK exercises the symmetric DPDK
// arm (already in tree from the #1525/#1528 retirement chain; #1476
// did not introduce DPDK rewrite but consolidated the helper so
// both retired values are handled in one place).
func TestRewriteRetiredDataplaneType_DPDK(t *testing.T) {
	t.Parallel()

	tree := mustParseTree(t, "set system dataplane-type dpdk")
	got := rewriteRetiredDataplaneType(tree, LoadCaller)
	if got != 1 {
		t.Fatalf("rewriteRetiredDataplaneType = %d; want 1", got)
	}
	if found := findDataplaneType(tree); found != "" {
		t.Fatalf("dataplane-type leaf survived rewrite: %q", found)
	}
}

// TestRewriteRetiredDataplaneType_NoOpForUserspace confirms that the
// rewrite does not mutate the tree when the dataplane type is the
// current default. A no-op is required: gratuitous rewrites would
// trip HA config-sync convergence checks.
func TestRewriteRetiredDataplaneType_NoOpForUserspace(t *testing.T) {
	t.Parallel()

	tree := mustParseTree(t, "set system dataplane-type userspace")
	got := rewriteRetiredDataplaneType(tree, LoadCaller)
	if got != 0 {
		t.Fatalf("rewriteRetiredDataplaneType = %d; want 0 (userspace is the default)", got)
	}
	if found := findDataplaneType(tree); found != "userspace" {
		t.Fatalf("userspace dataplane-type leaf must survive; got %q", found)
	}
}

// TestRewriteRetiredDataplaneType_NoSystemNode covers the defensive
// nil-tree and missing-system-node paths.
func TestRewriteRetiredDataplaneType_NoSystemNode(t *testing.T) {
	t.Parallel()

	if got := rewriteRetiredDataplaneType(nil, LoadCaller); got != 0 {
		t.Fatalf("rewriteRetiredDataplaneType(nil, LoadCaller) = %d; want 0", got)
	}
	empty := &config.ConfigTree{}
	if got := rewriteRetiredDataplaneType(empty, LoadCaller); got != 0 {
		t.Fatalf("rewriteRetiredDataplaneType(empty, LoadCaller) = %d; want 0", got)
	}
}

// TestRewriteRetiredDataplaneType_ApplyGroupsEBPF covers the
// Codex r1 (PR #1558) finding: a `dataplane-type ebpf` leaf hidden
// inside a `groups { legacy { system { ... } } }` definition must
// be rewritten too. Without the groups-aware second pass, the raw
// tree looks clean (top-level `system` only carries `apply-groups`)
// but `compileExpanded` expands the group and trips the strict
// retirement validator, returning ErrEBPFDataplaneRetired and
// stranding the daemon.
func TestRewriteRetiredDataplaneType_ApplyGroupsEBPF(t *testing.T) {
	t.Parallel()

	const src = `groups {
    legacy {
        system {
            dataplane-type ebpf;
        }
    }
}
system {
    apply-groups legacy;
    host-name fw1;
}`
	parser := config.NewParser(src)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	got := rewriteRetiredDataplaneType(tree, LoadCaller)
	if got != 1 {
		t.Fatalf("rewriteRetiredDataplaneType = %d; want 1 (apply-groups-nested ebpf)", got)
	}

	// After rewrite, compileExpanded must succeed without firing
	// the retirement validator. CompileConfigForNode forces the
	// node-aware expansion path used by HA-cluster boot.
	cfg, err := config.CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode after rewrite (apply-groups ebpf): %v", err)
	}
	if cfg.System.DataplaneType != "" {
		t.Fatalf("post-rewrite DataplaneType = %q; want empty (rewritten from group-injected ebpf)",
			cfg.System.DataplaneType)
	}
}

// TestRewriteRetiredDataplaneType_ApplyGroupsDPDK is the symmetric
// DPDK case. Both retired values share the same group-walking code
// path; this test prevents a future change from accidentally only
// covering one arm.
func TestRewriteRetiredDataplaneType_ApplyGroupsDPDK(t *testing.T) {
	t.Parallel()

	const src = `groups {
    legacy {
        system {
            dataplane-type dpdk;
        }
    }
}
system {
    apply-groups legacy;
}`
	parser := config.NewParser(src)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	got := rewriteRetiredDataplaneType(tree, SyncCaller)
	if got != 1 {
		t.Fatalf("rewriteRetiredDataplaneType = %d; want 1 (apply-groups-nested dpdk)", got)
	}
	cfg, err := config.CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode after rewrite (apply-groups dpdk): %v", err)
	}
	if cfg.System.DataplaneType != "" {
		t.Fatalf("post-rewrite DataplaneType = %q; want empty (rewritten from group-injected dpdk)",
			cfg.System.DataplaneType)
	}
}

// TestStoreLoad_RewritesPersistedEBPFDataplaneType end-to-ends the
// Store.Load() path: a persisted active config carrying
// `dataplane-type ebpf` must come up cleanly (no strict-validator
// error bubble) with DataplaneType empty after Load.
//
// Simulates a pre-#1476 persisted config by writing a tree directly
// through the store's db handle (which bypasses the commit-time
// strict validator). The new daemon then exercises the rewrite hook
// added to Store.Load().
func TestStoreLoad_RewritesPersistedEBPFDataplaneType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(filepath.Join(dir, "xpf.conf"))

	// Build a retired-EBPF tree off-store and stamp it on disk.
	retiredTree := mustParseTree(t, "set system dataplane-type ebpf")
	if err := store.db.WriteActive(retiredTree); err != nil {
		t.Fatalf("WriteActive (simulating pre-#1476 persisted config): %v", err)
	}

	// Now load — this must not error.
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Load — rewrite did not let the daemon boot")
	}
	if active.System.DataplaneType != "" {
		t.Fatalf("post-Load DataplaneType = %q; want empty (rewritten from retired ebpf)",
			active.System.DataplaneType)
	}
}

// findDataplaneType returns the dataplane-type leaf value if present.
func findDataplaneType(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	system := tree.FindChild("system")
	if system == nil {
		return ""
	}
	for _, child := range system.Children {
		if len(child.Keys) >= 2 && child.Keys[0] == "dataplane-type" {
			return child.Keys[1]
		}
	}
	return ""
}

// mustParseTree compiles a series of `set ...` commands into a
// ConfigTree for unit tests.
func mustParseTree(t *testing.T, setCmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range setCmds {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}
