package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1830 (e): the #1733 equal-flow worker-cap gate is retired — the v8
// lease rotation heap-sizes its per-worker scratch to the true worker
// count, so equal-flow-enforcement is supported at any worker count.
// These store-level tests pin the retirement across the three config
// ingress paths: Load (persisted), SyncApply (HA peer-sync), and the
// strict CommitCheck/Commit path.

// equalFlowManyWorkerSets is a config enabling CoS
// equal-flow-enforcement on more workers than the former 32-worker cap.
func equalFlowManyWorkerSets() []string {
	return []string{
		"set system dataplane-type userspace",
		"set system dataplane workers 64", // above the retired #1733 cap
		"set class-of-service schedulers ef-sched transmit-rate 10m exact",
		"set class-of-service schedulers ef-sched equal-flow-enforcement",
	}
}

func hasWorkerCapWarning(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			return true
		}
	}
	return false
}

// TestStoreLoad_AcceptsEqualFlowAboveLegacyWorkerCap: a persisted
// >32-worker + equal-flow config loads cleanly with NO retired cap
// warning and the equal-flow leaf preserved.
func TestStoreLoad_AcceptsEqualFlowAboveLegacyWorkerCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := newTestStoreAt(t, filepath.Join(dir, "xpf.conf"))

	tree := mustParseTree(t, equalFlowManyWorkerSets()...)
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	if err := store.Load(); err != nil {
		t.Fatalf("Load rejected a >32-worker equal-flow config (cap retired by #1830 (e)): %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Load")
	}
	if hasWorkerCapWarning(active) {
		t.Fatalf("Load surfaced a retired worker-cap warning: %v", active.Warnings)
	}
	sched := active.ClassOfService.Schedulers["ef-sched"]
	if sched == nil || !sched.EqualFlowEnforcement {
		t.Fatal("Load must preserve equal-flow-enforcement")
	}
}

// TestStoreSyncApply_AcceptsEqualFlowAboveLegacyWorkerCap: a peer-synced
// >32-worker + equal-flow config applies cleanly with no cap warning.
func TestStoreSyncApply_AcceptsEqualFlowAboveLegacyWorkerCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := newTestStoreAt(t, filepath.Join(dir, "xpf.conf"))

	content := mustParseTree(t, equalFlowManyWorkerSets()...).Format()

	compiled, err := store.SyncApply(content, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected a >32-worker equal-flow config: %v", err)
	}
	if hasWorkerCapWarning(compiled) {
		t.Fatalf("SyncApply surfaced a retired worker-cap warning: %v", compiled.Warnings)
	}
	sched := compiled.ClassOfService.Schedulers["ef-sched"]
	if sched == nil || !sched.EqualFlowEnforcement {
		t.Fatal("SyncApply must preserve equal-flow-enforcement")
	}
}

// TestCommitCheck_AcceptsEqualFlowAboveLegacyWorkerCap: the STRICT
// commit path accepts >32 workers + equal-flow — the operator-facing
// half of the #1830 (e) cap retirement (pre-#1830, CommitCheck and
// Commit hard-rejected this combination under #1733).
func TestCommitCheck_AcceptsEqualFlowAboveLegacyWorkerCap(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"system dataplane-type userspace",
		"system dataplane workers 64",
		"class-of-service schedulers ef-sched transmit-rate 10m exact",
		"class-of-service schedulers ef-sched equal-flow-enforcement",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck rejected >32-worker equal-flow config (cap retired by #1830 (e)): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit rejected >32-worker equal-flow config: %v", err)
	}
}
