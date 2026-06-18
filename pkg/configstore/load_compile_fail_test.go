package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLoadCommittedConfigCompileFailureFailsClosed pins the #1960 fail-closed
// contract at the configstore layer: a PRESENT, previously-committed
// active.json that is valid JSON but no longer COMPILES (even through the
// tolerant compileTreeLenient path) must:
//
//   - make Store.Load return an error that errors.Is(ErrConfigCompile) — so
//     the daemon can distinguish it from an absent DB (no error) and from
//     ErrConfigDBUnreadable (the bytes were fine here),
//   - leave ActiveConfig() == nil (compile failed, nothing promoted),
//   - leave EverCommitted() == true (the on-disk committed=1 marker stands).
//
// That (ActiveConfig()==nil, EverCommitted()==true) tuple is exactly the
// state that, before #1960, drove the boot predicate to NORMAL boot and the
// positional claim-all interface rename. The daemon-side test
// (TestCompileFailureForcesBootstrapNotClaimAll) proves the boot path now
// refuses takeover; this test proves the signal those decisions rely on.
func TestLoadCommittedConfigCompileFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()

	// Produce a committed DB (committed=1) whose tree no longer compiles.
	// `apply-groups badgroup` references an undefined group, which is a hard
	// error even on the lenient Load/SyncApply compile path — the realistic
	// regression is a committed config whose referenced group was later
	// deleted from a partially-edited DB.
	const brokenConfig = "apply-groups badgroup;\nsystem {\n  host-name box;\n}\n"
	tree, errs := config.NewParser(brokenConfig).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse broken config: %v", errs[0])
	}
	// Sanity: it really must fail the tolerant compile (otherwise the test
	// would silently stop exercising the fail-closed path).
	if _, err := config.CompileConfigLenient(tree); err == nil {
		t.Fatal("test precondition: broken config compiled cleanly through " +
			"CompileConfigLenient; it must fail to exercise the #1960 path")
	}

	db, err := NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-1.0")
	// WriteActive stamps committed=1 — the previously-committed case.
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	// Confirm the on-disk marker is committed=1 (the precondition that makes
	// the boot predicate dangerous: everCommitted=true with nil compiled).
	if _, committed, err := db.ReadActiveMeta(); err != nil || !committed {
		t.Fatalf("on-disk DB: committed=%v err=%v; want committed=true", committed, err)
	}

	// Load the same DB through a fresh store (a daemon restart).
	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	err = st.Load()
	if err == nil {
		t.Fatal("Load of a committed, non-compiling DB returned nil error; " +
			"want an ErrConfigCompile-tagged error (fail closed)")
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error not tagged ErrConfigCompile: %v", err)
	}
	// It must NOT be misclassified as the unreadable-bytes case (which is
	// fatal at the daemon and points the operator at the wrong remedy).
	if errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error wrongly tagged ErrConfigDBUnreadable (bytes were "+
			"fine; this is a compile failure): %v", err)
	}

	// The compile failed, so nothing was promoted: ActiveConfig() is nil.
	if st.ActiveConfig() != nil {
		t.Fatal("ActiveConfig() != nil after a compile failure; want nil " +
			"(nothing promoted)")
	}
	// The committed marker still stands: this is a previously-committed box.
	if !st.EverCommitted() {
		t.Fatal("EverCommitted() == false after loading a committed DB; " +
			"want true (this is the dangerous tuple #1960 fixes)")
	}
}

// TestCompileFailureRetainsTreeAndHistoryForRecovery proves the #1960 recovery
// path advertised in the daemon log and READMEs is real (Codex #1991 r1): a
// compile-failed Load must keep ActiveConfig() nil (the fail-closed signal) but
// STILL retain the parsed-but-broken tree as the active tree and load the
// on-disk rollback history, so an operator can fix the config from the CLI or
// roll back — in band, without hand-repairing the DB.
//
// Without the fix, Store.Load returned before assigning s.active and before
// loadRollbackHistory(): `configure` cloned the empty New() tree (operator saw
// an EMPTY config, not the broken one to fix) and `rollback`/`show rollback`
// saw NO history.
func TestCompileFailureRetainsTreeAndHistoryForRecovery(t *testing.T) {
	dir := t.TempDir()

	const brokenConfig = "apply-groups badgroup;\nsystem {\n  host-name box;\n}\n"
	tree, errs := config.NewParser(brokenConfig).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse broken config: %v", errs[0])
	}
	db, err := NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	// Seed one on-disk rollback file (xpf.conf.1) — the last good config the
	// operator would want to roll back to. loadRollbackHistory reads
	// <dir>/xpf.conf.<n>; it must pick this up even on the compile-failed path.
	const priorGood = "system {\n  host-name was-good;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "xpf.conf.1"), []byte(priorGood), 0o600); err != nil {
		t.Fatalf("seed rollback file: %v", err)
	}

	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error = %v; want ErrConfigCompile", err)
	}

	// Fail-closed signal intact: nothing compiled/promoted.
	if st.ActiveConfig() != nil {
		t.Fatal("ActiveConfig() != nil after compile failure; the bootstrap " +
			"signal would be lost")
	}

	// Recovery 1: the active TREE is the broken committed config, so
	// EnterConfigure clones it into the candidate and the operator can see and
	// fix the offending stanza — not the empty New() tree.
	active := st.ActiveTree()
	if active == nil {
		t.Fatal("ActiveTree() == nil after compile failure; `configure` would " +
			"clone an empty tree and the operator could not see the broken config")
	}
	if got := active.Format(); got == "" || !strings.Contains(got, "host-name box") ||
		!strings.Contains(got, "badgroup") {
		t.Fatalf("ActiveTree() does not contain the broken committed config; got:\n%s", got)
	}
	// Concretely confirm the configure candidate is seeded from it.
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure after compile failure: %v", err)
	}
	if cand := st.ShowCandidate(); !strings.Contains(cand, "host-name box") {
		t.Fatalf("configure candidate not seeded from the broken active tree; got:\n%s", cand)
	}

	// Recovery 2: the on-disk rollback history loaded, so `rollback 1` reaches
	// the last good config.
	if n := st.history.Len(); n < 1 {
		t.Fatalf("rollback history Len()=%d after compile failure; want >=1 "+
			"(the seeded xpf.conf.1 must load so `rollback` works)", n)
	}
	if err := st.Rollback(1); err != nil {
		t.Fatalf("Rollback(1) after compile failure: %v", err)
	}
	if cand := st.ShowCandidate(); !strings.Contains(cand, "host-name was-good") {
		t.Fatalf("Rollback(1) did not load the seeded prior-good config; got:\n%s", cand)
	}
}

// TestLoadAbsentDBIsNotCompileError guards the boundary: an ABSENT DB
// (start-fresh) must NOT report ErrConfigCompile — it returns no error and
// the daemon proceeds to its normal fresh-boot / bootstrap-from-file path.
// This keeps the #1960 fail-closed signal scoped to a genuinely present,
// non-compiling committed config.
func TestLoadAbsentDBIsNotCompileError(t *testing.T) {
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); err != nil {
		t.Fatalf("Load of an absent DB returned an error: %v", err)
	}
	if st.EverCommitted() {
		t.Fatal("absent DB: EverCommitted()=true; want false")
	}
	if st.ActiveConfig() != nil {
		t.Fatal("absent DB: ActiveConfig() != nil; want nil")
	}
}

// TestLoadValidCommittedConfigStillWorks is the no-regression guard: a
// committed DB that DOES compile loads normally — no ErrConfigCompile, a
// non-nil ActiveConfig, EverCommitted true. Without this, a too-aggressive
// fail-closed tag could break every normal boot.
func TestLoadValidCommittedConfigStillWorks(t *testing.T) {
	dir := t.TempDir()

	tree, errs := config.NewParser("system {\n  host-name box;\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	db, err := NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); err != nil {
		t.Fatalf("Load of a valid committed DB returned an error: %v", err)
	}
	if st.ActiveConfig() == nil {
		t.Fatal("valid committed DB: ActiveConfig()==nil; want non-nil")
	}
	if !st.EverCommitted() {
		t.Fatal("valid committed DB: EverCommitted()=false; want true")
	}
}
