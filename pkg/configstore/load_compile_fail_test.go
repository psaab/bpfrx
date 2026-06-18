package configstore

import (
	"errors"
	"path/filepath"
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
