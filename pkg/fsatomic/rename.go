package fsatomic

import (
	"fmt"
	"os"
	"path/filepath"
)

// RenameDurable renames oldpath to newpath and fsyncs the directory that now
// holds the entry, so the NAMESPACE change survives an unclean shutdown
// (#9057).
//
// # WHY THIS EXISTS AS ITS OWN PRIMITIVE
//
// The #1894 persistence taxonomy defines three classes — DurableState,
// AtomicGeneratedConfig, BestEffortKernelKnob — and every one of them is
// defined over REPLACE-A-FILE writes. Rotating a generation set
// (x -> x.1 -> x.2) is a different operation: it mutates the DIRECTORY, not a
// file's contents, and it had no row in the taxonomy and no primitive here.
// Four sites did it by hand and all four got it wrong the same way, which is
// what a missing class looks like from below.
//
// A rename is atomic with respect to the entry, but the directory ENTRY is not
// durable until the directory itself is fsynced. Without that, an unclean
// shutdown can lose the newest generation numbering — not the file contents,
// and not "corruption": the bounded, honest consequence is the newest seconds
// of a log plus possibly which generation a name points at.
//
// WHEN NOT TO USE IT: a SHIFT LOOP. Rotating N generations through this helper
// issues N directory fsyncs where one suffices, because every rename lands in
// the same directory. Do the renames, then call SyncDir once — that is the
// shape all four rotation sites use, and the sibling canary
// (TestNoUnsyncedRename) accepts a bare os.Rename in a function that also
// calls SyncDir for exactly this reason.
func RenameDurable(oldpath, newpath string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	if err := SyncDir(filepath.Dir(newpath)); err != nil {
		return fmt.Errorf("fsatomic: renamed %s -> %s but the directory fsync failed, "+
			"so the new name is not durable: %w", oldpath, newpath, err)
	}
	// A rename ACROSS directories changes two entry sets, and only one of them
	// is covered above. Callers doing a cross-directory move need both, and
	// silently syncing one of two would be the more dangerous outcome — it
	// looks like a durable move and is half of one.
	if src, dst := filepath.Dir(oldpath), filepath.Dir(newpath); src != dst {
		if err := SyncDir(src); err != nil {
			return fmt.Errorf("fsatomic: renamed %s -> %s across directories but the "+
				"SOURCE directory fsync failed, so the removal of the old name is "+
				"not durable: %w", oldpath, newpath, err)
		}
	}
	return nil
}
