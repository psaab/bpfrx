package fsatomic

// Test-only export hook for fsatomic. Lives in the production package (not
// an _test.go file) so a DEPENDENT package's tests — configstore, which
// cannot reach the package-private seams — can drive a REAL post-rename
// directory-fsync failure end-to-end. Not for production callers. Mirrors
// the pkg/configstore/test_seams.go convention.

// SetAfterRenameSyncDirForTesting overrides the post-rename
// directory-fsync seam (afterRenameSyncDir) and returns a func that
// restores the previous value. It exists SOLELY so a cross-package test can
// force the durability-sync failure that occurs strictly AFTER a successful
// rename — the *PostRenameSyncError path — through a real WriteFileDurable
// call it does not control directly (#5234).
//
// The motivating consumer is pkg/configstore: its converge-to-C tests
// inject failures via the Store's writeActiveFn seam, which BYPASSES the DB
// layer's fmt.Errorf("persist %s: %w", …) wrap, so nothing proved the
// *PostRenameSyncError classification (errors.As in
// isPostRenameDurabilityFailure) still survives that %w boundary. With this
// hook a configstore test can drive db.WriteActive → writeTreeMarked →
// WriteFileDurable and fail the real dir-fsync, exercising the whole chain.
//
// Passing nil is a no-op that still returns a working restore func.
// Production code must NEVER call this; it mutates a process-global seam and
// is not safe under t.Parallel with concurrent WriteFileDurable callers.
func SetAfterRenameSyncDirForTesting(fn func(dir string) error) (restore func()) {
	prev := afterRenameSyncDir
	if fn != nil {
		afterRenameSyncDir = fn
	}
	return func() { afterRenameSyncDir = prev }
}
