package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #4900: a stale 10-xpf-* file whose os.Remove fails (read-only /etc, immutable
// bit, EACCES) was warn-only — neither aggregated into the write-error set nor
// returned. If no other generated file changed, Apply returned nil without a
// reload, so the surviving unit re-applied the removed address / VRF / bond /
// bridge / rename on the next reload or boot while the commit reported success.
// The fix aggregates stale-remove failures and fails the commit (Apply + Clear).

// blockedStaleEntry creates a directory named like a managed .network file with
// a child inside, so os.Remove(path) fails with ENOTEMPTY regardless of the
// test uid (a chmod-based read-only dir would be bypassed when tests run as
// root). It stands in for a real stale file whose delete fails.
func blockedStaleEntry(t *testing.T, dir, base string) string {
	t.Helper()
	p := filepath.Join(dir, base)
	if err := os.Mkdir(p, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "child"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestApply_StaleRemoveFailureFailsCommit is the #4900 fail-on-revert for the
// Apply sweep: a stale managed file that cannot be removed must fail the commit
// rather than silently survive. With the pre-fix warn-only sweep Apply returns
// nil and this fails RED.
func TestApply_StaleRemoveFailureFailsCommit(t *testing.T) {
	stubNetworkctl(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	stale := blockedStaleEntry(t, dir, filePrefix+"old.network")

	// Apply a fresh interface; the stale "old.network" is not in the desired
	// set, so the sweep tries — and fails — to remove it.
	err := m.Apply([]InterfaceConfig{
		{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
	})
	if err == nil {
		t.Fatal("Apply must fail when a stale managed file cannot be removed " +
			"(got nil — the removed host config survives a 'successful' commit)")
	}
	if !strings.Contains(err.Error(), "remove") {
		t.Errorf("Apply error should name the remove failure: %v", err)
	}
	// The stale entry must still exist (best-effort remove failed) — the exact
	// surviving-file scenario the commit now refuses to hide.
	if _, statErr := os.Stat(stale); statErr != nil {
		t.Errorf("stale entry unexpectedly gone (%v); the test did not exercise a real remove failure", statErr)
	}
}

// TestApply_StaleRemoveFailureFailsEvenWithNoOtherChange covers the exact
// scenario in the issue: the ONLY thing to do is delete a stale file, and that
// delete fails. Pre-fix `changed` stayed false and Apply returned nil with no
// reload; the fix returns the joined remove error.
func TestApply_StaleRemoveFailureFailsEvenWithNoOtherChange(t *testing.T) {
	stubNetworkctl(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	blockedStaleEntry(t, dir, filePrefix+"old.network")

	// Empty desired set: nothing to write, the sweep is the whole job.
	err := m.Apply(nil)
	if err == nil {
		t.Fatal("Apply(nil) must fail when the sole stale file cannot be removed " +
			"(got nil — no write changed, so the pre-fix path returned success)")
	}
	if !strings.Contains(err.Error(), "remove") {
		t.Errorf("Apply error should name the remove failure: %v", err)
	}
}

// The #4900 fail-on-revert for the teardown path used to be duplicated here
// against Clear, with the same fixture and the same assertion as the Apply(nil)
// cell above. #6852 retired Clear, and the twin went with it rather than being
// left as a test of a method that no longer exists.
//
// Deleting it costs no coverage, and that is checked rather than assumed: the
// cell above uses the identical blockedStaleEntry fixture and asserts the
// identical property, so the #4900 contract is still owned by a named cell. A
// retirement that deleted the LAST owner of a property would be a silent
// decommission; this one is not.
