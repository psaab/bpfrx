package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUserspaceXDPShimObjectMatchesSourceManifest is the #4977 source→
// object freshness gate. It recomputes the freshness manifest from the
// working tree and asserts it byte-equals the committed
// userspace_xdp_manifest.json.
//
// A mismatch means the tracked pkg/dataplane/userspace_xdp_bpfel.o and
// the userspace-xdp/** source that produced it are out of lockstep —
// either:
//   - a userspace-xdp/** source or the build recipe changed without a
//     `make generate` (the embedded object is STALE), or
//   - a new *.rs module was added but not regenerated, or
//   - the tracked object changed without refreshing the manifest.
//
// The remedy is always `make generate`, which rebuilds the object
// (verifier-gated) and refreshes the manifest in one step.
func TestUserspaceXDPShimObjectMatchesSourceManifest(t *testing.T) {
	t.Parallel()

	const repoRoot = "../.."

	committedPath := filepath.Join(repoRoot, filepath.FromSlash(UserspaceXDPManifestRelPath))
	committedBytes, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed manifest %s: %v (run `make generate`)", UserspaceXDPManifestRelPath, err)
	}

	want, err := ComputeUserspaceXDPManifest(repoRoot)
	if err != nil {
		t.Fatalf("recompute manifest from working tree: %v", err)
	}
	wantBytes, err := MarshalUserspaceXDPManifest(want)
	if err != nil {
		t.Fatalf("marshal recomputed manifest: %v", err)
	}

	if string(committedBytes) == string(wantBytes) {
		return
	}

	// Drifted: build an operator-actionable diff instead of dumping two
	// blobs. Parse the committed manifest so we can point at the exact
	// input(s) that moved.
	got, perr := parseUserspaceXDPManifest(committedBytes)
	if perr != nil {
		t.Fatalf("committed manifest %s is not valid JSON: %v\nrun `make generate`",
			UserspaceXDPManifestRelPath, perr)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "userspace-xdp shim source is out of lockstep with the tracked object.\n")
	fmt.Fprintf(&b, "The embedded pkg/dataplane/userspace_xdp_bpfel.o may be STALE.\n")
	fmt.Fprintf(&b, "Fix: run `make generate` to rebuild the object and refresh %s.\n\n",
		UserspaceXDPManifestRelPath)

	if got.Object.SHA256 != want.Object.SHA256 {
		fmt.Fprintf(&b, "tracked object %s changed but the manifest was not refreshed:\n", want.Object.Path)
		fmt.Fprintf(&b, "  manifest %s\n  actual   %s\n\n", got.Object.SHA256, want.Object.SHA256)
	}

	gotInputs := make(map[string]string, len(got.Inputs))
	for _, e := range got.Inputs {
		gotInputs[e.Path] = e.SHA256
	}
	wantInputs := make(map[string]string, len(want.Inputs))
	for _, e := range want.Inputs {
		wantInputs[e.Path] = e.SHA256
	}

	for _, e := range want.Inputs {
		gh, ok := gotInputs[e.Path]
		switch {
		case !ok:
			fmt.Fprintf(&b, "new build input not in manifest: %s (added without `make generate`)\n", e.Path)
		case gh != e.SHA256:
			fmt.Fprintf(&b, "build input changed: %s\n  manifest %s\n  actual   %s\n", e.Path, gh, e.SHA256)
		}
	}
	for _, e := range got.Inputs {
		if _, ok := wantInputs[e.Path]; !ok {
			fmt.Fprintf(&b, "manifest input no longer present in tree: %s (removed without `make generate`)\n", e.Path)
		}
	}

	t.Fatal(b.String())
}

// TestUserspaceXDPManifestCoversTrackedShimInputs guards the input SET
// itself: the manifest must list the tracked object plus every
// freshness-relevant build input the enumerator finds, with no extras.
// This catches manifest hand-edits that drop or invent entries
// independently of any hash change.
func TestUserspaceXDPManifestCoversTrackedShimInputs(t *testing.T) {
	t.Parallel()

	const repoRoot = "../.."

	committedBytes, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(UserspaceXDPManifestRelPath)))
	if err != nil {
		t.Fatalf("read committed manifest: %v", err)
	}
	got, err := parseUserspaceXDPManifest(committedBytes)
	if err != nil {
		t.Fatalf("parse committed manifest: %v", err)
	}

	if got.Object.Path != userspaceXDPObjectRelPath {
		t.Fatalf("manifest object path = %q, want %q", got.Object.Path, userspaceXDPObjectRelPath)
	}

	wantPaths, err := userspaceXDPFreshnessInputPaths(repoRoot)
	if err != nil {
		t.Fatalf("enumerate freshness inputs: %v", err)
	}
	want := make(map[string]bool, len(wantPaths))
	for _, p := range wantPaths {
		want[p] = true
	}
	gotPaths := make(map[string]bool, len(got.Inputs))
	for _, e := range got.Inputs {
		gotPaths[e.Path] = true
	}

	for p := range want {
		if !gotPaths[p] {
			t.Errorf("freshness input %q missing from manifest (run `make generate`)", p)
		}
	}
	for p := range gotPaths {
		if !want[p] {
			t.Errorf("manifest lists %q which is not a recognized freshness input", p)
		}
	}

	// The build recipe and the Cargo lock/manifest are the highest-value
	// non-source inputs; assert they are present so a future refactor of
	// the fixed-input list cannot silently drop them.
	for _, must := range []string{
		"pkg/dataplane/build-userspace-xdp.sh",
		"userspace-xdp/Cargo.lock",
		"userspace-xdp/Cargo.toml",
		"userspace-xdp/rust-toolchain.toml",
	} {
		if !gotPaths[must] {
			t.Errorf("manifest must cover critical build input %q", must)
		}
	}
}
