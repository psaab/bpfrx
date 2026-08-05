package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate module root (go.mod) above pkg/dataplane/userspace")
	return ""
}

// TestScreenUnresolvedDispositionHasOneSource is a SOURCE-IDENTITY guard, not a
// value guard (#5806).
//
// The earlier tests asserted only that the disposition sentence APPEARS in the
// metric HELP and in the rendered status block. That permits exactly the failure
// the exported constant exists to prevent: replace both uses with identical
// duplicated string literals and every value-containment assertion still passes,
// while the two surfaces are now free to drift the moment either literal is
// edited. Equal values are not common source.
//
// So this asserts common source directly: the sentence exists as a literal
// EXACTLY ONCE in the tree — its `const` definition — and every consumer
// reaches it through the identifier. A duplicated literal raises the count and
// fails here.
//
// Scope of the scan is stated so it is not mistaken for broader: non-test .go
// files under pkg/ and cmd/. A copy introduced in a _test.go file would not be
// caught, which is acceptable — a test copy cannot cause the production
// surfaces to disagree.
func TestScreenUnresolvedDispositionHasOneSource(t *testing.T) {
	root := repoRoot(t)
	// A distinctive fragment that fits INSIDE ONE string-literal chunk. The
	// constant is a multi-line `+` concatenation, so any fragment spanning a
	// chunk boundary matches nothing in the source and the guard would pass
	// vacuously — the self-check below is what catches that.
	const fragment = "checks are applied to this zone; policy evaluation is unaffected"
	if !strings.Contains(ScreenUnresolvedDisposition, fragment) {
		t.Fatalf("guard fragment is stale: %q is not inside the constant %q",
			fragment, ScreenUnresolvedDisposition)
	}

	var hits []string
	for _, sub := range []string{"pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, sub), func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") ||
				strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			if strings.Contains(string(b), fragment) {
				hits = append(hits, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if len(hits) != 1 {
		t.Fatalf("the disposition sentence must exist as a literal EXACTLY ONCE (its "+
			"const definition) so every surface shares one source; found %d: %v. "+
			"A duplicated literal lets the metric HELP and the status block drift.",
			len(hits), hits)
	}
	if !strings.HasSuffix(hits[0], filepath.Join("pkg", "dataplane", "userspace", "screens.go")) {
		t.Errorf("the single literal must live in screens.go beside the builder; found %s", hits[0])
	}

	// And the consumers must reach it by identifier, not by their own copy.
	for _, consumer := range []string{
		filepath.Join(root, "pkg", "api", "metrics_descriptors_global.go"),
		filepath.Join(root, "pkg", "dataplane", "userspace", "screens.go"),
	} {
		b, err := os.ReadFile(consumer)
		if err != nil {
			t.Fatalf("read %s: %v", consumer, err)
		}
		if !strings.Contains(string(b), "ScreenUnresolvedDisposition") {
			t.Errorf("%s must reference the ScreenUnresolvedDisposition identifier", consumer)
		}
	}
}

// TestScreenMissingProfilesPublishedToSnapshot binds the publication path the
// whole SSOT argument rests on (#5806): the metric and status block claim to
// report "the same set the dataplane was told about", which is only true while
// the snapshot actually carries it. Breaking that wiring previously passed every
// test.
//
// RED on revert: drop or misroute ScreenMissingProfiles in buildSnapshot and the
// published set no longer matches the exported builder.
func TestScreenMissingProfilesPublishedToSnapshot(t *testing.T) {
	cfg := unresolvedRefConfig()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 1)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	want := ScreenMissingProfileRefs(cfg)
	if len(want) == 0 {
		t.Fatal("fixture must contain at least one unresolved reference")
	}
	if len(snap.ScreenMissingProfiles) != len(want) {
		t.Fatalf("snapshot published %d missing-profile refs, want %d (%+v vs %+v) — "+
			"the metric/status SSOT claim depends on this path carrying the set",
			len(snap.ScreenMissingProfiles), len(want), snap.ScreenMissingProfiles, want)
	}
	for i := range want {
		if snap.ScreenMissingProfiles[i] != want[i] {
			t.Fatalf("published ref %d = %+v, want %+v", i, snap.ScreenMissingProfiles[i], want[i])
		}
	}
}
