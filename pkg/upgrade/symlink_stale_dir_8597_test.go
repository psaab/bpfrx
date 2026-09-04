package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #8597 (muse-004 K55) — the symlink flip could not recover from a stale
// DIRECTORY at its temp path.
//
// `repointSymlink`/`repointSymlinkAbs` cleared the temp path with `os.Remove`,
// which fails on a directory; the `os.Symlink` that follows then fails EEXIST.
// The symlink flip is the step that makes an upgrade take effect, so a leftover
// directory wedges every subsequent attempt until someone removes it by hand.
//
// The sibling seed path already fixed exactly this and says so —
// `pkg/upgrade/runtime/seed.go`'s `RemoveAll` carries the reasoning ("a stale
// DIRECTORY at the temp path ... makes os.Remove fail and the subsequent
// Symlink fail EEXIST"), and `stagedgen`'s atomic-symlink helper uses
// `RemoveAll` too. `flip.go` — the one that performs the actual cutover — was
// the copy left behind.

func tmpPathFor(linkPath string) string {
	return filepath.Join(filepath.Dir(linkPath), "."+filepath.Base(linkPath)+".tmp")
}

// TestRepointSymlinkRecoversFromAStaleTempDirectory_8597 is the RED-on-revert
// core, for both entry points.
func TestRepointSymlinkRecoversFromAStaleTempDirectory_8597(t *testing.T) {
	for _, tc := range []struct {
		name string
		flip func(r *Runner, link, target string) error
	}{
		{"relative", func(r *Runner, link, target string) error {
			return r.repointSymlink(link, filepath.Base(target))
		}},
		{"absolute", func(r *Runner, link, target string) error {
			return r.repointSymlinkAbs(link, target)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "v2")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatalf("mkdir target: %v", err)
			}
			link := filepath.Join(dir, "current")

			// The stale state: a DIRECTORY where the temp symlink goes, with
			// something inside it so a bare rmdir would not clear it either.
			stale := tmpPathFor(link)
			if err := os.MkdirAll(filepath.Join(stale, "leftover"), 0o755); err != nil {
				t.Fatalf("seed stale dir: %v", err)
			}

			r := &Runner{}
			if err := tc.flip(r, link, target); err != nil {
				t.Fatalf("the flip failed with a stale directory at the temp path: %v\n"+
					"os.Remove cannot clear a directory, so the Symlink that follows "+
					"fails EEXIST and every subsequent upgrade attempt wedges until "+
					"someone removes it by hand (#8597/K55)", err)
			}

			got, err := os.Readlink(link)
			if err != nil {
				t.Fatalf("readlink: %v", err)
			}
			if !strings.HasSuffix(got, "v2") {
				t.Errorf("link points at %q, want something ending in v2", got)
			}
			if _, err := os.Lstat(stale); !os.IsNotExist(err) {
				t.Errorf("the temp path still exists after a successful flip: %v", err)
			}
		})
	}
}

// TestRepointSymlinkStillWorksWithNoStaleState_8597 is the OVER-BROAD control:
// RemoveAll is more destructive than Remove, so the ordinary path — and
// repeated flips — must keep working, and the flip must not disturb anything
// outside its own temp path.
func TestRepointSymlinkStillWorksWithNoStaleState_8597(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"v1", "v2"} {
		if err := os.Mkdir(filepath.Join(dir, v), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", v, err)
		}
	}
	bystander := filepath.Join(dir, "keep-me")
	if err := os.WriteFile(bystander, []byte("x"), 0o600); err != nil {
		t.Fatalf("write bystander: %v", err)
	}

	link := filepath.Join(dir, "current")
	r := &Runner{}
	for _, v := range []string{"v1", "v2", "v1"} {
		if err := r.repointSymlink(link, v); err != nil {
			t.Fatalf("flip to %s: %v", v, err)
		}
		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("readlink: %v", err)
		}
		if got != v {
			t.Fatalf("link = %q after flipping to %q", got, v)
		}
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("the flip removed an unrelated file in the same directory: %v", err)
	}
}

// TestFlipUsesTheSamePathClearAsItsSiblings_8597 is the census. The defect was
// one copy of a shared pattern left behind, so the guard is that no copy is
// left behind again.
func TestFlipUsesTheSamePathClearAsItsSiblings_8597(t *testing.T) {
	src, err := os.ReadFile("flip.go")
	if err != nil {
		t.Fatalf("read flip.go: %v", err)
	}
	var offenders []string
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(line, "os.Remove(tmp)") {
			offenders = append(offenders, itoa8597flip(i+1)+": "+trimmed)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("flip.go clears its temp path with os.Remove, which cannot clear a "+
			"DIRECTORY — the sibling seed and stagedgen paths both use RemoveAll and "+
			"say why:\n  %s", strings.Join(offenders, "\n  "))
	}
	// Positive control: the census must be able to see the pattern at all.
	if !strings.Contains(string(src), "os.RemoveAll(tmp)") {
		t.Fatal("flip.go contains no temp-path clear of either spelling; the census " +
			"is looking at the wrong thing")
	}
}

func itoa8597flip(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
