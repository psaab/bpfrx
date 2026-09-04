package memlockcensus

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

// repoRoot walks up to the directory holding go.mod, so the scan reads the
// tree rather than a path baked in at authoring time.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

var funcLine = regexp.MustCompile(`^func\s+([A-Za-z0-9_]+)`)

// scanTree returns every (file, test) that calls rlimit.RemoveMemlock, read
// from the tree rather than from the registry — so the two can disagree.
func scanTree(t *testing.T) []Site {
	t.Helper()
	root := repoRoot(t)
	// git grep rather than a filepath.Walk: it honours .gitignore, so a stale
	// worktree artifact or a vendored copy cannot inflate the census.
	out, err := exec.Command("git", "-C", root, "grep", "-l", "rlimit.RemoveMemlock()", "--", "pkg/**/*_test.go").Output()
	if err != nil {
		t.Fatalf("git grep: %v", err)
	}
	var got []Site
	for _, rel := range strings.Fields(string(out)) {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		fn := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := funcLine.FindStringSubmatch(line); m != nil {
				fn = m[1]
			}
			if strings.Contains(line, "rlimit.RemoveMemlock()") && fn != "" {
				got = append(got, Site{File: rel, Test: fn})
			}
		}
	}
	sort.Slice(got, func(i, j int) bool {
		if got[i].File != got[j].File {
			return got[i].File < got[j].File
		}
		return got[i].Test < got[j].Test
	})
	// One row per (file, test): a test calling RemoveMemlock twice is still one
	// conditional guard, and counting the calls would make the registry a
	// measure of style rather than of coverage.
	var uniq []Site
	for i, s := range got {
		if i == 0 || got[i-1] != s {
			uniq = append(uniq, s)
		}
	}
	return uniq
}

// TestMemlockCensusMatchesTheTree is the gate: the set of memlock-gated guards
// cannot change without being recorded (#8371).
//
// Both directions matter and they fail differently. A guard added without a row
// grows the inert set silently — the exact way this reached 42. A row without a
// guard is a dead entry that makes the registry overstate what is conditional,
// which is the same false-record harm one surface over.
func TestMemlockCensusMatchesTheTree(t *testing.T) {
	tree := scanTree(t)

	// Positive control on the scanner itself. If the scan comes back empty the
	// registry check below would pass vacuously for an empty registry and fail
	// confusingly for a full one; either way the number is about the scanner,
	// not the tree.
	if len(tree) == 0 {
		t.Fatal("the scan found NO memlock-gated tests, which cannot be right while " +
			"the registry holds entries — the git grep pattern or the pathspec has " +
			"stopped matching, and every verdict below would be about the scanner")
	}

	key := func(s Site) string { return s.File + "\t" + s.Test }
	inReg := map[string]bool{}
	for _, s := range Registry {
		inReg[key(s)] = true
	}
	inTree := map[string]bool{}
	for _, s := range tree {
		inTree[key(s)] = true
	}

	var added, removed []string
	for _, s := range tree {
		if !inReg[key(s)] {
			added = append(added, s.File+" -> "+s.Test)
		}
	}
	for _, s := range Registry {
		if !inTree[key(s)] {
			removed = append(removed, s.File+" -> "+s.Test)
		}
	}

	if len(added) > 0 {
		t.Errorf("#8371: %d memlock-gated guard(s) exist in the tree but are NOT in the "+
			"registry:\n  %s\n\nA guard that skips on RemoveMemlock provides no protection "+
			"where the privilege is unavailable, and the package still reports ok — so a "+
			"reviewer who greps for it concludes the defect is guarded when it may not be. "+
			"Before adding a row, ask whether the test NEEDS a real BPF map: #8370 moved "+
			"four of its own below the privilege boundary using the fakeCtrlMap seam and "+
			"they now execute unprivileged. Record it here only if it genuinely needs the "+
			"kernel.", len(added), strings.Join(added, "\n  "))
	}
	if len(removed) > 0 {
		t.Errorf("#8371: %d registry row(s) name a guard that no longer exists:\n  %s\n\n"+
			"Delete the row. A dead entry makes the registry overstate how much of the "+
			"suite is environment-conditional, which is a false statement in the record "+
			"the registry exists to be.", len(removed), strings.Join(removed, "\n  "))
	}
}

// TestMemlockGuardsAreInertHere reports, by name, which guards did not run in
// THIS environment — and fails instead of reporting when the environment is
// declared to be one that must execute them.
//
// It deliberately does not fail by default. Turning every developer's
// `make test-go` red for an environment property they cannot change produces a
// gate everyone learns to ignore, which is worse than the silence it replaces.
// XPF_REQUIRE_MEMLOCK_GUARDS=1 is for a privileged CI leg, where a run that
// stops executing them IS a regression.
func TestMemlockGuardsAreInertHere(t *testing.T) {
	err := rlimit.RemoveMemlock()
	required := os.Getenv("XPF_REQUIRE_MEMLOCK_GUARDS") == "1"

	if err == nil {
		t.Logf("#8371: memlock is available here — all %d registered guards execute.",
			len(Registry))
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "#8371: memlock is NOT available here (%v), so the following %d "+
		"guards SKIP and their packages still report ok:\n", err, len(Registry))
	for _, s := range Registry {
		fmt.Fprintf(&b, "  %s -> %s\n", s.File, s.Test)
	}
	fmt.Fprintf(&b, "\nEach names a real defect it does not protect against in this "+
		"environment. Run as root or with CAP_SYS_RESOURCE to execute them.")

	if required {
		t.Fatalf("%s\n\nXPF_REQUIRE_MEMLOCK_GUARDS=1 declared this environment must "+
			"execute them, and it did not.", b.String())
	}
	t.Log(b.String())
}
