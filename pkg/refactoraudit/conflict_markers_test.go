package refactoraudit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// conflict_markers_test.go — a repo-wide sweep for unresolved merge-conflict
// markers in tracked files.
//
// This exists because master carried SIX of them in `_Log.md`, across two
// blocks, for days. Both arrived the same way: a `git merge` conflicted,
// the conflict was not checked, and a `git add -A` staged the marker-laden
// file. Nothing caught it — `_Log.md` is prose, so no compiler, linter or
// test ever reads it, and the damage is invisible in `go test ./...` output.
// The second block swallowed an entire log entry into the "ours" side of a
// block whose "theirs" side was empty.
//
// A conflict marker in a SOURCE file breaks the build loudly, so the real
// exposure is everything else: docs, prose, configs, fixtures, JSON goldens.
// Those are exactly the files a marker can sit in indefinitely.
//
// The sweep is over `git ls-files`, not a filesystem walk, on purpose: this
// repo keeps many git worktrees under `.claude/wt-*`, and a walk would descend
// into every one of them — scanning other branches' trees, reporting findings
// that are not in THIS tree, and taking a long time to do it.

// markerPrefixes are the three conflict-marker line prefixes, ASSEMBLED AT
// RUNTIME rather than written as literals.
//
// That is not stylistic. A gate that greps for a string must not contain that
// string, or it reports itself: written literally, this file would be the
// permanent first hit of its own sweep, and the only way to keep the suite
// green would be to exempt the file — which then also exempts any real marker
// that ever lands in it. Assembling the needles means no line of this source
// begins with one.
func markerPrefixes() []string {
	return []string{
		strings.Repeat("<", 7) + " ",
		strings.Repeat("=", 7),
		strings.Repeat(">", 7) + " ",
	}
}

// TestNoUnresolvedConflictMarkers fails if any tracked file contains a line
// that BEGINS with a conflict marker.
//
// Anchored at line start, deliberately. An unanchored search false-positives on
// prose ABOUT conflict markers — including this file's own doc comments, and
// the `_Log.md` entries that describe resolving a conflict. The anchor is what
// makes the gate usable in a repo whose log discusses its own merges.
func TestNoUnresolvedConflictMarkers(t *testing.T) {
	root := repoRootForMarkerSweep(t)

	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable (%v); the sweep needs a git checkout", err)
	}
	// DEDUPE. `git ls-files` returns one row per STAGE for an unmerged path, so
	// during a conflicted merge the very file this gate is about appears three
	// times and every finding in it is reported three times over. That is exactly
	// the moment the output most needs to be readable, and a tripled finding list
	// reads like three separate defects.
	seenPath := map[string]bool{}
	var files []string
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if f == "" || seenPath[f] {
			continue
		}
		seenPath[f] = true
		files = append(files, f)
	}
	if len(files) < 100 {
		// A sweep that enumerated almost nothing is a PASS that proves nothing —
		// the failure mode where the gate goes green because it looked at an
		// empty set. This repo has thousands of tracked files.
		t.Fatalf("git ls-files returned only %d paths; the sweep did not run over "+
			"the repository", len(files))
	}

	prefixes := markerPrefixes()
	var findings []string
	scanned := 0
	for _, rel := range files {
		if rel == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			// A tracked path that cannot be read here is a submodule, a symlink
			// to nowhere, or a file removed in the working tree. Not this gate's
			// business.
			continue
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue // binary
		}
		scanned++
		for i, line := range strings.Split(string(data), "\n") {
			for _, p := range prefixes {
				if !strings.HasPrefix(line, p) {
					continue
				}
				// `=======` is also a legitimate Markdown setext heading underline
				// and a common ASCII rule, so it only counts as a marker when the
				// line is EXACTLY the seven characters. The other two carry a
				// trailing space and a branch name, which prose does not.
				if p == strings.Repeat("=", 7) && strings.TrimRight(line, "\r") != p {
					continue
				}
				findings = append(findings,
					filepath.Join(rel)+":"+itoa(i+1)+": "+truncate(line, 60))
			}
		}
	}
	if scanned < 100 {
		t.Fatalf("only %d text files were scanned; the sweep is not covering the "+
			"repository", scanned)
	}
	if len(findings) > 0 {
		t.Fatalf("unresolved merge-conflict markers in %d tracked line(s) — a "+
			"conflicted file was staged with `git add -A` without checking "+
			"`git diff --diff-filter=U` first:\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
	t.Logf("swept %d tracked text files, no conflict markers", scanned)
}

// TestConflictMarkerSweepDetectsAMarker is the sensitivity control.
//
// Without it, `TestNoUnresolvedConflictMarkers` passing means either "the repo
// is clean" or "the matcher matches nothing" — and those are the same green.
// This drives the same predicate over a synthetic conflicted document and
// requires all three marker lines to be found, plus requires the prose forms
// that must NOT match to stay unmatched.
func TestConflictMarkerSweepDetectsAMarker(t *testing.T) {
	prefixes := markerPrefixes()
	lt, eq, gt := prefixes[0], prefixes[1], prefixes[2]

	match := func(line string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				if p == eq && strings.TrimRight(line, "\r") != p {
					continue
				}
				return true
			}
		}
		return false
	}

	for _, want := range []string{lt + "HEAD", eq, gt + "origin/master"} {
		if !match(want) {
			t.Errorf("the sweep does not match %q; it would pass over a genuinely "+
				"conflicted file", want)
		}
	}
	// Directions that must stay quiet, or the gate is unusable in this repo:
	// `_Log.md` and the docs discuss conflict resolution in prose, and Markdown
	// uses `=====` rules and setext underlines.
	for _, quiet := range []string{
		"  " + lt + "HEAD",                    // indented, i.e. quoted in prose
		"a " + lt + "HEAD marker was staged",  // mid-line mention
		eq + "==",                             // a longer ASCII rule
		eq + " (a markdown setext underline)", // seven equals plus text
		"# " + gt + "origin/master",           // quoted inside a heading
	} {
		if match(quiet) {
			t.Errorf("the sweep matches %q; prose about conflict markers and "+
				"markdown rules would make the gate unusable", quiet)
		}
	}
}

func repoRootForMarkerSweep(t *testing.T) string {
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
			t.Fatal("could not find the repository root (no go.mod above the test)")
		}
		dir = parent
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
