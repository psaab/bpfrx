package refactoraudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// logClosedSentinel6874 marks the end of the historical `_Log.md`. Nothing may
// follow it.
const logClosedSentinel6874 = "<!-- LOG-CLOSED-SENTINEL-6874:"

// #6874: `_Log.md` was an append-only file every lane wrote to, which made it an
// O(n^2) serialization point — merging one PR flipped every other open PR to
// CONFLICTING, on that file alone, and resolving one did not help the others.
// Logs now go to `docs/log/<issue>.md`, one file per issue.
//
// This guard exists because the old destination is the one habit reaches for,
// and an append there is invisible until the next merge storm. A sentinel at
// the END is the cheap mechanical check: an append lands after it, so "is the
// sentinel the last content line" answers exactly the question.
//
// A sentinel at the end rather than a line count or a hash, deliberately —
// those would also fire on a legitimate edit to the historical body (fixing a
// typo, resolving an old marker), which is not what this is guarding against.
func TestLogMdIsClosedToNewEntries6874(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "_Log.md"))
	if err != nil {
		t.Fatalf("read _Log.md: %v", err)
	}
	lines := strings.Split(string(raw), "\n")

	idx := -1
	for i, l := range lines {
		if strings.Contains(l, logClosedSentinel6874) {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("_Log.md has lost its LOG-CLOSED sentinel. It marks the file as closed "+
			"to new entries (#6874); without it nothing stops the O(n^2) append pattern "+
			"returning. Restore the line, or if _Log.md is being retired entirely, delete "+
			"this test in the same change. Expected to contain: %s", logClosedSentinel6874)
	}

	for i := idx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		t.Errorf("_Log.md line %d is AFTER the LOG-CLOSED sentinel:\n\n    %s\n\n"+
			"`_Log.md` is closed to new entries (#6874). Write your action log to "+
			"docs/log/<issue>.md — one file per issue — so your change does not conflict "+
			"with every other open PR. See docs/log/README.md.",
			i+1, strings.TrimSpace(lines[i]))
	}
}

// The convention this redirects to must actually exist. Without this, deleting
// docs/log/README.md would leave the guard above pointing at nothing and the
// rule undiscoverable.
func TestLogConventionIsDocumented6874(t *testing.T) {
	root := repoRoot(t)
	readme := filepath.Join(root, "docs", "log", "README.md")
	raw, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("docs/log/README.md is missing (%v) — the guard in this file redirects "+
			"writers there, so it must exist", err)
	}
	for _, want := range []string{"docs/log/<issue>.md", "merge=union"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("docs/log/README.md no longer mentions %q. The union-driver warning "+
				"in particular is load-bearing: it is the obvious one-line alternative and "+
				"it silently fuses same-minute entries (measured in #6874).", want)
		}
	}
}
