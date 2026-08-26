package refactoraudit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// log_duplicate_entry_test.go — the gate the conflict-marker sweep could not be.
//
// The marker sweep (conflict_markers_test.go) catches a conflict that was never
// resolved. It cannot catch a conflict that was resolved WRONGLY, which is the
// other half of the same accident and leaves no marker behind.
//
// Two of those were live in `_Log.md` when this was written. A bad union merge
// had copied the #6797 entry's whole body under the #6799 heading — so the
// record of #6799 read as a description of a different change entirely, while
// #6799's real body sat below it looking like a continuation — and an older
// merge had doubled a #5078 entry outright. Nothing could see either: the file
// is prose, and both are syntactically fine Markdown.
//
// The invariant: no two log entries may share a body. `_Log.md` is a
// chronological record of distinct changes, so two entries with byte-identical
// prose is a duplication accident every time — there is no legitimate reason to
// write the same paragraph under two different dates or issue numbers.

var logEntryHeading = regexp.MustCompile(`(?m)^## .*$`)

// TestLogHasNoDuplicatedEntryBodies fails when two `## ` entries in _Log.md have
// the same body.
//
// Bodies are compared with whitespace normalised, so a re-wrap does not hide a
// duplicate. Only substantial entries are compared: the file contains short
// stub entries and bare date dividers whose bodies legitimately coincide, and
// flagging those would make the gate noise rather than signal.
func TestLogHasNoDuplicatedEntryBodies(t *testing.T) {
	root := repoRootForMarkerSweep(t)
	raw, err := os.ReadFile(filepath.Join(root, "_Log.md"))
	if err != nil {
		t.Skipf("_Log.md unreadable (%v)", err)
	}

	entries := splitLogEntries(string(raw))
	if len(entries) < 500 {
		// _Log.md carries close to two thousand entries. A run that found almost
		// none is a pass that proves nothing — the split broke, not the file.
		t.Fatalf("only %d log entries were parsed; the split is not working", len(entries))
	}

	const minBody = 200 // bytes, normalised — skips stubs and date dividers
	var subst []logEntry
	for _, e := range entries {
		if len(e.body) >= minBody {
			subst = append(subst, e)
		}
	}

	var findings []string

	// (1) EXACT duplicates — a whole entry copied twice.
	seen := map[string]string{}
	for _, e := range subst {
		if first, ok := seen[e.body]; ok {
			findings = append(findings, "identical bodies: "+first+"\n         and: "+e.heading)
			continue
		}
		seen[e.body] = e.heading
	}

	// (2) PREFIX containment — one entry's whole body is the START of another's.
	//
	// This is the shape a bad union merge actually produces, and (1) cannot see
	// it. When a conflict is resolved by concatenating both sides under ONE
	// heading, the survivor's body is the losing entry's body followed by its
	// own, so the two are not identical — they nest. That is exactly how the
	// #6797 entry came to be duplicated under the #6799 heading, and how a
	// truncated copy of a #6865 entry sat beside its full version. Neither was
	// visible to an equality check, and neither left a conflict marker behind.
	//
	// It cannot fire on honest prose: an entry whose body begins with another
	// entry's ENTIRE body, verbatim and normalised, is a copy.
	for i, a := range subst {
		for j, b := range subst {
			if i == j || len(b.body) <= len(a.body) || !strings.HasPrefix(b.body, a.body) {
				continue
			}
			findings = append(findings,
				"body of "+a.heading+"\n      is a PREFIX of: "+b.heading)
		}
	}

	if len(findings) > 0 {
		t.Fatalf("%d duplicated entry body/bodies in _Log.md — a conflict resolved "+
			"WRONGLY leaves no marker behind, so this is the only thing that sees "+
			"it:\n  - %s", len(findings), strings.Join(findings, "\n  - "))
	}
	t.Logf("%d log entries, %d with a substantial body, no exact duplicates and "+
		"no prefix containment", len(entries), len(subst))
}

// TestLogDuplicateDetectorFindsADuplicate is the sensitivity control.
//
// Without it, the gate passing means either "the log is clean" or "the splitter
// returns one entry and the comparison never runs" — the same green. This drives
// the real splitter and the real comparison over a synthetic log built to
// contain exactly one duplicated body, and over one that differs only in
// wrapping (which must still be caught) and one whose entries genuinely differ
// (which must not be).
func TestLogDuplicateDetectorFindsADuplicate(t *testing.T) {
	body := strings.Repeat("some long entry body text that exceeds the floor. ", 6)

	dup := func(entries ...string) int {
		seen, n := map[string]bool{}, 0
		for _, e := range splitLogEntries(strings.Join(entries, "")) {
			if len(e.body) < 200 {
				continue
			}
			if seen[e.body] {
				n++
			}
			seen[e.body] = true
		}
		return n
	}

	a := "## 2026-01-01 — entry A\n\n" + body + "\n"
	b := "## 2026-01-02 — entry B\n\n" + body + "\n"
	// Same prose, re-wrapped: normalisation must still see it as a duplicate,
	// or a reflow would launder one past the gate.
	bWrapped := "## 2026-01-02 — entry B\n\n" + strings.ReplaceAll(body, ". ", ".\n  ") + "\n"
	c := "## 2026-01-03 — entry C\n\n" + body + "and this one is different.\n"

	if got := dup(a, b); got != 1 {
		t.Errorf("identical bodies: detector found %d duplicates, want 1", got)
	}
	if got := dup(a, bWrapped); got != 1 {
		t.Errorf("re-wrapped body: detector found %d duplicates, want 1 — a reflow "+
			"must not launder a duplicate past the gate", got)
	}
	if got := dup(a, c); got != 0 {
		t.Errorf("genuinely different bodies: detector found %d duplicates, want 0 — "+
			"the gate would fire on every honest entry", got)
	}
	// A short stub body must be ignored, or bare date dividers make the gate noise.
	stub := "## 2026-01-04 — s\n\ntiny\n"
	if got := dup(stub, stub); got != 0 {
		t.Errorf("short stubs: detector found %d duplicates, want 0", got)
	}

	// The CONTAINMENT half, which the equality check above cannot see. This is
	// the shape a bad union merge produces and the shape that was actually live
	// in _Log.md: one entry's whole body concatenated in front of another's.
	contained := func(entries ...string) int {
		var subst []logEntry
		for _, e := range splitLogEntries(strings.Join(entries, "")) {
			if len(e.body) >= 200 {
				subst = append(subst, e)
			}
		}
		n := 0
		for i, a := range subst {
			for j, b := range subst {
				if i != j && len(b.body) > len(a.body) && strings.HasPrefix(b.body, a.body) {
					n++
				}
			}
		}
		return n
	}
	// #6797's body glued in front of #6799's own — nests, is not identical.
	glued := "## 2026-01-05 — entry D\n\n" + body + " plus this entry's own distinct prose.\n"
	if got := dup(a, glued); got != 0 {
		t.Errorf("the equality check reported %d on a GLUED body; it cannot see "+
			"containment, and claiming otherwise would overstate the gate", got)
	}
	if got := contained(a, glued); got != 1 {
		t.Errorf("containment: detector found %d, want 1 — the bad-union shape "+
			"would pass the gate", got)
	}
	// The negative must be a genuinely UNRELATED body, not an extension.
	// `c` above is `body` plus a suffix, which IS containment by construction —
	// using it here would have asserted the gate stays quiet on exactly the shape
	// it is built to catch, and the assertion would have been the wrong way round.
	unrelated := "## 2026-01-06 — entry E\n\n" +
		strings.Repeat("an entirely separate change with its own prose. ", 6) + "\n"
	if got := contained(a, unrelated); got != 0 {
		t.Errorf("containment on genuinely unrelated bodies: found %d, want 0 — "+
			"the gate would fire on every honest entry", got)
	}
}

type logEntry struct{ heading, body string }

// splitLogEntries cuts _Log.md at `## ` headings and returns each entry with its
// body whitespace-normalised, so a re-wrap cannot hide a duplicate.
func splitLogEntries(s string) []logEntry {
	locs := logEntryHeading.FindAllStringIndex(s, -1)
	out := make([]logEntry, 0, len(locs))
	for i, loc := range locs {
		end := len(s)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, logEntry{
			heading: s[loc[0]:loc[1]],
			body:    strings.Join(strings.Fields(s[loc[1]:end]), " "),
		})
	}
	return out
}
