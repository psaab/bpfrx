package termsafe

import (
	"fmt"
	"strings"
	"testing"
)

// #6468: SanitizeRowForDisplay exists because guarding the ONE column believed
// to carry device text is wrong for a table scraped out of command stdout —
// column identity shifts, and "this column is numeric" is a property of the
// current upstream rather than of the protocol. These tests bind the
// whole-row property, not just that some escaping happened.

func TestSanitizeRowSanitizesEveryCell(t *testing.T) {
	// One hostile cell per position, so a guard applied to only some cells
	// leaves at least one raw ESC behind.
	cells := []string{
		"a\x1bb", "c\x1bd", "e\x1bf", "g\x1bh", "i\x1bj",
	}
	got := SanitizeRowForDisplay(cells...)
	if len(got) != len(cells) {
		t.Fatalf("row width must be preserved: want %d cells, got %d", len(cells), len(got))
	}
	for i, v := range got {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("cell %d must stay a string for %%s formatting; got %T", i, v)
		}
		if strings.Contains(s, "\x1b") {
			t.Fatalf("cell %d still carries a raw ESC — every cell of the row must be "+
				"sanitized, not just the one believed to be device-controlled; got %q", i, s)
		}
		if !strings.Contains(s, `\x1b`) {
			t.Fatalf("cell %d must render the ESC as a visible escape rather than dropping "+
				"the value; got %q", i, s)
		}
	}
}

func TestSanitizeRowSpreadsIntoPrintf(t *testing.T) {
	// The whole point of returning []any is that it spreads into the caller's
	// existing format string with the column widths unchanged.
	out := fmt.Sprintf("  %-20s %-14s %-10s %-10s %s",
		SanitizeRowForDisplay("rtr1\x1b[2Kforged", "ge-0-0-1", "2", "Up", "27")...)

	if strings.Contains(out, "\x1b") {
		t.Fatalf("the formatted row must carry no raw ESC; got %q", out)
	}
	if !strings.Contains(out, `\x1b`) || !strings.Contains(out, "ge-0-0-1") {
		t.Fatalf("the escaped cell and the clean cells must both render; got %q", out)
	}
	if strings.Contains(out, "\n") {
		t.Fatalf("a row must stay on one line; got %q", out)
	}
}

func TestSanitizeRowEscapesNewlineInACell(t *testing.T) {
	// A cell reached via strings.Fields can never hold a newline (the split
	// consumed it), but a cell decoded out of FRR's JSON output can — and there
	// a surviving LF forges an extra table row. This is why the row helper uses
	// the single-line sanitizer and not the block variant.
	got := SanitizeRowForDisplay("peer\nforged-row", "clean")
	first, ok := got[0].(string)
	if !ok {
		t.Fatalf("cell must stay a string; got %T", got[0])
	}
	if strings.Contains(first, "\n") {
		t.Fatalf("a newline inside a CELL forges a table row and must be escaped; got %q", first)
	}
	if !strings.Contains(first, `\x0a`) {
		t.Fatalf("the newline must render as \\x0a — if this ever passes through, the row "+
			"helper has been switched to the block sanitizer, which preserves LF by "+
			"design and is wrong for a field; got %q", first)
	}
}

func TestSanitizeRowLeavesCleanCellsIdentical(t *testing.T) {
	// Anti-pessimization: the uniform guard is only defensible because a clean
	// cell costs nothing. If this regresses, sanitizing every column stops being
	// free and the per-column ledger argument comes back.
	in := []string{"10.0.0.1", "ge-0-0-1", "65001", "Established", "00:12:34"}
	got := SanitizeRowForDisplay(in...)
	for i, v := range got {
		if v.(string) != in[i] {
			t.Fatalf("clean cell %d must pass through byte-identical: want %q, got %q",
				i, in[i], v.(string))
		}
	}
	if len(SanitizeRowForDisplay()) != 0 {
		t.Fatalf("an empty row must produce an empty argument list")
	}
}
