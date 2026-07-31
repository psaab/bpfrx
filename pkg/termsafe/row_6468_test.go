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

// --- U+2028/U+2029 in a CELL (#6579 fold) -----------------------------------
//
// The first pass gave SanitizeBlockForDisplay line-separator escaping and left
// SanitizeForDisplay passing them through, on the reasoning that a single-line
// field is bounded by the caller's format string. Expanding the guard to
// per-cell row rendering made that gap reachable in exactly the path the row
// helper feeds: a cell IS a single-line field, so it now takes the single-line
// variant, and a U+2028 in it can break the row on a terminal or pager that
// honors it. Escaping LF but not U+2028 was incoherent — this variant is the
// STRICTER of the two about line breaks.

func TestSanitizeFieldEscapesUnicodeLineSeparators(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"line separator", "peer\u2028forged-row", `\u2028`},
		{"paragraph separator", "peer\u2029forged-row", `\u2029`},
	} {
		got := SanitizeForDisplay(tc.in)
		if strings.ContainsAny(got, "\u2028\u2029") {
			t.Fatalf("%s: a Unicode line separator inside a single-line FIELD forges a row "+
				"and must be escaped; got %q", tc.name, got)
		}
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s: want the visible %s escape (a \\xHH byte escape cannot represent "+
				"a rune above U+00FF); got %q", tc.name, tc.want, got)
		}
		if !strings.HasPrefix(got, "peer") || !strings.HasSuffix(got, "forged-row") {
			t.Fatalf("%s: the surrounding text must survive; got %q", tc.name, got)
		}
	}
}

func TestDisplaySafeRejectsUnicodeLineSeparators(t *testing.T) {
	// DisplaySafe is SanitizeForDisplay's fast-path guard: anything it calls
	// safe is returned UNSANITIZED. If it drifts out of lockstep with the
	// escaping rules, that escaping is dead code.
	for _, in := range []string{"peer\u2028x", "peer\u2029x"} {
		if DisplaySafe(in) {
			t.Fatalf("DisplaySafe(%q) must be false - it gates SanitizeForDisplay's "+
				"allocation-free return, so calling this safe skips the escaping entirely", in)
		}
	}
	if !DisplaySafe("rtr1.example.net") {
		t.Fatalf("a clean field must still take the fast path")
	}
}

func TestSanitizeRowEscapesUnicodeLineSeparatorInACell(t *testing.T) {
	// The row helper is why this matters: a cell IS a single-line field, so it
	// takes the single-line variant, and the gap was reachable per cell in the
	// very path #6579 expanded.
	got := SanitizeRowForDisplay("peer\u2028forged-row", "clean")
	first := got[0].(string)
	if strings.ContainsAny(first, "\u2028\u2029") {
		t.Fatalf("a Unicode line separator must not survive in a rendered cell; got %q", first)
	}
	if !strings.Contains(first, `\u2028`) {
		t.Fatalf("want the visible \\u2028 escape; got %q", first)
	}
	if got[1].(string) != "clean" {
		t.Fatalf("a clean sibling cell must pass through byte-identical; got %q", got[1])
	}
}

// --- cost (#6579 fold, MINOR-3) ---------------------------------------------

func TestSanitizeCleanFieldIsAllocationFree(t *testing.T) {
	// The substantive claim in SanitizeRowForDisplay's doc: the per-cell guard
	// itself is free, so guarding every column instead of a hand-picked subset
	// costs nothing at the cell. (The helper's own []any is a separate,
	// measured cost — see the benchmarks below.)
	clean := "10.0.0.1" + strings.Repeat("", 0) // defeat constant folding
	if n := testing.AllocsPerRun(200, func() { _ = SanitizeForDisplay(clean) }); n != 0 {
		t.Fatalf("SanitizeForDisplay must not allocate for a clean field, got %.0f allocs/op — "+
			"the whole-row guard is justified by this fast path being free", n)
	}
	block := "line one\n\tindented\n"
	if n := testing.AllocsPerRun(200, func() { _ = SanitizeBlockForDisplay(block) }); n != 0 {
		t.Fatalf("SanitizeBlockForDisplay must not allocate for a clean block, got %.0f allocs/op", n)
	}
}

// benchRoute mirrors the production shape: cells are STRUCT FIELDS, not string
// constants. Benchmarking constants understates the unguarded baseline, because
// the compiler boxes a constant into a read-only static and reports ~0 allocs
// for a path that allocates 3/row in production.
type benchRoute struct{ Network, NextHop, Path string }

var benchRoutes = func() []benchRoute {
	out := make([]benchRoute, 1000)
	for i := range out {
		out[i] = benchRoute{
			Network: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			NextHop: fmt.Sprintf("10.0.0.%d", i%256),
			Path:    "65001 65002 65003",
		}
	}
	return out
}()

var benchSink string

// BenchmarkSanitizedRowUnguarded is the honest baseline: the same render with
// NO sanitizer. Compare against BenchmarkSanitizedRowHelper to attribute cost.
func BenchmarkSanitizedRowUnguarded(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		for _, r := range benchRoutes {
			fmt.Fprintf(&sb, "%-24s %-20s %s\n", r.Network, r.NextHop, r.Path)
		}
		benchSink = sb.String()
	}
}

// BenchmarkSanitizedRowInline isolates the per-cell guard from the helper. It
// lands on the unguarded baseline, which is the measurement behind "sanitizing
// a clean cell is genuinely free".
func BenchmarkSanitizedRowInline(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		for _, r := range benchRoutes {
			fmt.Fprintf(&sb, "%-24s %-20s %s\n",
				SanitizeForDisplay(r.Network), SanitizeForDisplay(r.NextHop), SanitizeForDisplay(r.Path))
		}
		benchSink = sb.String()
	}
}

// BenchmarkSanitizedRowHelper is the shipped path. The delta against
// BenchmarkSanitizedRowUnguarded is one allocation and 48 bytes per row: the
// returned []any. Everything else is fmt's own boxing, paid either way.
func BenchmarkSanitizedRowHelper(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sb strings.Builder
		for _, r := range benchRoutes {
			fmt.Fprintf(&sb, "%-24s %-20s %s\n",
				SanitizeRowForDisplay(r.Network, r.NextHop, r.Path)...)
		}
		benchSink = sb.String()
	}
}
