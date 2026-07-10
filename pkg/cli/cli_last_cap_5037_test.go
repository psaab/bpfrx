package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestParseLastCountCap pins the operand bound for `| last N` (#5037). The
// `show` pipe is read-only (PermView), so an unbounded N would let a viewer
// force a huge up-front allocation. parseLastCount must default to 10, ignore
// non-positive/unparseable operands, and clamp any N above maxTailLines to the
// cap. Reverting the clamp makes the "2000000000" case return the raw operand
// (which the old code fed straight into make([]string, N)) and this test fails.
func TestParseLastCountCap(t *testing.T) {
	cases := []struct {
		arg  string
		want int
	}{
		{"", 10},                     // default
		{"5", 5},                     // in-range
		{"0", 10},                    // non-positive -> default
		{"-4", 10},                   // negative -> default
		{"abc", 10},                  // unparseable -> default
		{"100000", maxTailLines},     // exactly the cap
		{"100001", maxTailLines},     // just over the cap -> clamped
		{"2000000000", maxTailLines}, // the ~32 GiB OOM operand -> clamped
		{"99999999999999999999", 10}, // strconv overflow -> err -> default
	}
	for _, c := range cases {
		if got := parseLastCount(c.arg); got != c.want {
			t.Errorf("parseLastCount(%q) = %d, want %d", c.arg, got, c.want)
		}
	}
}

// TestFilterStreamLastHugeOperandBounded exercises the whole `| last N` path
// end-to-end with a huge operand on a modest input (#5037): the ring grows
// lazily and the operand is capped, so this returns the full input as its tail
// without attempting an operand-sized allocation. With the pre-fix
// make([]string, N) this input would try to allocate ~32 GiB.
func TestFilterStreamLastHugeOperandBounded(t *testing.T) {
	var in strings.Builder
	const lines = 2000
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&in, "line%06d\n", i)
	}

	var got bytes.Buffer
	filterStream(strings.NewReader(in.String()), &got, "last", "2000000000")

	// Input (2000 lines) is far below the cap, so `last <huge>` returns every
	// line in order — identical to the tail of the whole input.
	if got.String() != in.String() {
		t.Fatalf("filterStream last huge-operand: output did not equal the full %d-line input", lines)
	}
}

// TestFilterStreamLastCapTruncates proves the cap actually bounds retention:
// with more input lines than the cap, `| last <over-cap>` returns exactly the
// last maxTailLines lines (not the whole input, not an operand-sized slice).
func TestFilterStreamLastCapTruncates(t *testing.T) {
	total := maxTailLines + 25
	var in strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&in, "L%d\n", i)
	}

	var got bytes.Buffer
	// Operand well above the cap; retention must be bounded to maxTailLines.
	filterStream(strings.NewReader(in.String()), &got, "last", "999999999")

	outLines := strings.Split(strings.TrimRight(got.String(), "\n"), "\n")
	if len(outLines) != maxTailLines {
		t.Fatalf("last over-cap returned %d lines, want cap %d", len(outLines), maxTailLines)
	}
	// The very last line must be preserved (the tail is the newest lines).
	wantLast := fmt.Sprintf("L%d", total-1)
	if outLines[len(outLines)-1] != wantLast {
		t.Fatalf("tail last line = %q, want %q", outLines[len(outLines)-1], wantLast)
	}
	// The first retained line must be the (total-maxTailLines)-th line.
	wantFirst := fmt.Sprintf("L%d", total-maxTailLines)
	if outLines[0] != wantFirst {
		t.Fatalf("tail first line = %q, want %q", outLines[0], wantFirst)
	}
}
