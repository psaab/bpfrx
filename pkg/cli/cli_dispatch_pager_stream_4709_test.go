package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cliterm"
)

func bufioReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

// morePrompt and clearPrompt are the exact control sequences pageStream writes
// around each "--More--" prompt. Tests strip them to recover the pure line
// content that was streamed.
const (
	morePrompt  = "\033[7m--More--\033[0m"
	clearPrompt = "\r        \r"
)

func stripPagerControls(s string) string {
	s = strings.ReplaceAll(s, morePrompt, "")
	s = strings.ReplaceAll(s, clearPrompt, "")
	return s
}

// countingReader serves data from a fixed buffer and records how many bytes
// have been consumed, so a test can observe how much of the source pageStream
// has read at a given moment.
type countingReader struct {
	data []byte
	pos  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// spyKeys feeds a fixed reply byte for every --More-- prompt and invokes
// onFirstRead exactly once, the first time the pager asks for a keypress. That
// callback fires while the pager is paused at its first --More--, which is the
// moment to sample how much of the source has been consumed.
type spyKeys struct {
	reply       byte
	onFirstRead func()
	fired       bool
}

func (k *spyKeys) Read(p []byte) (int, error) {
	if !k.fired {
		k.fired = true
		if k.onFirstRead != nil {
			k.onFirstRead()
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = k.reply
	return 1, nil
}

// TestPageStreamOrderAndCompleteness proves that every byte of a multi-page
// input reaches the writer, in order, when the user pages through with spaces.
// A regression that dropped, reordered, or truncated output fails here.
func TestPageStreamOrderAndCompleteness(t *testing.T) {
	const n = 500
	var in strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, "line%04d\n", i)
	}

	src := strings.NewReader(in.String())
	// Plenty of spaces so the pager advances a full page each prompt.
	keys := strings.NewReader(strings.Repeat(" ", n))
	var out bytes.Buffer

	pageStream(src, &out, keys, 3)

	got := stripPagerControls(out.String())
	if got != in.String() {
		// Report the first divergence to keep the failure readable.
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(in.String(), "\n")
		if len(gotLines) != len(wantLines) {
			t.Fatalf("line count mismatch: got %d want %d", len(gotLines), len(wantLines))
		}
		for i := range wantLines {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("line %d mismatch: got %q want %q", i, gotLines[i], wantLines[i])
			}
		}
		t.Fatal("output mismatch")
	}
}

// TestPageStreamSmallNoPrompt confirms that output that fits on one screen is
// printed verbatim with no --More-- prompt, matching the pre-streaming behavior.
func TestPageStreamSmallNoPrompt(t *testing.T) {
	src := strings.NewReader("a\nb\nc\n")
	var out bytes.Buffer

	pageStream(src, &out, strings.NewReader(""), 10)

	if out.String() != "a\nb\nc\n" {
		t.Fatalf("unexpected output %q", out.String())
	}
	if strings.Contains(out.String(), "More") {
		t.Fatalf("pager prompt shown for sub-page output: %q", out.String())
	}
}

// TestPageStreamDoesNotBufferAll is the core anti-buffering assertion for
// #4709: when the pager pauses at its first --More--, it must NOT already have
// read the entire (large) source. It should have consumed only a bounded amount
// (roughly one bufio fill), proving output is streamed page-by-page rather than
// materialized whole in memory before paging.
func TestPageStreamDoesNotBufferAll(t *testing.T) {
	const n = 200000 // ~2.2 MB, far larger than any single buffer
	var in strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, "line%06d\n", i)
	}
	data := []byte(in.String())

	src := &countingReader{data: data}
	var readAtFirstMore int
	keys := &spyKeys{
		reply:       'q', // quit right after sampling so the test is fast
		onFirstRead: func() { readAtFirstMore = src.pos },
	}
	var out bytes.Buffer

	pageStream(src, &out, keys, 2)

	if readAtFirstMore == 0 {
		t.Fatal("first --More-- never reached; pager did not page a large input")
	}
	if readAtFirstMore >= len(data) {
		t.Fatalf("pager buffered the entire %d-byte source before the first --More-- "+
			"(read %d bytes); output is not streamed", len(data), readAtFirstMore)
	}
	// One screen of tiny lines plus a single bufio fill is well under 64 KiB.
	if readAtFirstMore > 64*1024 {
		t.Fatalf("pager read %d bytes before the first pause; expected a bounded, "+
			"screen-sized amount, not the whole table", readAtFirstMore)
	}
}

// TestPageStreamQuitDrains verifies that quitting ('q') drains the rest of the
// source. dispatchWithPager relies on this: the command writes into a pipe on
// another goroutine, and if the pager stopped reading on quit the writer would
// block forever on a full pipe.
func TestPageStreamQuitDrains(t *testing.T) {
	src := &countingReader{data: []byte(strings.Repeat("x\n", 5000))}
	keys := &spyKeys{reply: 'q'}
	var out bytes.Buffer

	pageStream(src, &out, keys, 2)

	if src.pos != len(src.data) {
		t.Fatalf("quit did not drain source: consumed %d of %d bytes", src.pos, len(src.data))
	}
}

// TestPageStreamEnterAdvancesThenPages locks the existing scroll semantics:
// pressing Enter at --More-- prints one extra line and then the next page, and
// nothing is lost. This guards the behavioral parity the streaming rewrite must
// preserve.
func TestPageStreamEnterAdvancesThenPages(t *testing.T) {
	src := strings.NewReader("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n")
	// First prompt: Enter; subsequent prompts: space.
	keys := strings.NewReader("\n        ")
	var out bytes.Buffer

	pageStream(src, &out, keys, 3)

	got := stripPagerControls(out.String())
	if got != "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n" {
		t.Fatalf("Enter/paging lost or reordered output: %q", got)
	}
}

// TestLineSourceSemantics pins the line-splitting semantics to match the
// previous strings.Split(output, "\n") + trailing-empty-drop behavior exactly.
func TestLineSourceSemantics(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a\nb\nc\n", []string{"a", "b", "c"}},
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"\n", []string{""}},
		{"a\n\nb\n", []string{"a", "", "b"}},
		{"abc", []string{"abc"}},
		{"a\r\nb\r\n", []string{"a\r", "b\r"}}, // only "\n" is the delimiter
	}
	for _, tc := range cases {
		// #7210: LineSource moved to pkg/cliterm and is now shared with the
		// remote CLI. This test moved with it rather than being left pointing
		// at a name that no longer exists — the splitting contract it pins is
		// unchanged and now covers BOTH surfaces.
		ls := cliterm.NewLineSource(strings.NewReader(tc.in))
		var got []string
		for ls.HasMore() {
			l, ok := ls.Next()
			if !ok {
				t.Fatalf("hasMore/next disagreed for %q", tc.in)
			}
			got = append(got, l)
		}
		if !equalStrings(got, tc.want) {
			t.Fatalf("lineSource(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
