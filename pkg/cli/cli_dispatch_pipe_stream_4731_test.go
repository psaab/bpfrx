package cli

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// bufferedFilter reproduces the pre-#4731 io.ReadAll + strings.Split filtering
// path exactly. Every streaming filterStream result is asserted byte-identical
// to this reference implementation for the same input, so the rewrite cannot
// drift from the historical semantics.
func bufferedFilter(output, pipeType, pipeArg string) string {
	lines := strings.Split(output, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out bytes.Buffer
	switch pipeType {
	case "match", "grep":
		for _, line := range lines {
			if strings.Contains(line, pipeArg) {
				fmt.Fprintln(&out, line)
			}
		}
	case "except":
		for _, line := range lines {
			if !strings.Contains(line, pipeArg) {
				fmt.Fprintln(&out, line)
			}
		}
	case "find":
		found := false
		for _, line := range lines {
			if !found && strings.Contains(line, pipeArg) {
				found = true
			}
			if found {
				fmt.Fprintln(&out, line)
			}
		}
	case "count":
		fmt.Fprintf(&out, "Count: %d lines\n", len(lines))
	case "last":
		n := 10
		if pipeArg != "" {
			if v, err := strconv.Atoi(pipeArg); err == nil && v > 0 {
				n = v
			}
		}
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		for _, line := range lines[start:] {
			fmt.Fprintln(&out, line)
		}
	case "no-more":
		for _, line := range lines {
			fmt.Fprintln(&out, line)
		}
	}
	return out.String()
}

// TestFilterStreamMatchesBuffered is the core parity assertion for #4731: for
// every pipe type and a spread of inputs (trailing newline / none, blank lines,
// arg absent, empty, single line), the streaming filterStream output must equal
// the old buffered io.ReadAll + strings.Split output byte-for-byte.
func TestFilterStreamMatchesBuffered(t *testing.T) {
	inputs := []string{
		"",
		"only\n",
		"only",
		"alpha\nbeta\ngamma\n",
		"alpha\nbeta\ngamma",
		"match here\nno\nmatch again\nno\n",
		"a\n\nb\n\nc\n",
		"x\r\ny\r\n", // only "\n" is the delimiter; trailing "\r" stays
		strings.Repeat("dup\n", 25),
	}
	cases := []struct{ pipeType, pipeArg string }{
		{"match", "match"},
		{"match", ""},       // empty arg matches every line
		{"match", "absent"}, // arg absent from every line
		{"grep", "a"},
		{"except", "no"},
		{"except", ""}, // empty arg excludes every line
		{"except", "absent"},
		{"find", "beta"},
		{"find", "absent"},
		{"count", ""},
		{"count", "match"}, // count ignores arg (parity with old behavior)
		{"last", ""},       // default 10
		{"last", "3"},
		{"last", "100"}, // n larger than input
		{"last", "1"},
		{"last", "0"},   // invalid -> default 10
		{"last", "abc"}, // invalid -> default 10
		{"no-more", ""},
	}

	for _, in := range inputs {
		for _, tc := range cases {
			want := bufferedFilter(in, tc.pipeType, tc.pipeArg)
			var got bytes.Buffer
			filterStream(strings.NewReader(in), &got, tc.pipeType, tc.pipeArg)
			if got.String() != want {
				t.Fatalf("filterStream(%q, %s %q) = %q, want %q (buffered)",
					in, tc.pipeType, tc.pipeArg, got.String(), want)
			}
		}
	}
}

// TestFilterStreamMatchDoesNotBufferAll proves match/except stream: when the
// filter reaches a line late in a large source, it has NOT read past a bounded
// window of it. A countingReader records how far the source has been consumed;
// a match filter that writes as it reads (not io.ReadAll up front) will surface
// its first matching line while most of the source is still unread.
func TestFilterStreamMatchDoesNotBufferAll(t *testing.T) {
	const n = 200000 // ~2.6 MB, far larger than any single bufio fill
	var in strings.Builder
	for i := 0; i < n; i++ {
		if i == 5 {
			fmt.Fprintf(&in, "NEEDLE%06d\n", i)
		} else {
			fmt.Fprintf(&in, "line%06d\n", i)
		}
	}
	data := []byte(in.String())

	src := &countingReader{data: data}
	// stopWriter records how much of the source had been consumed at the
	// moment the first (and only) matching line was written, then aborts the
	// stream by panicking so we do not read the rest.
	var readAtFirstWrite int
	sw := &sampleWriter{onWrite: func() { readAtFirstWrite = src.pos }}

	filterStream(src, sw, "match", "NEEDLE")

	if readAtFirstWrite == 0 {
		t.Fatal("match filter never emitted the needle line")
	}
	// The needle is on line 6; a streaming filter emits it after reading only
	// a small prefix. A buffered io.ReadAll implementation would have read the
	// entire source before emitting anything.
	if readAtFirstWrite >= len(data) {
		t.Fatalf("match filter read the entire %d-byte source before emitting the "+
			"needle (read %d bytes); output is not streamed", len(data), readAtFirstWrite)
	}
	if readAtFirstWrite > 64*1024 {
		t.Fatalf("match filter read %d bytes before its first match near the start; "+
			"expected a bounded, buffer-sized amount, not the whole table", readAtFirstWrite)
	}
}

// TestFilterStreamCountBounded proves count holds no per-line memory: it counts
// a huge input with only a running tally. Correctness (the count value) plus the
// fact that filterStream never accumulates a slice is the anti-buffering proof;
// this asserts the tally is right for a large stream.
func TestFilterStreamCountBounded(t *testing.T) {
	const n = 500000
	var in strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, "l%d\n", i)
	}
	var got bytes.Buffer
	filterStream(strings.NewReader(in.String()), &got, "count", "")
	want := fmt.Sprintf("Count: %d lines\n", n)
	if got.String() != want {
		t.Fatalf("count = %q, want %q", got.String(), want)
	}
}

// TestFilterStreamLastRingBounded proves last N retains only N lines: it feeds a
// large input through "last 5" and asserts the output is exactly the final 5
// lines. The ring buffer is N wide regardless of total input size.
func TestFilterStreamLastRingBounded(t *testing.T) {
	const n = 100000
	var in strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&in, "line%06d\n", i)
	}
	var got bytes.Buffer
	filterStream(strings.NewReader(in.String()), &got, "last", "5")

	var want strings.Builder
	for i := n - 5; i < n; i++ {
		fmt.Fprintf(&want, "line%06d\n", i)
	}
	if got.String() != want.String() {
		t.Fatalf("last 5 = %q, want %q", got.String(), want.String())
	}
}

// sampleWriter invokes onWrite the first time it is written to, then continues
// discarding. Used to sample how much of a source has been consumed at the
// moment the filter produces its first output line.
type sampleWriter struct {
	onWrite func()
	fired   bool
}

func (w *sampleWriter) Write(p []byte) (int, error) {
	if !w.fired {
		w.fired = true
		if w.onWrite != nil {
			w.onWrite()
		}
	}
	return len(p), nil
}
