package cliterm

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Junos-style output pipe filtering, shared by BOTH CLI surfaces: the
// in-process interactive CLI (pkg/cli) and the remote gRPC client (cmd/cli).
//
// WHY THIS LIVES HERE RATHER THAN BEING DUPLICATED. The two surfaces must agree
// on filter semantics, and a divergence between them is ALWAYS a bug, never a
// legitimate difference — #4968 is the proof: the remote copy lowercased both
// operands, so `| match Foo` matched `foo` on remote and not on local. Two
// copies can drift; one cannot. cliterm was already the established home for
// exactly this (the readline loop moved here "so there is one"), and it adds no
// dependency edge — both surfaces already import it, while cmd/cli deliberately
// does NOT import pkg/cli, which would drag the whole in-process CLI into the
// thin remote client.
//
// Everything here streams. match/except/find/no-more hold at most one line at a
// time; count keeps only a running tally; last keeps a bounded ring. None
// buffers the full output (#4731, #7210).

// MaxTailLines bounds the ring the `| last N` filter retains and grows,
// independent of the operator-supplied N (#5037). `show` is a read-only
// (PermView) command, so without a bound a viewer could run
// `show ... | last 2000000000` and force a ~32 GiB up-front []string
// allocation. 100,000 lines is far more tail than any operator needs, yet caps
// the ring's worst-case slice header at ~1.6 MiB (64-bit) plus the retained
// line strings.
const MaxTailLines = 100_000

// ParseLastCount parses the `| last N` operand. It defaults to 10, ignores a
// non-positive or unparseable N (Junos-compatible leniency), and clamps N to
// MaxTailLines so the retained/grown ring is bounded by a fixed operator cap
// rather than an untrusted operand (#5037).
func ParseLastCount(arg string) int {
	n := 10
	if arg != "" {
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			n = v
		}
	}
	if n > MaxTailLines {
		n = MaxTailLines
	}
	return n
}

// LineSource is a one-line-lookahead reader. The lookahead is what lets a
// filter ask "is there more?" without reading the rest of the stream, which is
// what keeps the filters streaming rather than buffering.
// NewLineSource wraps src with the one-line lookahead the streaming filters
// and the pager both rely on.
func NewLineSource(src io.Reader) *LineSource {
	return &LineSource{r: bufio.NewReader(src)}
}

type LineSource struct {
	r       *bufio.Reader
	peeked  string
	hasPeek bool
	done    bool
}

// read pulls the next line directly from the underlying reader.
func (ls *LineSource) read() (string, bool) {
	line, err := ls.r.ReadString('\n')
	if len(line) == 0 && err != nil {
		ls.done = true
		return "", false
	}
	if err != nil {
		ls.done = true
	}
	return strings.TrimSuffix(line, "\n"), true
}

// Next returns the next line, or ("", false) at end of input.
func (ls *LineSource) Next() (string, bool) {
	if ls.hasPeek {
		ls.hasPeek = false
		return ls.peeked, true
	}
	return ls.read()
}

// HasMore reports whether another line is available, buffering it for the next
// next() call.
func (ls *LineSource) HasMore() bool {
	if ls.hasPeek {
		return true
	}
	if ls.done {
		return false
	}
	l, ok := ls.read()
	if !ok {
		return false
	}
	ls.peeked = l
	ls.hasPeek = true
	return true
}

// FilterStream reads newline-delimited output from src and applies a Junos-style
// output filter (match/grep/except/find/count/last/no-more), writing the result
// to out as each line is read.
//
// match/grep/except/find are CASE-SENSITIVE. Junos `| match` never case-folds
// (#4968).
//
// The line splitting is byte-identical to a
// strings.Split(output, "\n")-with-trailing-empty-dropped pass over the same
// input, so replacing a buffer-then-filter implementation with this one changes
// no output.
func FilterStream(src io.Reader, out io.Writer, pipeType, pipeArg string) {
	ls := NewLineSource(src)

	switch pipeType {
	case "match", "grep":
		for ls.HasMore() {
			line, _ := ls.Next()
			if strings.Contains(line, pipeArg) {
				fmt.Fprintln(out, line)
			}
		}
	case "except":
		for ls.HasMore() {
			line, _ := ls.Next()
			if !strings.Contains(line, pipeArg) {
				fmt.Fprintln(out, line)
			}
		}
	case "find":
		found := false
		for ls.HasMore() {
			line, _ := ls.Next()
			if !found && strings.Contains(line, pipeArg) {
				found = true
			}
			if found {
				fmt.Fprintln(out, line)
			}
		}
	case "count":
		count := 0
		for ls.HasMore() {
			ls.Next()
			count++
		}
		fmt.Fprintf(out, "Count: %d lines\n", count)
	case "last":
		n := ParseLastCount(pipeArg)
		// Circular buffer of the last n lines: slot i%n holds the i-th line,
		// overwriting the oldest once more than n have arrived. The ring GROWS
		// LAZILY (append until it holds n lines, then overwrite) so its memory
		// is O(min(n, lines produced)) — never O(operand), never pre-allocated
		// from an untrusted N (#5037). Only n lines are ever retained, not the
		// whole output.
		ring := make([]string, 0)
		count := 0
		for ls.HasMore() {
			line, _ := ls.Next()
			if len(ring) < n {
				ring = append(ring, line)
			} else {
				ring[count%n] = line
			}
			count++
		}
		total := count
		if total > n {
			total = n
		}
		for i := count - total; i < count; i++ {
			fmt.Fprintln(out, ring[i%n])
		}
	case "no-more":
		for ls.HasMore() {
			line, _ := ls.Next()
			fmt.Fprintln(out, line)
		}
	}
}
