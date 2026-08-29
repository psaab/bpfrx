package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cliterm"
)

// #7210: the remote CLI's pipe filter must consume its input INCREMENTALLY.
//
// WHY OUTPUT CORRECTNESS CANNOT TEST THIS. A streaming filter and a
// buffer-everything-then-filter one produce byte-identical output for every
// finite input. So no assertion over the result distinguishes them, and the
// property being fixed — bounded memory on huge output — is invisible to the
// obvious test. The instrument has to be TIME: feed a reader that yields some
// lines and then BLOCKS, and assert that filtered output appears while it is
// still blocked. A buffering implementation emits nothing until EOF, which
// never comes.

// blockingReader yields payload, then blocks until release is closed, then EOF.
type blockingReader struct {
	payload []byte
	off     int
	release chan struct{}
	done    bool
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if b.off < len(b.payload) {
		n := copy(p, b.payload[b.off:])
		b.off += n
		return n, nil
	}
	if !b.done {
		<-b.release // hold the stream open with no further data
		b.done = true
	}
	return 0, io.EOF
}

// syncBuf is written by the filter goroutine and read by the test goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRemotePipeFilterStreamsBeforeEOF7210(t *testing.T) {
	// Several matching lines up front, then the stream stalls. A buffering
	// implementation cannot emit any of them until EOF.
	var head strings.Builder
	for i := 0; i < 64; i++ {
		head.WriteString("hit line\n")
	}
	r := &blockingReader{payload: []byte(head.String()), release: make(chan struct{})}
	out := &syncBuf{}

	filterDone := make(chan struct{})
	go func() {
		cliterm.FilterStream(r, out, "match", "hit")
		close(filterDone)
	}()

	// Poll for output while the reader is still blocked. The deadline is
	// generous on purpose: it is a "did anything come out at all" bound, not a
	// latency assertion, so a loaded box does not turn this into a flake.
	deadline := time.Now().Add(10 * time.Second)
	got := ""
	for time.Now().Before(deadline) {
		if got = out.String(); strings.Contains(got, "hit line") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !strings.Contains(got, "hit line") {
		close(r.release)
		<-filterDone
		t.Fatal("no filtered output was produced while the input stream was still open, so the " +
			"filter is buffering to EOF before filtering. That is the #7210 defect: a large " +
			"`show ... | match ...` materializes the whole output in the cli process first")
	}

	// Release and confirm it terminates and produced everything.
	close(r.release)
	select {
	case <-filterDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the filter did not finish after the reader reached EOF")
	}
	if n := strings.Count(out.String(), "hit line"); n != 64 {
		t.Errorf("streamed output lost lines: got %d, want 64", n)
	}
}

// Control for the cell above: the same harness against a reader that blocks
// with NOTHING buffered must NOT produce output. Without this, "output appeared"
// could be explained by the harness emitting something on its own, and the
// streaming cell would pass for a reason unrelated to streaming.
func TestRemotePipeFilterProducesNothingWithoutInput7210(t *testing.T) {
	r := &blockingReader{payload: nil, release: make(chan struct{})}
	out := &syncBuf{}
	filterDone := make(chan struct{})
	go func() {
		cliterm.FilterStream(r, out, "match", "hit")
		close(filterDone)
	}()
	time.Sleep(200 * time.Millisecond)
	if s := out.String(); s != "" {
		t.Errorf("control: filter emitted %q with no input available — the streaming cell's "+
			"output would not prove streaming", s)
	}
	close(r.release)
	<-filterDone
}

// Acceptance 2: `| last N` for a huge N must clamp rather than allocate from N.
func TestRemotePipeLastClampsHugeN7210(t *testing.T) {
	if got := cliterm.ParseLastCount("2000000000"); got != cliterm.MaxTailLines {
		t.Errorf("| last 2000000000 parsed to %d, want the %d cap — an unclamped N is a "+
			"~32 GiB up-front allocation from an untrusted operand (#5037)", got, cliterm.MaxTailLines)
	}
	// The tail itself must still be correct for a normal N.
	var in strings.Builder
	for i := 0; i < 100; i++ {
		in.WriteString("line\n")
	}
	var out strings.Builder
	cliterm.FilterStream(strings.NewReader(in.String()), &out, "last", "3")
	if n := strings.Count(out.String(), "line"); n != 3 {
		t.Errorf("| last 3 emitted %d lines, want 3", n)
	}
}

// Binds the DELEGATION, not just the behaviour. If cmd/cli reintroduced its own
// filter, every behavioural test above would still pass — they exercise
// cliterm directly — so the thing that actually prevents a re-fork is that
// dispatchWithPipe calls the shared function. That is a fact about this
// package's source, so the source is what is asserted, via go/parser rather
// than a textual scan (the doc comments here and on dispatchWithPipe both
// mention the old buffering shape, which a grep would match).
func TestRemotePipeUsesTheSharedFilter7210(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "shared.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing shared.go: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "dispatchWithPipe" {
			body = fn.Body
			break
		}
	}
	if body == nil {
		t.Fatal("dispatchWithPipe not found in shared.go — if it was renamed, move this test " +
			"with it; a missing function must not read as a passing delegation check")
	}

	callsShared, readsAll := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name == "cliterm" && sel.Sel.Name == "FilterStream" {
			callsShared = true
		}
		if pkg.Name == "io" && sel.Sel.Name == "ReadAll" {
			readsAll = true
		}
		return true
	})

	if !callsShared {
		t.Error("dispatchWithPipe does not call cliterm.FilterStream. The remote CLI must not " +
			"carry its own filter: the copy it used to have drifted into the #4968 case-folding " +
			"divergence, where `| match Foo` matched `foo` on remote but not local")
	}
	if readsAll {
		t.Error("dispatchWithPipe calls io.ReadAll — that is the #7210 defect verbatim, " +
			"materializing the command's entire output before the filter runs")
	}
}
