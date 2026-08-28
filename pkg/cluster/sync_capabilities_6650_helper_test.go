package cluster

import (
	"go/scanner"
	"go/token"
	"os"
	"strings"
	"testing"
)

func mustReadClusterFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// sourceContainsFlat searches with all whitespace collapsed, so a needle still
// matches when gofmt has wrapped the call across lines. A line-oriented search
// here would silently stop seeing the very statements these guards exist to
// pin the moment the surrounding code grows an indent level.
//
// #7449: the source is tokenised first, so COMMENTS are not searched. Before
// that, every guard built on this helper was satisfiable by prose. The failure
// mode is not hypothetical and not rare — it is the single most likely way the
// pinned call ever disappears, because whoever removes a call tends to leave a
// note saying so ("removed the advertisement here, see X"), and that note names
// the call. sync_conn.go already carries prose about sendCapabilities right
// beside the call it pins.
//
// Tokenising also drops the search from "any byte sequence in the file" to
// "the program text", which is what every caller of this helper meant. It
// still tolerates gofmt wrapping: token text is re-emitted space-separated and
// then flattened, so the result is whitespace-insensitive exactly as before.
func sourceContainsFlat(src, needle string) bool {
	flat := flattenGoTokens(src)
	return strings.Contains(flat, strings.Join(strings.Fields(needle), ""))
}

// flattenGoTokens re-emits src as its Go tokens with all whitespace removed.
// Comments are not tokens (the scanner is initialised without ScanComments),
// so they do not appear in the result.
//
// It does not require src to parse. These guards read production files that
// always do, but a scanner-level walk keeps the helper usable on a fragment
// and means a syntax error elsewhere in the file surfaces as the guard's own
// mismatch rather than as an unrelated parse failure.
func flattenGoTokens(src string) string {
	var b strings.Builder
	fset := token.NewFileSet()
	f := fset.AddFile("", fset.Base(), len(src))
	var sc scanner.Scanner
	sc.Init(f, []byte(src), nil, 0) // mode 0: do NOT emit comments
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if lit != "" {
			b.WriteString(lit)
			continue
		}
		b.WriteString(tok.String())
	}
	return strings.Join(strings.Fields(b.String()), "")
}

// #7449: the helper's own contract. Every source-identity guard in this package
// is built on sourceContainsFlat, so a defect here is a defect in all of them at
// once — the issue named one call site, but the same text search backed eight.
//
// The middle row is the one that matters, and it is the row the raw-text version
// failed: a file where the statement has been DELETED and a comment naming it
// left behind. That is not a contrived shape. It is what the file looks like
// after someone removes the call and explains why.
func TestSourceContainsFlatIgnoresComments_7449(t *testing.T) {
	const needle = "s.sendCapabilities(conn)"
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "the call is present",
			src:  "package p\nfunc f() {\n\ts.sendCapabilities(conn)\n}\n",
			want: true,
		},
		{
			// The whitespace tolerance the doc comment is really about: the
			// statement gaining indent levels as the surrounding code grows.
			name: "the call is present, more deeply indented",
			src:  "package p\nfunc f() {\n\tif x {\n\t\tfor {\n\t\t\ts.sendCapabilities(conn)\n\t\t}\n\t}\n}\n",
			want: true,
		},
		{
			// Measured, and TRUE ON MASTER TOO -- not a regression from the
			// #7449 tokenising change. The doc comment claims the needle "still
			// matches when gofmt has wrapped the call across lines", and for an
			// ARGUMENT-LIST wrap that is false in both versions: gofmt puts the
			// closing paren on its own line and adds a trailing comma, so the
			// flattened text is `s.sendCapabilities(conn,)` and the needle
			// `s.sendCapabilities(conn)` does not occur in it.
			//
			// Pinned rather than fixed. Making the search comma-insensitive
			// would loosen every guard in the package to buy tolerance for a
			// shape none of the eight pinned calls has (they are all
			// single-argument and fit on one line). Recorded here so the next
			// reader learns it from a test instead of from a guard that went
			// quiet after an unrelated reformat.
			name: "argument-list wrap adds a trailing comma and does NOT match",
			src:  "package p\nfunc f() {\n\ts.sendCapabilities(\n\t\tconn,\n\t)\n}\n",
			want: false,
		},
		{
			name: "DELETED, with a comment left behind that names it",
			src:  "package p\nfunc f() {\n\t// removed s.sendCapabilities(conn) here, see X\n}\n",
			want: false,
		},
		{
			name: "DELETED, named in a block comment",
			src:  "package p\n\n/* s.sendCapabilities(conn) used to live here */\nfunc f() {}\n",
			want: false,
		},
		{
			name: "DELETED, named in a doc comment on the function",
			src:  "package p\n\n// f used to call s.sendCapabilities(conn).\nfunc f() {}\n",
			want: false,
		},
		{
			name: "absent entirely",
			src:  "package p\nfunc f() {}\n",
			want: false,
		},
		{
			// A string literal IS program text, so this is a true match by the
			// helper's contract. Recorded so the distinction is deliberate: the
			// guard's subject is "the file says this", and only comments are
			// excluded, not every non-statement occurrence.
			name: "named inside a string literal",
			src:  "package p\nvar s = \"s.sendCapabilities(conn)\"\n",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceContainsFlat(tc.src, needle); got != tc.want {
				t.Fatalf("sourceContainsFlat(%q) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}
