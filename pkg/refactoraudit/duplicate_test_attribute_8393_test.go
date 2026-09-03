package refactoraudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #8393: a Rust function carrying two `#[test]` attributes registers TWICE, and
// the reason it ends up with two is that it STOLE one from the function above it.
//
// The live instance this guard was written from: a new test was pasted between
// an existing test's doc comment and its `fn`, so the new function absorbed the
// old `#[test]` and the displaced function was left with none. It stopped running
// entirely — and it was the guard for the very renderer that same change rewrote.
//
// Nothing in the ordinary signal can see this:
//
//   - a test that stops existing cannot FAIL, so the suite stayed green;
//   - the total went UP, because the duplicate registration adds one, so even
//     "did the test count drop?" points the wrong way;
//   - `cargo test` prints ONE name in its failures block while reporting two
//     failures, and that discrepancy reads as noise.
//
// So the check has to be structural. Two `#[test]` on one function has no
// legitimate use — it runs the same body twice for no benefit — which is what
// makes this bannable outright rather than allowlisted. A guard that forces a
// workaround would be mis-specified; there is nothing here to work around.
//
// Deliberately NOT checked: "a fn inside `mod tests` with no `#[test]`". That
// over-approximates — test modules legitimately hold helpers, builders and
// fixtures — and a guard that fires on correct code teaches people to route
// around it. The duplicate is the sound half, and it is the half that actually
// marks the theft.
func TestNoRustFunctionCarriesTwoTestAttributes8393(t *testing.T) {
	root := repoRoot(t)

	var scanned int
	var findings []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "target", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		scanned++
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		findings = append(findings, duplicateTestAttrs8393(rel, string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// A zero from a scanner is worth nothing if the scanner never looked at
	// anything. The tree has hundreds of .rs files; a handful means the walk
	// broke, not that the repo shrank.
	if scanned < 100 {
		t.Fatalf("only scanned %d .rs files — the walk is broken, so the "+
			"'no duplicates' result below would be vacuous", scanned)
	}

	for _, f := range findings {
		t.Errorf("%s\n\nTwo `#[test]` attributes on one function register it twice, and the "+
			"usual cause is that it took the attribute belonging to the function above it — "+
			"which then stops running silently (#8393). Delete the stray attribute AND check "+
			"that the function it belonged to still has one:\n\n"+
			"    cargo test <filter> -- --list | sort | uniq -d\n\n"+
			"Verify by the registered LIST, never by the pass count — the count goes UP when "+
			"this happens.", f)
	}
}

// testAttrLine reports whether a trimmed line is a test-registering attribute.
// Matched exactly rather than by substring so a doc comment mentioning
// `#[test]` in prose — of which this repo has several — is not a finding.
func testAttrLine(trimmed string) bool {
	switch trimmed {
	case "#[test]", "#[tokio::test]":
		return true
	}
	return strings.HasPrefix(trimmed, "#[test_case") ||
		strings.HasPrefix(trimmed, "#[tokio::test(")
}

// duplicateTestAttrs8393 returns one finding per function preceded by two or
// more test attributes. Split out from the test body so the detector can be
// exercised against known-good and known-bad input directly — a scanner whose
// only evidence is "it found nothing in the repo" is indistinguishable from one
// whose pattern never matches.
func duplicateTestAttrs8393(rel, src string) []string {
	var out []string
	var attrs []int // 1-based line numbers of pending test attributes
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case testAttrLine(trimmed):
			attrs = append(attrs, i+1)
		case isFnDecl8393(trimmed):
			if len(attrs) >= 2 {
				where := make([]string, 0, len(attrs))
				for _, a := range attrs {
					where = append(where, itoa8393(a))
				}
				out = append(out, rel+":"+itoa8393(i+1)+" — attributes at lines "+
					strings.Join(where, ", "))
			}
			attrs = nil
		case trimmed == "" ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#["):
			// doc comments, `#[ignore]`, `#[should_panic]`, `#[cfg(...)]` and
			// blank lines all legitimately sit between an attribute and its fn.
		default:
			// Any other code ends the attribute run.
			attrs = nil
		}
	}
	return out
}

func isFnDecl8393(trimmed string) bool {
	for _, p := range []string{"fn ", "pub fn ", "pub(crate) fn ", "async fn ",
		"pub async fn ", "const fn ", "unsafe fn "} {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return strings.HasPrefix(trimmed, "pub(") && strings.Contains(trimmed, ") fn ")
}

func itoa8393(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The detector needs its own table, because the repo-wide result is a ZERO and a
// zero proves nothing about a scanner that cannot match. The rows that matter are
// the near-misses: input that is CORRECT but structurally close to the defect. A
// detector that only passes the obvious-good and obvious-bad cases would fire on
// `#[ignore] #[test]` or on a doc comment quoting the attribute, and a guard that
// fires on correct code gets routed around rather than fixed.
func TestDuplicateTestAttrDetectorCanSeeAndCanAbstain8393(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			// The live #8393 shape: a test pasted between a doc comment and its fn.
			name: "attribute stolen by an inserted test",
			src: "    /// old doc\n    #[test]\n    /// new doc\n    #[test]\n" +
				"    fn inserted() {}\n",
			want: 1,
		},
		{
			name: "ordinary single test",
			src:  "    /// doc\n    #[test]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: two attributes, only one of them registering.
			name: "test plus ignore is not a duplicate",
			src:  "    #[test]\n    #[ignore]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: two attributes, only one of them registering.
			name: "test plus should_panic is not a duplicate",
			src:  "    #[test]\n    #[should_panic]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: prose mentioning the attribute must not count. This
			// repo's own comments discuss `#[test]` in several places.
			name: "doc comment quoting the attribute",
			src:  "    /// use #[test] here\n    /// and #[test] there\n    #[test]\n    fn ok() {}\n",
			want: 0,
		},
		{
			// NEAR-MISS: intervening code ends the run, so two tests separated
			// by a real function body are two separate registrations.
			name: "two separate tests are not a duplicate",
			src:  "    #[test]\n    fn a() {}\n    #[test]\n    fn b() {}\n",
			want: 0,
		},
		{
			name: "duplicate on an async test",
			src:  "    #[tokio::test]\n    #[tokio::test]\n    async fn dup() {}\n",
			want: 1,
		},
	}

	for _, tc := range cases {
		got := duplicateTestAttrs8393("x.rs", tc.src)
		if len(got) != tc.want {
			t.Errorf("%s: got %d findings, want %d\n  findings: %v\n  src:\n%s",
				tc.name, len(got), tc.want, got, tc.src)
		}
	}
}
