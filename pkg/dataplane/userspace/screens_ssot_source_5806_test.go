package userspace

import (
	"encoding/json"
	"fmt"
	goscanner "go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate module root (go.mod) above pkg/dataplane/userspace")
	return ""
}

// TestScreenUnresolvedDispositionHasOneSource is a SOURCE-IDENTITY guard, not a
// value guard (#5806).
//
// The earlier tests asserted only that the disposition sentence APPEARS in the
// metric HELP and in the rendered status block. That permits exactly the failure
// the exported constant exists to prevent: replace both uses with identical
// duplicated string literals and every value-containment assertion still passes,
// while the two surfaces are now free to drift the moment either literal is
// edited. Equal values are not common source.
//
// So this asserts common source directly: the sentence exists as a literal
// EXACTLY ONCE in the tree — its `const` definition — and every consumer
// reaches it through the identifier. A duplicated literal raises the count and
// fails here.
//
// Scope of the scan is stated so it is not mistaken for broader: non-test .go
// files under pkg/ and cmd/. A copy introduced in a _test.go file would not be
// caught, which is acceptable — a test copy cannot cause the production
// surfaces to disagree.
func TestScreenUnresolvedDispositionHasOneSource(t *testing.T) {
	root := repoRoot(t)
	// A distinctive fragment that fits INSIDE ONE string-literal chunk. The
	// constant is a multi-line `+` concatenation, so any fragment spanning a
	// chunk boundary matches nothing in the source and the guard would pass
	// vacuously — the self-check below is what catches that.
	//
	// This guard's SUBJECT has moved twice, and the moves are the change to
	// understand before editing it. #7059 shared one tail between both
	// no-enforcement dispositions, because both states had the identical
	// consequence and differed only in why. #7168 gave the UNRESOLVED state a
	// substituted conservative default, making "no screen checks are applied"
	// false for it, so the tail was split and belonged to the inert disposition
	// alone. #7888 then settled the same posture for the INERT state, so the two
	// consequences are identical again and the tail is shared again — now
	// describing the substituted default rather than the absence of enforcement.
	//
	// The COUNT property never changed and is the point of the guard: the shared
	// sentence must appear exactly once across pkg/ and cmd/, however split
	// across `+` seams. What moves is which constants may contain it, and how
	// many — never how many literals may exist.
	const fragment = "the dataplane enforces a substituted conservative default for this zone"
	// Self-check FIRST, and now against BOTH constants: a fragment that has gone
	// stale matches nothing and the count below would pass vacuously at zero.
	// After #7888 both dispositions must reach the sentence through the shared
	// tail, so a fragment missing from either one is the tell that a constant was
	// re-inlined rather than composed.
	for _, c := range []struct {
		name  string
		value string
	}{
		{"ScreenUnresolvedDisposition", ScreenUnresolvedDisposition},
		{"ScreenInertDisposition", ScreenInertDisposition},
	} {
		if !strings.Contains(c.value, fragment) {
			t.Fatalf("guard fragment is stale: %q is not inside %s (%q)",
				fragment, c.name, c.value)
		}
	}
	// Sharing the consequence must NOT collapse the two states into one message.
	// The whole of #7059/#7888 is that an operator can tell WHICH configuration
	// they have — "the profile does not exist" and "the profile exists and
	// enforces nothing" have different remedies, and identical rendering is the
	// defect, not the fix.
	if ScreenUnresolvedDisposition == ScreenInertDisposition {
		t.Error("the two dispositions render identically; sharing the CONSEQUENCE must not " +
			"erase the diagnosis — an operator has to know whether to define the profile " +
			"or to add a check to it")
	}
	if !strings.Contains(ScreenUnresolvedDisposition, "does not resolve") {
		t.Errorf("ScreenUnresolvedDisposition lost its distinguishing cause: %q",
			ScreenUnresolvedDisposition)
	}
	if !strings.Contains(ScreenInertDisposition, "defined but enables no checks") {
		t.Errorf("ScreenInertDisposition lost its distinguishing cause: %q",
			ScreenInertDisposition)
	}
	if strings.Contains(ScreenInertDisposition, "does not resolve") {
		t.Errorf("ScreenInertDisposition must not tell an operator the reference does not "+
			"resolve — it DOES resolve, and saying otherwise sends them looking for a "+
			"definition that is present: %q", ScreenInertDisposition)
	}

	// Count OCCURRENCES, not files: a second copy in the SAME file is exactly as
	// drift-prone as one in another file, and a file-level count would miss it.
	//
	// The count is taken on the SPLICE-NORMALISED source (#6839 round 2), so a
	// copy deliberately broken across `+` concatenation chunks is rejoined before
	// counting. Round 1 normalised only the two files on the consumer list below,
	// so a split copy in any THIRD non-test file under pkg/ or cmd/ was invisible
	// to both halves: the raw scan could not see it (the fragment spans a chunk
	// boundary) and the splice check never looked at that file. Normalising the
	// whole walk makes the count itself the property — one literal, anywhere,
	// however split across a `" + "` seam — instead of a property of an
	// enumeration that has to be kept in sync with the consumer set.
	//
	// That widening is real, and measured both ways (#6839 round 3): a plain
	// `+`-seam copy planted in pkg/api/metrics.go — a file no round tested and
	// which is not on the consumer list — builds rc=0 and REDS this guard, and
	// reverting just this walk to the round-1 raw strings.Count shape makes that
	// same plant pass rc=0.
	//
	// The seam is also the BOUNDARY, and it is narrower than "however spelled".
	// concatSplice below requires double quotes around a single `+`, with
	// NOTHING but whitespace elsewhere in the seam, so the scan is a source-text
	// scan, not a semantic one.
	// Four escapes were planted and measured at round 3 — each `go build` rc=0
	// and this guard rc=0, i.e. a compiling duplicate the count cannot see:
	//
	//   1. the `+` seam interrupted by a `// comment`   (pkg/api/metrics.go)
	//   2. backtick raw-string chunks joined by `+`     (pkg/api/metrics.go)
	//   3. one character written `\x79`                 (pkg/api/metrics.go)
	//   4. strings.Join([]string{…}, "")                (pkg/grpcapi/…_text.go)
	//
	// Two of those (1 and 2) are split-concatenation copies, so the claim fails
	// even on its charitable reading. This is a deliberate limit, not a defect to
	// chase: catching them needs a go/ast or type-checked constant walk, and the
	// failure mode being defended against is an ordinary copy-paste of a
	// sentence, not an adversary hand-obfuscating one.
	//
	// FIXED in #7061. The scan used to count raw source bytes, so quoting this
	// sentence inside a `//` comment in any non-test .go under pkg/ or cmd/ red
	// the guard — measured — with a message asserting a duplicated literal that
	// "lets the metric HELP and the status block drift". A comment cannot cause
	// drift, and the risk was not theoretical: screens.go and
	// server_show_security_text.go carry long comments ABOUT this sentence, so
	// the guard was one reword away from firing on prose.
	//
	// Comments are now blanked before the count (blankGoComments). That also
	// narrows escape 1 above — a `+` seam interrupted by a comment is spliceable
	// once the comment is whitespace — which is measured in
	// TestBlankGoCommentsHidesProseAndExposesACommentInterruptedSeam_7061.
	// Escapes 2, 3 and 4 are unchanged and remain deliberate limits.
	total := 0
	var hits []string
	for _, sub := range []string{"pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, sub), func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") ||
				strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			if n := strings.Count(concatSplice.ReplaceAllString(blankGoComments(string(b)), ""), fragment); n > 0 {
				total += n
				hits = append(hits, fmt.Sprintf("%s (x%d)", p, n))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if total != 1 {
		t.Fatalf("the disposition sentence must exist as a literal EXACTLY ONCE (its "+
			"const definition) so every surface shares one source; found %d occurrence(s) "+
			"in %v. A duplicated literal — in any file, including this one's own — lets "+
			"the metric HELP and the status block drift.", total, hits)
	}

	// And the consumers must reach it by identifier, not by their own copy.
	//
	// What this list DOES cover, stated exactly (#6839 round 2): that each named
	// file mentions the identifier. It is no longer the only defence against a
	// split-concatenation copy — the tree-wide count above is spliced first, so a
	// split copy in ANY non-test .go file under pkg/ or cmd/ raises that count,
	// listed or not. Keeping the per-consumer splice check as well is deliberate
	// belt-and-braces: it reports the offending file by name with a message about
	// the shared constant, which is the more useful failure when the copy lands
	// in a known renderer.
	for _, consumer := range []string{
		filepath.Join(root, "pkg", "api", "metrics_descriptors_global.go"),
		filepath.Join(root, "pkg", "dataplane", "userspace", "screens.go"),
	} {
		blob, err := os.ReadFile(consumer)
		if err != nil {
			t.Fatalf("read %s: %v", consumer, err)
		}
		body := string(blob)
		if !strings.Contains(body, "ScreenUnresolvedDisposition") {
			t.Errorf("%s must reference the ScreenUnresolvedDisposition identifier", consumer)
		}
		// A split-concatenation copy: two adjacent quoted chunks that together
		// reproduce the sentence. Normalising away Go string concatenation and
		// re-counting catches it where the plain scan cannot.
		normalised := concatSplice.ReplaceAllString(blankGoComments(body), "")
		if n := strings.Count(normalised, fragment); n > 0 && consumer != filepath.Join(
			root, "pkg", "dataplane", "userspace", "screens.go") {
			t.Errorf("%s appears to inline the disposition via a split string "+
				"concatenation (%d occurrence(s) after splicing) instead of using the "+
				"shared constant", consumer, n)
		}
	}
}

// concatSplice matches a Go source string-concatenation seam — `" +\n\t\t"` in any
// spacing — so a literal deliberately broken across chunks can be rejoined and
// compared against the shared sentence.
var concatSplice = regexp.MustCompile(`"\s*\+\s*\n?\s*"`)

// blankGoComments replaces every Go comment in src with spaces, preserving the
// byte offsets and the newlines of everything else so the concatSplice seam
// regex and the offsets in any message still line up with the original file.
//
// #7061: without this the scan counted raw source bytes, so prose that merely
// QUOTED the disposition sentence reddened a guard whose message asserts a
// duplicated literal — a drift a comment cannot cause. The guard's subject is
// what the program says, not what the file contains.
//
// The scanner tolerates a file that does not parse: it reports errors to the
// handler and keeps going, and a malformed file would fail this package's own
// build long before this test runs.
func blankGoComments(src string) string {
	out := []byte(src)
	fset := token.NewFileSet()
	f := fset.AddFile("", fset.Base(), len(src))
	var sc goscanner.Scanner
	sc.Init(f, []byte(src), func(token.Position, string) {}, goscanner.ScanComments)
	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		start := f.Offset(pos)
		for i := start; i < start+len(lit) && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// TestScreenMissingProfilesPublishedToSnapshot binds the publication path the
// whole SSOT argument rests on (#5806): the metric and status block claim to
// report "the same set the dataplane was told about", which is only true while
// the snapshot actually carries it. Breaking that wiring previously passed every
// test.
//
// RED on revert: drop or misroute ScreenMissingProfiles in buildSnapshot and the
// published set no longer matches the exported builder.
func TestScreenMissingProfilesPublishedToSnapshot(t *testing.T) {
	// buildSnapshot enumerates ip-rules through the real netlink stack
	// (routes.go ruleListFn), which fails "operation not permitted" in a
	// restricted sandbox — BEFORE reaching the screen assertion below, so
	// without this the guard silently never runs.
	stubRuleListHermetic(t)

	cfg := unresolvedRefConfig()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 1)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	want := ScreenMissingProfileRefs(cfg)
	if len(want) == 0 {
		t.Fatal("fixture must contain at least one unresolved reference")
	}
	if len(snap.ScreenMissingProfiles) != len(want) {
		t.Fatalf("snapshot published %d missing-profile refs, want %d (%+v vs %+v) — "+
			"the metric/status SSOT claim depends on this path carrying the set",
			len(snap.ScreenMissingProfiles), len(want), snap.ScreenMissingProfiles, want)
	}
	for i := range want {
		if snap.ScreenMissingProfiles[i] != want[i] {
			t.Fatalf("published ref %d = %+v, want %+v", i, snap.ScreenMissingProfiles[i], want[i])
		}
	}

	// The Go struct being right is not enough: the SSOT claim is that the
	// DATAPLANE was told the same set, and the dataplane reads JSON. A rename of
	// the wire tag, or of the Rust-side field, breaks publication while leaving
	// every Go-struct assertion above green. Marshal and check the wire key and
	// its contents, and pin the names the Rust decoder expects
	// (userspace-dp/src/protocol/snapshot.rs `screen_missing_profile_zones`,
	// whose element carries `zone` / `profile`).
	blob, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var wire struct {
		Refs []struct {
			Zone    string `json:"zone"`
			Profile string `json:"profile"`
		} `json:"screen_missing_profile_zones"`
	}
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatalf("unmarshal snapshot wire: %v", err)
	}
	if len(wire.Refs) != len(want) {
		t.Fatalf("wire key screen_missing_profile_zones carried %d refs, want %d — "+
			"the Rust decoder reads this exact key, so a tag rename silently stops "+
			"publishing while the Go struct stays correct", len(wire.Refs), len(want))
	}
	for i := range want {
		if wire.Refs[i].Zone != want[i].Zone || wire.Refs[i].Profile != want[i].Profile {
			t.Fatalf("wire ref %d = {zone:%q profile:%q}, want {zone:%q profile:%q}",
				i, wire.Refs[i].Zone, wire.Refs[i].Profile, want[i].Zone, want[i].Profile)
		}
	}
}

// #7061: blankGoComments' own contract, plus the one escape it narrows.
//
// The middle row is the point. TestScreenUnresolvedDispositionHasOneSource's
// message asserts a duplicated LITERAL that "lets the metric HELP and the status
// block drift"; a comment cannot cause that, so a guard that reds on prose is
// asserting something it has not observed. Two production files already carry
// long comments about this very sentence.
func TestBlankGoCommentsHidesProseAndExposesACommentInterruptedSeam_7061(t *testing.T) {
	const sentence = "no screen checks are applied"

	t.Run("prose quoting the sentence is not counted", func(t *testing.T) {
		src := "package p\n\n// Prose only: " + sentence + " to this zone.\nvar x = 1\n"
		if strings.Count(src, sentence) != 1 {
			t.Fatalf("fixture is wrong: the raw source must contain the sentence once")
		}
		if n := strings.Count(blankGoComments(src), sentence); n != 0 {
			t.Fatalf("blankGoComments left %d occurrence(s) of a sentence that appears only in a comment", n)
		}
	})

	t.Run("a real string literal is still counted", func(t *testing.T) {
		src := "package p\n\nconst D = \"" + sentence + " to this zone\"\n"
		if n := strings.Count(blankGoComments(src), sentence); n != 1 {
			t.Fatalf("blankGoComments removed a real literal: %d occurrence(s), want 1", n)
		}
	})

	t.Run("the sentence inside a block comment is not counted", func(t *testing.T) {
		src := "package p\n\n/*\n" + sentence + " to this zone\n*/\nvar x = 1\n"
		if n := strings.Count(blankGoComments(src), sentence); n != 0 {
			t.Fatalf("blankGoComments left %d occurrence(s) of a sentence inside a block comment", n)
		}
	})

	t.Run("byte offsets are preserved", func(t *testing.T) {
		src := "package p\n\n// a comment\nconst D = \"x\"\n"
		if got, want := len(blankGoComments(src)), len(src); got != want {
			t.Fatalf("blankGoComments changed the length: %d, want %d — the concatSplice seam offsets depend on this", got, want)
		}
	})

	t.Run("escape 1: a + seam interrupted by a comment becomes spliceable", func(t *testing.T) {
		// Escape 1 in the scan's own list: a split-concatenation copy whose
		// seam is interrupted by a `//` comment, which defeated concatSplice
		// because the comment text sat between the two quotes. With the comment
		// blanked to spaces the seam is whitespace again and splices.
		src := "package p\n\nconst D = \"" + sentence + "\" + // seam\n\t\" to this zone\"\n"
		if n := strings.Count(concatSplice.ReplaceAllString(src, ""), sentence+" to this zone"); n != 0 {
			t.Fatalf("fixture is wrong: the RAW seam must not splice (that is what made it an escape); got %d", n)
		}
		spliced := concatSplice.ReplaceAllString(blankGoComments(src), "")
		if n := strings.Count(spliced, sentence+" to this zone"); n != 1 {
			t.Fatalf("blanking the comment did not make the seam spliceable: %d occurrence(s), want 1", n)
		}
	})
}
