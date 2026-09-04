package main

import (
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tree's Go sources must be gofmt-clean, asserted rather than assumed.
//
// WHY THIS EXISTS, and it is a signal problem rather than a style one. Twenty-two
// files had drifted out of format. None of them was wrong; the cost was that
// `gofmt -l` printed twenty-two names on every run, so the output stopped being
// a signal and became a list to mentally filter. I filtered it, and shipped an
// unformatted test file of my own an hour later without noticing — the new name
// was indistinguishable from the twenty-two I had already decided to ignore.
//
// That is the same failure this tree keeps meeting in other clothes: a check
// whose output is dominated by accepted noise cannot report the one thing that
// is new. The repair is not "look harder", it is to make the expected output
// EMPTY, so any name at all is a result.
//
// IT USES THE TOOLCHAIN'S OWN FORMATTER, not the `gofmt` binary on PATH.
// `go/format` is the package `gofmt` is built from, so this asserts against the
// formatting the compiler toolchain in `go.mod` defines. Shelling out would make
// the verdict depend on which `gofmt` happens to be installed, which is a
// different question and a flaky one — a developer with a newer Go could red
// this on a file their toolchain formats differently.
//
// NO ALLOWLIST, deliberately. An allowlist is right where an entry encodes a
// decision someone made for a reason (see #8258's dead-entry checks). Formatting
// carries no decision: every entry would mean "not yet run through a command
// that takes one second", and a list of those institutionalises exactly the
// noise this removes.
func TestTreeIsGofmtClean(t *testing.T) {
	roots := []string{"../../pkg", "../../cmd"}

	var unformatted []string
	var scanned int
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// Vendored and build-output trees are not ours to format.
				if name := info.Name(); name == "vendor" || name == "target" || name == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			formatted, err := format.Source(src)
			if err != nil {
				// A file that does not PARSE is a different failure, and it is
				// not this cell's. Report it rather than silently counting it
				// as clean, which is how a scanner starts agreeing with itself.
				t.Errorf("%s does not parse: %v", path, err)
				return nil
			}
			if string(formatted) != string(src) {
				unformatted = append(unformatted, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// POSITIVE CONTROL. A walk that matched nothing would compare an empty set
	// to an empty expectation and pass forever — the failure mode a scanner is
	// least able to notice about itself, because the scanner is what you would
	// consult to find it.
	if scanned < 500 {
		t.Fatalf("the walk found only %d .go files under pkg/ and cmd/ — the "+
			"roots or the suffix test are wrong, and this cell is asserting "+
			"cleanliness over almost nothing", scanned)
	}

	if len(unformatted) > 0 {
		t.Errorf("%d file(s) are not gofmt-clean:\n  %s\n\n"+
			"Run `gofmt -w` on them. This is a signal problem rather than a "+
			"style one: while any file is listed here, a NEWLY unformatted file "+
			"is indistinguishable from the backlog, which is exactly how one "+
			"got shipped.",
			len(unformatted), strings.Join(unformatted, "\n  "))
	}
}
