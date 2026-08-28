// Command structaudit emits the #6937 struct-heterogeneity rows for the
// modularity audit.
//
// It takes the exclusion regex and the audited roots as ARGUMENTS rather
// than reimplementing them. scripts/refactoring-audit-lib.sh is the single
// source of truth for "which paths are audited" and a second copy in Go
// would drift from it — which is the exact failure the lib was factored
// out to prevent (#6232/#7253).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/psaab/xpf/pkg/refactoraudit"
)

func main() {
	skip := flag.String("skip", "", "AUDIT_SKIP_RE from refactoring-audit-lib.sh (required)")
	goRoots := flag.String("go-roots", "", "AUDIT_ROOTS_GO, space separated")
	rsRoots := flag.String("rs-roots", "", "AUDIT_ROOTS_RS, space separated")
	all := flag.Bool("all", false, "emit every struct, not only those at or above the watch floor")
	flag.Parse()

	if *skip == "" {
		fmt.Fprintln(os.Stderr, "structaudit: -skip is required; pass $AUDIT_SKIP_RE so the "+
			"shell lib stays the single source of truth for exclusions")
		os.Exit(2)
	}
	skipRe, err := regexp.Compile(*skip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "structaudit: bad -skip regex: %v\n", err)
		os.Exit(2)
	}
	audited := func(rel string) bool { return !skipRe.MatchString(rel) }

	var rows []refactoraudit.StructRow
	collect := func(roots string, fn func(string, func(string) bool) ([]refactoraudit.StructRow, error)) {
		for _, r := range strings.Fields(roots) {
			if _, statErr := os.Stat(r); statErr != nil {
				continue // a root that does not exist is tolerated, as the LOC generator does
			}
			got, ferr := fn(r, func(rel string) bool { return audited(filepath.Join(r, rel)) })
			if ferr != nil {
				fmt.Fprintf(os.Stderr, "structaudit: %v\n", ferr)
				os.Exit(1)
			}
			for i := range got {
				got[i].Path = filepath.Join(r, got[i].Path)
			}
			rows = append(rows, got...)
		}
	}
	collect(*goRoots, refactoraudit.GoStructs)
	collect(*rsRoots, refactoraudit.RustStructs)

	refactoraudit.SortStructRows(rows)
	for _, r := range rows {
		tag := r.Tag()
		if tag == "" && !*all {
			continue
		}
		if *all && tag == "" {
			tag = "[-]"
		}
		fmt.Printf("%-12s %4d types  %5d fields  %s.%s\n", tag, r.DistinctTypes, r.Fields, r.Path, r.Name)
	}
}
