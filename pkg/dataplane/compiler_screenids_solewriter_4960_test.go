package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestAssignScreenIDsIsTheSoleWriter_4960 is the canary the sibling key-set test
// could not be (#6894 r6 F1).
//
// The zone -> screen reference is resolved at two sites: against the compiled
// `result.ScreenIDs` (compiler_iface.go, buildZoneConfig) and against the raw
// `cfg.Security.Screen` (compiler_iface.go, mapZoneInterface). Neither is
// independently bound by a test, and the reasoning recorded for why that is
// acceptable — rather than a coverage hole to fill — is that the two key sets
// are identical BY CONSTRUCTION, so no config can distinguish the sites.
//
// `TestScreenIDsKeySetMirrorsConfig_4960` was written to pin that, and it only
// half does. It calls `assignScreenIDs` and compares its output against
// `cfg.Security.Screen`, so it fires when the divergence is introduced INSIDE
// that function — but a realistic second writer (a synced peer, a cached
// snapshot, an id reserved for a profile absent from this config) would be a
// SEPARATE SITE, writing after `assignScreenIDs` has returned. Measured:
// inserting `result.ScreenIDs["synced-from-peer"] = 0xfffe` at BOTH production
// call sites left the whole package GREEN. The comment claimed "this test is
// what fails at that moment"; for the shape it named, it was not.
//
// So bind the structural property the reasoning actually rests on: that
// `assignScreenIDs` is the ONLY thing that writes the map. It is today —
// compiler.go carries the single `result.ScreenIDs[name] = screenID`, and every
// other non-test mention is a read. A second writer anywhere makes the
// key sets separable, at which point the two resolution sites stop being
// redundant and each needs its own binding.
func TestAssignScreenIDsIsTheSoleWriter_4960(t *testing.T) {
	writers := map[string][]string{} // enclosing func -> file:line
	scanned := 0

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch st := n.(type) {
				case *ast.AssignStmt:
					// `X.ScreenIDs[k] = v` — an index expression on the LHS.
					for _, lhs := range st.Lhs {
						if isScreenIDsIndex(lhs) {
							writers[fn.Name.Name] = append(writers[fn.Name.Name],
								filepath.Join(name)+":"+itoa(fset.Position(st.Pos()).Line))
						}
					}
				case *ast.CallExpr:
					// `delete(X.ScreenIDs, k)` removes a key — also a write.
					if id, ok := st.Fun.(*ast.Ident); ok && id.Name == "delete" &&
						len(st.Args) == 2 && isScreenIDsSelector(st.Args[0]) {
						writers[fn.Name.Name] = append(writers[fn.Name.Name],
							filepath.Join(name)+":"+itoa(fset.Position(st.Pos()).Line))
					}
				}
				return true
			})
		}
	}

	// FLOOR: if the scan stopped seeing the package, `writers` would be empty
	// and the assertion below would pass having examined nothing.
	if scanned < 10 {
		t.Fatalf("scanned only %d non-test .go files in pkg/dataplane — the scan is "+
			"not reaching the package, so a second ScreenIDs writer could be added "+
			"without this canary noticing", scanned)
	}
	if len(writers) == 0 {
		t.Fatal("found ZERO writes to result.ScreenIDs. Either the map was renamed " +
			"or the write form changed (an index assignment or a delete); this " +
			"canary is now blind and must be taught the new shape")
	}

	var names []string
	for fn := range writers {
		names = append(names, fn)
	}
	sort.Strings(names)

	if len(names) != 1 || names[0] != "assignScreenIDs" {
		t.Errorf("result.ScreenIDs is written from %v, expected only assignScreenIDs.\n"+
			"  sites: %v\n\n"+
			"A SECOND writer breaks the construction invariant the zone->screen "+
			"redundancy argument rests on. `assignScreenIDs` builds ScreenIDs by "+
			"ranging cfg.Security.Screen, so while it is the sole writer the two "+
			"key sets are identical and the two resolution sites (buildZoneConfig "+
			"against the compiled map, mapZoneInterface against the raw config) "+
			"cannot be distinguished by any config — which is why neither is "+
			"independently bound and why that is recorded as acceptable rather "+
			"than a gap.\n\nWith another writer, a profile can exist in one and "+
			"not the other: a zone naming it passes one check and fails the other, "+
			"so WHICH site runs first changes the verdict. Give each site its own "+
			"test and correct the redundancy reasoning in "+
			"compiler_zone_screen_prepass_4960_test.go before removing this "+
			"canary (#6894 r6 F1).", names, writers)
	}
}

func isScreenIDsIndex(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	return ok && isScreenIDsSelector(ix.X)
}

func isScreenIDsSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "ScreenIDs"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
