package config

// #5886 canary: a repository-wide guard against RAW read-only interface/unit
// derefs re-appearing in the remote/CLI presenter packages. The nil-safe walk
// owner is this package (RangeInterfaces / RangeUnits / LookupInterface /
// LookupUnit). A tolerant load / HA sync can leave a present-but-nil
// InterfaceConfig / InterfaceUnit map value, so a raw walk that does not
// nil-skip the value panics a read-only presenter (the #5886 DoS).
//
// The canary flags three dangerous shapes in any NON-test .go file under
// pkg/grpcapi / pkg/api / pkg/cli / pkg/monitoriface:
//
//  1. 2-var RANGE with a named value that is NOT nil-skipped on the next line
//     (`for k, v := range X.Interfaces.Interfaces { … v.Field … }`).
//  2. SAME-LINE map-index-then-deref (`if v, ok := X…[k]; ok && v.Field`).
//  3. MULTI-LINE map-index whose `ok` gates a block and whose value is NOT
//     nil-skipped on the next line (`if v, ok := X…[k]; ok {` then a bare
//     `v.Field` on a later line). This is #5931: `ok` proves KEY presence, not
//     a non-nil value, so the deref inside the block still nil-derefs. The
//     fixed fabric-lookup sites (server_cluster.go, …) route through
//     config.LookupInterface, which returns ok ONLY for a non-nil slot; a
//     future revert to the raw multi-line map index is caught here.
//
// A `_`-blank presence check (`if _, isLocal := X…[k]; isLocal {`) can never
// deref the value and is NOT flagged; a next-line `if v == nil { … }` guard is
// an accepted inline nil-skip (mirrors the range rule).
import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// reRange: a 2-var range over the interface or `.Units` map binding a NAMED
// value var (a `_` value is deref-free and safe).
var reRange = regexp.MustCompile(`^\s*for \w+, ([A-Za-z]\w*) := range \w+\.(?:Interfaces\.Interfaces|Units) \{\s*$`)

// reMapIndexDeref: SAME-LINE map-index-then-deref, `if v, ok := X.Interfaces.
// Interfaces[k]; ok && v.Field` (or `.Units[k]`) — the deref is in the same
// condition. Route through config.LookupInterface / LookupUnit (ok ⇒ non-nil).
var reMapIndexDeref = regexp.MustCompile(`:= \w+\.(?:Interfaces\.Interfaces|Units)\[[^\]]*\]; \w+ && \w+\.`)

// reMapIndexMultiline: MULTI-LINE map-index whose `ok` opens a block,
// `if v, ok := X.Interfaces.Interfaces[k]; ok {` with a NAMED value var (group
// 1; a `_`-blank value never derefs, so [A-Za-z] excludes it). The deref is on
// a LATER line, so reMapIndexDeref/reRange both miss it (#5931). Flagged unless
// the value is nil-skipped on the very next line.
var reMapIndexMultiline = regexp.MustCompile(`^\s*if ([A-Za-z]\w*), \w+ := \w+\.(?:Interfaces\.Interfaces|Units)\[[^\]]*\]; \w+ \{\s*$`)

// nilSkippedNext reports whether line `next` inline-guards value var `v` with a
// nil check (`if v == nil` / `if v != nil`) — the accepted inline nil-skip.
func nilSkippedNext(v, next string) bool {
	return strings.Contains(next, "if "+v+" == nil") || strings.Contains(next, "if "+v+" != nil")
}

// rawInterfaceDerefViolations returns the 0-based indices of lines in `lines`
// that match a dangerous raw interface/unit deref shape (#5886/#5931). Shared by
// the tree scan and the self-test so both exercise the identical detection.
func rawInterfaceDerefViolations(lines []string) []int {
	var out []int
	for i, l := range lines {
		if reMapIndexDeref.MatchString(l) {
			out = append(out, i)
			continue
		}
		if m := reMapIndexMultiline.FindStringSubmatch(l); m != nil {
			next := ""
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			if !nilSkippedNext(m[1], next) {
				out = append(out, i)
			}
			continue
		}
		if m := reRange.FindStringSubmatch(l); m != nil {
			next := ""
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			if !nilSkippedNext(m[1], next) {
				out = append(out, i)
			}
		}
	}
	return out
}

func TestNoRawInterfaceUnitRangeDerefInPresenters_5886(t *testing.T) {
	dirs := []string{"../grpcapi", "../api", "../cli", "../monitoriface"}
	var violations []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			lines := strings.Split(string(data), "\n")
			for _, idx := range rawInterfaceDerefViolations(lines) {
				violations = append(violations, path+":"+strconv.Itoa(idx+1)+": "+strings.TrimSpace(lines[idx]))
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("raw unguarded interface/unit deref in a read-only presenter (nil-deref DoS, #5886/#5931) — "+
			"add `if <v> == nil { continue }` or use config.RangeInterfaces/RangeUnits/LookupInterface/LookupUnit:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// TestNilInterfaceCanarySelfCheck_5931 pins the detection itself with in-test
// fixtures (no production source needed) and proves the #5931 multi-line
// extension is load-bearing: the multi-line shape is caught by the new regex and
// MISSED by the pre-#5931 pair (reRange + reMapIndexDeref).
func TestNilInterfaceCanarySelfCheck_5931(t *testing.T) {
	// The #5931 dangerous shape: ok gates a block, the deref is on a LATER line.
	multiline := []string{
		"\tif ifc, ok := cfg.Interfaces.Interfaces[name]; ok {",
		"\t\tout = ifc.Description",
		"\t}",
	}
	if got := rawInterfaceDerefViolations(multiline); len(got) != 1 || got[0] != 0 {
		t.Fatalf("multi-line map-index-deref NOT flagged (canary blind spot #5931): violations=%v", got)
	}
	// RED-ON-REVERT: the pre-#5931 regex pair MISSES the multi-line shape, so
	// reverting reMapIndexMultiline out would re-open the blind spot.
	if reMapIndexDeref.MatchString(multiline[0]) {
		t.Fatal("precondition: same-line reMapIndexDeref must NOT match the multi-line shape (it would already be covered)")
	}
	if reRange.MatchString(multiline[0]) {
		t.Fatal("precondition: reRange must NOT match the multi-line shape")
	}
	if !reMapIndexMultiline.MatchString(multiline[0]) {
		t.Fatal("reMapIndexMultiline must match the multi-line shape (the load-bearing extension)")
	}

	positives := [][]string{
		multiline,
		// same-line deref (shape 2, existing).
		{"\tif ifc, ok := cfg.Interfaces.Interfaces[name]; ok && ifc.Description != \"\" {", "\t}"},
		// unit-map multi-line.
		{"\tif u, ok := ifc.Units[num]; ok {", "\t\tx = u.VlanID", "\t}"},
		// range without a next-line nil-skip (shape 1, existing).
		{"\tfor name, ifc := range cfg.Interfaces.Interfaces {", "\t\tuse(ifc.Name)", "\t}"},
	}
	for i, p := range positives {
		if len(rawInterfaceDerefViolations(p)) == 0 {
			t.Errorf("positive[%d] not flagged (should be a violation): %q", i, p)
		}
	}

	negatives := [][]string{
		// _-blank presence-only: the value can never be dereferenced.
		{"\tif _, isLocal := cfg.Interfaces.Interfaces[name]; isLocal {", "\t\tcontinue"},
		// nil-safe accessor (the steered-to form, #5930).
		{"\tif ifc, ok := config.LookupInterface(cfg, name); ok {", "\t\tx = ifc.Description"},
		// raw map-index but nil-skipped on the very next line (accepted inline guard).
		{"\tif ifc, ok := cfg.Interfaces.Interfaces[name]; ok {", "\t\tif ifc == nil {", "\t\t\tcontinue", "\t\t}"},
		// range WITH a next-line nil-skip.
		{"\tfor name, ifc := range cfg.Interfaces.Interfaces {", "\t\tif ifc == nil {", "\t\t\tcontinue", "\t\t}"},
	}
	for i, ne := range negatives {
		if got := rawInterfaceDerefViolations(ne); len(got) != 0 {
			t.Errorf("negative[%d] false-positived at lines %v (should be safe): %q", i, got, ne)
		}
	}
}
