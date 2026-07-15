package config

// #5886 canary: a repository-wide guard against RAW read-only interface/unit
// range-derefs re-appearing in the remote/CLI presenter packages. The nil-safe
// walk owner is this package (RangeInterfaces / RangeUnits / LookupInterface /
// LookupUnit). A tolerant load / HA sync can leave a present-but-nil
// InterfaceConfig / InterfaceUnit map value; a `for k, v := range
// X.Interfaces.Interfaces { … v.Field … }` (or `range X.Units`) that does not
// immediately nil-skip the value panics a read-only presenter (the #5886 DoS).
//
// This canary fails if any NON-test .go file in pkg/grpcapi / pkg/api / pkg/cli
// contains a 2-variable range over the interface or unit map whose value
// variable is NOT nil-skipped on the very next line. It does not require the
// shared iterator specifically (an inline `if v == nil { continue }` is fine) —
// it only forbids the raw, unguarded shape. New presenters must keep the guard.
import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestNoRawInterfaceUnitRangeDerefInPresenters_5886(t *testing.T) {
	// range over the interface map or a `.Units` map, binding a NAMED value var
	// (a `_` value is deref-free and safe).
	reRange := regexp.MustCompile(`^\s*for \w+, ([A-Za-z]\w*) := range \w+\.(?:Interfaces\.Interfaces|Units) \{\s*$`)

	// map-INDEX-then-deref in one condition: `if v, ok := X.Interfaces.Interfaces[k];
	// ok && v.Field` (or `.Units[k]`). This is the shape #5886/monitor.go:343 hid in
	// — the range regex above does not catch it. Route the lookup through
	// config.LookupInterface / LookupUnit (which return ok only for a non-nil slot)
	// so `ok` implies a safe dereference.
	reMapIndexDeref := regexp.MustCompile(`:= \w+\.(?:Interfaces\.Interfaces|Units)\[[^\]]*\]; \w+ && \w+\.`)

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
			for i, l := range lines {
				if reMapIndexDeref.MatchString(l) {
					violations = append(violations, path+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(l))
				}
				m := reRange.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				v := m[1]
				next := ""
				if i+1 < len(lines) {
					next = lines[i+1]
				}
				if !strings.Contains(next, "if "+v+" == nil") && !strings.Contains(next, "if "+v+" != nil") {
					violations = append(violations, path+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(l))
				}
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("raw unguarded interface/unit range-deref in a read-only presenter (nil-deref DoS, #5886) — "+
			"add `if <v> == nil { continue }` or use config.RangeInterfaces/RangeUnits:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
