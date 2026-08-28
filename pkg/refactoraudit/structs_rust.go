package refactoraudit

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// rustVis strips ANY Rust visibility prefix.
//
// #6937: this was a hardcoded list — "pub ", "pub(crate) ", "pub(super) ",
// "pub(in crate) " — and it silently missed `pub(in crate::afxdp)`, which
// is how `ForwardingState` (one of the two god-structs the issue was filed
// about) produced NO ROW AT ALL. Not a wrong count: absent, with no error.
//
// An unreadable declaration must never be indistinguishable from an absent
// one, which is why RustStructsFound exists and why
// TestRustScannerSeesPubInPathStructs6937 pins this exact shape.
var rustVis = regexp.MustCompile(`^pub(\([^)]*\))?\s+`)

// RustStructs is the Rust half of the #6937 signal.
//
// Rust has no AST available here the way go/ast is, so this is a
// depth-tracking scanner rather than a parser. It is deliberately
// conservative: a shape it cannot read confidently is SKIPPED rather than
// guessed at, because a wrong distinct-type count on a real struct is
// worse than an absent row. The Go side is authoritative for the two
// structs #6937 names; this exists so Rust accretion is not structurally
// invisible the way it is today.
//
// What it counts: `struct Name {` ... `}` at brace depth 0, then each
// `name: Type` field at depth 1 inside it. What it skips: tuple structs
// (`struct P(u32, u32);`) and unit structs (`struct M;`), which have no
// named fields to accrete; anything inside a `fn`; and the inner fields
// of a nested brace, mirroring the Go side's collapse.
func RustStructs(root string, audited func(relPath string) bool) ([]StructRow, error) {
	var rows []StructRow
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".rs") {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || !audited(rel) {
			return nil
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
		depth := 0
		inStruct := false
		structDepth := 0
		var name string
		var fields int
		var types map[string]struct{}

		flush := func() {
			if inStruct && name != "" {
				rows = append(rows, StructRow{
					Name: name, Path: rel,
					Fields: fields, DistinctTypes: len(types),
				})
			}
			inStruct, name, fields, types = false, "", 0, nil
		}

		for sc.Scan() {
			raw := sc.Text()
			line := strings.TrimSpace(raw)
			if i := strings.Index(line, "//"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line == "" || strings.HasPrefix(line, "#[") {
				continue
			}

			if !inStruct && depth == 0 {
				if n, ok := rustStructHeader(line); ok {
					inStruct, name = true, n
					fields, types = 0, map[string]struct{}{}
					structDepth = depth
				}
			} else if inStruct && depth == structDepth+1 {
				// A field line at the struct's own depth. Nested braces
				// push depth and are skipped by this guard, which is the
				// Rust equivalent of collapsing an anonymous inner struct.
				if n, t, ok := rustField(line); ok {
					fields++
					types[t] = struct{}{}
					_ = n
				}
			}

			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if inStruct && depth <= structDepth {
				flush()
			}
		}
		flush()
		return sc.Err()
	})
	return rows, err
}

// rustStructHeader matches a brace-struct declaration opening on this
// line. Tuple and unit structs are rejected: they carry no named fields.
func rustStructHeader(line string) (string, bool) {
	s := strings.TrimPrefix(rustVis.ReplaceAllString(line, ""), "default ")
	if !strings.HasPrefix(s, "struct ") {
		return "", false
	}
	if !strings.Contains(s, "{") {
		return "", false // tuple `struct P(..)`, unit `struct M;`, or a wrapped header
	}
	rest := strings.TrimSpace(strings.TrimPrefix(s, "struct "))
	name := rest
	for _, cut := range []string{"<", "{", "(", " ", "\t"} {
		if i := strings.Index(name, cut); i >= 0 {
			name = name[:i]
		}
	}
	if name == "" {
		return "", false
	}
	return name, true
}

// rustField matches `name: Type,` at a struct's own depth.
func rustField(line string) (string, string, bool) {
	// Strip visibility BEFORE splitting on the colon. #6937: a
	// `pub(in crate::afxdp)` prefix CONTAINS `::`, so splitting first put
	// the separator inside the visibility path — the name parsed as
	// "pub(in crate", failed the identifier check, and the field was
	// dropped. `ForwardingState` reported 3 fields instead of ~59, which
	// is a wrong number rather than an absent row and therefore harder to
	// notice than the missing-struct bug above. Pinned by
	// TestRustScannerCountsPubInPathFields6937.
	s := rustVis.ReplaceAllString(strings.TrimSuffix(strings.TrimSpace(line), ","), "")
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(s[:i])
	if name == "" || strings.ContainsAny(name, " \t(){}<>") {
		return "", "", false
	}
	typ := strings.TrimSpace(s[i+1:])
	if typ == "" {
		return "", "", false
	}
	return name, typ, true
}
