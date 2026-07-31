package ddns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// checkip_cause_structural_6545_test.go: the STRUCTURAL half of the
// urlParseCause no-leak invariant (#6545 review, MINOR).
//
// The value-based gate next door (TestURLParseCauseAlwaysReturnsAConstant)
// checks that the reasons it INVOKES are all declared. That is a coverage
// check, not a structural one, and the difference is not academic: a reviewer
// inserted a selective pass-through
//
//	if strings.HasPrefix(cause, "some-unexercised-prefix: ") { return cause }
//
// and the value-based test still PASSED, because no input it feeds produces
// that prefix. Adding a new constant returned only from a new, unexercised
// branch is invisible to it for the same reason.
//
// This test closes that hole by reading the SOURCE rather than the behaviour:
// every return statement inside urlParseCause must be a bare identifier naming
// one of the declared parseReason constants. That holds for branches no test
// input reaches, and it rejects the form the parseReason type alone cannot —
// an explicit parseReason(cause) conversion, which compiles fine.
//
// Together: the type stops the accidental pass-through at compile time, and
// this stops the deliberate-looking one at test time.

const checkipSourceFile = "checkip.go"

// TestURLParseCauseReturnsOnlyDeclaredConstants is the structural gate.
func TestURLParseCauseReturnsOnlyDeclaredConstants(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, checkipSourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", checkipSourceFile, err)
	}

	// Collect the parseReason constant names declared in this file. Reading
	// them from the source is not circular: the property under test is "every
	// return names a DECLARED CONSTANT", and a pass-through returns a local
	// variable, which is by construction not in this set. The separate
	// value-based test pins what those constants actually SAY, using a literal
	// list that is independent of production.
	declared := map[string]bool{}
	for _, decl := range file.Decls {
		gd, isGen := decl.(*ast.GenDecl)
		if !isGen || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, isVal := spec.(*ast.ValueSpec)
			if !isVal {
				continue
			}
			ident, isIdent := vs.Type.(*ast.Ident)
			if !isIdent || ident.Name != "parseReason" {
				continue
			}
			for _, name := range vs.Names {
				declared[name.Name] = true
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no parseReason constants in " + checkipSourceFile +
			"; this gate cannot work and must not silently pass")
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Name.Name == "urlParseCause" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("urlParseCause not found in " + checkipSourceFile +
			"; if it moved, move this gate with it rather than deleting it")
	}

	returns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, isReturn := n.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		returns++
		pos := fset.Position(ret.Pos())
		if len(ret.Results) != 1 {
			t.Errorf("%s: urlParseCause return has %d results, want exactly 1",
				pos, len(ret.Results))
			return true
		}
		ident, isIdent := ret.Results[0].(*ast.Ident)
		if !isIdent {
			t.Errorf("%s: urlParseCause returns a %T, not a bare constant identifier. "+
				"Every return must name one of the declared parseReason constants — a "+
				"conversion such as parseReason(cause), a call, or a literal can carry "+
				"input-derived text into the daemon log and the process-lifetime dedup key.",
				pos, ret.Results[0])
			return true
		}
		if !declared[ident.Name] {
			t.Errorf("%s: urlParseCause returns %q, which is NOT a declared parseReason "+
				"constant. Returning a local (for example the raw parse cause) leaks the "+
				"offending URL text into the checkip warning and its dedup key; add a "+
				"constant instead.", pos, ident.Name)
		}
		return true
	})

	// Guard the guard: if urlParseCause were reduced to a single return, or the
	// walk silently found nothing, this test would pass vacuously.
	if returns < 5 {
		t.Errorf("urlParseCause has only %d return statements; the AST walk is probably "+
			"not seeing the function body it is supposed to check", returns)
	}
}
