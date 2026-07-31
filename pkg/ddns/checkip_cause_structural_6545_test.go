package ddns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// checkip_cause_structural_6545_test.go: the STRUCTURAL half of the
// urlParseCause no-leak invariant (#6545 review).
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
// every return statement inside urlParseCause must name a package-level
// parseReason CONSTANT. That holds for branches no test input reaches, and it
// rejects the form the parseReason type alone cannot — an explicit
// parseReason(cause) conversion, which compiles fine.
//
// IT RESOLVES, IT DOES NOT NAME-MATCH (#6545 review round 6). The first version
// of this gate compared the returned identifier's NAME against the set of
// declared constant names, and a reviewer walked straight through it with a
// SHADOW:
//
//	if strings.HasPrefix(cause, "future private parser detail: ") {
//		causeMalformedURL := parseReason(cause)
//		return causeMalformedURL
//	}
//
// The local variable shadows the constant, the bare identifier still spells a
// declared name, and the mutation compiled, vetted, and passed both gates while
// returning the raw parse cause. Names are not identity. This version
// type-checks the file and asks what the identifier RESOLVES to: it must be a
// *types.Const, declared in the PACKAGE scope, whose name is one of the
// declared constants AND whose constant VALUE is one of the literals the
// value-based gate independently allows. A shadowing local resolves to a
// *types.Var and fails on the first of those.
//
// Together: the type stops the accidental pass-through at compile time, and
// this stops every deliberate-looking one at test time.

const checkipSourceFile = "checkip.go"

// unresolvedImporter deliberately resolves nothing. The gate type-checks
// checkip.go ALONE — every identifier it cares about (parseReason, the cause*
// constants, urlParseCause) is declared in that one file, so the package's
// imports do not need to resolve for those to be resolved correctly. Refusing
// to import keeps the gate hermetic and fast: no go/packages, no build of
// pkg/config, no module graph, nothing that can fail for an unrelated reason
// and turn a security gate into a flake.
//
// go/types keeps checking past the resulting errors because types.Config.Error
// is set below; without it, it would bail at the first unresolved import and
// Info.Uses would be empty.
type unresolvedImporter struct{}

func (unresolvedImporter) Import(path string) (*types.Package, error) {
	return nil, fmt.Errorf("unresolvedImporter deliberately does not resolve %q", path)
}

// TestURLParseCauseReturnsOnlyDeclaredConstants is the structural gate.
func TestURLParseCauseReturnsOnlyDeclaredConstants(t *testing.T) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, checkipSourceFile, nil, parser.SkipObjectResolution)
	if perr != nil {
		t.Fatalf("parse %s: %v", checkipSourceFile, perr)
	}

	// Collect the parseReason constant names declared in this file. Reading
	// them from the source is not circular: the property under test is "every
	// return resolves to a DECLARED PACKAGE CONSTANT", and a pass-through
	// returns a local, which is by construction not one. The separate
	// value-based test pins what those constants actually SAY, using a literal
	// list that is independent of production — and this gate cross-checks the
	// resolved constant's VALUE against that same independent list.
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

	// Type-check checkip.go on its own. Errors are EXPECTED and ignored: the
	// imports do not resolve. What must work is local/package-scope resolution.
	info := &types.Info{
		Defs: map[*ast.Ident]types.Object{},
		Uses: map[*ast.Ident]types.Object{},
	}
	conf := types.Config{
		Importer:                 unresolvedImporter{},
		Error:                    func(error) {}, // keep going past unresolved imports
		DisableUnusedImportCheck: true,
	}
	pkg, _ := conf.Check("ddns", fset, []*ast.File{file}, info)
	if pkg == nil {
		t.Fatal("go/types returned no package for " + checkipSourceFile +
			"; the gate cannot resolve identifiers and must not silently pass")
	}
	if len(info.Uses) == 0 {
		t.Fatal("go/types resolved no identifier uses in " + checkipSourceFile +
			"; the gate would pass vacuously")
	}
	// Non-vacuity of the resolution itself: the constants this gate exists to
	// recognise must actually be resolvable as package-scope constants.
	for name := range declared {
		obj := pkg.Scope().Lookup(name)
		if _, isConst := obj.(*types.Const); !isConst {
			t.Fatalf("package scope does not resolve %q to a constant (got %T); "+
				"the resolution the gate depends on is broken", name, obj)
		}
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, isFunc := decl.(*ast.FuncDecl); isFunc && fd.Name.Name == "urlParseCause" && fd.Recv == nil {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("urlParseCause not found in " + checkipSourceFile +
			"; if it moved, move this gate with it rather than deleting it")
	}
	// The signature is half the invariant: widening the result to `string` would
	// re-open the accidental `return cause` form that the closed type forbids.
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		t.Fatal("urlParseCause must return exactly one result")
	}
	resultType, isIdent := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !isIdent || resultType.Name != "parseReason" {
		t.Fatalf("urlParseCause returns %v, want the closed parseReason type; the type is "+
			"what makes a bare `return cause` fail to COMPILE", fn.Type.Results.List[0].Type)
	}

	returns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		// Do NOT descend into a closure. Its returns are the CLOSURE's, not
		// urlParseCause's, so counting them would let a closure satisfy the
		// non-vacuity floor below while the real body was gutted (#6545 review
		// round 6). A closure also cannot carry input out through urlParseCause's
		// own return, which must still be a bare package constant.
		if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			return false
		}
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
		ident, identOK := ret.Results[0].(*ast.Ident)
		if !identOK {
			t.Errorf("%s: urlParseCause returns a %T, not a bare constant identifier. "+
				"Every return must name one of the declared parseReason constants — a "+
				"conversion such as parseReason(cause), a call, or a literal can carry "+
				"input-derived text into the daemon log and the process-lifetime dedup key.",
				pos, ret.Results[0])
			return true
		}
		obj := info.Uses[ident]
		if obj == nil {
			t.Errorf("%s: urlParseCause returns %q, which go/types did not resolve; "+
				"the gate cannot vouch for it, so it fails closed", pos, ident.Name)
			return true
		}
		// THE resolution check. A shadowing local — `causeMalformedURL :=
		// parseReason(cause)` — spells a declared name but resolves to a
		// *types.Var, and that is the whole point of resolving rather than
		// name-matching.
		konst, isConst := obj.(*types.Const)
		if !isConst {
			t.Errorf("%s: urlParseCause returns %q, which resolves to a %T, not a constant. "+
				"An identifier that merely SPELLS a declared constant name — a local "+
				"shadowing it, for example `causeMalformedURL := parseReason(cause)` — "+
				"carries the raw parse cause into the daemon log and the process-lifetime "+
				"dedup key. Return the package constant itself.", pos, ident.Name, obj)
			return true
		}
		if konst.Parent() != pkg.Scope() {
			t.Errorf("%s: urlParseCause returns %q, a constant declared in an INNER scope "+
				"rather than at package level. A function-local `const` can be computed "+
				"from anything in scope; only the audited package-level cause* set is "+
				"admissible.", pos, ident.Name)
			return true
		}
		if !declared[konst.Name()] {
			t.Errorf("%s: urlParseCause returns %q, which is NOT one of the declared "+
				"parseReason constants. Returning anything else leaks the offending URL "+
				"text into the checkip warning and its dedup key; add a constant instead.",
				pos, konst.Name())
			return true
		}
		// Cross-check the VALUE against the independent literal list in
		// checkip_url_redaction_6545_test.go. A constant declared with the right
		// name but an input-shaped value would satisfy every check above.
		if konst.Val().Kind() != constant.String {
			t.Errorf("%s: urlParseCause returns %q, whose constant value is %v, not a string",
				pos, konst.Name(), konst.Val().Kind())
			return true
		}
		if value := constant.StringVal(konst.Val()); !urlParseCauseAllowed[parseReason(value)] {
			t.Errorf("%s: urlParseCause returns %q whose value is %q, which is NOT in the "+
				"independently-declared allowed set in checkip_url_redaction_6545_test.go. "+
				"Adding a reason must be a reviewed edit in both places.",
				pos, konst.Name(), value)
		}
		return true
	})

	// Guard the guard: if urlParseCause were reduced to a single return, or the
	// walk silently found nothing, this test would pass vacuously. Closures are
	// excluded above, so this counts only urlParseCause's own returns.
	if returns < 5 {
		t.Errorf("urlParseCause has only %d return statements; the AST walk is probably "+
			"not seeing the function body it is supposed to check", returns)
	}
}
