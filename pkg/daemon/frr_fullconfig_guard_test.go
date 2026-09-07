package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// frrFullConfigAllowlist is the closed set of production files allowed
// to construct frr.FullConfig composite literals. The #1827 plan made
// assembleFRRConfig the SOLE production constructor (one overlay, one
// constructor, two triggers): any other construction site bypasses the
// ip-monitoring effective-route overlay, so an active failover route
// would be silently wiped from the FRR managed section the next time
// that caller ran (AGY review on PR #1843, finding F1 — the legacy
// frr.Apply/ApplyWithInstances bypasses were deleted under the same
// finding).
var frrFullConfigAllowlist = map[string]string{
	// The assembler itself.
	"pkg/daemon/daemon_ipmon.go": "assembleFRRConfig — the sole production constructor",
	// Legacy standalone-CLI fallback: per the file's package comment,
	// production xpfd always wires applyConfigFn so this path is
	// skipped; it exists only for a CLI spawned without a daemon
	// (no ipmon engine, hence no overlay to preserve). Pre-dates
	// #1827. Do NOT add new entries here — route through the
	// daemon's assembleFRRConfig instead.
	"pkg/cli/apply.go": "legacy standalone-CLI fallback (skipped when the daemon wires applyConfigFn)",
}

// TestFRRFullConfigConstructedOnlyByAssembler walks every production
// (non-test) .go file under pkg/ and cmd/ and fails if a
// frr.FullConfig (or, inside pkg/frr, a bare FullConfig) composite
// literal appears outside the allowlist. Follows the
// legacy_dataplane_canary_test.go AST-guard precedent.
func TestFRRFullConfigConstructedOnlyByAssembler(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var offenders []string

	for _, top := range []string{"pkg", "cmd"} {
		root := filepath.Join(repoRoot, top)
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			if _, allowed := frrFullConfigAllowlist[rel]; allowed {
				return nil
			}

			file, perr := parser.ParseFile(fset, path, nil, parser.AllErrors)
			if perr != nil {
				t.Fatalf("parse %s: %v", rel, perr)
			}
			inFRRPackage := strings.HasPrefix(rel, "pkg/frr/")

			ast.Inspect(file, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				switch typ := cl.Type.(type) {
				case *ast.SelectorExpr:
					// frr.FullConfig{...} (any import alias would
					// still name the type FullConfig).
					if typ.Sel != nil && typ.Sel.Name == "FullConfig" {
						pos := fset.Position(cl.Pos())
						offenders = append(offenders,
							rel+":"+itoa(pos.Line)+": frr.FullConfig composite literal")
					}
				case *ast.Ident:
					// Bare FullConfig{...} inside pkg/frr itself.
					if inFRRPackage && typ.Name == "FullConfig" {
						pos := fset.Position(cl.Pos())
						offenders = append(offenders,
							rel+":"+itoa(pos.Line)+": FullConfig composite literal")
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("frr.FullConfig constructed outside assembleFRRConfig in production code:\n  %s\n"+
			"assembleFRRConfig (pkg/daemon/daemon_ipmon.go) is the SOLE production\n"+
			"constructor (#1827): it injects the ip-monitoring effective-route overlay\n"+
			"(PreferredRoutes), so a bypassing construction site silently wipes an\n"+
			"active failover route from the FRR managed section. Route the new caller\n"+
			"through the daemon's assembler (AGY review on PR #1843, F1).",
			strings.Join(offenders, "\n  "))
	}
}

// TestEveryFRRFullConfigConstructorWiresIfNameResolver9405 closes the second
// constructor.
//
// TestFRRFullConfigConstructedOnlyByAssembler above proves the set of
// production FullConfig constructors is exactly frrFullConfigAllowlist. Each
// one must set IfNameResolver, because pkg/frr treats a nil resolver as
// IDENTITY — a deliberate compatibility default so the 86 direct
// generateProtocols callers in frr_test.go stay byte-identical — and identity
// is precisely the pre-#9405 defect: the managed section goes back to naming
// devices Linux dev_valid_name() rejects, and every IGP silently fails to
// attach.
//
// A behavioural cell can only cover the constructor it can drive.
// TestAssembleFRRConfigWiresProtocolIfNameResolver9405 drives the daemon's;
// the legacy standalone-CLI path (pkg/cli/apply.go) needs a CLI with a live
// FRR manager to reach, so this AST cell covers BOTH — and, unlike either
// behavioural cell, it also covers a THIRD constructor nobody has written yet.
func TestEveryFRRFullConfigConstructorWiresIfNameResolver9405(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var offenders []string
	seen := 0

	for rel := range frrFullConfigAllowlist {
		path := filepath.Join(repoRoot, filepath.FromSlash(rel))
		file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := cl.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "FullConfig" {
				return true
			}
			seen++
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "IfNameResolver" {
					return true
				}
			}
			offenders = append(offenders, rel+":"+itoa(fset.Position(cl.Pos()).Line))
			return true
		})
	}

	// Non-vacuity: an empty walk would satisfy "no offenders" while measuring
	// nothing, which is exactly how a guard keyed on a moved file goes green
	// forever.
	if seen == 0 {
		t.Fatalf("found no frr.FullConfig composite literal in the allowlist %v — "+
			"this guard measured nothing", frrFullConfigAllowlist)
	}
	if len(offenders) > 0 {
		t.Fatalf("frr.FullConfig constructed without IfNameResolver at:\n  %s\n"+
			"pkg/frr treats a nil resolver as IDENTITY, so this renders the AUTHORED\n"+
			"Junos interface reference (`ge-0/0/1.0`) into the managed section. Linux\n"+
			"dev_valid_name() forbids '/', so the stanza binds no netdev and no OSPF /\n"+
			"OSPFv3 / IS-IS / RIP adjacency forms — on a commit that succeeds with no\n"+
			"warning. Set IfNameResolver: cfg.ResolveKernelIfName (#9405).",
			strings.Join(offenders, "\n  "))
	}
}
