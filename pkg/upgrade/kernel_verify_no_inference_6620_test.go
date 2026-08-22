package upgrade

import (
	"go/ast"
	"strings"
	"testing"
)

// #6620: the INNER promote hop must not infer which xpfd to run from
// filesystem evidence.
//
// The OUTER hop (scripts/image/xpf-kernel-promote) closed this class in #6601
// r5 after four review rounds, each of which shut one ambiguous case and left
// another. It converged only when the filesystem fallbacks were DELETED in
// favour of "unambiguous or refuse". `resolveVerifyGateBin` was the same shape
// one level down: os.Executable() first — authoritative, the kernel's answer
// for the running process — then <SbinDir>/xpfd, then
// <VersionsDir>/current/xpfd.
//
// WHY A SOURCE-LEVEL GUARD AND NOT ONLY A BEHAVIOURAL ONE. Deleting the
// fallbacks also deleted the seams a test used to point them at a temp tree.
// So a behavioural refusal test can no longer PLANT a leftover for the
// resolver to find: restore the fallbacks and the reverted code reaches for
// the machine's REAL /usr/local/sbin/xpfd and /var/lib/xpf/versions/current/xpfd.
// Whether that reds is then a property of the test HOST, not of the code.
//
// The behavioural tests in kernel_verify_explicit_path_6541_test.go close as
// much of that as they can without a seam (empty return value, plus the
// absence of the pre-#6620 fallback labels in the refusal). This guard closes
// the rest, and it is host-independent by construction: it reads the source.
//
// Two tests for one property is the right count here for the reason stated in
// each: the behavioural leg is probe-bounded, the textual leg is not.
//
// FAIL-ON-REVERT: reintroduce either fallback in resolveVerifyGateBin and
// TestResolveVerifyGateBinHasNoFilesystemInference fails, naming the
// identifier or call it found.

// bannedInferenceIdents are the configured-layout roots the deleted fallbacks
// were built from. Referencing any of them from inside resolveVerifyGateBin
// means a path is being CONSTRUCTED rather than reported by the kernel.
//
// The package vars (gateSbinDir / gateVersionsDir) are named as well as the
// exported defaults, so that re-adding the indirection does not launder the
// revert past this check.
var bannedInferenceIdents = map[string]string{
	"gateSbinDir":        "the deleted managed-sbin fallback root",
	"gateVersionsDir":    "the deleted versioned-runtime fallback root",
	"DefaultSbinDir":     "the compiled-in default sbin root",
	"DefaultVersionsDir": "the compiled-in default versions root",
}

// findFuncDecl returns the named top-level function from the parsed package,
// failing the test if it is absent — an absent target would make every
// assertion below vacuously true.
func findFuncDecl(t *testing.T, files map[string]*ast.File, name string) (*ast.FuncDecl, string) {
	t.Helper()
	for path, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && fd.Recv == nil && fd.Name.Name == name {
				return fd, path
			}
		}
	}
	t.Fatalf("no top-level func %s found in pkg/upgrade — this guard would "+
		"vacuously pass", name)
	return nil, ""
}

// TestResolveVerifyGateBinHasNoFilesystemInference pins the #6620 invariant on
// the SOURCE: the resolver names exactly one authority and builds no path.
//
// Three separate assertions, because a revert can take three shapes:
//
//	filepath.Join(root, name)  — how both deleted fallbacks were written
//	root + "/" + name          — the same thing via concatenation, which a
//	                             Join-only check would miss
//	no call to osExecutable    — the authority removed rather than added to
//
// The last one is not paranoia about deletion: it is what keeps the other two
// from passing vacuously if the function is ever gutted.
func TestResolveVerifyGateBinHasNoFilesystemInference_6620(t *testing.T) {
	_, files := parseUpgradeTree(t, upgradeTreeRoot(t))
	fn, path := findFuncDecl(t, files, "resolveVerifyGateBin")

	var joins, authority int
	var offenders []string

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			if why, banned := bannedInferenceIdents[e.Name]; banned {
				offenders = append(offenders, e.Name+" ("+why+")")
			}
			if e.Name == "osExecutable" {
				authority++
			}
		case *ast.CallExpr:
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok &&
					x.Name == "filepath" && sel.Sel.Name == "Join" {
					joins++
				}
			}
		}
		return true
	})

	if len(offenders) > 0 {
		t.Errorf("%s: resolveVerifyGateBin references a configured-layout root: %s\n\n"+
			"That is the #6620 defect. `--sbin-dir` and `--versions-dir` relocate "+
			"INDEPENDENTLY and neither relocation removes what it left behind, so a "+
			"leftover at a compiled-in default is indistinguishable from a live "+
			"install — including the both-roots-relocated shape where the surviving "+
			"symlink still points at the surviving runtime, making the two candidates "+
			"ONE INODE exactly like a healthy layout. Executing the stale half "+
			"verifies the candidate KERNEL against the wrong DATAPLANE and then "+
			"authorizes a permanent promotion on that result. Refuse instead: a "+
			"Gate-3 error routes to revert(), which is a correct terminal outcome.",
			path, strings.Join(offenders, ", "))
	}
	if joins > 0 {
		t.Errorf("%s: resolveVerifyGateBin calls filepath.Join %d time(s). The "+
			"resolver must REPORT the path the kernel gave it, never CONSTRUCT one "+
			"(#6620).", path, joins)
	}
	if authority == 0 {
		t.Fatalf("%s: resolveVerifyGateBin never calls osExecutable — its single "+
			"authority is gone, and the assertions above would pass vacuously on a "+
			"gutted function.", path)
	}
}

// TestVerifyGateSeamsAreOnlyTheRunningBinary pins the SEAM SURFACE itself.
//
// The fallbacks were reachable in tests only because gateSbinDir and
// gateVersionsDir were package vars. Their absence is what makes "a test cannot
// model the resolver consulting a root" true rather than merely currently-true,
// so a revert that re-adds the vars — even before wiring them up — is caught
// here, one step earlier than the resolver check above.
func TestVerifyGateSeamsAreOnlyTheRunningBinary_6620(t *testing.T) {
	_, files := parseUpgradeTree(t, upgradeTreeRoot(t))

	for path, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok.String() != "var" {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if name.Name == "gateSbinDir" || name.Name == "gateVersionsDir" {
						t.Errorf("%s: package var %s is back. It exists only to let "+
							"resolveVerifyGateBin fall back to a configured root, which "+
							"#6620 deleted — an inference a relocation leftover satisfies "+
							"just as well as a live install.", path, name.Name)
					}
				}
			}
		}
	}
}
