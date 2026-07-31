package upgrade

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/manifest"
)

// #6541 lint: no shell-out in the pkg/upgrade tree may name an xpf-OWNED
// artifact by anything other than an ABSOLUTE path.
//
// Rationale. These execs run as root on the upgrade and kernel promote/rollback
// paths, and their exit status decides promote-vs-rollback. A bare name is
// resolved against $PATH, so an attacker-writable PATH entry ordered ahead of
// the real location — or merely a stale artifact left in another directory —
// gets to author that decision. A relative path is resolved against the process
// CWD, which for a root-run systemd unit is whatever WorkingDirectory= says and
// which any intervening chdir can move. Every xpf artifact must be reached
// through an absolute path (the #1917 version-multiplexed layout:
// versions/<ver>/<bin>, versions/current/<bin>, or a resolved os.Executable).
//
// The rule tracks the production validator exactly: validateGateBin rejects
// every non-absolute path, so this guard does too. A guard MORE permissive than
// the code it guards would bless the next variant of the bug.
//
// SCOPE — deliberately narrow, so this rule never has to be disabled for a
// false positive:
//
//   - Only the COMMAND-NAME argument is examined, and only when it evaluates at
//     COMPILE TIME — a string literal, a package-level string const, or a `+`
//     chain of those (constFoldString). `exec.Command(bin, ...)`, where bin was
//     built at run time by filepath.Join, is the CORRECT pattern and is
//     untouched; a lint that chased variables would flag every correct site.
//   - Only xpf's OWN artifacts are flagged, and the list comes from
//     pkg/upgrade/manifest — the SSOT — so a newly added managed binary is
//     covered automatically with no edit here.
//   - System binaries are NOT flagged. `systemctl`, `apt-get`, `efibootmgr`,
//     `dpkg-query`, `ping`, `uname`, `ip`, `update-grub`, ... are legitimately
//     PATH-resolved: they belong to the distribution, live in root-owned
//     system directories, and hardcoding their paths would be wrong (they move
//     between /bin, /usr/bin, /sbin, /usr/sbin across distributions).
//   - An artifact name appearing as a non-first ARGUMENT is NOT flagged.
//     `runCmd("systemctl", "is-active", "xpfd")` names a systemd UNIT, which
//     systemd resolves from its own unit search path, not $PATH.
//   - An ABSOLUTE literal is NOT flagged — it is anchored by construction. This
//     rule is about how the target gets resolved, not about which absolute path
//     was chosen (that judgement lives in resolveVerifyGateBin's doc).
//
// The call sites are ENUMERATED from the AST rather than compared against a
// checked-in list, so a NEW bare or relative invocation added anywhere under
// pkg/upgrade fails this test the moment it lands. Both plain functions and
// METHODS are traced (calleeFinalName), so a call through System.VerifyDataplane
// or System.BinaryVersion is checked like a direct exec.Command.
//
// WHAT THIS DOES NOT COVER — stated so the guard is not read as stronger than
// it is:
//
//   - Run-time values. `exec.Command(bin, ...)` where bin came from
//     filepath.Join, a struct field, or any variable is NOT classified. That is
//     deliberate and load-bearing: it is the CORRECT pattern, and chasing
//     variables would flag every correct site. A hostile or mistaken run-time
//     path is out of reach of a static check here; resolveVerifyGateBin's
//     validateGateBin is what defends the one call that matters at run time.
//   - An identifier declared as a const in more than one place is dropped
//     rather than guessed (no scope resolution here), so such a site is simply
//     not classified.
//   - Method matching is by final name, so a same-named method on an unrelated
//     type also matches. Erring toward MORE enumeration is the right direction
//     for a guard.
//   - Only pkg/upgrade is walked. This is a package-scoped guard, not a
//     repo-wide one.
//
// FAIL-ON-REVERT: restore `exec.Command("xpfd", "verify-dataplane")` in
// kernel_linux.go and TestNoBareOrRelativeXpfArtifactExec fails, naming the
// file:line.

// execCallSite is one enumerated shell-out.
type execCallSite struct {
	pos      string // file:line, repo-relative
	callee   string // e.g. "exec.Command", "runCmd"
	nameExpr string // the command-name argument as written
	literal  string // its compile-time value when it has one, else ""
}

// upgradeTreeRoot returns the directory holding this package's source. The test
// walks it (and its subpackages) rather than hardcoding a file list.
func upgradeTreeRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

// parseUpgradeTree parses every non-test .go file under root.
func parseUpgradeTree(t *testing.T, root string) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files[path] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Fatalf("parsed no .go files under %s — the lint would vacuously pass", root)
	}
	return fset, files
}

// selectorName renders pkg.Fn / Fn for a call's callee, or "" for anything
// else (a method value, a func literal, ...).
func selectorName(fn ast.Expr) string {
	switch e := fn.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			return x.Name + "." + e.Sel.Name
		}
	}
	return ""
}

// calleeFinalName returns the FUNCTION or METHOD name of a call's callee,
// discarding any receiver/package qualifier: Fn -> "Fn", pkg.Fn -> "Fn",
// s.Method -> "Method", a.b.c.Method -> "Method".
//
// This exists because wrapper discovery and call enumeration were keyed
// differently, and the mismatch silently dropped real call paths.
// execWrapperNames records a declaration's BARE name (realSystem's method is
// "VerifyDataplane"), while selectorName renders a call receiver-qualified
// ("s.VerifyDataplane") or, for a nested receiver like r.cfg.Sys.VerifyDataplane,
// gives up entirely and returns "". So every call THROUGH a method wrapper —
// System.VerifyDataplane and BinaryVersion, both of which take an explicit `bin`
// as their first parameter and exec it — was invisible to the lint.
//
// Matching on the final segment is an approximation: a same-named method on an
// unrelated type would also match. That is the right direction to err for a
// guard — the only way to trip it is to pass a literal xpf-artifact name as the
// first argument to something named like an exec wrapper, which is itself worth
// a look.
func calleeFinalName(fn ast.Expr) string {
	switch e := fn.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// stringLit returns the value of a plain string literal, and whether e was one.
func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// stringConsts collects string constants so constFoldString can resolve an
// identifier operand.
//
// It covers both PACKAGE-LEVEL and FUNCTION-LOCAL `const` declarations, and it
// iterates to a fixpoint so a const whose initializer is ITSELF an expression
// resolves:
//
//	const command = "./" + verifyGateBin
//
// An earlier version took only initializers that were direct string literals,
// which meant the lint claimed compile-time constant-expression coverage while
// silently skipping both of those shapes.
//
// AMBIGUITY IS TREATED AS UNRESOLVABLE. The map is flat, so a local const that
// shadows a package const of the same name has no scope to disambiguate it.
// Rather than guess — and risk folding to a string the exec never sees — a name
// bound to two different values is DROPPED, so the site is simply not
// classified. Not classifying is the same conservative default the lint already
// applies to variables.
func stringConsts(files map[string]*ast.File) map[string]string {
	type binding struct {
		expr ast.Expr
		seen int
	}
	// Collect every const spec, package-level and local.
	raw := map[string]*binding{}
	record := func(vs *ast.ValueSpec) {
		for i, name := range vs.Names {
			if i >= len(vs.Values) || name.Name == "_" {
				continue
			}
			if b, dup := raw[name.Name]; dup {
				b.seen++
				continue
			}
			raw[name.Name] = &binding{expr: vs.Values[i], seen: 1}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				return true
			}
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					record(vs)
				}
			}
			return true
		})
	}

	consts := map[string]string{}
	// Fixpoint: each pass resolves consts whose operands became known in the
	// previous one. Bounded by the number of bindings.
	for range len(raw) + 1 {
		progress := false
		for name, b := range raw {
			if _, done := consts[name]; done {
				continue
			}
			if v, ok := constFoldString(b.expr, consts); ok {
				consts[name] = v
				progress = true
			}
		}
		if !progress {
			break
		}
	}

	// Drop ambiguous names: an identifier declared as a const in more than one
	// place has no scope here to disambiguate it, so it is not classified.
	for name, b := range raw {
		if b.seen > 1 {
			delete(consts, name)
		}
	}
	return consts
}

// constFoldString evaluates a command-name expression to a compile-time string
// when it is one: a literal, a package-level string const, or any `+` chain of
// those.
//
// This exists because the plain-literal check alone had a hole the original
// #6541 red-probe walked straight into. The reviewer's stated failure scenario
// is a helper that chdirs to the version dir and then does
//
//	exec.Command("./"+verifyGateBin, "verify-dataplane")
//
// which is an *ast.BinaryExpr, not an *ast.BasicLit — so a literal-only lint
// classifies it as "not a literal, not our business" and stays green on exactly
// the construct it was added to catch. Folding closes that.
//
// It deliberately does NOT resolve variables. `exec.Command(bin, ...)`, where
// bin was built at run time by filepath.Join, is the CORRECT pattern and must
// stay unflagged; a lint that tried to chase variables would flag every correct
// site. So an unresolvable operand yields ok=false and the site is left alone —
// the same conservative default as before, just with a much smaller blind spot.
func constFoldString(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		return stringLit(v)
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	case *ast.ParenExpr:
		return constFoldString(v.X, consts)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, lok := constFoldString(v.X, consts)
		if !lok {
			return "", false
		}
		r, rok := constFoldString(v.Y, consts)
		if !rok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// exprText renders an expression roughly as written, for the report.
func exprText(fset *token.FileSet, e ast.Expr, consts map[string]string) string {
	if _, isLit := e.(*ast.BasicLit); !isLit {
		// A const-folded expression: show the VALUE the exec will actually see,
		// with the source shape appended so the report points at real code.
		if v, ok := constFoldString(e, consts); ok {
			return strconv.Quote(v) + " [const-folded]"
		}
	}
	if lit, ok := stringLit(e); ok {
		return strconv.Quote(lit)
	}
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return selectorName(v)
	case *ast.CallExpr:
		return selectorName(v.Fun) + "(...)"
	}
	return "<expr@" + relPos(fset, e.Pos()) + ">"
}

func relPos(fset *token.FileSet, p token.Pos) string {
	pos := fset.Position(p)
	// Trim to the last two path elements so the report is stable across
	// checkouts (…/pkg/upgrade/kernel_linux.go -> upgrade/kernel_linux.go).
	dir, file := filepath.Split(pos.Filename)
	parent := filepath.Base(filepath.Clean(dir))
	return filepath.Join(parent, file) + ":" + strconv.Itoa(pos.Line)
}

// execWrapperNames DERIVES the package's own exec wrappers: a function whose
// body hands its OWN first (string) parameter to exec.Command /
// exec.CommandContext as the command name. That is how runCmd and captureCmd
// are written, so a caller passing a literal artifact name to one of them is
// exactly as dangerous as calling exec.Command directly — and deriving the set
// means a NEW wrapper is covered without editing this test.
func execWrapperNames(files map[string]*ast.File) map[string]bool {
	wrappers := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 {
				continue
			}
			first := fd.Type.Params.List[0]
			if len(first.Names) == 0 {
				continue
			}
			if id, ok := first.Type.(*ast.Ident); !ok || id.Name != "string" {
				continue
			}
			param := first.Names[0].Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				nameArg, ok := commandNameArg(selectorName(call.Fun), call)
				if !ok {
					return true
				}
				if id, ok := nameArg.(*ast.Ident); ok && id.Name == param {
					wrappers[fd.Name.Name] = true
				}
				return true
			})
		}
	}
	return wrappers
}

// commandNameArg returns the argument holding the command NAME for a known
// exec constructor, skipping the leading ctx of the Context variants.
func commandNameArg(callee string, call *ast.CallExpr) (ast.Expr, bool) {
	switch callee {
	case "exec.Command", "exec.LookPath":
		if len(call.Args) >= 1 {
			return call.Args[0], true
		}
	case "exec.CommandContext":
		if len(call.Args) >= 2 {
			return call.Args[1], true
		}
	}
	return nil, false
}

// enumerateExecCallSites walks the whole tree and returns every shell-out: the
// direct exec.* constructors plus every call to a DERIVED package exec wrapper.
func enumerateExecCallSites(fset *token.FileSet, files map[string]*ast.File, wrappers map[string]bool, consts map[string]string) []execCallSite {
	var sites []execCallSite
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := selectorName(call.Fun)
			nameArg, ok := commandNameArg(callee, call)
			if !ok {
				// A call to one of the package's own exec wrappers: its first
				// argument is the command name. Keyed on the FINAL name so a
				// method call (s.VerifyDataplane, r.cfg.Sys.VerifyDataplane)
				// matches the declaration's bare name.
				if !wrappers[calleeFinalName(call.Fun)] || len(call.Args) == 0 {
					return true
				}
				if callee == "" {
					callee = calleeFinalName(call.Fun)
				}
				nameArg = call.Args[0]
			}
			lit, _ := constFoldString(nameArg, consts)
			sites = append(sites, execCallSite{
				pos:      relPos(fset, call.Pos()),
				callee:   callee,
				nameExpr: exprText(fset, nameArg, consts),
				literal:  lit,
			})
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].pos < sites[j].pos })
	return sites
}

// xpfArtifactNames is the SSOT set of xpf's own managed binaries.
func xpfArtifactNames() map[string]bool {
	set := map[string]bool{}
	for _, n := range manifest.Names() {
		set[n] = true
	}
	return set
}

// isNonAbsoluteXpfArtifact reports whether a command-name literal names one of
// our own managed binaries WITHOUT anchoring it to an absolute path — i.e. the
// exec target would be resolved at run time against something the caller does
// not control:
//
//   - a BARE name ("xpfd") is resolved against $PATH;
//   - a RELATIVE path ("./xpfd", "../versions/v1/xpfd") is resolved against the
//     process CWD, which for a root-run systemd unit is whatever
//     WorkingDirectory= says (/ by default) and which any intervening chdir can
//     move out from under the call.
//
// Both are the same defect class, and the production validator agrees:
// validateGateBin rejects every non-absolute path, not merely bare names. This
// predicate deliberately matches it — a regression guard that is MORE permissive
// than the code it guards would bless the next variant of the bug. flip.go's
// header records a real past incident of exactly the CWD-dependent-resolution
// class, so the relative case is not hypothetical.
func isNonAbsoluteXpfArtifact(lit string, artifacts map[string]bool) bool {
	if lit == "" || filepath.IsAbs(lit) {
		return false
	}
	return artifacts[filepath.Base(lit)]
}

func TestNoBareOrRelativeXpfArtifactExec(t *testing.T) {
	root := upgradeTreeRoot(t)
	fset, files := parseUpgradeTree(t, root)
	wrappers := execWrapperNames(files)
	sites := enumerateExecCallSites(fset, files, wrappers, stringConsts(files))
	artifacts := xpfArtifactNames()

	if len(sites) == 0 {
		t.Fatal("enumerated no exec call sites under pkg/upgrade — the lint " +
			"is not actually inspecting anything (did the AST shape change?)")
	}
	// The wrapper derivation is load-bearing: without it, a
	// runCmd("xpfd", ...) would slip past. Assert it found the wrappers that
	// exist, so a refactor that renames or restructures them is not a silent
	// coverage loss.
	if len(wrappers) == 0 {
		t.Error("derived no package exec wrappers; runCmd/captureCmd-style " +
			"callers would no longer be inspected")
	}

	var bad []string
	for _, s := range sites {
		if isNonAbsoluteXpfArtifact(s.literal, artifacts) {
			bad = append(bad, "  "+s.pos+": "+s.callee+"("+s.nameExpr+", ...)")
		}
	}
	if len(bad) > 0 {
		var all []string
		for _, s := range sites {
			all = append(all, "  "+s.pos+": "+s.callee+"("+s.nameExpr+", ...)")
		}
		t.Fatalf("NON-ABSOLUTE xpf artifact name passed to a shell-out in pkg/upgrade (#6541).\n"+
			"These run as root on the upgrade / kernel promote paths, where the exit\n"+
			"status decides promote-vs-rollback. A BARE name is resolved against $PATH\n"+
			"and a RELATIVE one against the process CWD, so neither the operator nor\n"+
			"this code controls which binary actually runs. Build an ABSOLUTE path\n"+
			"instead (versions/<ver>/<bin>, versions/current/<bin>, or a validated\n"+
			"os.Executable) — see resolveVerifyGateBin in kernel_linux.go.\n\n"+
			"OFFENDING:\n%s\n\nALL ENUMERATED SHELL-OUTS:\n%s",
			strings.Join(bad, "\n"), strings.Join(all, "\n"))
	}
}

// TestNonAbsoluteXpfArtifactDetectorScoping pins the classifier's boundaries so the
// rule cannot be quietly loosened into uselessness, and — just as important —
// cannot start false-positiving on the system binaries this package must keep
// PATH-resolving. A rule that false-positives gets disabled.
func TestNonAbsoluteXpfArtifactDetectorScoping(t *testing.T) {
	artifacts := xpfArtifactNames()

	// The SSOT must actually carry the daemon, or every case below is vacuous.
	if !artifacts[verifyGateBin] {
		t.Fatalf("manifest.Names() = %v does not contain %q; the lint would not "+
			"flag the very site #6541 is about", manifest.Names(), verifyGateBin)
	}

	for _, tc := range []struct {
		name string
		lit  string
		want bool
	}{
		// Flagged: bare xpf-owned artifacts.
		{"bare xpfd", "xpfd", true},
		{"bare helper", "xpf-userspace-dp", true},
		{"bare cli", "cli", true},
		{"bare day0", "xpf-day0-config", true},

		// Not flagged: ABSOLUTE paths to our artifacts.
		{"absolute versioned", "/var/lib/xpf/versions/v1/xpfd", false},
		{"absolute current", "/var/lib/xpf/versions/current/xpfd", false},
		{"absolute sbin", "/usr/local/sbin/xpfd", false},

		// Flagged: RELATIVE paths to our artifacts. A separator does not make a
		// target explicit — these resolve against the process CWD, which for a
		// root-run systemd unit is WorkingDirectory= (/ by default). This is the
		// same position validateGateBin takes; see
		// TestValidateGateBinRejectsNonExplicitTargets, which pins "./xpfd" as an
		// ERROR. The two must not disagree.
		{"dot-relative", "./xpfd", true},
		{"parent-relative", "../versions/v1/xpfd", true},
		{"bare-relative subdir", "versions/current/xpfd", true},
		{"relative helper", "./xpf-userspace-dp", true},

		// Not flagged: system binaries. PATH resolution is correct by design —
		// they are distribution-owned and move between /bin, /usr/bin, /sbin,
		// and /usr/sbin across distributions.
		{"systemctl", "systemctl", false},
		{"apt-get", "apt-get", false},
		{"apt-mark", "apt-mark", false},
		{"apt-cache", "apt-cache", false},
		{"efibootmgr", "efibootmgr", false},
		{"dpkg-query", "dpkg-query", false},
		{"update-grub", "update-grub", false},
		{"update-initramfs", "update-initramfs", false},
		{"uname", "uname", false},
		{"ip", "ip", false},
		{"ping", "ping", false},

		// Not flagged: a non-literal command name is not classifiable here.
		{"empty (non-literal)", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNonAbsoluteXpfArtifact(tc.lit, artifacts); got != tc.want {
				t.Fatalf("isNonAbsoluteXpfArtifact(%q) = %v, want %v", tc.lit, got, tc.want)
			}
		})
	}
}

// TestConstFoldClosesTheConcatenationHole pins the folding that the review
// fold's own red-probe forced into existence.
//
// The probe injected the reviewer's exact failure scenario —
// `exec.Command("./"+verifyGateBin, "verify-dataplane")` — and the lint stayed
// GREEN, because that argument is an *ast.BinaryExpr, not an *ast.BasicLit, so
// a literal-only classifier never looked at it. The tightened absoluteness rule
// was correct but unreachable for the very construct it was written for.
//
// This asserts folding on the shapes that matter, and — just as important —
// asserts it does NOT reach into variables, which would flag every correct
// `exec.Command(bin, ...)` site and get the rule disabled.
func TestConstFoldClosesTheConcatenationHole(t *testing.T) {
	// The real package consts, resolved the way the lint resolves them.
	_, files := parseUpgradeTree(t, upgradeTreeRoot(t))
	consts := stringConsts(files)

	if got := consts["verifyGateBin"]; got != verifyGateBin {
		t.Fatalf("stringConsts did not pick up verifyGateBin (got %q, want %q); "+
			"const folding would silently no-op", got, verifyGateBin)
	}

	artifacts := xpfArtifactNames()
	for _, tc := range []struct {
		name      string
		expr      string
		wantFold  string
		wantFlags bool
	}{
		// The probe's construct, and the shape that motivated all of this.
		{"dot-relative concat", `"./" + verifyGateBin`, "./xpfd", true},
		{"subdir concat", `"versions/current/" + verifyGateBin`, "versions/current/xpfd", true},
		{"bare const alone", `verifyGateBin`, "xpfd", true},
		// Absolute stays unflagged however it is spelled.
		{"absolute concat", `"/usr/local/sbin/" + verifyGateBin`, "/usr/local/sbin/xpfd", false},
		{"const root concat", `DefaultVersionsDir + "/current/" + verifyGateBin`,
			DefaultVersionsDir + "/current/xpfd", false},
		// A system binary is still a system binary after folding.
		{"system concat", `"systemctl"`, "systemctl", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := parser.ParseExpr(tc.expr)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.expr, err)
			}
			got, ok := constFoldString(e, consts)
			if !ok {
				t.Fatalf("constFoldString(%s) did not fold; the lint would skip "+
					"this call site entirely", tc.expr)
			}
			if got != tc.wantFold {
				t.Fatalf("constFoldString(%s) = %q, want %q", tc.expr, got, tc.wantFold)
			}
			if flags := isNonAbsoluteXpfArtifact(got, artifacts); flags != tc.wantFlags {
				t.Fatalf("%s folded to %q; flagged=%v, want %v", tc.expr, got, flags, tc.wantFlags)
			}
		})
	}

	// A const whose initializer is itself an expression must resolve. The
	// literal-initializer-only version of stringConsts skipped these while the
	// lint claimed compile-time constant-expression coverage.
	t.Run("const with expression initializer", func(t *testing.T) {
		src := `package p
const gateBin = "xpfd"
const relCommand = "./" + gateBin
const absCommand = "/usr/local/sbin/" + gateBin
`
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := stringConsts(map[string]*ast.File{"x.go": f})
		if got["relCommand"] != "./xpfd" {
			t.Fatalf("relCommand = %q, want %q — a const whose initializer is a "+
				"concatenation must fold", got["relCommand"], "./xpfd")
		}
		if got["absCommand"] != "/usr/local/sbin/xpfd" {
			t.Fatalf("absCommand = %q, want /usr/local/sbin/xpfd", got["absCommand"])
		}
		if isNonAbsoluteXpfArtifact(got["relCommand"], artifacts) != true {
			t.Fatal("the folded relative const was not flagged")
		}
		if isNonAbsoluteXpfArtifact(got["absCommand"], artifacts) != false {
			t.Fatal("the folded absolute const was wrongly flagged")
		}
	})

	// FUNCTION-LOCAL consts must resolve too — package-level-only collection
	// was another silently-uncovered shape.
	t.Run("function-local const", func(t *testing.T) {
		src := `package p
const gateBin = "xpfd"
func f() {
	const localCommand = "./" + gateBin
	_ = localCommand
}
`
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := stringConsts(map[string]*ast.File{"x.go": f}); got["localCommand"] != "./xpfd" {
			t.Fatalf("localCommand = %q, want %q — a function-local const must fold",
				got["localCommand"], "./xpfd")
		}
	})

	// AMBIGUOUS names must be dropped, not guessed. Two bindings for one
	// identifier and no scope to tell them apart: not classifying is the
	// conservative answer, matching how variables are handled.
	t.Run("ambiguous const dropped", func(t *testing.T) {
		src := `package p
const dup = "xpfd"
func f() {
	const dup = "/usr/local/sbin/xpfd"
	_ = dup
}
`
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if v, ok := stringConsts(map[string]*ast.File{"x.go": f})["dup"]; ok {
			t.Fatalf("dup resolved to %q; an identifier with two const bindings "+
				"must be dropped rather than guessed", v)
		}
	})

	// MUST NOT fold: a run-time value. `exec.Command(bin, ...)` where bin came
	// from filepath.Join is the correct pattern; folding it (or guessing) would
	// flag every correct site and the rule would be disabled within a week.
	for _, expr := range []string{
		`bin`,
		`filepath.Join(dir, "xpfd")`,
		`dir + "/xpfd"`,
		`"./" + someVar`,
	} {
		t.Run("unfoldable/"+expr, func(t *testing.T) {
			e, err := parser.ParseExpr(expr)
			if err != nil {
				t.Fatalf("parse %q: %v", expr, err)
			}
			if got, ok := constFoldString(e, consts); ok {
				t.Fatalf("constFoldString(%s) folded to %q; it must not resolve "+
					"run-time values, or every correct exec.Command(bin, ...) "+
					"site gets flagged", expr, got)
			}
		})
	}
}

// TestLintAgreesWithProductionValidator binds the two guards together so they
// cannot drift apart again.
//
// The original #6541 review caught them disagreeing: the lint blessed "./xpfd"
// while validateGateBin rejected it, so the regression guard was MORE permissive
// than the code it guarded — and that disagreement was itself codified in two
// assertions pointing opposite ways. This asserts the invariant directly: for
// any literal naming an xpf artifact, the lint flags it EXACTLY when
// validateGateBin rejects it for not being absolute.
//
// One-directional by design: validateGateBin additionally rejects absolute
// paths that are missing / not regular / not executable, which a STATIC lint
// cannot and should not judge. So the comparison is against the not-absolute
// rejection specifically, on inputs that all exist.
func TestLintAgreesWithProductionValidator(t *testing.T) {
	artifacts := xpfArtifactNames()
	root := t.TempDir()

	// A real, absolute, executable artifact so the absolute cases clear
	// validateGateBin's existence checks and isolate the absoluteness verdict.
	abs := fakeXpfd(t, root, 0)

	for _, lit := range []string{
		verifyGateBin,
		"xpf-userspace-dp",
		"cli",
		"./" + verifyGateBin,
		"../versions/v1/" + verifyGateBin,
		"versions/current/" + verifyGateBin,
		abs,
	} {
		t.Run(lit, func(t *testing.T) {
			lintFlags := isNonAbsoluteXpfArtifact(lit, artifacts)

			err := validateGateBin(lit)
			validatorRejectsAsRelative := err != nil &&
				strings.Contains(err.Error(), "not an absolute path")

			if lintFlags != validatorRejectsAsRelative {
				t.Fatalf("guards disagree on %q: lint flags=%v, validateGateBin "+
					"rejects-as-non-absolute=%v (err=%v).\n"+
					"A regression guard more permissive than the production "+
					"validator blesses the next variant of the bug (#6541).",
					lit, lintFlags, validatorRejectsAsRelative, err)
			}
		})
	}
}

// TestExecEnumerationCoversKnownSites is the enumeration's own sanity check: it
// asserts the walker actually reaches the two files the #6541 audit named, and
// that it sees BOTH the direct exec.* constructors AND the derived-wrapper
// callers. Without this a walker bug (wrong root, wrong suffix filter) would
// make TestNoBareOrRelativeXpfArtifactExec pass vacuously.
func TestExecEnumerationCoversKnownSites(t *testing.T) {
	root := upgradeTreeRoot(t)
	fset, files := parseUpgradeTree(t, root)
	wrappers := execWrapperNames(files)
	sites := enumerateExecCallSites(fset, files, wrappers, stringConsts(files))

	seenFiles := map[string]bool{}
	var direct, viaWrapper int
	for _, s := range sites {
		seenFiles[filepath.Base(strings.SplitN(s.pos, ":", 2)[0])] = true
		if strings.HasPrefix(s.callee, "exec.") {
			direct++
		} else {
			viaWrapper++
		}
	}

	for _, want := range []string{"kernel_linux.go", "system_linux.go", "seed.go"} {
		if !seenFiles[want] {
			t.Errorf("enumeration never reached %s (walked files: %v)", want, sortedKeys(seenFiles))
		}
	}

	// METHOD-wrapper call sites must be enumerated. System.VerifyDataplane and
	// System.BinaryVersion both take an explicit `bin` first parameter and exec
	// it, so they ARE exec wrappers — but wrapper discovery records a bare
	// declaration name while selectorName renders a call receiver-qualified
	// (and returns "" outright for a nested receiver like r.cfg.Sys.X). That
	// mismatch made every call through them invisible. calleeFinalName closes
	// it; this asserts the closure against real code rather than a fixture.
	if !seenFiles["cutover.go"] {
		t.Errorf("enumeration never reached cutover.go, whose r.cfg.Sys.VerifyDataplane / "+
			"r.cfg.Sys.BinaryVersion calls are the method-wrapper call paths the "+
			"receiver-qualification mismatch used to drop (walked files: %v)",
			sortedKeys(seenFiles))
	}
	var methodWrapperSites int
	for _, s := range sites {
		switch s.callee {
		case "VerifyDataplane", "BinaryVersion":
			methodWrapperSites++
		}
	}
	if methodWrapperSites == 0 {
		t.Error("no METHOD-wrapper call site enumerated; a literal artifact name " +
			"passed to System.VerifyDataplane / System.BinaryVersion would go " +
			"unchecked")
	}
	if direct == 0 {
		t.Error("enumerated no direct exec.* constructors")
	}
	if viaWrapper == 0 {
		t.Error("enumerated no calls through a derived exec wrapper; the " +
			"runCmd/captureCmd hole would be uncovered")
	}
	// The `runCmd("systemctl", "is-active", "xpfd")` shape must be enumerated
	// (so the rule is exercised) and must NOT be flagged — "xpfd" there is a
	// systemd UNIT name, resolved by systemd, not $PATH. This is the precise
	// false positive that would get the rule disabled.
	var sawUnitNameCall bool
	for _, s := range sites {
		if s.literal == "systemctl" {
			sawUnitNameCall = true
			if isNonAbsoluteXpfArtifact(s.literal, xpfArtifactNames()) {
				t.Fatalf("%s: flagged a systemctl invocation", s.pos)
			}
		}
	}
	if !sawUnitNameCall {
		t.Error("no systemctl call enumerated; the unit-name-vs-binary " +
			"distinction is untested against real code")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
