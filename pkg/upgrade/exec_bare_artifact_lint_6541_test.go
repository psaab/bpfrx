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
// artifact as a BARE command name.
//
// Rationale. These execs run as root on the upgrade and kernel promote/rollback
// paths, and their exit status decides promote-vs-rollback. A bare name is
// resolved against $PATH, so an attacker-writable PATH entry ordered ahead of
// the real location — or merely a stale artifact left in another directory —
// gets to author that decision. Every xpf artifact must be reached through an
// explicit path (the #1917 version-multiplexed layout: versions/<ver>/<bin>,
// versions/current/<bin>, or a resolved os.Executable).
//
// SCOPE — deliberately narrow, so this rule never has to be disabled for a
// false positive:
//
//   - Only the COMMAND-NAME argument is examined, and only when it is a string
//     literal. `exec.Command(bin, ...)` (an explicit path in a variable) is the
//     correct pattern and is untouched.
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
//   - A literal that already contains a path separator is NOT flagged — it is
//     explicit by construction (this rule is about bareness, not about which
//     explicit path was chosen).
//
// The call sites are ENUMERATED from the AST rather than compared against a
// checked-in list, so a NEW bare invocation added anywhere under pkg/upgrade
// fails this test the moment it lands.
//
// FAIL-ON-REVERT: restore `exec.Command("xpfd", "verify-dataplane")` in
// kernel_linux.go and TestNoBareXpfArtifactExec fails, naming the file:line.

// execCallSite is one enumerated shell-out.
type execCallSite struct {
	pos      string // file:line, repo-relative
	callee   string // e.g. "exec.Command", "runCmd"
	nameExpr string // the command-name argument as written
	literal  string // its value when it is a string literal, else ""
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

// exprText renders an expression roughly as written, for the report.
func exprText(fset *token.FileSet, e ast.Expr) string {
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
func enumerateExecCallSites(fset *token.FileSet, files map[string]*ast.File, wrappers map[string]bool) []execCallSite {
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
				// argument is the command name.
				if !wrappers[callee] || len(call.Args) == 0 {
					return true
				}
				nameArg = call.Args[0]
			}
			lit, _ := stringLit(nameArg)
			sites = append(sites, execCallSite{
				pos:      relPos(fset, call.Pos()),
				callee:   callee,
				nameExpr: exprText(fset, nameArg),
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

// isBareXpfArtifact reports whether a command-name literal is a BARE xpf
// artifact name: no path separator (so it would be $PATH-resolved) AND the
// name of one of our own managed binaries.
func isBareXpfArtifact(lit string, artifacts map[string]bool) bool {
	if lit == "" || strings.ContainsRune(lit, os.PathSeparator) || strings.Contains(lit, "/") {
		return false
	}
	return artifacts[lit]
}

func TestNoBareXpfArtifactExec(t *testing.T) {
	root := upgradeTreeRoot(t)
	fset, files := parseUpgradeTree(t, root)
	wrappers := execWrapperNames(files)
	sites := enumerateExecCallSites(fset, files, wrappers)
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
		if isBareXpfArtifact(s.literal, artifacts) {
			bad = append(bad, "  "+s.pos+": "+s.callee+"("+s.nameExpr+", ...)")
		}
	}
	if len(bad) > 0 {
		var all []string
		for _, s := range sites {
			all = append(all, "  "+s.pos+": "+s.callee+"("+s.nameExpr+", ...)")
		}
		t.Fatalf("BARE xpf artifact name passed to a shell-out in pkg/upgrade (#6541).\n"+
			"These run as root on the upgrade / kernel promote paths, where the exit\n"+
			"status decides promote-vs-rollback; a $PATH entry ordered ahead of the\n"+
			"real location must not be able to author that decision. Build an explicit\n"+
			"path instead (versions/<ver>/<bin>, versions/current/<bin>, or a validated\n"+
			"os.Executable) — see resolveVerifyGateBin in kernel_linux.go.\n\n"+
			"OFFENDING:\n%s\n\nALL ENUMERATED SHELL-OUTS:\n%s",
			strings.Join(bad, "\n"), strings.Join(all, "\n"))
	}
}

// TestBareXpfArtifactDetectorScoping pins the classifier's boundaries so the
// rule cannot be quietly loosened into uselessness, and — just as important —
// cannot start false-positiving on the system binaries this package must keep
// PATH-resolving. A rule that false-positives gets disabled.
func TestBareXpfArtifactDetectorScoping(t *testing.T) {
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

		// Not flagged: explicit paths to our artifacts.
		{"absolute versioned", "/var/lib/xpf/versions/v1/xpfd", false},
		{"absolute current", "/var/lib/xpf/versions/current/xpfd", false},
		{"absolute sbin", "/usr/local/sbin/xpfd", false},
		{"relative with separator", "./xpfd", false},

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
			if got := isBareXpfArtifact(tc.lit, artifacts); got != tc.want {
				t.Fatalf("isBareXpfArtifact(%q) = %v, want %v", tc.lit, got, tc.want)
			}
		})
	}
}

// TestExecEnumerationCoversKnownSites is the enumeration's own sanity check: it
// asserts the walker actually reaches the two files the #6541 audit named, and
// that it sees BOTH the direct exec.* constructors AND the derived-wrapper
// callers. Without this a walker bug (wrong root, wrong suffix filter) would
// make TestNoBareXpfArtifactExec pass vacuously.
func TestExecEnumerationCoversKnownSites(t *testing.T) {
	root := upgradeTreeRoot(t)
	fset, files := parseUpgradeTree(t, root)
	wrappers := execWrapperNames(files)
	sites := enumerateExecCallSites(fset, files, wrappers)

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
			if isBareXpfArtifact(s.literal, xpfArtifactNames()) {
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
