package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8189: BIND THE WIRING, not the function it calls.
//
// The commit-time advisory only exists for an operator if this package actually
// registers its command set. Deleting the init() would leave every cell in
// pkg/config green — those inject their own surface — while the shipped daemon
// silently emitted no advisory at all, which is the same silence the issue is
// replacing.
func TestGRPCSurfaceIsRegisteredForCommitAdvisories_8189(t *testing.T) {
	// A deny pattern that matches nothing this surface can produce. If the
	// registration ran, pkg/config can see the surface and name it.
	rules, err := config.CompileLoginRegexes(
		config.LoginRegexPlainFamily, "", false, "^zzz-not-a-real-command", true)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	surfaces := config.UnenforceableDenySurfaces(rules)
	found := false
	for _, s := range surfaces {
		if s == grpcSurfaceName {
			found = true
		}
	}
	if !found {
		t.Fatalf("pkg/config does not know about %q (saw %q). The init() registration in "+
			"authz_command_gate_7172.go is what carries this surface across the import "+
			"boundary; without it the commit advisory is silently absent in the daemon "+
			"while every pkg/config cell still passes.", grpcSurfaceName, surfaces)
	}

	// And the registered set must be non-empty, because an empty one is
	// treated as "say nothing" — a registration that reported zero commands
	// would look wired while being inert.
	if n := len(allCanonicalCommands()); n == 0 {
		t.Fatal("the registered command set is empty; the advisory would be silent")
	}
}

// The accept-side half at THIS layer: a pattern the surface can enforce must
// not be reported unenforceable through the delegation either.
func TestEnforceablePatternNotReportedByDelegation_8189(t *testing.T) {
	cmds := allCanonicalCommands()
	if len(cmds) == 0 {
		t.Skip("no canonical commands registered")
	}
	// Anchor on a real command from the table so the pattern is enforceable by
	// construction rather than by a guess about what the table contains.
	rules, err := config.CompileLoginRegexes(
		config.LoginRegexPlainFamily, "", false, "^"+regexpEscapeForTest(cmds[0]), true)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	if got := unenforceableDenyPatterns(rules); len(got) != 0 {
		t.Errorf("pattern matching the real command %q was reported unenforceable: %q",
			cmds[0], got)
	}
}

func regexpEscapeForTest(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`, `.`, `\.`, `+`, `\+`, `*`, `\*`, `?`, `\?`,
		`(`, `\(`, `)`, `\)`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`,
		`^`, `\^`, `$`, `\$`, `|`, `\|`,
	)
	return r.Replace(s)
}
