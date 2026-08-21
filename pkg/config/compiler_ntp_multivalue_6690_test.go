package config

import (
	"strings"
	"testing"
)

// #6690: `system { ntp { server { a; b; } } }` compiled ZERO NTP servers and
// the commit was green — the compiler read only ntpChild.Keys[1], which the
// nested-block spelling never populates. The bracketed spelling kept only the
// first server for the same reason (#2419 collapses the list onto Keys[1:]).
//
// These guards pin the compiled server LIST, not its length, across every
// spelling the parser can produce, and pin the non-regression that a
// per-server OPTION keyword is not compiled as an extra server.

// ntpServersFromBlock compiles a hierarchical (brace) config body and returns
// the compiled NTP server list.
func ntpServersFromBlock(t *testing.T, body string) []string {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", body, errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig %q: %v", body, err)
	}
	return cfg.System.NTPServers
}

// ntpServersFromSet applies flat `set` commands and returns the compiled NTP
// server list. Per CLAUDE.md the flat-set path must be driven through
// ParseSetCommand + SetPath, never NewParser.
func ntpServersFromSet(t *testing.T, cmds ...string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg.System.NTPServers
}

func assertServers(t *testing.T, spelling string, got, want []string) {
	t.Helper()
	if len(got) != len(want) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: NTPServers = %v, want %v", spelling, got, want)
	}
}

// Test_6690_NTPServerEveryHierarchicalSpelling covers the three brace-parsed
// spellings. The nested block is the one that compiled to ZERO.
func Test_6690_NTPServerEveryHierarchicalSpelling(t *testing.T) {
	want := []string{"1.1.1.1", "2.2.2.2"}

	assertServers(t, "nested block `server { a; b; }`",
		ntpServersFromBlock(t, `system { ntp { server { 1.1.1.1; 2.2.2.2; } } }`), want)

	assertServers(t, "bracket list `server [ a b ];`",
		ntpServersFromBlock(t, `system { ntp { server [ 1.1.1.1 2.2.2.2 ]; } }`), want)

	assertServers(t, "repeated leaf `server a; server b;`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1; server 2.2.2.2; } }`), want)
}

// Test_6690_NTPServerEveryFlatSetSpelling covers the two flat-set spellings.
// The bracket list dropped every server past the first.
func Test_6690_NTPServerEveryFlatSetSpelling(t *testing.T) {
	want := []string{"1.1.1.1", "2.2.2.2"}

	assertServers(t, "flat-set repeated leaf",
		ntpServersFromSet(t,
			"set system ntp server 1.1.1.1",
			"set system ntp server 2.2.2.2"), want)

	assertServers(t, "flat-set bracket list",
		ntpServersFromSet(t, "set system ntp server [ 1.1.1.1 2.2.2.2 ]"), want)
}

// Test_6690_NTPServerOptionTokensAreNotServers is the non-regression half.
// After the lexer strips brackets, `server 1.1.1.1 prefer` and
// `server [ 1.1.1.1 2.2.2.2 ]` are the SAME AST shape, so a naive
// read-every-key fix would compile "prefer" as an NTP server and render it
// verbatim into a chrony `server` directive. Each option keyword must be
// skipped together with its argument tokens.
func Test_6690_NTPServerOptionTokensAreNotServers(t *testing.T) {
	one := []string{"1.1.1.1"}

	assertServers(t, "`server a prefer;`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1 prefer; } }`), one)

	assertServers(t, "`server a key 5;`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1 key 5; } }`), one)

	assertServers(t, "`server a version 4;`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1 version 4; } }`), one)

	assertServers(t, "`server a routing-instance mgmt;`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1 routing-instance mgmt; } }`), one)

	// Option carried as a child of the address leaf rather than as a trailing
	// key: `server 1.1.1.1 { prefer; }` → Keys=["server","1.1.1.1"], child
	// Keys=["prefer"]. The child walk must skip it too.
	assertServers(t, "`server a { prefer; }`",
		ntpServersFromBlock(t, `system { ntp { server 1.1.1.1 { prefer; } } }`), one)

	// An option on a real multi-server statement must not swallow a server.
	assertServers(t, "`server [ a b ] prefer;`",
		ntpServersFromBlock(t, `system { ntp { server [ 1.1.1.1 2.2.2.2 ] prefer; } }`),
		[]string{"1.1.1.1", "2.2.2.2"})
}
