package config

import "testing"

// #3996: a policy-options prefix-list DEFINITION written as a bracketed list
// (`set policy-options prefix-list NAME [ p1 p2 p3 ]`) collapsed in
// compilation — the lexer strips the brackets and packs every prefix onto a
// SINGLE child node's Keys (the #2419/#3842 dual-shape class), but the
// prefix-list compiler read only that child's Keys[0], keeping just the FIRST
// prefix and silently dropping the rest. An under-populated prefix-list used by
// a route-filter, a firewall filter, or a dynamic address group then matches a
// partial prefix set.
//
// Fix (compiler_routing.go compilePolicyOptions): read the FULL Keys slice of
// every child, not just Keys[0].
//
// Fail-on-revert: restore the `entry.Keys[0]`-only read and the bracketed-list
// assertion below drops to a single prefix, so the test goes RED. The
// single-prefix and separate-command forms are unaffected either way.

func TestPrefixListBracketedListKeepsAllPrefixes(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list PL [ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatalf("prefix-list PL not compiled")
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(pl.Prefixes) != len(want) || !containsAll(pl.Prefixes, want) {
		t.Fatalf("bracketed prefix-list PL = %v (N=%d), want all %v (N=%d) — "+
			"the bracketed list collapsed to first-only (#3996)",
			pl.Prefixes, len(pl.Prefixes), want, len(want))
	}
}

// The separate-set-command form (one prefix per line) and the single-prefix
// form must remain intact — the fix must not disturb the existing shapes.
func TestPrefixListSeparateCommandsKeepAllPrefixes(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list PL 10.0.0.0/8",
		"set policy-options prefix-list PL 172.16.0.0/12",
		"set policy-options prefix-list PL 192.168.0.0/16",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatalf("prefix-list PL not compiled")
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(pl.Prefixes) != len(want) || !containsAll(pl.Prefixes, want) {
		t.Fatalf("separate-command prefix-list PL = %v, want all %v", pl.Prefixes, want)
	}
}

func TestPrefixListSinglePrefixUnchanged(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list PL 10.0.0.0/8",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatalf("prefix-list PL not compiled")
	}
	if len(pl.Prefixes) != 1 || pl.Prefixes[0] != "10.0.0.0/8" {
		t.Fatalf("single-prefix prefix-list PL = %v, want [10.0.0.0/8]", pl.Prefixes)
	}
}

// The bracketed-list body must survive a display-set round-trip: FormatSet →
// re-parse (ParseSetCommand + SetPath) → compile must still yield all three
// prefixes. A drop anywhere in that chain leaves a partial prefix-list.
func TestPrefixListBracketedListDisplaySetRoundTrip(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list PL [ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ]",
	})
	setOut := tree.FormatSet()

	rt := &ConfigTree{}
	for _, line := range splitNonEmptyLines(setOut) {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := rt.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(rt)
	if err != nil {
		t.Fatalf("CompileConfig(round-trip): %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatalf("prefix-list PL not compiled after round-trip (display-set:\n%s)", setOut)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(pl.Prefixes) != len(want) || !containsAll(pl.Prefixes, want) {
		t.Fatalf("round-trip prefix-list PL = %v, want all %v (display-set:\n%s)",
			pl.Prefixes, want, setOut)
	}
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if line := s[start:i]; line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		if line := s[start:]; line != "" {
			out = append(out, line)
		}
	}
	return out
}
