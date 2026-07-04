package config

import (
	"strings"
	"testing"
)

// #3980: a path-scoped `show configuration <path>` (and its
// `| display set` / xml renderers) that terminates on a bare keyword must
// emit EVERY sibling statement sharing that leading keyword, not just the
// first. navigatePath's terminal single-key match previously returned
// `[]*Node{n}` — the first sibling only — so `show configuration system
// ntp server` and `show configuration system ntp server | display set`
// showed only `server 1.1.1.1`, hiding 2.2.2.2 / 3.3.3.3. A scoped
// display-set backup taken that way silently dropped the hidden servers on
// restore. These are fail-on-revert guards: reverting navigatePath to
// return only the first match drops the trailing siblings and fails the
// count assertions below.
//
// The FULL-tree renderers (Format / FormatSet, no path) already walked
// every sibling slice element and are exercised here as the control that
// must stay correct.

// buildRepeatedNTP builds a tree with three distinct `system ntp server`
// statements sharing the `server` leading keyword, using the hierarchical
// parser (which appends one node per statement — the shape a committed
// config loads into).
func buildRepeatedNTP(t *testing.T) *ConfigTree {
	t.Helper()
	src := `system {
    ntp {
        server 1.1.1.1;
        server 2.2.2.2;
        server 3.3.3.3;
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return tree
}

func TestShowConfigRepeatedKeywordPathScoped(t *testing.T) {
	tree := buildRepeatedNTP(t)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}

	// Path-scoped hierarchical: `show configuration system ntp server`.
	hier := tree.FormatPath([]string{"system", "ntp", "server"})
	for _, ip := range want {
		if !strings.Contains(hier, "server "+ip) {
			t.Errorf("FormatPath([system ntp server]) missing %q; got:\n%s", ip, hier)
		}
	}
	if n := strings.Count(hier, "server "); n != len(want) {
		t.Errorf("FormatPath([system ntp server]) rendered %d servers, want %d; got:\n%s", n, len(want), hier)
	}

	// Path-scoped display-set: `show configuration system ntp server | display set`.
	set := tree.FormatPathSet([]string{"system", "ntp", "server"})
	for _, ip := range want {
		if !strings.Contains(set, "set system ntp server "+ip) {
			t.Errorf("FormatPathSet([system ntp server]) missing %q; got:\n%s", ip, set)
		}
	}
	if n := strings.Count(set, "set system ntp server "); n != len(want) {
		t.Errorf("FormatPathSet([system ntp server]) rendered %d set lines, want %d; got:\n%s", n, len(want), set)
	}
}

// TestShowConfigRepeatedRoutePathScoped covers static routes — a keyed
// container class the issue names ("several static route entries") — for
// the same navigatePath terminal-keyword defect. `show configuration
// routing-options static route` must list every route, not just the first.
// RED on revert (navigatePath returned only the first `route` node).
func TestShowConfigRepeatedRoutePathScoped(t *testing.T) {
	src := `routing-options {
    static {
        route 10.0.0.0/24 next-hop 192.168.1.1;
        route 10.0.1.0/24 next-hop 192.168.1.2;
        route 10.0.2.0/24 next-hop 192.168.1.3;
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	dests := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}

	set := tree.FormatPathSet([]string{"routing-options", "static", "route"})
	for _, d := range dests {
		if !strings.Contains(set, "route "+d+" next-hop") {
			t.Errorf("FormatPathSet([...static route]) missing route %q; got:\n%s", d, set)
		}
	}

	hier := tree.FormatPath([]string{"routing-options", "static", "route"})
	if n := strings.Count(hier, "route "); n != len(dests) {
		t.Errorf("FormatPath([...static route]) rendered %d routes, want %d; got:\n%s", n, len(dests), hier)
	}
}

// TestShowConfigRepeatedRouteDisplaySetRoundTrip proves a scoped
// display-set backup round-trips faithfully for a keyed container: render
// `| display set`, re-apply those lines via ParseSetCommand + SetPath (the
// load-set path), and reproduce every route. Before the navigatePath fix
// only the first route's set lines were emitted, so the reloaded tree lost
// the other two destinations.
func TestShowConfigRepeatedRouteDisplaySetRoundTrip(t *testing.T) {
	src := `routing-options {
    static {
        route 10.0.0.0/24 next-hop 192.168.1.1;
        route 10.0.1.0/24 next-hop 192.168.1.2;
        route 10.0.2.0/24 next-hop 192.168.1.3;
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	set := tree.FormatPathSet([]string{"routing-options", "static", "route"})

	reloaded := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(set), "\n") {
		if line == "" {
			continue
		}
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := reloaded.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%v): %v", toks, err)
		}
	}
	out := reloaded.FormatPathSet([]string{"routing-options", "static", "route"})
	for _, pair := range [][2]string{
		{"10.0.0.0/24", "192.168.1.1"},
		{"10.0.1.0/24", "192.168.1.2"},
		{"10.0.2.0/24", "192.168.1.3"},
	} {
		want := "set routing-options static route " + pair[0] + " next-hop " + pair[1]
		if !strings.Contains(out, want) {
			t.Errorf("display-set round-trip lost %q; reloaded:\n%s", want, out)
		}
	}
}

// TestShowConfigRepeatedKeywordFullTreeControl is the control: the full
// (unscoped) renderers already walk every sibling and must keep rendering
// all three servers.
func TestShowConfigRepeatedKeywordFullTreeControl(t *testing.T) {
	tree := buildRepeatedNTP(t)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}

	full := tree.Format()
	if n := strings.Count(full, "server "); n != len(want) {
		t.Errorf("Format() rendered %d servers, want %d; got:\n%s", n, len(want), full)
	}
	fullSet := tree.FormatSet()
	if n := strings.Count(fullSet, "set system ntp server "); n != len(want) {
		t.Errorf("FormatSet() rendered %d set lines, want %d; got:\n%s", n, len(want), fullSet)
	}
}

// TestShowConfigPathScopedSingleStatementUnchanged guards against
// over-broadening: a single, non-repeated statement path-scoped render is
// unchanged (still exactly one line), and naming a specific keyed value
// (`... server 2.2.2.2`) still resolves to that one entry, not all
// siblings.
func TestShowConfigPathScopedSingleStatementUnchanged(t *testing.T) {
	single, perrs := NewParser("system { host-name fw1; }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	got := single.FormatPathSet([]string{"system", "host-name"})
	if strings.TrimSpace(got) != "set system host-name fw1" {
		t.Errorf("FormatPathSet([system host-name]) = %q, want single host-name line", got)
	}

	tree := buildRepeatedNTP(t)
	one := tree.FormatPathSet([]string{"system", "ntp", "server", "2.2.2.2"})
	if strings.TrimSpace(one) != "set system ntp server 2.2.2.2" {
		t.Errorf("FormatPathSet([system ntp server 2.2.2.2]) = %q, want only the named entry", one)
	}
}
