package config

import (
	"testing"
)

// #6564 — the compact-leaf / vacuous-gate cohort.
//
// The parser builds a `;`-terminated statement as ONE node: `Keys: keys,
// IsLeaf: true`, with NO Children (parser.go). `FindChild` matches
// `child.Keys[0]` over `n.Children` only (ast.go). So the SAME configuration
// reaches the compiler in two different shapes:
//
//	security { alg { dns { disable; } } }   -> child "dns" with child "disable"
//	security { alg { dns disable; } }       -> ONE leaf, Keys=["dns","disable"]
//
// A compiler that reaches the operand through `FindChild` / `range .Children`
// is structurally blind to the second shape. The operand is dropped BEFORE an
// otherwise-correct strict validator reads it, so the validator iterates an
// empty slice and passes VACUOUSLY — the config commits clean and the control
// is silently not in force.
//
// The canonical correct readers accumulate BOTH sides (`firewallMatchValues`,
// `addressSetMemberValues`, `applicationSetMemberValues`).
//
// Reachability: the compact-leaf spellings below are reachable via hierarchical
// text ingest — `load override` / `load merge`, the persisted config file, and
// the HA `SyncApply` path — i.e. the boot path and the peer-sync path. They are
// not reachable from the `set` CLI, and `show configuration | display set`
// round-trips safely. Each test therefore asserts that BOTH shapes agree,
// rather than asserting the compact shape in isolation.

// compileHier6564 compiles hierarchical (brace/compact) config text.
func compileHier6564(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return cfg
}

// compileSet6564 compiles flat `set` commands. Per CLAUDE.md this MUST go
// through ParseSetCommand + SetPath, never NewParser — the parser treats
// newlines as whitespace and would merge every set line into one node.
func compileSet6564(t *testing.T, cmds ...string) *Config {
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
		t.Fatalf("compile set commands: %v", err)
	}
	return cfg
}

// --- Member 1: `security alg { <proto> disable; }` leaves the ALG ENABLED ----

// TestCompactLeafALGDisable6564 pins that the compact-leaf ALG disable takes
// effect. Before the fix, `alg { dns disable; }` compiled to DNSDisable=false
// while `alg { dns { disable; } }` compiled to true — the operator disabled the
// ALG and it stayed on, with no warning (the #4232 unsupported-proto advisory
// does not fire either, because `dns` IS a wired proto).
//
// FAIL-ON-REVERT: restore the `FindChild("disable") != nil` form in compileALG.
func TestCompactLeafALGDisable6564(t *testing.T) {
	for _, tc := range []struct {
		proto string
		get   func(ALGConfig) bool
	}{
		{"dns", func(a ALGConfig) bool { return a.DNSDisable }},
		{"ftp", func(a ALGConfig) bool { return a.FTPDisable }},
		{"sip", func(a ALGConfig) bool { return a.SIPDisable }},
		{"tftp", func(a ALGConfig) bool { return a.TFTPDisable }},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			block := compileHier6564(t, "security {\n alg {\n  "+tc.proto+" {\n   disable;\n  }\n }\n}\n")
			compact := compileHier6564(t, "security {\n alg {\n  "+tc.proto+" disable;\n }\n}\n")
			flat := compileSet6564(t, "set security alg "+tc.proto+" disable")

			if !tc.get(block.Security.ALG) {
				t.Fatalf("setup: the brace form must disable the %s ALG", tc.proto)
			}
			if !tc.get(flat.Security.ALG) {
				t.Fatalf("setup: the flat-set form must disable the %s ALG", tc.proto)
			}
			if !tc.get(compact.Security.ALG) {
				t.Fatalf("#6564: `alg { %s disable; }` (compact leaf) left the %s ALG ENABLED — "+
					"the operand rides on the leaf's own Keys and compileALG read Children only, "+
					"so an operator-disabled ALG silently stays in force", tc.proto, tc.proto)
			}
		})
	}
}

// --- Member 3: `prefix-list PL <prefix>;` compiles to an EMPTY list ----------

// TestCompactLeafPrefixList6564 pins that a compact-leaf prefix-list carries
// its prefix. Before the fix it compiled to a NAMED but EMPTY list, so any
// filter term scoped by it silently stopped matching — a fail-open on a
// security control that commits clean.
//
// FAIL-ON-REVERT: drop the `inst.node.Keys[2:]` read from the prefix-list loop.
func TestCompactLeafPrefixList6564(t *testing.T) {
	block := compileHier6564(t, "policy-options {\n prefix-list PL {\n  10.0.0.0/8;\n }\n}\n")
	compact := compileHier6564(t, "policy-options {\n prefix-list PL 10.0.0.0/8;\n}\n")
	flat := compileSet6564(t, "set policy-options prefix-list PL 10.0.0.0/8")

	want := []string{"10.0.0.0/8"}
	for name, cfg := range map[string]*Config{"brace": block, "flat-set": flat} {
		pl := cfg.PolicyOptions.PrefixLists["PL"]
		if pl == nil || len(pl.Prefixes) != 1 || pl.Prefixes[0] != want[0] {
			t.Fatalf("setup: the %s form must carry %v; got %+v", name, want, pl)
		}
	}

	pl := compact.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatal("#6564: compact-leaf prefix-list produced no list at all")
	}
	if len(pl.Prefixes) != 1 || pl.Prefixes[0] != want[0] {
		t.Fatalf("#6564: `prefix-list PL 10.0.0.0/8;` (compact leaf) compiled to an EMPTY "+
			"prefix-list — a filter term scoped by it silently stops matching; got %v", pl.Prefixes)
	}
}

// --- Member 4: `next-hop { <gw>; }` compiles to ZERO next-hops ---------------

// TestCompactLeafStaticNextHop6564 pins the INVERSE shape: here the operand
// lands in Children while the reader takes it from Keys, and the Children loop
// only recognises the `interface` modifier. The route then carries no
// disposition at all, and staticRouteDispositionConflict only rejects TWO or
// more — never zero — so it commits clean and renders nothing into FRR.
//
// FAIL-ON-REVERT: drop the bare-gateway arm from the next-hop Children loop.
func TestCompactLeafStaticNextHop6564(t *testing.T) {
	inline := compileHier6564(t, "routing-options {\n static {\n  route 10.9.0.0/16 next-hop 192.168.1.1;\n }\n}\n")
	block := compileHier6564(t, "routing-options {\n static {\n  route 10.9.0.0/16 {\n   next-hop {\n    192.168.1.1;\n   }\n  }\n }\n}\n")
	flat := compileSet6564(t, "set routing-options static route 10.9.0.0/16 next-hop 192.168.1.1")

	nextHops := func(cfg *Config) []string {
		for _, r := range cfg.RoutingOptions.StaticRoutes {
			if r.Destination == "10.9.0.0/16" {
				var out []string
				for _, nh := range r.NextHops {
					out = append(out, nh.Address)
				}
				return out
			}
		}
		return nil
	}

	for name, cfg := range map[string]*Config{"inline": inline, "flat-set": flat} {
		if got := nextHops(cfg); len(got) != 1 || got[0] != "192.168.1.1" {
			t.Fatalf("setup: the %s form must carry one next-hop; got %v", name, got)
		}
	}

	if got := nextHops(block); len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("#6564: `next-hop { 192.168.1.1; }` (block form) compiled to ZERO next-hops — "+
			"the route carries no disposition, staticRouteDispositionConflict only rejects >=2, "+
			"so it commits clean and renders nothing into FRR; got %v", got)
	}
}

// --- Member 7: `flow { tcp-mss all-tcp <n>; }` disables MSS clamping --------

// TestCompactLeafTCPMSS6564 pins the fully-packed tcp-mss leaf.
//
// Shapes, confirmed against the parser:
//
//	flow { tcp-mss { all-tcp { mss 1350; } } }  -> tcp-mss > all-tcp > [mss 1350]
//	flow { tcp-mss { all-tcp mss 1350; } }      -> tcp-mss > [all-tcp mss 1350]
//	flow { tcp-mss all-tcp 1350; }              -> ONE leaf [tcp-mss all-tcp 1350]
//	set security flow tcp-mss all-tcp 1350      -> tcp-mss > [all-tcp 1350]
//
// The compiler and validateTCPMSSRanges both walk `mssNode.Children`, so the
// fully-packed leaf presented an EMPTY child slice: the validator passed
// VACUOUSLY and TCPMSSAllTCP was never assigned. MSS clamping silently did not
// happen on a config that committed clean.
//
// FAIL-ON-REVERT: drop the packed-leaf arm from tcpMSSOptionNodes.
func TestCompactLeafTCPMSS6564(t *testing.T) {
	block := compileHier6564(t, "security {\n flow {\n  tcp-mss {\n   all-tcp {\n    mss 1350;\n   }\n  }\n }\n}\n")
	compact := compileHier6564(t, "security {\n flow {\n  tcp-mss all-tcp 1350;\n }\n}\n")
	flat := compileSet6564(t, "set security flow tcp-mss all-tcp 1350")

	for name, cfg := range map[string]*Config{"brace": block, "flat-set": flat} {
		if cfg.Security.Flow.TCPMSSAllTCP != 1350 {
			t.Fatalf("setup: the %s form must set TCPMSSAllTCP=1350; got %d",
				name, cfg.Security.Flow.TCPMSSAllTCP)
		}
	}

	if compact.Security.Flow.TCPMSSAllTCP != 1350 {
		t.Fatalf("#6564: `tcp-mss all-tcp 1350;` (fully-packed leaf) silently disabled MSS "+
			"clamping — the compiler and validateTCPMSSRanges both read Children only, so the "+
			"validator passed vacuously; got TCPMSSAllTCP=%d", compact.Security.Flow.TCPMSSAllTCP)
	}
}

// TestCompactLeafTCPMSSKeywordIsAcceptedEverywhere6564 REPLACES
// TestCompactLeafTCPMSSKeywordStillRejected6564, which asserted the opposite.
//
// The old cell pinned `tcp-mss <kind> mss <n>` as REJECTED, on the premise that
// `mss` is the hierarchical keyword and "legitimate only as a child", so inline
// it is a typo. THE DISCONFIRMING ROW WAS ALWAYS IN THE SAME INSTRUMENT and was
// never put beside the others:
//
//	all-tcp { mss 1350; }             ACCEPTED, compiles to 1350
//	tcp-mss { all-tcp mss 1350; }     was REJECTED
//	tcp-mss all-tcp mss 1350;         was REJECTED
//	set … all-tcp mss 1350            was REJECTED
//
// If `mss` were a typo the braced form would refuse it too. It does not, so
// `mss` is a real keyword in this grammar — and CLAUDE.md's contract is that a
// hierarchical form and its flat-set flattening compile the same, because flat
// `set` IS the hierarchy written inline. The old premise was half right: `mss`
// is legitimate as a child, and that is exactly why it is legitimate flattened.
//
// HOW A CORRECT-LOOKING CRITERION PRODUCED IT, worth keeping because the
// criterion is still in use. #6564's acceptance was "compile identically in
// both AST shapes OR be rejected at commit". It found the half-packed form
// rejecting and satisfied the criterion through the OR branch — propagating the
// rejection so the two shapes would agree — without checking the third shape,
// which already ACCEPTED. That is consistency by LEVELLING DOWN: two forms made
// to agree by matching the broken one, with a working form a single spelling
// away. An "identical OR rejected" criterion is satisfiable by making
// everything wrong.
//
// Adjudicated by team-lead on the measurement above; the reversal is recorded
// here rather than left to read as drift.
func TestCompactLeafTCPMSSKeywordIsAcceptedEverywhere6564(t *testing.T) {
	allTCP := func(t *testing.T, label, src string) (int, bool) {
		t.Helper()
		tree, perrs := NewParser(src).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse %s: %v", label, perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			return 0, true
		}
		return cfg.Security.Flow.TCPMSSAllTCP, false
	}

	// Every spelling of the SAME statement delivers the same value. Asserted on
	// the value, never on acceptance: the doubly-elided form used to COMMIT
	// while discarding the value, so an acceptance check passes on that defect.
	for _, c := range []struct{ label, src string }{
		{"braced `all-tcp { mss 1350; }`",
			"security {\n flow {\n  tcp-mss {\n   all-tcp {\n    mss 1350;\n   }\n  }\n }\n}\n"},
		{"half-packed `tcp-mss { all-tcp mss 1350; }`",
			"security {\n flow {\n  tcp-mss {\n   all-tcp mss 1350;\n  }\n }\n}\n"},
		{"fully-packed `tcp-mss all-tcp mss 1350;`",
			"security {\n flow {\n  tcp-mss all-tcp mss 1350;\n }\n}\n"},
		{"doubly-elided `flow tcp-mss all-tcp mss 1350;`",
			"security {\n flow tcp-mss all-tcp mss 1350;\n}\n"},
	} {
		got, rejected := allTCP(t, c.label, c.src)
		if rejected || got != 1350 {
			t.Errorf("%s: TCPMSSAllTCP=%d rejected=%v, want 1350. `mss` is accepted as a "+
				"child, so its flattening must compile the same — that is the dual-AST "+
				"contract, and refusing it rejects the flattening of a config this same "+
				"compiler accepts", c.label, got, rejected)
		}
	}

	// THE SHIPPED SHORT FORM MUST KEEP WORKING. docs/ha-cluster.conf:140 writes
	// `tcp-mss { all-tcp 1396; }`, so widening acceptance for the `mss` keyword
	// must not cost the spelling the project itself ships.
	for _, c := range []struct{ label, src string }{
		{"shipped `tcp-mss { all-tcp 1396; }`",
			"security {\n flow {\n  tcp-mss {\n   all-tcp 1396;\n  }\n }\n}\n"},
		{"doubly-elided short `flow tcp-mss all-tcp 1396;`",
			"security {\n flow tcp-mss all-tcp 1396;\n}\n"},
	} {
		got, rejected := allTCP(t, c.label, c.src)
		if rejected || got != 1396 {
			t.Errorf("%s: TCPMSSAllTCP=%d rejected=%v, want 1396", c.label, got, rejected)
		}
	}

	// A GENUINE TYPO IS STILL REFUSED. Without these the change above would be
	// indistinguishable from "consume whatever follows the kind", which is the
	// over-fix: it would accept `all-tcp msss 1350` and silently clamp nothing.
	for _, c := range []struct{ label, src string }{
		{"typo `all-tcp msss 1350`",
			"security {\n flow {\n  tcp-mss {\n   all-tcp msss 1350;\n  }\n }\n}\n"},
		{"`mss` with no value",
			"security {\n flow {\n  tcp-mss {\n   all-tcp mss;\n  }\n }\n}\n"},
	} {
		if _, rejected := allTCP(t, c.label, c.src); !rejected {
			t.Errorf("%s was ACCEPTED; only the exact keyword `mss` followed by a value may "+
				"be consumed", c.label)
		}
	}
}
