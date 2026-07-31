package config

import (
	"strings"
	"testing"
)

// #6524: a chained flat-set custom application compiled PROTOCOL-ONLY.
//
// `set a b c d` builds a CHAIN of single-key nodes, so in
//
//	set applications application myapp protocol tcp destination-port 8080
//
// `destination-port` is nested under the VALUE node `tcp` and is never a
// sibling of `protocol`. compileApplications iterated only
// inst.node.Children, saw only `protocol`, and never assigned
// app.DestinationPort — an empty port term matches ANY port, so a policy
// referencing the application permitted all TCP.
//
// Nothing caught it: `protocol` / `destination-port` / `source-port` are the
// only application match leaves that are neither typed nor `scalar: true`
// (schema_security.go), so no arity gate engages and the chained form validates
// clean at BOTH SchemaValidate and strict commit. The REVERSE token order was
// caught only incidentally, by the #3109 protocol-less gate — that asymmetry
// hid this.
//
// The fix is in the COMPILER (applicationDirectLeaves walks the chain across
// both AST shapes) rather than in the schema. A schema-only reject would leave
// the LENIENT path — boot load and HA SyncApply, where a schema rejection is
// downgraded to a warning — still compiling protocol-only and still permitting
// all TCP; see TestChainedAppLenientPathAlsoHonorsChain.
//
// The policy-OUTCOME fail-on-revert lives in
// pkg/policymatch/app_chained_leaves_6524_test.go (pkg/config cannot import
// pkg/policymatch — policymatch imports config).

func setTree6524(t *testing.T, cmds ...string) *ConfigTree {
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
	return tree
}

// TestChainedAppDirectLeavesCompile is the core structural fail-on-revert: each
// chained leaf must land in its own typed field.
func TestChainedAppDirectLeavesCompile(t *testing.T) {
	cases := []struct {
		name  string
		set   string
		check func(t *testing.T, app *Application)
	}{
		{
			name: "protocol + destination-port",
			set:  "set applications application myapp protocol tcp destination-port 8080",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q destination-port=%q, want tcp/8080 — the "+
						"chained destination-port was dropped (#6524)",
						app.Protocol, app.DestinationPort)
				}
			},
		},
		{
			name: "protocol + source-port",
			set:  "set applications application myapp protocol udp source-port 5000",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "udp" || app.SourcePort != "5000" {
					t.Fatalf("protocol=%q source-port=%q, want udp/5000", app.Protocol, app.SourcePort)
				}
			},
		},
		{
			name: "three-deep chain",
			set:  "set applications application myapp protocol tcp source-port 5000 destination-port 8080",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.SourcePort != "5000" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q source-port=%q destination-port=%q, want "+
						"tcp/5000/8080 — the walk must follow the WHOLE chain, not "+
						"just one link", app.Protocol, app.SourcePort, app.DestinationPort)
				}
			},
		},
		{
			name: "protocol + icmp-type",
			set:  "set applications application myapp protocol icmp icmp-type 8",
			check: func(t *testing.T, app *Application) {
				if app.ICMPType == nil || *app.ICMPType != 8 {
					t.Fatalf("ICMPType=%v, want 8 — a dropped icmp-type leaves the "+
						"application matching EVERY ICMP type", app.ICMPType)
				}
			},
		},
		{
			name: "protocol + icmp-type + icmp-code",
			set:  "set applications application myapp protocol icmp icmp-type 3 icmp-code 1",
			check: func(t *testing.T, app *Application) {
				if app.ICMPType == nil || *app.ICMPType != 3 {
					t.Fatalf("ICMPType=%v, want 3", app.ICMPType)
				}
				if app.ICMPCode == nil || *app.ICMPCode != 1 {
					t.Fatalf("ICMPCode=%v, want 1 (a type<->code swap shows 3)", app.ICMPCode)
				}
			},
		},
		{
			name: "protocol + inactivity-timeout",
			set:  "set applications application myapp protocol tcp inactivity-timeout 1800",
			check: func(t *testing.T, app *Application) {
				if app.InactivityTimeout != 1800 {
					t.Fatalf("InactivityTimeout=%d, want 1800 — a dropped timeout "+
						"silently falls back to the global per-protocol timeout",
						app.InactivityTimeout)
				}
			},
		},
		{
			name: "protocol + alg",
			set:  "set applications application myapp protocol tcp alg ftp",
			check: func(t *testing.T, app *Application) {
				if app.ALG != "ftp" {
					t.Fatalf("ALG=%q, want ftp", app.ALG)
				}
			},
		},
		{
			name: "named service port resolves through the chain",
			set:  "set applications application myapp protocol tcp destination-port https",
			check: func(t *testing.T, app *Application) {
				// resolveAppPort must still run on a chained value.
				if app.DestinationPort != "443" {
					t.Fatalf("destination-port=%q, want 443 (the service name must "+
						"resolve on the chained path too)", app.DestinationPort)
				}
			},
		},
		{
			name: "port range survives the chain",
			set:  "set applications application myapp protocol tcp destination-port 8080-8090",
			check: func(t *testing.T, app *Application) {
				if app.DestinationPort != "8080-8090" {
					t.Fatalf("destination-port=%q, want 8080-8090", app.DestinationPort)
				}
			},
		},
		{
			// REVERSE order. Pre-#6524 this dropped `protocol`, leaving a
			// protocol-less app that the #3109 gate rejected — the incidental
			// catch that hid the forward-order hole. It must now compile BOTH
			// leaves rather than reject.
			name: "reverse order (destination-port first)",
			set:  "set applications application myapp destination-port 8080 protocol tcp",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q destination-port=%q, want tcp/8080", app.Protocol, app.DestinationPort)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree6524(t, c.set))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			app := cfg.Applications.Applications["myapp"]
			if app == nil {
				t.Fatalf("application myapp missing from compiled config")
			}
			c.check(t, app)
		})
	}
}

// TestChainedAppLenientPathAlsoHonorsChain is the reason the fix lives in the
// COMPILER and not (only) in the schema. CompileConfigLenient is the tolerant
// boot-load / HA SyncApply path: it downgrades a strict rejection to a warning
// and keeps compiling. A schema-only fix would reject the chained form at
// interactive commit but leave a PERSISTED or PEER-PUSHED config compiling
// protocol-only — still permitting all TCP, and precisely where an operator
// would never see the warning.
func TestChainedAppLenientPathAlsoHonorsChain(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp protocol tcp destination-port 8080"))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing from lenient-compiled config")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" {
		t.Fatalf("lenient path: protocol=%q destination-port=%q, want tcp/8080 — "+
			"a persisted or peer-synced chained application must NOT compile "+
			"protocol-only (it would permit ALL TCP with no operator-visible "+
			"error, #6524)", app.Protocol, app.DestinationPort)
	}
}

// TestChainedAppUnrepresentableTailRejected covers the tokens the chain walk
// cannot honor. A direct application body holds ONE protocol and ONE port
// (Application.Protocol / .DestinationPort are single fields — multi-valued
// matching is what `term` sub-blocks are for), so a bracketed list silently
// dropped every value past the first, and a typo'd leaf silently dropped its
// whole constraint. Both widen the application; both must now be
// operator-visible commit errors.
func TestChainedAppUnrepresentableTailRejected(t *testing.T) {
	cases := []struct {
		name      string
		set       string
		wantToken string
	}{
		{"bracketed protocol list", "set applications application myapp protocol [ tcp udp ]", "udp"},
		{"bracketed dest-port list", "set applications application myapp protocol tcp destination-port [ 22 23 ]", "23"},
		{"bracketed source-port list", "set applications application myapp protocol tcp source-port [ 1 2 ]", "2"},
		{"typo'd chained leaf", "set applications application myapp protocol tcp destination-poort 8080", "destination-poort"},
		{"typo'd leading leaf", "set applications application myapp protocoll tcp", "protocoll"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6524(t, c.set))
			if err == nil {
				t.Fatalf("expected commit to REJECT %q — the unrepresentable tail "+
					"was silently dropped, widening the application (#6524)", c.set)
			}
			if !strings.Contains(err.Error(), c.wantToken) {
				t.Fatalf("reject message must name the offending token %q, got: %v",
					c.wantToken, err)
			}
			if !strings.Contains(err.Error(), "myapp") {
				t.Fatalf("reject message must name the application, got: %v", err)
			}
		})
	}
}

// TestChainedAppUnrepresentableTailLenientWarns pins the other half of the
// strict-reject / lenient-warn contract (#1960 no-brick): the same config must
// still BOOT on the tolerant path, downgraded to a warning.
func TestChainedAppUnrepresentableTailLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp protocol [ tcp udp ]"))
	if err != nil {
		t.Fatalf("lenient path must not hard-fail on an unrepresentable tail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "myapp") && strings.Contains(w, "udp") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("lenient path must record a downgrade warning naming myapp/udp, got %v",
			cfg.Warnings)
	}
}

// TestTermBearingAppStrayTokenStillRejected closes the propagation path. For a
// term-bearing application the parent `app` struct is DISCARDED (only the
// generated per-term applications are stored), so an UnknownDirectLeaves record
// left on the parent would vanish and escape the strict gate.
func TestTermBearingAppStrayTokenStillRejected(t *testing.T) {
	_, err := CompileConfig(setTree6524(t,
		"set applications application myapp term t1 protocol tcp destination-port 80",
		"set applications application myapp bogus-leaf 1",
	))
	if err == nil {
		t.Fatal("expected commit to REJECT a stray token on a term-bearing " +
			"application body — the parent struct is discarded, so the record " +
			"must be carried onto the generated term applications (#6524)")
	}
	if !strings.Contains(err.Error(), "bogus-leaf") {
		t.Fatalf("reject message must name the stray token, got: %v", err)
	}
}

// TestChainedAppDuplicateDetectionStillFires proves the #5574 conflicting-
// duplicate gate still engages once the chain is flattened — the chained
// spelling must not become a way to smuggle two conflicting values past it.
func TestChainedAppDuplicateDetectionStillFires(t *testing.T) {
	_, err := CompileConfig(setTree6524(t,
		"set applications application myapp protocol tcp destination-port 22",
		"set applications application myapp destination-port 53",
	))
	if err == nil {
		t.Fatal("expected commit to REJECT conflicting duplicate destination-port")
	}
	if !strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("reject message must name destination-port, got: %v", err)
	}
}

// TestHierarchicalAppBodyUnchanged is the over-reach guard: the hierarchical
// (braced) shape, where the leaves are already siblings, must compile exactly
// as before. This subtest must stay GREEN under a revert of the #6524 compiler
// change — if it goes RED the fix altered a shape it had no business touching.
func TestHierarchicalAppBodyUnchanged(t *testing.T) {
	p := NewParser(`
applications {
    application myapp {
        protocol tcp;
        destination-port 8080;
        source-port 5000;
        inactivity-timeout 1800;
        description sample;
    }
}
`)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" ||
		app.SourcePort != "5000" || app.InactivityTimeout != 1800 ||
		app.Description != "sample" {
		t.Fatalf("hierarchical body compiled differently: %+v", app)
	}
	if len(app.UnknownDirectLeaves) != 0 {
		t.Fatalf("hierarchical body must record no unknown leaves, got %v",
			app.UnknownDirectLeaves)
	}
}

// TestSiblingFlatSetAppBodyUnchanged is the second over-reach guard: the
// one-leaf-per-set-line spelling (the shape that always worked) is untouched,
// and records no unknown leaves. Also stays GREEN under revert.
func TestSiblingFlatSetAppBodyUnchanged(t *testing.T) {
	cfg, err := CompileConfig(setTree6524(t,
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
		"set applications application myapp description sample",
	))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" || app.Description != "sample" {
		t.Fatalf("sibling flat-set body compiled differently: %+v", app)
	}
	if len(app.UnknownDirectLeaves) != 0 {
		t.Fatalf("sibling body must record no unknown leaves, got %v", app.UnknownDirectLeaves)
	}
}

// TestApplicationDirectLeafKeywordsCoverCompilerSwitch is a drift canary: every
// keyword the direct-body switch in compileApplications handles must also be in
// applicationDirectLeafKeywords. A keyword added to the switch but missed here
// would be classified as garbage and hard-rejected at commit — a fail-CLOSED
// regression on valid config.
func TestApplicationDirectLeafKeywordsCoverCompilerSwitch(t *testing.T) {
	// The cases of the direct-body switch, kept in sync by this test.
	switchCases := []string{
		"protocol", "destination-port", "source-port",
		"inactivity-timeout", "timeout", "icmp-type", "icmp-code",
		"alg", "description", "term",
	}
	for _, kw := range switchCases {
		if !applicationDirectLeafKeywords[kw] {
			t.Fatalf("compileApplications handles %q but applicationDirectLeaves "+
				"does not recognize it — a valid statement would be recorded as "+
				"unknown and hard-rejected at commit", kw)
		}
	}
	if len(applicationDirectLeafKeywords) != len(switchCases) {
		t.Fatalf("applicationDirectLeafKeywords has %d entries, the compiler switch "+
			"has %d — an entry here with no switch case is silently ignored "+
			"rather than rejected", len(applicationDirectLeafKeywords), len(switchCases))
	}
}
