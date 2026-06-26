package config

import (
	"strings"
	"testing"
)

// Tests for #3141 (codex-review-068 finding 068-01): a flat-set
// `then deny log session-init` collapses the `log session-init` modifier
// onto the deny node (Keys=["deny","log","session-init"]) instead of
// nesting it as a sibling `then log` node. compilePolicy's `then` switch
// `deny` arm used to read only t.Name() and silently dropped the collapsed
// modifier, so a deny-with-logging rule committed but `pol.Log` was never
// set — the configured audit logging was silently inert (a deny-rule
// observability / compliance failure, not a packet fail-open).
//
// Chosen contract: WIRE the legitimate log/count modifiers under collapsed
// `then deny` (applyCollapsedDenyModifiers) so deny+log works in BOTH the
// flat-collapsed and the separate-node forms, matching the standalone
// `then log`/`then count` arms; REJECT any OTHER collapsed deny modifier at
// commit (validatePolicyThenDenyStrict), mirroring the #3114/#3115
// then-permit / then-reject gates.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser. buildPolicyThenTree is shared with the #3114 test in this
// package.

// findZonePairPolicy returns the named policy under a from-zone/to-zone pair.
func findZonePairPolicy(t *testing.T, cfg *Config, from, to, name string) *Policy {
	t.Helper()
	for _, zp := range cfg.Security.Policies {
		if zp.FromZone != from || zp.ToZone != to {
			continue
		}
		for _, p := range zp.Policies {
			if p.Name == name {
				return p
			}
		}
	}
	t.Fatalf("policy %q (from-zone %s to-zone %s) not found", name, from, to)
	return nil
}

// findGlobalPolicy returns the named global policy.
func findGlobalPolicy(t *testing.T, cfg *Config, name string) *Policy {
	t.Helper()
	for _, p := range cfg.Security.GlobalPolicies {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("global policy %q not found", name)
	return nil
}

// TestPolicyThenDenyCollapsedLogWired is the fail-on-revert proof: a
// flat-set `then deny log session-init` (and session-close, and both, and
// count) sets the corresponding pol.Log / pol.Count fields. Reverting
// applyCollapsedDenyModifiers to a no-op leaves pol.Log nil — every
// assertion here goes RED. Covers zone-pair and global scopes.
func TestPolicyThenDenyCollapsedLogWired(t *testing.T) {
	t.Run("zone-pair deny log session-init", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny log session-init",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny log session-init: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Action != PolicyDeny {
			t.Fatalf("Action = %v, want PolicyDeny", p.Action)
		}
		if p.Log == nil {
			t.Fatal("pol.Log is nil — collapsed `then deny log session-init` dropped the log modifier (#3141)")
		}
		if !p.Log.SessionInit {
			t.Fatal("pol.Log.SessionInit = false, want true (#3141)")
		}
		if p.Log.SessionClose {
			t.Fatal("pol.Log.SessionClose = true, want false (only session-init configured)")
		}
	})

	t.Run("zone-pair deny log session-close", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny log session-close",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny log session-close: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Log == nil || !p.Log.SessionClose {
			t.Fatalf("pol.Log session-close not wired: %+v (#3141)", p.Log)
		}
		if p.Log.SessionInit {
			t.Fatal("pol.Log.SessionInit = true, want false (only session-close configured)")
		}
	})

	t.Run("zone-pair deny log session-init session-close", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny log session-init session-close",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny log session-init session-close: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Log == nil || !p.Log.SessionInit || !p.Log.SessionClose {
			t.Fatalf("pol.Log both flags not wired: %+v (#3141)", p.Log)
		}
	})

	t.Run("zone-pair deny count", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny count",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny count: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if !p.Count {
			t.Fatal("pol.Count = false, want true for collapsed `then deny count` (#3141)")
		}
	})

	t.Run("zone-pair deny log session-init session-close count", func(t *testing.T) {
		// All supported modifiers in one collapsed tail must commit and wire
		// every field — no trailing token is mistaken for an unsupported
		// modifier (#3141 review fold).
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny log session-init session-close count",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny log session-init session-close count: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Action != PolicyDeny {
			t.Fatalf("Action = %v, want PolicyDeny", p.Action)
		}
		if p.Log == nil || !p.Log.SessionInit || !p.Log.SessionClose {
			t.Fatalf("pol.Log both flags not wired: %+v (#3141)", p.Log)
		}
		if !p.Count {
			t.Fatal("pol.Count = false, want true (#3141)")
		}
	})

	t.Run("global deny log session-init", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security policies global policy g1 match source-address any",
			"set security policies global policy g1 match destination-address any",
			"set security policies global policy g1 match application any",
			"set security policies global policy g1 then deny log session-init",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected global then deny log session-init: %v", err)
		}
		p := findGlobalPolicy(t, cfg, "g1")
		if p.Action != PolicyDeny {
			t.Fatalf("Action = %v, want PolicyDeny", p.Action)
		}
		if p.Log == nil || !p.Log.SessionInit {
			t.Fatalf("global pol.Log session-init not wired: %+v (#3141)", p.Log)
		}
	})
}

// TestPolicyThenDenySeparateNodeLogStillWorks proves the canonical
// separate-node form `then { deny; log session-init; }` (two distinct set
// lines, handled by the standalone `log` arm) keeps wiring the log modifier
// — the #3141 collapsed-form fix does not regress it.
func TestPolicyThenDenySeparateNodeLogStillWorks(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy web match source-address any",
		"set security policies from-zone trust to-zone untrust policy web match destination-address any",
		"set security policies from-zone trust to-zone untrust policy web match application any",
		"set security policies from-zone trust to-zone untrust policy web then deny",
		"set security policies from-zone trust to-zone untrust policy web then log session-init",
		"set security policies from-zone trust to-zone untrust policy web then log session-close",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected separate-node deny + log: %v", err)
	}
	p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
	if p.Action != PolicyDeny {
		t.Fatalf("Action = %v, want PolicyDeny", p.Action)
	}
	if p.Log == nil || !p.Log.SessionInit || !p.Log.SessionClose {
		t.Fatalf("separate-node deny+log dropped a flag: %+v", p.Log)
	}
}

// TestPolicyThenDenyBareStillCommits proves a plain `then deny` (no
// modifier) still commits for both zone-pair and global scopes — the gate
// only fires on an UNSUPPORTED modifier under `then deny`.
func TestPolicyThenDenyBareStillCommits(t *testing.T) {
	t.Run("zone-pair bare deny", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy d1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy d1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy d1 match application any",
			"set security policies from-zone trust to-zone untrust policy d1 then deny",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected a bare then deny: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "d1")
		if p.Action != PolicyDeny {
			t.Fatalf("Action = %v, want PolicyDeny", p.Action)
		}
		if p.Log != nil {
			t.Fatalf("bare then deny should not set Log, got %+v", p.Log)
		}
	})
	t.Run("global bare deny", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security policies global policy g1 match source-address any",
			"set security policies global policy g1 match destination-address any",
			"set security policies global policy g1 match application any",
			"set security policies global policy g1 then deny",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a global bare then deny: %v", err)
		}
	})
}

// TestPolicyThenDenyUnsupportedModifierRejectedAtCommit proves a collapsed
// `then deny <unsupported>` modifier is hard-rejected at commit for both
// zone-pair and global scopes. Reverting validatePolicyThenDenyStrict to
// `return nil, nil` turns these GREEN and so RED.
func TestPolicyThenDenyUnsupportedModifierRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "zone-pair unsupported modifier",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny profile blocked-web",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "profile"`,
		},
		{
			name: "global unsupported modifier",
			cmds: []string{
				"set security policies global policy gd match source-address any",
				"set security policies global policy gd match destination-address any",
				"set security policies global policy gd match application any",
				"set security policies global policy gd then deny foobar",
			},
			want: `global policy "gd" then deny "foobar"`,
		},
		{
			// Supported token LEADS, unsupported token TRAILS. Checking only
			// Keys[1] ("count", supported) let "evilmod" slip through silently
			// — the #3141 review-fold gap. The whole collapsed tail must be
			// inspected.
			name: "zone-pair supported-leads unsupported-trails (count evilmod)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny count evilmod",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "evilmod"`,
		},
		{
			// log + its session-init sub-token LEAD; unsupported token TRAILS.
			name: "zone-pair log session-init then unsupported-trails (evilmod)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny log session-init evilmod",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "evilmod"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildPolicyThenTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted unsupported then-deny modifier; want commit rejection (#3141)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3141") {
				t.Fatalf("CompileConfig error = %q, want #3141 reference", err.Error())
			}
		})
	}
}

// TestPolicyThenDenyUnsupportedModifierLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on an
// unsupported then-deny modifier — it compiles and records a #3141 warning
// so an already-persisted config still boots (#1960 fail-closed-on-load).
func TestPolicyThenDenyUnsupportedModifierLenientWarns(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security policies from-zone trust to-zone untrust policy web then deny profile blocked-web",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on unsupported then-deny modifier; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3141") && strings.Contains(w, "profile") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3141 then-deny warning", cfg.Warnings)
	}
}
