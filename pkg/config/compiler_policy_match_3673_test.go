package config

import (
	"strings"
	"testing"
)

// Tests for #3673 (codex-review-125 finding M06): the #3142 tail-scan closed
// the multi-value-leaf escape for the KNOWN unsupported match keywords
// (dynamic-application / url-category / source-identity), but it did NOT reject
// from-zone / to-zone collapsed onto the same tail. Under a ZONE-PAIR policy
// match, from-zone/to-zone are NOT registered `match` siblings, so a flat-set
// or bracketed list that writes them after a value collapses them onto the
// preceding multi-value leaf's tail (the #2419 collapse) and they are consumed
// as bogus application/address operands.
//
// The undefined-application gate (#3144) and the address-definedness gate
// reject the unknown token today — but ONLY because it is not a defined
// application/address. An operator who defines an application (or address-book
// entry) literally named "from-zone"/"to-zone" satisfies those gates, and the
// reserved keyword then commits silently as a bogus operand — the exact
// "reserved keyword accepted as an operand" fail-open class #3113/#3142 exists
// to reject. The #3673 fix extends validatePolicyMatchLeavesStrict's tail scan
// to reject from-zone/to-zone in a supported multi-value leaf's collapsed tail.
//
// Flat-set / bracketed syntax MUST be built with ParseSetCommand/SetPath — the
// bracket stripping and the flat-set token collapse only happen there.
func build3673Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// TestPolicyMatchSwallowedZoneTokenRejected is the primary fail-on-revert
// anchor. Each case defines applications named "from-zone"/"to-zone" (and any
// extra operand token) so the #3144 undefined-application gate and the
// address-definedness gate are SATISFIED — the ONLY thing that can reject the
// config is the #3673 swallowed-structural-token check. Reverting that check
// makes every case COMMIT (the genuine fail-open: a reserved match keyword
// silently consumed as an application/address operand), turning these RED.
func TestPolicyMatchSwallowedZoneTokenRejected(t *testing.T) {
	// Defining trust/untrust plus applications literally named from-zone/
	// to-zone/bad removes every OTHER reason to reject, isolating the #3673 gate.
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set applications application from-zone protocol tcp destination-port 1",
		"set applications application to-zone protocol tcp destination-port 2",
		"set applications application bad protocol tcp destination-port 3",
	}
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error
	}{
		{
			name: "flat-set from-zone swallowed onto application tail",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any from-zone bad",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match application absorbed the reserved match keyword "from-zone"`,
		},
		{
			name: "flat-set to-zone swallowed onto application tail",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any to-zone bad",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match application absorbed the reserved match keyword "to-zone"`,
		},
		{
			name: "bracketed from-zone swallowed onto application tail",
			cmds: []string{
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application [ from-zone bad ]",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match application absorbed the reserved match keyword "from-zone"`,
		},
		{
			name: "flat-set from-zone swallowed onto source-address tail",
			cmds: []string{
				// from-zone/bad are also defined as address-book entries below so
				// only the #3673 gate can reject the source-address tail.
				"set security zones security-zone trust address-book address from-zone 10.0.0.1/32",
				"set security zones security-zone trust address-book address bad 10.0.0.2/32",
				"set security policies from-zone trust to-zone untrust policy p match source-address any from-zone bad",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
			want: `from-zone trust to-zone untrust policy "p" match source-address absorbed the reserved match keyword "from-zone"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := build3673Tree(t, append(append([]string{}, base...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a swallowed structural match keyword; want commit rejection (#3673)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3673") {
				t.Fatalf("CompileConfig error = %q, want #3673 reference", err.Error())
			}
		})
	}
}

// TestPolicyMatchSwallowedZoneTokenLenientWarns proves the tolerant load /
// peer-sync path (CompileConfigLenient) does NOT hard-fail on the swallowed
// zone token — it compiles and records a warning naming the keyword, so an
// already-persisted config an older binary accepted still boots (#1960).
func TestPolicyMatchSwallowedZoneTokenLenientWarns(t *testing.T) {
	tree := build3673Tree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set applications application from-zone protocol tcp destination-port 1",
		"set applications application bad protocol tcp destination-port 3",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any from-zone bad",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on a swallowed zone token; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3673") && strings.Contains(w, `keyword "from-zone"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3673 swallowed-zone-token warning", cfg.Warnings)
	}
}

// TestPolicyMatchLegitimateAppListNotOverRejectedBy3673 proves the #3673 gate
// does NOT over-reject legitimate application/address lists that happen to
// collapse onto the same multi-value leaf. Real app names and the `any`
// wildcard are never from-zone/to-zone, so a normal bracketed list still
// commits — and a GLOBAL policy that legitimately carries from-zone/to-zone as
// its own match context (a registered sibling, #3148) is untouched.
func TestPolicyMatchLegitimateAppListNotOverRejectedBy3673(t *testing.T) {
	t.Run("zone-pair bracketed application list", func(t *testing.T) {
		tree := build3673Tree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application [ junos-http junos-https ]",
			"set security policies from-zone trust to-zone untrust policy p then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig over-rejected a legit bracketed application list: %v", err)
		}
	})
	t.Run("global policy from-zone/to-zone match context still commits", func(t *testing.T) {
		tree := build3673Tree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies global policy g match source-address any",
			"set security policies global policy g match destination-address any",
			"set security policies global policy g match application any",
			"set security policies global policy g match from-zone trust",
			"set security policies global policy g match to-zone untrust",
			"set security policies global policy g then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig over-rejected a legit global from-zone/to-zone match context: %v", err)
		}
	})
}
