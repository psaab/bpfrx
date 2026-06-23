package config

import (
	"strings"
	"testing"
)

// TestPolicyUndefinedZoneFailsCommit asserts that a security policy whose
// from-zone or to-zone names a security zone the configuration never defines
// is HARD-REJECTED at commit (#2401).
//
// This is the fail-on-revert guard for the fail-open bug: before the fix such a
// reference was only a warning, the commit succeeded, and the rule was compiled
// and kept but never indexed into the dataplane zone-pair lookup (the
// userspace-dp unknown-zone branch keeps the rule but does not index it), so
// the zone pair fell through to the default action — a silent fail-OPEN under a
// permit default. Remove validatePolicyZoneReferencesStrict (or its dispatch in
// compiler.go) and these subtests go green on the BAD config, which is exactly
// the regression this test exists to catch.
func TestPolicyUndefinedZoneFailsCommit(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string
	}{
		{
			name: "undefined from-zone",
			cmds: []string{
				// only "untrust" is defined; "trustt" is a typo.
				"set security zones security-zone untrust",
				"set security policies from-zone trustt to-zone untrust policy p match source-address any",
				"set security policies from-zone trustt to-zone untrust policy p match destination-address any",
				"set security policies from-zone trustt to-zone untrust policy p match application any",
				"set security policies from-zone trustt to-zone untrust policy p then deny",
			},
			wantSub: `undefined from-zone "trustt"`,
		},
		{
			name: "undefined to-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security policies from-zone trust to-zone untrustt policy p match source-address any",
				"set security policies from-zone trust to-zone untrustt policy p match destination-address any",
				"set security policies from-zone trust to-zone untrustt policy p match application any",
				"set security policies from-zone trust to-zone untrustt policy p then deny",
			},
			wantSub: `undefined to-zone "untrustt"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject a policy referencing an undefined zone, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name the unknown zone (want substring %q)", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestPolicySpecialZoneTokensCommit asserts the strict validator does NOT
// reject the legitimate reserved zone tokens (#2401 anti-over-reject): the
// `any` wildcard zone, the `junos-host` self-traffic zone, and global policies
// (which carry no from/to-zone strings). A regression here would break valid
// operator configs.
func TestPolicySpecialZoneTokensCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		// from-zone any -> a defined zone
		"set security policies from-zone any to-zone trust policy fa match source-address any",
		"set security policies from-zone any to-zone trust policy fa match application any",
		"set security policies from-zone any to-zone trust policy fa then permit",
		// a defined zone -> to-zone any
		"set security policies from-zone trust to-zone any policy ta match source-address any",
		"set security policies from-zone trust to-zone any policy ta match application any",
		"set security policies from-zone trust to-zone any policy ta then permit",
		// junos-host self-traffic context on both sides
		"set security policies from-zone trust to-zone junos-host policy host match source-address any",
		"set security policies from-zone trust to-zone junos-host policy host match application any",
		"set security policies from-zone trust to-zone junos-host policy host then permit",
		// a global policy (no from/to-zone) must not be flagged
		"set security policies global policy g match source-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g then permit",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a legitimate special-zone policy: %v", err)
	}
}

// TestPolicyJunosHostNoWarningOrReject asserts the strict gate and the
// ValidateConfig warn pass agree on the special-zone exemption set (#2401
// consistency fold): a policy referencing the reserved `junos-host` self-traffic
// zone produces NEITHER a hard commit reject NOR a spurious
// "policy to-zone \"junos-host\": zone not defined" warning. Before the fix the
// warn validator only exempted `any`, so junos-host drew a confusing warning
// even though the strict path correctly accepted it. This is the fail-on-revert
// guard for the warn/strict divergence: narrowing the warn exemption back to
// just `any` makes the spurious-warning assertion fail.
func TestPolicyJunosHostNoWarningOrReject(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies from-zone trust to-zone junos-host policy host match source-address any",
		"set security policies from-zone trust to-zone junos-host policy host match application any",
		"set security policies from-zone trust to-zone junos-host policy host then permit",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a junos-host policy: %v", err)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "junos-host") && strings.Contains(w, "zone not defined") {
			t.Fatalf("ValidateConfig emitted a spurious junos-host zone-not-defined warning: %q", w)
		}
	}
}

// TestPolicyDefinedZonesCommit asserts that a wholly normal policy with every
// referenced zone defined commits cleanly (#2401).
func TestPolicyDefinedZonesCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a fully-defined policy: %v", err)
	}
}

// TestPolicyUndefinedZoneLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the undefined-zone reference to a warning instead
// of failing the compile, so an already-persisted or peer-synced config with a
// stale zone reference still boots (#2401 / #1960 no-brick). The dataplane
// drops the unindexed rule on its own, so the leniently-loaded bad config is
// inert.
func TestPolicyUndefinedZoneLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security policies from-zone trustt to-zone untrust policy p match source-address any",
		"set security policies from-zone trustt to-zone untrust policy p match application any",
		"set security policies from-zone trustt to-zone untrust policy p then deny",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a stale zone reference: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy zone reference (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded policy zone-reference warning, got warnings: %v", cfg.Warnings)
	}
}
