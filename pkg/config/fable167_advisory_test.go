package config

import (
	"strings"
	"testing"
)

// warn167Has reports whether any compile warning contains sub.
func warn167Has(cfg *Config, sub string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// TestFable167P1ZonePairFromZoneJunosHostRejected is the RED-on-revert guard
// for #4230 (fable-167 P-1): a `from-zone junos-host to-zone <z>` zone-pair
// policy is host-ORIGINATED and inert (locally generated traffic egresses via
// the kernel TX path, never the AF_XDP RX gate), so it must be HARD-REJECTED at
// strict commit — mirroring the existing GLOBAL `match from-zone junos-host`
// gate (#3611 Piece A). Before the fix it committed clean (policyZoneSpecialTokens
// exempts junos-host from the undefined-zone check), so removing the zone-pair
// junos-host arm in validatePolicyZoneReferencesStrict turns this RED (the
// commit succeeds on the BAD config).
func TestFable167P1ZonePairFromZoneJunosHostRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies from-zone junos-host to-zone trust policy hb1 match source-address any",
		"set security policies from-zone junos-host to-zone trust policy hb1 match destination-address any",
		"set security policies from-zone junos-host to-zone trust policy hb1 match application any",
		"set security policies from-zone junos-host to-zone trust policy hb1 then deny",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected strict commit to reject a from-zone junos-host zone-pair policy (host-originated, inert), got nil error")
	}
	if !strings.Contains(err.Error(), "junos-host") || !strings.Contains(err.Error(), "host-originated") {
		t.Fatalf("reject error %q should name junos-host / host-originated", err.Error())
	}
}

// TestFable167P1LenientLoadWarnsNotBricks asserts the #1960 no-brick doctrine:
// the same from-zone junos-host zone-pair that strict commit REJECTS is
// downgraded to a warning on the tolerant load / peer-sync path so an
// already-persisted or peer-synced config still boots.
func TestFable167P1LenientLoadWarnsNotBricks(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies from-zone junos-host to-zone trust policy hb1 match source-address any",
		"set security policies from-zone junos-host to-zone trust policy hb1 match destination-address any",
		"set security policies from-zone junos-host to-zone trust policy hb1 match application any",
		"set security policies from-zone junos-host to-zone trust policy hb1 then deny",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not brick on a from-zone junos-host zone-pair: %v", err)
	}
	if !warn167Has(cfg, "junos-host") {
		t.Fatalf("lenient load should warn about the from-zone junos-host zone-pair; warnings=%v", cfg.Warnings)
	}
}

// TestFable167P1ToZoneJunosHostStillCommits guards against over-rejection:
// `to-zone junos-host` (host-INBOUND, #3019/#3639) is a supported context and
// must still commit — only the FROM side is rejected.
func TestFable167P1ToZoneJunosHostStillCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security policies from-zone trust to-zone junos-host policy host match source-address any",
		"set security policies from-zone trust to-zone junos-host policy host match destination-address any",
		"set security policies from-zone trust to-zone junos-host policy host match application any",
		"set security policies from-zone trust to-zone junos-host policy host then permit",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("to-zone junos-host (host-inbound) must still commit: %v", err)
	}
}

// TestFable167P3FlowKnobAdvisories is the RED-on-revert guard for #4231
// (fable-167 P-3): each of the five accepted-only `security flow` knobs must
// emit a commit advisory. Removing the compileFlow parsing or the
// compiler_validate_warn advisory turns these RED (silent accept).
func TestFable167P3FlowKnobAdvisories(t *testing.T) {
	cases := []struct {
		name    string
		set     string
		wantSub string
	}{
		{"route-change-timeout", "set security flow route-change-timeout 30", "route-change-timeout"},
		{"force-ip-reassembly", "set security flow force-ip-reassembly", "force-ip-reassembly"},
		{"multicast-session-lifetime", "set security flow multicast-session-lifetime 30", "multicast-session-lifetime"},
		{"preserve-incoming-fragment-size", "set security flow preserve-incoming-fragment-size", "preserve-incoming-fragment-size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.set})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("knob %q should commit (accepted-only), got err: %v", tc.name, err)
			}
			if !warn167Has(cfg, tc.wantSub) {
				t.Fatalf("knob %q should emit an accepted-only advisory; warnings=%v", tc.name, cfg.Warnings)
			}
			if !warn167Has(cfg, "#4231") {
				t.Fatalf("knob %q advisory should reference #4231; warnings=%v", tc.name, cfg.Warnings)
			}
		})
	}
}

// TestFable167P3SyncICMPSessionStrongAdvisory asserts sync-icmp-session gets its
// own, HA-specific advisory (ICMP sessions do NOT sync / survive failover).
func TestFable167P3SyncICMPSessionStrongAdvisory(t *testing.T) {
	tree := buildTree(t, []string{"set security flow sync-icmp-session"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("sync-icmp-session should commit (accepted-only): %v", err)
	}
	if !warn167Has(cfg, "sync-icmp-session") ||
		!warn167Has(cfg, "NOT sync") ||
		!warn167Has(cfg, "failover") {
		t.Fatalf("sync-icmp-session advisory should warn ICMP sessions do NOT sync / survive failover; warnings=%v", cfg.Warnings)
	}
}

// TestFable167P4aALGAdvisory is the RED-on-revert guard for #4232 P-4a: an
// unimplemented `security alg <proto>` stanza (e.g. h323) must emit an
// accepted-but-inert advisory instead of a silent drop.
func TestFable167P4aALGAdvisory(t *testing.T) {
	tree := buildTree(t, []string{"set security alg h323 disable"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("alg h323 should commit (accepted-only): %v", err)
	}
	if !warn167Has(cfg, "h323") || !warn167Has(cfg, "#4232") {
		t.Fatalf("alg h323 should emit an accepted-but-inert advisory (#4232); warnings=%v", cfg.Warnings)
	}
}

// TestFable167P4aALGSupportedNoAdvisory guards against a false advisory: a
// supported ALG proto (ftp) must NOT trigger the P-4a warning.
func TestFable167P4aALGSupportedNoAdvisory(t *testing.T) {
	tree := buildTree(t, []string{"set security alg ftp disable"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("alg ftp should commit: %v", err)
	}
	if warn167Has(cfg, "accepted but inert") {
		t.Fatalf("supported alg ftp should not emit the P-4a inert advisory; warnings=%v", cfg.Warnings)
	}
}

// TestFable167P4bPolicyUnknownChildAdvisory is the RED-on-revert guard for
// #4232 P-4b: an unrecognized direct child of `policy <name>` (a typo like
// `descripton`) must emit a probable-typo advisory instead of a silent drop.
func TestFable167P4bPolicyUnknownChildAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone untrust policy p1 descripton typo",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unknown policy child should commit (advisory, not reject): %v", err)
	}
	if !warn167Has(cfg, "descripton") || !warn167Has(cfg, "#4232") {
		t.Fatalf("unknown policy child should emit a probable-typo advisory (#4232); warnings=%v", cfg.Warnings)
	}
}

// TestFable167P4bKnownPolicyChildrenNoAdvisory guards against a false advisory:
// the recognized policy children (description/scheduler-name) must NOT trigger
// the P-4b warning.
func TestFable167P4bKnownPolicyChildrenNoAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone untrust policy p1 description ok",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("policy with description should commit: %v", err)
	}
	if warn167Has(cfg, "unrecognized child keyword") {
		t.Fatalf("recognized policy children should not emit the P-4b advisory; warnings=%v", cfg.Warnings)
	}
}
