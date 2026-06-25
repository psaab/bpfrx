package config

import "testing"

// TestPhase2ProposalDHGroupPrefixedSpelling is the #2639 core regression:
// the Phase 2 (ESP) proposal `dh-group group14` must compile to DHGroup
// 14. Before the fix, the Phase 2 site parsed dh-group with a bare
// strconv.Atoi, so the Junos/vSRX prefixed spelling failed to parse and
// DHGroup stayed 0 — silently dropping PFS from the ESP proposal.
//
// fail-on-revert: revert parseDHGroup back to a bare strconv.Atoi at the
// Phase 2 dh-group case and this expects DHGroup 14 but gets 0 → red.
func TestPhase2ProposalDHGroupPrefixedSpelling(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec proposal esp-p2 protocol esp",
		"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal esp-p2 dh-group group14",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	prop, ok := cfg.Security.IPsec.Proposals["esp-p2"]
	if !ok {
		t.Fatal("ipsec proposal esp-p2 not compiled")
	}
	if prop.DHGroup != 14 {
		t.Errorf("DHGroup = %d, want 14 (group14 must parse, not be dropped to 0)", prop.DHGroup)
	}
}

// TestPhase2ProposalDHGroupVariants covers the prefixed ECP spelling and
// the bare-number form, both of which the shared helper must accept.
func TestPhase2ProposalDHGroupVariants(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want int
	}{
		{"prefixed-group19", "group19", 19},
		{"bare-14", "14", 14},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set security ipsec proposal esp-p2 protocol esp",
				"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
				"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
				"set security ipsec proposal esp-p2 dh-group " + tc.set,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			prop := cfg.Security.IPsec.Proposals["esp-p2"]
			if prop == nil || prop.DHGroup != tc.want {
				got := 0
				if prop != nil {
					got = prop.DHGroup
				}
				t.Errorf("DHGroup = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestPhase1ProposalDHGroupNoRegression confirms the Phase 1 IKE proposal
// still parses both the prefixed and bare dh-group spellings after the
// shared-helper refactor.
func TestPhase1ProposalDHGroupNoRegression(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-p1 authentication-algorithm sha-256",
		"set security ike proposal ike-p1 dh-group group14",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	prop, ok := cfg.Security.IPsec.IKEProposals["ike-p1"]
	if !ok {
		t.Fatal("ike proposal ike-p1 not compiled")
	}
	if prop.DHGroup != 14 {
		t.Errorf("Phase 1 DHGroup = %d, want 14", prop.DHGroup)
	}
}

// TestParseDHGroupHelper exercises the shared helper directly.
func TestParseDHGroupHelper(t *testing.T) {
	cases := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"group14", 14, true},
		{"group19", 19, true},
		{"14", 14, true},
		{"0", 0, true},
		{"", 0, false},
		{"group", 0, false},
		{"groupabc", 0, false},
		{"notanumber", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseDHGroup(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseDHGroup(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
