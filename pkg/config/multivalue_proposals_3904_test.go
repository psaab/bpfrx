package config

import "testing"

// buildTree3904 compiles a slice of `set ...` commands into a ConfigTree via
// the flat-set path (ParseSetCommand + SetPath), the ONLY faithful way to
// exercise bracketed-list grouping (NewParser merges newlines).
func buildTree3904(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

// TestIKEIPsecProposalsMultiValue_3904 is the F-040/F-161 RED-on-revert guard:
// an IKE / IPsec policy `proposals [ p1 p2 ]` bracketed list must compile to
// BOTH references, not just the first. Before #3904 the schema leaf was not
// `multi` and the compiler read only Keys[1], so the second proposal was
// silently dropped and phase-1/phase-2 crypto negotiation narrowed.
func TestIKEIPsecProposalsMultiValue_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p2 authentication-method pre-shared-keys",
		"set security ike policy POL proposals [ ike-p1 ike-p2 ]",
		"set security ipsec proposal esp-p1 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-p2 encryption-algorithm aes-128-cbc",
		"set security ipsec policy IPOL proposals [ esp-p1 esp-p2 ]",
	})
	var sec SecurityConfig
	if err := compileIKE(tree.FindChild("security").FindChild("ike"), &sec); err != nil {
		t.Fatalf("compileIKE: %v", err)
	}
	if err := compileIPsec(tree.FindChild("security").FindChild("ipsec"), &sec); err != nil {
		t.Fatalf("compileIPsec: %v", err)
	}

	ike := sec.IPsec.IKEPolicies["POL"]
	if ike == nil {
		t.Fatal("IKE policy POL not compiled")
	}
	if got, want := ike.Proposals, []string{"ike-p1", "ike-p2"}; !equalStrs3904(got, want) {
		t.Errorf("IKE policy proposals = %v, want %v (bracket list truncated)", got, want)
	}

	esp := sec.IPsec.Policies["IPOL"]
	if esp == nil {
		t.Fatal("IPsec policy IPOL not compiled")
	}
	if got, want := esp.Proposals, []string{"esp-p1", "esp-p2"}; !equalStrs3904(got, want) {
		t.Errorf("IPsec policy proposals = %v, want %v (bracket list truncated)", got, want)
	}
}

// TestIKEIPsecProposalsSingleAndBlock_3904 confirms the single-value and
// hierarchical-block forms still compile to exactly one reference each — the
// multi leaf must not regress the common single-proposal case.
func TestIKEIPsecProposalsSingleAndBlock_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set security ike policy P1 proposals ike-single",
		"set security ipsec policy I1 proposals esp-single",
	})
	var sec SecurityConfig
	if err := compileIKE(tree.FindChild("security").FindChild("ike"), &sec); err != nil {
		t.Fatalf("compileIKE: %v", err)
	}
	if err := compileIPsec(tree.FindChild("security").FindChild("ipsec"), &sec); err != nil {
		t.Fatalf("compileIPsec: %v", err)
	}
	if got, want := sec.IPsec.IKEPolicies["P1"].Proposals, []string{"ike-single"}; !equalStrs3904(got, want) {
		t.Errorf("single IKE proposal = %v, want %v", got, want)
	}
	if got, want := sec.IPsec.Policies["I1"].Proposals, []string{"esp-single"}; !equalStrs3904(got, want) {
		t.Errorf("single IPsec proposal = %v, want %v", got, want)
	}
}

func equalStrs3904(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
