package config

import (
	"strings"
	"testing"
)

// #5195 (codex-177 A3-b2-F7): the compiler mints synthetic proposals under the
// reserved `__proposal-set/<policy>/<set>/<index>` name namespace when expanding
// a predefined `proposal-set` (expandIKEProposalSets / expandIPsecProposalSets)
// and writes them into the SAME name-keyed maps that hold operator-authored
// proposals. The lexer permits `/ _ .` in bare identifiers, so an operator can
// author a proposal with that exact name; the unconditional map write then
// silently overwrites one with the other, installing a different — typically
// weaker — crypto proposal than configured (a silent downgrade).
//
// Fix: validateReservedIPsecProposalNamesAST reserves the prefix at strict
// commit (hard-reject) and warns on the tolerant load / peer-sync path; the
// expand loops keep an occupancy guard so a leniently-loaded squatter is never
// clobbered either.

// STRICT: an operator-authored IKE proposal squatting a synthetic name is
// rejected at commit — the collision (and thus the silent downgrade) cannot
// commit. RED-on-revert: without the gate, expandIKEProposalSets overwrites the
// authored proposal and CompileConfig returns nil, so the t.Fatal below fires.
func TestReservedProposalName_StrictRejectsIKE_5195(t *testing.T) {
	name := "__proposal-set/ike-pol/standard/1"
	tree := buildTree(t, []string{
		// Operator authors a STRONG proposal that happens to take the exact
		// name the `standard` set would synthesize for policy ike-pol.
		"set security ike proposal " + name + " authentication-method pre-shared-keys",
		"set security ike proposal " + name + " encryption-algorithm aes-256-cbc",
		"set security ike proposal " + name + " authentication-algorithm sha-256",
		"set security ike proposal " + name + " dh-group group14",
		// A policy whose proposal-set expansion targets that same name with the
		// WEAK standard member 1 (3des-cbc/sha1).
		"set security ike policy ike-pol proposal-set standard",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of reserved __proposal-set/ IKE proposal name, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") ||
		!strings.Contains(err.Error(), reservedProposalSetNamePrefix) ||
		!strings.Contains(err.Error(), "#5195") {
		t.Fatalf("unexpected error text (want reserved-prefix #5195 reject): %v", err)
	}
	if !strings.Contains(err.Error(), "ike") {
		t.Fatalf("error should name the ike section: %v", err)
	}
}

// STRICT: same reject for the IPsec (ESP) proposal namespace.
func TestReservedProposalName_StrictRejectsIPsec_5195(t *testing.T) {
	name := "__proposal-set/esp-pol/standard/1"
	tree := buildTree(t, []string{
		"set security ipsec proposal " + name + " protocol esp",
		"set security ipsec proposal " + name + " encryption-algorithm aes-256-cbc",
		"set security ipsec proposal " + name + " authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy esp-pol proposal-set standard",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of reserved __proposal-set/ IPsec proposal name, got nil")
	}
	if !strings.Contains(err.Error(), "reserved") ||
		!strings.Contains(err.Error(), reservedProposalSetNamePrefix) ||
		!strings.Contains(err.Error(), "#5195") {
		t.Fatalf("unexpected error text (want reserved-prefix #5195 reject): %v", err)
	}
	if !strings.Contains(err.Error(), "ipsec") {
		t.Fatalf("error should name the ipsec section: %v", err)
	}
}

// LENIENT (load / peer-sync): the reject downgrades to a warning so an
// already-persisted config an older binary accepted still boots — AND the
// expand-time occupancy guard preserves the operator-authored (strong) crypto
// instead of silently overwriting it with the weak set member. This directly
// asserts NO DOWNGRADE on the tolerant path.
//
// RED-on-revert (occupancy guard): without the guard, expandIKEProposalSets
// overwrites the authored aes-256-cbc proposal with the standard member 1
// (3des-cbc), so the EncryptionAlg assertion fails.
// RED-on-revert (gate): without the gate there is no #5195 warning.
func TestReservedProposalName_LenientPreservesAuthoredCrypto_5195(t *testing.T) {
	name := "__proposal-set/ike-pol/standard/1"
	tree := buildTree(t, []string{
		"set security ike proposal " + name + " authentication-method pre-shared-keys",
		"set security ike proposal " + name + " encryption-algorithm aes-256-cbc",
		"set security ike proposal " + name + " authentication-algorithm sha-256",
		"set security ike proposal " + name + " dh-group group14",
		"set security ike policy ike-pol proposal-set standard",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: reserved proposal name must downgrade to a warning, got error: %v", err)
	}

	// A #5195 warning must be emitted (the operator is told).
	sawWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5195") {
			sawWarn = true
			break
		}
	}
	if !sawWarn {
		t.Fatalf("expected a #5195 reserved-name warning on the lenient path, got: %v", cfg.Warnings)
	}

	// NO DOWNGRADE: the authored strong proposal must survive unclobbered.
	p := cfg.Security.IPsec.IKEProposals[name]
	if p == nil {
		t.Fatalf("authored proposal %q missing after lenient compile", name)
	}
	if p.EncryptionAlg != "aes-256-cbc" {
		t.Fatalf("SILENT DOWNGRADE: authored proposal %q EncryptionAlg = %q, want aes-256-cbc "+
			"(the synthetic standard member 1 = 3des-cbc must not overwrite it)", name, p.EncryptionAlg)
	}
}

// A normal proposal-set config with NO reserved-prefix authored names commits
// cleanly and expands to distinct synthetic proposals — the gate must not
// over-reject legitimate configs, and expansion still works.
func TestReservedProposalName_NoFalsePositive_5195(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike policy ike-pol proposal-set standard",
		"set security ipsec policy esp-pol proposal-set standard",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a clean proposal-set config must commit, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5195") {
			t.Fatalf("unexpected #5195 warning on a config without reserved-prefix names: %q", w)
		}
	}
	// The two synthetic standard members must both be installed and DISTINCT.
	m1 := cfg.Security.IPsec.IKEProposals["__proposal-set/ike-pol/standard/1"]
	m2 := cfg.Security.IPsec.IKEProposals["__proposal-set/ike-pol/standard/2"]
	if m1 == nil || m2 == nil {
		t.Fatalf("expected both synthetic standard members installed, got m1=%v m2=%v", m1, m2)
	}
	if m1.EncryptionAlg == m2.EncryptionAlg {
		t.Fatalf("synthetic members should be distinct, both = %q", m1.EncryptionAlg)
	}
}
