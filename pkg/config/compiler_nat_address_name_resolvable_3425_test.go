package config

import (
	"strings"
	"testing"
)

// #3425: NAT `match {source,destination}-address-name <name>` strict validation
// previously checked only that the name was DEFINED in the address book, not
// whether it RESOLVES to any concrete address. A defined-but-empty address-set
// (or a prefix-less address) passed commit, but the snapshot builder
// (resolveUserspaceAddressBookEntry → empty) then appends the raw unparseable
// token to keep the constraint non-empty, so the rule translates NO traffic.
// This is the NAT analog of the #3149 policy-address representability gate and
// the #3434 NAT match-application gate.
//
// validateNATSourceAddressNameReferencesStrict now rejects a defined-but-
// unresolvable reference at strict commit (hard error), warns on the tolerant
// load / peer-sync path (#1960), and accepts a DIRECT dynamic-address feed
// binding (resolved via the live overlay at runtime, #3303).
//
// All trees use ParseSetCommand + SetPath (buildTree), never NewParser.

// emptySetSNATSource builds a source NAT rule whose match source-address-name
// references the named address-set, which is DEFINED but has no members.
func emptySetSNATSource(matchName string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// Define the set but give it no members: it is present in
		// ab.AddressSets yet expands to nothing.
		"set security address-book global address-set " + matchName + " description empty",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name " + matchName,
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
}

// emptySetDNATDest builds a destination NAT rule whose match
// destination-address-name references a defined-but-empty address-set.
func emptySetDNATDest(matchName string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security address-book global address-set " + matchName + " description empty",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address-name " + matchName,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

// TestNATSourceAddressNameEmptySetRejected is the RED-on-revert anchor: an SNAT
// rule referencing a defined-but-empty address-set must be hard-rejected at
// strict commit. Reverting the #3425 resolvability gate (back to the bare
// `defined` existence check) makes CompileConfig accept it — this test then
// fails.
func TestNATSourceAddressNameEmptySetRejected(t *testing.T) {
	tree := buildTree(t, emptySetSNATSource("EMPTY"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("SNAT referencing a defined-but-empty source-address-name must be rejected at commit (#3425)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "source-address-name") ||
		!strings.Contains(msg, "EMPTY") ||
		!strings.Contains(msg, "does not resolve") {
		t.Fatalf("error must name the field, the entry, and the unresolvable cause, got: %v", err)
	}
}

// TestNATDestinationAddressNameEmptySetRejected: the destination twin (#3229)
// must reject a defined-but-empty destination-address-name too.
func TestNATDestinationAddressNameEmptySetRejected(t *testing.T) {
	tree := buildTree(t, emptySetDNATDest("EMPTY"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("DNAT referencing a defined-but-empty destination-address-name must be rejected at commit (#3425)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-address-name") ||
		!strings.Contains(msg, "EMPTY") ||
		!strings.Contains(msg, "does not resolve") {
		t.Fatalf("error must name the field, the entry, and the unresolvable cause, got: %v", err)
	}
}

// TestNATSourceAddressNamePrefixlessAddressRejected: a defined `address` with
// no configured prefix (empty Value) also resolves to nothing. The snapshot
// builder would append the raw token; strict commit must reject it.
func TestNATSourceAddressNamePrefixlessAddressRejected(t *testing.T) {
	// `address foo description ...` creates the address object with an empty
	// Value (no prefix leaf), exercising the addr.Value == "" branch of
	// resolveUserspaceAddressBookEntry / policyMatchAddressBookResolves.
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address noprefix description placeholder",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name noprefix",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("SNAT referencing a prefix-less address must be rejected at commit (#3425)")
	}
	if !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("error must explain the address resolves to nothing, got: %v", err)
	}
}

// TestNATAddressNameEmptySetLenientWarns: the tolerant load / peer-sync path
// must NOT hard-reject (so an already-persisted or peer-synced config still
// boots #1960) and must record a warning naming the dead reference.
func TestNATAddressNameEmptySetLenientWarns(t *testing.T) {
	tree := buildTree(t, emptySetSNATSource("EMPTY"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not hard-reject a defined-but-empty reference, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-address-name") && strings.Contains(w, "EMPTY") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path must warn about the unresolvable reference, got warnings: %v", cfg.Warnings)
	}
}

// TestNATSourceAddressNameNonEmptySetAccepted: the gate must NOT regress a
// VALID reference — a defined set with a resolvable member still commits.
func TestNATSourceAddressNameNonEmptySetAccepted(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address corp-a 198.51.100.0/24",
		"set security address-book global address-set corp-net address corp-a",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name corp-net",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("SNAT referencing a resolvable address-set must commit, got: %v", err)
	}
}

// TestNATSourceAddressNameDirectFeedAccepted: a DIRECT dynamic-address feed
// binding name has an empty STATIC book expansion but resolves via the live
// feed overlay at runtime (#3303). It must be accepted at strict commit, like
// the policy-address feed carve-out (#3294) — otherwise the documented
// feed-in-NAT feature is un-committable.
func TestNATSourceAddressNameDirectFeedAccepted(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name bad-actors profile feed-name malware",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name bad-actors",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("SNAT referencing a direct dynamic-address feed binding must commit (#3303/#3425), got: %v", err)
	}
}
