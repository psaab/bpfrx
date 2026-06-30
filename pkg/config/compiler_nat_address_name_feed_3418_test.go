package config

import (
	"testing"
)

// #3418: the strict NAT commit validator
// (validateNATSourceAddressNameReferencesStrict) must ACCEPT a NAT
// `match {source,destination}-address-name <name>` that names a feed-only
// `security dynamic-address address-name <name> profile feed-name <feed>`
// binding with NO static `security address-book` duplicate. #3303/#3312
// threaded the live dynamic-address feed overlay into the NAT snapshot builder
// (resolveNATAddressNamePrefixes unions the static book with feedOverlay[name]),
// so such a reference DOES carry prefixes at runtime — but the strict commit
// gate originally only recognized static address-book names and hard-rejected
// the feed-only name as "undefined", a post-#3303 contradiction that forced
// operators to author a redundant static address-book object.
//
// The #3425 feed carve-out (the `feedBinding` short-circuit in `nameError`)
// fixes the over-reject, and #3303's pkg/dataplane/userspace tests prove the
// snapshot carries the feed prefixes for all four SNAT/DNAT source/dest paths.
// But the strict-commit ACCEPT was only pinned for ONE of the four
// combinations (SNAT source, TestNATSourceAddressNameDirectFeedAccepted) — the
// reason the contradiction survived (#3418 L01): reverting the carve-out would
// still leave SNAT-destination, DNAT-source, and DNAT-destination feed-only
// references silently rejected with no failing test. These tests close that
// gap across the full matrix.
//
// RED-on-revert: removing the `feedBinding(name)` short-circuit from
// `nameError` makes `defined(name)` (static-book-only) return false for a
// feed-only name, so CompileConfig hard-rejects it as undefined and every test
// below fails. The complementary "genuinely-undefined reference is STILL
// rejected" direction is anchored by the #2416 (source) and #3229
// (destination) undefined-reference tests for both SNAT and DNAT, so accepting
// feed-only names does NOT open a fail-open hole.
//
// All trees use ParseSetCommand + SetPath (buildTree), never NewParser (the
// flat-set gotcha in CLAUDE.md), so the production strict validator is
// exercised — the #3303 tests call buildSnapshotWithSchedulerState directly and
// bypass CompileConfig, which is how the contradiction stayed invisible.

// feedServerBinding returns the dynamic-address feed-server + address-name
// binding lines for a feed-only name (no static address-book entry for it).
func feedServerBinding(bindingName string) []string {
	return []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name " + bindingName + " profile feed-name malware",
	}
}

// TestNATSNATDestinationAddressNameDirectFeedAccepted: an SNAT rule whose
// `match destination-address-name` names a feed-only dynamic-address binding
// must commit clean (#3418 / #3303 / #3425).
func TestNATSNATDestinationAddressNameDirectFeedAccepted(t *testing.T) {
	lines := append(feedServerBinding("bad-actors"),
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match destination-address-name bad-actors",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	)
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("SNAT match destination-address-name referencing a direct "+
			"dynamic-address feed binding must commit (#3418/#3303/#3425), got: %v", err)
	}
}

// TestNATDNATSourceAddressNameDirectFeedAccepted: a DNAT rule whose
// `match source-address-name` (the #2394 source constraint) names a feed-only
// dynamic-address binding must commit clean (#3418 / #3303 / #3425).
func TestNATDNATSourceAddressNameDirectFeedAccepted(t *testing.T) {
	lines := append(feedServerBinding("bad-actors"),
		"set security zones security-zone untrust",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match source-address-name bad-actors",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	)
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("DNAT match source-address-name referencing a direct "+
			"dynamic-address feed binding must commit (#3418/#3303/#3425), got: %v", err)
	}
}

// TestNATDNATDestinationAddressNameDirectFeedAccepted: a DNAT rule whose
// `match destination-address-name` names a feed-only dynamic-address binding
// must commit clean (#3418 / #3303 / #3425).
func TestNATDNATDestinationAddressNameDirectFeedAccepted(t *testing.T) {
	lines := append(feedServerBinding("bad-actors"),
		"set security zones security-zone untrust",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address-name bad-actors",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	)
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("DNAT match destination-address-name referencing a direct "+
			"dynamic-address feed binding must commit (#3418/#3303/#3425), got: %v", err)
	}
}
