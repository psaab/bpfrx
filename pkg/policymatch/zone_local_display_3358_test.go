package policymatch

import (
	"net"
	"slices"
	"testing"
)

// #3358: a zone-local address book (#3061) is folded into the global book under
// the synthetic key zone-local/<zone>/<name>, and resolveZoneLocalAddressBooks
// rewrites each policy's match tokens to those qualified names. matchedResult
// (the SSOT for all three `show security match-policies` transports — CLI,
// gRPC MatchPolicies, REST MatchPoliciesResult) copied the raw qualified tokens
// into the display Result, so the operator saw `zone-local/trust/web` instead of
// the authored name `web`. It now unqualifies via config.DisplayAddressNames.
// This is the fail-on-revert guard at the SSOT: revert the wrap in
// matchedResult and the assertions below go RED across all three transports.

func TestMatchedResultUnqualifiesZoneLocalNames(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address external 198.51.100.0/24",
		"set security zones security-zone trust address-book address web 10.0.1.100/32",
		"set security zones security-zone untrust address-book address svc 192.0.2.5/32",
		// Zone-local policy: source resolves trust-local web, destination
		// resolves untrust-local svc.
		"set security policies from-zone trust to-zone untrust policy zl match source-address web",
		"set security policies from-zone trust to-zone untrust policy zl match destination-address svc",
		"set security policies from-zone trust to-zone untrust policy zl match application any",
		"set security policies from-zone trust to-zone untrust policy zl then permit",
		// Control: a global-book source name (NOT in trust's local book) stays
		// the bare authored token.
		"set security policies from-zone trust to-zone untrust policy normal match source-address external",
		"set security policies from-zone trust to-zone untrust policy normal match destination-address any",
		"set security policies from-zone trust to-zone untrust policy normal match application any",
		"set security policies from-zone trust to-zone untrust policy normal then permit",
		"set security policies default-policy deny-all",
	})

	// Hit the zone-local policy: src in web, dst in svc.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.100"),
		DstIP: net.ParseIP("192.0.2.5"),
	})
	if !res.Matched || res.PolicyName != "zl" {
		t.Fatalf("expected match on zl, got Matched=%v PolicyName=%q", res.Matched, res.PolicyName)
	}
	if !slices.Equal(res.SrcAddresses, []string{"web"}) {
		t.Fatalf("zl Result.SrcAddresses = %v, want [web] "+
			"(match-policies SSOT leaked the synthetic zone-local token — #3358 regression)", res.SrcAddresses)
	}
	if !slices.Equal(res.DstAddresses, []string{"svc"}) {
		t.Fatalf("zl Result.DstAddresses = %v, want [svc] "+
			"(match-policies SSOT leaked the synthetic zone-local token — #3358 regression)", res.DstAddresses)
	}

	// Control: hit the global-name policy; the authored token passes through.
	resCtl := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("198.51.100.7"),
		DstIP: net.ParseIP("203.0.113.9"),
	})
	if !resCtl.Matched || resCtl.PolicyName != "normal" {
		t.Fatalf("expected match on normal, got Matched=%v PolicyName=%q", resCtl.Matched, resCtl.PolicyName)
	}
	if !slices.Equal(resCtl.SrcAddresses, []string{"external"}) {
		t.Fatalf("normal Result.SrcAddresses = %v, want [external] (global name regressed)", resCtl.SrcAddresses)
	}
}
