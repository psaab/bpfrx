package config

import "testing"

// TestJunosHostExemptionFlagsCaseInsensitive_5557 is the fail-on-revert guard
// for the #5557 host-inbound service-token case drift. Enforcement lower-cases
// every host-inbound token before admitting (unionHostInboundTokens /
// lowerTokens in pkg/dataplane/userspace and the Rust classify_system_service),
// so a lenient-loaded UPPER-case `IKE`/`IPSEC`/`ALL` is admitted (and
// `IDENT-RESET` RST-marked) on the wire. The junos-host coarse `application
// any` shield must reach the SAME verdict, or it drops the very IKE/NAT-T (udp
// 500/4500) and ident (tcp 113 RST) traffic enforcement admits. Only `ALL`/
// `any-service` are packet-wide full-admits; `IKE`/`IPsec` admit udp 500/4500.
//
// This mirrors the lower-case TestJunosHostExemptionFlags with upper-case
// tokens. Reverting the case-fold (junosHostSvcAdmitsIKE / the note() loop /
// HostInboundFullAdmitService going back to raw `==`) makes every upper-case
// token miss its match, so CoarseAdmitsIKE / CoarseIdentResets go false and this
// test goes RED via a clean assertion.
func TestJunosHostExemptionFlagsCaseInsensitive_5557(t *testing.T) {
	mk := func(svc ...string) JunosHostDenyProgram {
		cfg := jhTestConfig()
		cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = svc
		cfg.Security.Policies = []*ZonePairPolicies{{FromZone: "untrust", ToZone: "junos-host",
			Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}}}
		proj := BuildJunosHostDenyProjection(cfg)
		if len(proj.Programs) != 1 {
			t.Fatalf("want 1 program, got %d", len(proj.Programs))
		}
		return proj.Programs[0]
	}

	// IKE / IPsec / full-admit are all case-insensitive coarse-admits for IKE.
	for _, tok := range []string{"IKE", "IPsec", "ALL", "Any-Service"} {
		if p := mk(tok); !p.CoarseAdmitsIKE {
			t.Errorf("system-services %q: want CoarseAdmitsIKE (enforcement admits, shield must too)", tok)
		}
	}
	// Upper-case ident-reset must set the RST verdict, matching enforcement.
	if p := mk("IDENT-RESET"); !p.CoarseIdentResets {
		t.Error("system-services IDENT-RESET: want CoarseIdentResets")
	}
	// A zone-level upper-case IKE service must scope the exemption to a netdev
	// (the CoarseAdmitsIKE bit follows len(IKEExemptNetdevs)).
	if p := mk("IKE"); len(p.IKEExemptNetdevs) == 0 {
		t.Error("system-services IKE: want a scoped IKE-exempt netdev, got none")
	}
}

// TestHostInboundFullAdmitServiceCaseInsensitive_5557 pins the SSOT predicate
// itself. Enforcement lower-cases before calling it, but the coarse-shield and
// the commit-time full-admit advisory feed it the raw authored case; a
// case-sensitive `== "all"` let an upper-case `ALL` escape both. Reverting to
// the raw comparison makes these assertions RED.
func TestHostInboundFullAdmitServiceCaseInsensitive_5557(t *testing.T) {
	for _, tok := range []string{"ALL", "All", "Any-Service", "ANY-SERVICE", " all "} {
		if !HostInboundFullAdmitService(tok) {
			t.Errorf("HostInboundFullAdmitService(%q) = false, want true (case/space-insensitive full admit)", tok)
		}
	}
	// Non-full-admit tokens stay negative regardless of case.
	for _, tok := range []string{"ssh", "SSH", "ike", "IKE", "protocols-all", ""} {
		if HostInboundFullAdmitService(tok) {
			t.Errorf("HostInboundFullAdmitService(%q) = true, want false", tok)
		}
	}
}
