package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// protoConstrainedAppCfg builds a trust->untrust permit policy whose application
// term is the predefined junos-http (TCP destination-port 80). Zones are defined
// so the #3355 transit guard passes and this test isolates the #3323 protocol
// semantics.
func protoConstrainedAppCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "http-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"junos-http"},
						},
					},
				},
			},
		},
	}
	return cfgWith(sec, config.ApplicationsConfig{})
}

// TestProtoConstrainedAppOmittedQueryProtoNoMatch pins #3323: an
// application-constrained policy must NOT match when the query OMITS the
// protocol. The runtime always carries a concrete protocol and keys its
// per-application terms under it (policy.rs CompiledApplications.matches does
// `by_protocol.get(&protocol)?`), so a protocol-bearing app term only ever
// matches a packet whose protocol equals it. An omitted query protocol cannot
// describe any such packet, so the term fails closed and the query falls through
// to the configured default-policy.
//
// FAIL-ON-REVERT: restoring the `if proto == "" { return true }` short-circuit
// in matchApp makes the protocol-less query match the junos-http permit
// (Matched=true, permit), failing the want-default-deny assertion — the exact
// over-match #3323 fixes.
func TestProtoConstrainedAppOmittedQueryProtoNoMatch(t *testing.T) {
	cfg := protoConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"}) // Protocol omitted ("")
	if res.Matched {
		t.Fatalf("app-constrained policy over-matched an omitted query protocol (#3323); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an omitted query protocol, got %+v", res)
	}
}

// TestProtoConstrainedAppMatchingProtoStillPermits is the positive control: the
// concrete protocol+port still matches (the fix narrows, not breaks, matching).
func TestProtoConstrainedAppMatchingProtoStillPermits(t *testing.T) {
	cfg := protoConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("concrete tcp/80 no longer matches junos-http (#3323 over-narrowed); res = %+v", res)
	}
}

// TestProtoConstrainedAppWrongProtoNoMatch confirms the constraint is live: a
// concrete NON-matching protocol does not match the TCP-only app.
func TestProtoConstrainedAppWrongProtoNoMatch(t *testing.T) {
	cfg := protoConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: 80})
	if res.Matched {
		t.Fatalf("udp matched a tcp-only app (#3323); res = %+v", res)
	}
}

// TestProtocolLessNamedAppNeverMatches pins the parity contract for a NAMED
// application that carries NO protocol. The dataplane cannot represent such an
// app and never enforces it: the snapshot builder fails closed
// (deriveUserspaceCapabilities, pkg/dataplane/userspace/capabilities.go returns
// ok=false for proto=="" → the __unsupported__ sentinel → whole-snapshot reject,
// #3261) and strict commit hard-rejects it
// (pkg/config/compiler_validate_strict.go). A protocol-less named app can only
// exist via a lenient/HA-loaded config, where the runtime STILL never enforces
// it. The simulator must therefore NOT report it as a concrete match — reporting
// a match-any the dataplane would never produce is the simulator-vs-runtime
// divergence #3323 is about. It must fall through to the configured
// default-policy, EVEN when the query supplies a concrete protocol (the app is
// unrepresentable regardless of the query).
//
// FAIL-ON-REVERT: restoring the `if app.Protocol != "" { ... }` guard (skipping
// the protocol gate for an empty app.Protocol) makes a protocol-less named app
// match-any (Matched=true, permit), failing the want-default-deny assertions.
func TestProtocolLessNamedAppNeverMatches(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "badapp-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"noproto"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// Named app with no protocol: unrepresentable by the dataplane.
			"noproto": {Name: "noproto"},
		},
	}
	cfg := cfgWith(sec, apps)

	// Omitted query protocol: must not match.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
	if res.Matched {
		t.Fatalf("protocol-less named app matched an omitted query protocol; res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for a protocol-less named app, got %+v", res)
	}

	// Concrete query protocol: still must not match — the app is unrepresentable
	// regardless of the query, mirroring the dataplane reject.
	res = Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("protocol-less named app matched a concrete query (dataplane rejects it); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for a protocol-less named app, got %+v", res)
	}
}

// TestAnyApplicationOmittedQueryProtoStillMatches confirms the literal
// `application any` term remains match-any for an omitted protocol — it is
// handled by matchApp's `a == "any"` short-circuit, independent of the protocol
// gate, exactly like the runtime's match_any.
func TestAnyApplicationOmittedQueryProtoStillMatches(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "any-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
				},
			},
		},
	}
	cfg := cfgWith(sec, config.ApplicationsConfig{})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"}) // Protocol omitted
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("`application any` must match an omitted protocol; res = %+v", res)
	}
}
