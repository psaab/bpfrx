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

// TestUnconstrainedAppOmittedQueryProtoStillMatches guards the narrow exception:
// an application term that is GENUINELY unconstrained on protocol (no protocol,
// no ports, no ICMP-type constraint) is a true match-any term and must still
// match an omitted query protocol — removing the short-circuit must not turn a
// real match-any app into a fail-closed term. Mirrors the runtime keying such an
// app under every protocol bucket / its match-any short-circuit.
func TestUnconstrainedAppOmittedQueryProtoStillMatches(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "anyapp-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"matchall"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// No protocol, no ports, no ICMP type: a genuinely unconstrained app.
			"matchall": {Name: "matchall"},
		},
	}
	cfg := cfgWith(sec, apps)

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"}) // Protocol omitted
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("protocol-unconstrained app must still match an omitted protocol; res = %+v", res)
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
