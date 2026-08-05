// #5629: a strict PREDEFINED application-set bundle (junos-ms-rpc,
// junos-sun-rpc, junos-cifs, junos-routing-inbound) referenced by a source-NAT
// or destination-NAT `match application` MUST expand to its member
// applications, exactly as the #4102 shared resolver (config.ResolveApplication
// Set + config.ExpandApplicationSet) does. Before this fix both NAT snapshot
// builders gated set expansion on a bare cfg.Applications.ApplicationSets map
// membership test, which only sees USER-defined sets. A predefined bundle
// matched neither the application branch nor the (user-only) set branch, so:
//   - source NAT resolved zero terms and failed CLOSED to natProtoNever, so the
//     rule silently never translated;
//   - destination NAT resolved zero terms, fell through to the #3434 never-match
//     sentinel, and silently disabled the rule.
//
// RED-on-revert: restore the `cfg.Applications.ApplicationSets[appName]` guard
// (drop the config.ResolveApplicationSet call) and both builders stop expanding
// junos-ms-rpc — the SNAT term collapses to the single natProtoNever sentinel
// and the DNAT rule collapses to one Protocol="" never-match snapshot, failing
// the member-expansion asserts below.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// protoPort is a compact (protocol, destination-port) pair used to compare the
// expanded NAT terms against the expected predefined-bundle members regardless
// of member ordering.
type protoPort struct {
	proto uint16
	port  uint16
}

func TestSourceNATPredefinedApplicationSetExpands_5629(t *testing.T) {
	cfg := &config.Config{}
	// AppID disabled — the NAT expansion must be predefined-set-aware anyway.
	cfg.Services.ApplicationIdentification = false
	// NOTE: junos-ms-rpc is NOT defined in cfg.Applications.ApplicationSets. It
	// is a PREDEFINED bundle (config.PredefinedApplicationSets) referenced by
	// name only, which is exactly the #5629 bypass condition.
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"sp1": {Name: "sp1", Address: "203.0.113.5"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name: "r1",
			Match: config.NATMatch{
				SourceAddress: "10.0.0.0/24",
				Application:   "junos-ms-rpc",
			},
			Then: config.NATThen{Type: config.NATSource, PoolName: "sp1"},
		}},
	}}

	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	terms := snaps[0].MatchApplications
	// junos-ms-rpc = { junos-ms-rpc-tcp (tcp/135), junos-ms-rpc-udp (udp/135) }.
	// tcp=6, udp=17 per appid.ProtocolNumber.
	want := map[protoPort]bool{
		{proto: 6, port: 135}:  true,
		{proto: 17, port: 135}: true,
	}
	if len(terms) != len(want) {
		t.Fatalf("MatchApplications = %+v (len %d), want %d terms (tcp/135 + udp/135); "+
			"the predefined bundle silently failed CLOSED to the natProtoNever "+
			"sentinel on the pre-fix bypass", terms, len(terms), len(want))
	}
	for _, term := range terms {
		if term.Protocol == natProtoNever {
			t.Fatalf("MatchApplications carries the natProtoNever sentinel %+v — "+
				"the predefined bundle resolved to no terms (the #5629 bypass)", term)
		}
		if len(term.Ports) != 1 {
			t.Fatalf("term %+v: want exactly one destination-port range", term)
		}
		pp := protoPort{proto: term.Protocol, port: term.Ports[0].Low}
		if term.Ports[0].Low != term.Ports[0].High {
			t.Fatalf("term %+v: want an exact port (Low==High)", term)
		}
		if !want[pp] {
			t.Fatalf("unexpected term %+v (proto %d port %d)", term, pp.proto, pp.port)
		}
		delete(want, pp)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected predefined-bundle terms: %+v", want)
	}
}

func TestDestinationNATPredefinedApplicationSetExpands_5629(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{{
			Name:     "rs",
			FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationAddress: "203.0.113.10",
					Application:        "junos-ms-rpc", // PREDEFINED bundle
				},
				Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			}},
		}},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	// One snapshot per resolved member (tcp/135, udp/135) × one destination.
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2 (tcp/135 + udp/135); the predefined "+
			"bundle collapsed to the #3434 never-match sentinel on the pre-fix "+
			"bypass: %+v", len(snaps), snaps)
	}
	want := map[protoPort]bool{
		{proto: 6, port: 135}:  true, // "tcp" resolved below
		{proto: 17, port: 135}: true, // "udp"
	}
	protoNum := func(s string) uint16 {
		switch s {
		case "tcp":
			return 6
		case "udp":
			return 17
		}
		return 0xFFFF
	}
	for _, s := range snaps {
		if s.Protocol == "" {
			t.Fatalf("snapshot %+v carries an empty protocol — the never-match "+
				"sentinel of the #5629 bypass", s)
		}
		pp := protoPort{proto: protoNum(s.Protocol), port: s.DestinationPort}
		if !want[pp] {
			t.Fatalf("unexpected snapshot proto=%q port=%d (%+v)", s.Protocol, s.DestinationPort, s)
		}
		delete(want, pp)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected predefined-bundle DNAT snapshots: %+v", want)
	}
}

// A USER-defined application-set must stay bit-identical: the fix only widened
// the SET lookup to be predefined-aware, so a user set still resolves through
// exactly the same expansion path. This guards against a precedence regression.
func TestSourceNATUserApplicationSetUnaffected_5629(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false
	cfg.Applications.Applications = map[string]*config.Application{
		"my-tcp": {Name: "my-tcp", Protocol: "tcp", DestinationPort: "4444"},
		"my-udp": {Name: "my-udp", Protocol: "udp", DestinationPort: "5555"},
	}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"my-set": {Name: "my-set", Applications: []string{"my-tcp", "my-udp"}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"sp1": {Name: "sp1", Address: "203.0.113.5"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name:  "r1",
			Match: config.NATMatch{SourceAddress: "10.0.0.0/24", Application: "my-set"},
			Then:  config.NATThen{Type: config.NATSource, PoolName: "sp1"},
		}},
	}}

	terms := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	want := map[protoPort]bool{{proto: 6, port: 4444}: true, {proto: 17, port: 5555}: true}
	if len(terms) != len(want) {
		t.Fatalf("user application-set expansion changed: got %+v, want tcp/4444 + udp/5555", terms)
	}
	// #5718 D-A6-b00-C1: consume each match with delete() and assert the want
	// set drains. A membership-only `if !want[pp]` check is satisfied by ANY
	// multiset whose members are all in want — with the len() check above
	// holding the count at 2, two duplicate tcp/4444 terms passed while the
	// missing udp/5555 went undetected, i.e. the guard could not observe the
	// regression it exists to catch. The per-term shape assertions match the
	// predefined-bundle sibling above and keep Ports[0] from being an
	// unchecked index.
	for _, term := range terms {
		if term.Protocol == natProtoNever {
			t.Fatalf("user-set term carries the natProtoNever sentinel %+v — "+
				"the user application-set resolved to no terms", term)
		}
		if len(term.Ports) != 1 {
			t.Fatalf("term %+v: want exactly one destination-port range", term)
		}
		if term.Ports[0].Low != term.Ports[0].High {
			t.Fatalf("term %+v: want an exact port (Low==High)", term)
		}
		pp := protoPort{proto: term.Protocol, port: term.Ports[0].Low}
		if !want[pp] {
			t.Fatalf("unexpected or duplicate user-set term %+v (proto %d port %d)", term, pp.proto, pp.port)
		}
		delete(want, pp)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected user application-set terms: %+v", want)
	}
}
