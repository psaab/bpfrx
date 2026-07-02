// #3726: appPortsFromSpec must REJECT a reversed application port range
// ("200-100", lo>hi) rather than silently narrowing it to an exact match on the
// low port ([200]). A reversed range can never match any port, so it must fail
// CLOSED — source NAT emits the never-match sentinel, destination NAT emits no
// snapshot (no translation) — instead of translating traffic to the low port.
//
// The equal-bound case (hi==lo, e.g. "100-100") is a legitimate single exact
// port and must be preserved. Valid ranges (lo<hi) still expand.
//
// Strict commit already rejects lo>hi (pkg/config range validation); these
// guard the #1960 tolerant-load / peer-sync backstop, the same accepted threat
// model as #3429 / #3437 / #3446 / #3491.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAppPortsFromSpecRejectsReversedRange is the direct unit test on the
// helper. RED-on-revert: the pre-fix helper returned []int{lo} for lo>hi.
func TestAppPortsFromSpecRejectsReversedRange(t *testing.T) {
	if got := appPortsFromSpec("200-100"); len(got) != 0 {
		t.Fatalf("appPortsFromSpec(\"200-100\") = %+v, want nil (reversed range rejected, NOT narrowed to [200])", got)
	}
	// hi == lo is a legitimate single exact port.
	if got := appPortsFromSpec("100-100"); len(got) != 1 || got[0] != 100 {
		t.Fatalf("appPortsFromSpec(\"100-100\") = %+v, want [100] (equal-bound single port)", got)
	}
	// A single bare port is unchanged.
	if got := appPortsFromSpec("443"); len(got) != 1 || got[0] != 443 {
		t.Fatalf("appPortsFromSpec(\"443\") = %+v, want [443]", got)
	}
	// A valid ascending range still expands inclusively.
	if got := appPortsFromSpec("100-102"); len(got) != 3 || got[0] != 100 || got[2] != 102 {
		t.Fatalf("appPortsFromSpec(\"100-102\") = %+v, want [100 101 102]", got)
	}
}

// Source NAT: an application whose destination-port is a reversed range must
// emit the never-match sentinel, NOT an exact match on the low port and NOT an
// empty (unconstrained) list. RED-on-revert: the pre-fix helper returned [200],
// so MatchApplications[0].Ports coalesced to {200,200} (exact match on 200).
func TestBuildSourceNATSnapshotsAppReversedDestPortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"rev": {Name: "rev", Protocol: "tcp", DestinationPort: "200-100"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "rev"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	want := []NatPortRangeWire{natNeverMatchPortRange}
	if len(apps[0].Ports) != len(want) || apps[0].Ports[0] != want[0] {
		t.Fatalf("term ports = %+v, want one never-match range %+v (reversed range fails closed, NOT exact-low-port [200])",
			apps[0].Ports, want)
	}
}

// Source NAT over-reject control: an equal-bound "100-100" is a legitimate
// single exact port and must still compile to {100,100}.
func TestBuildSourceNATSnapshotsAppEqualDestPortStaysExact(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"eq": {Name: "eq", Protocol: "tcp", DestinationPort: "100-100"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "eq"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	want := []NatPortRangeWire{{Low: 100, High: 100}}
	if len(apps[0].Ports) != len(want) || apps[0].Ports[0] != want[0] {
		t.Fatalf("term ports = %+v, want %+v (equal-bound single port preserved)", apps[0].Ports, want)
	}
}

// Destination NAT: an application whose destination-port is a reversed range
// must fail CLOSED — emit NO snapshot so the rule installs nothing and does not
// translate. RED-on-revert covers BOTH halves of the fix:
//   - revert appPortsFromSpec (returns [200]): the term carries an exact port
//     200 and a snapshot with DestinationPort=200 is emitted (len 1).
//   - revert the dstPortConfigured guard (term.ports nil, no configured
//     signal): the term falls through to the wildcard match-any-port default
//     and a snapshot with DestinationPort=0 is emitted (len 1).
//
// Either regression makes len(snaps) == 1, so the len==0 assertion goes RED.
func TestBuildDNATSnapshotAppReversedDestPortFailsClosed(t *testing.T) {
	cfg := dnatAppConfig("rev", &config.Application{
		Name:            "rev",
		Protocol:        "tcp",
		DestinationPort: "200-100",
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("DNAT snapshots = %+v, want none (reversed app destination-port fails closed: no exact-low-port match, no wildcard match-any-port)", snaps)
	}
}

// Destination NAT over-reject control: an equal-bound "100-100" is a legitimate
// single exact port and must still publish the DNAT rule with DestinationPort
// 100 (not dropped, not widened).
func TestBuildDNATSnapshotAppEqualDestPortStaysExact(t *testing.T) {
	cfg := dnatAppConfig("eq", &config.Application{
		Name:            "eq",
		Protocol:        "tcp",
		DestinationPort: "100-100",
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("DNAT snapshots = %d, want 1 (equal-bound single port preserved)", len(snaps))
	}
	if snaps[0].DestinationPort != 100 {
		t.Fatalf("DNAT DestinationPort = %d, want 100 (equal-bound single exact port)", snaps[0].DestinationPort)
	}
}
