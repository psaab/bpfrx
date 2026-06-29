// #3434 (Codex audit 095 H07/H08): a DNAT rule whose `match application`
// names an UNDEFINED application (H07) or a defined-but-EMPTY application-set
// (H08) resolves to zero application terms. Before the fix the builder fell
// THROUGH to its explicit-match fallback (protocol="" + destination-port 0),
// emitting a wildcard match-all snapshot (DestinationPort=0, Protocol="") that
// published the pool VIP for EVERY flow to the destination — a fail-open
// wildcard translation. The fix substitutes a never-match term reusing the
// #3437 source-port never-match sentinel ({Low:1, High:0}) so the installed
// entry can never satisfy l4_extra_matches.
//
// RED-on-revert: with the explicit-match fallback restored for a configured
// app, MatchSourcePorts is empty and DestinationPort is 0 (the wildcard).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dnatAppRefConfig builds a DNAT rule-set whose only rule matches via
// `match application appName`, WITHOUT defining that application or
// application-set (the H07 undefined-token case). No explicit protocol /
// destination-port is configured — the operator scoped the rule via the app.
func dnatAppRefConfig(appName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name:     "rs",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name: "r1",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.10",
						Application:        appName,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
				}},
			},
		},
	}
	return cfg
}

// H07: an undefined `match application` token must fail CLOSED — the snapshot
// carries the never-match source-port sentinel, NOT a wildcard term.
func TestBuildDNATSnapshotUndefinedApplicationFailsClosed(t *testing.T) {
	cfg := dnatAppRefConfig("does-not-exist")
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchSourcePorts
	if len(got) != 1 || got[0] != (NatPortRangeWire{Low: 1, High: 0}) {
		t.Fatalf("MatchSourcePorts = %+v, want one never-match sentinel {1,0} (fail-closed)", got)
	}
}

// H08: a defined-but-EMPTY application-set must fail CLOSED the same way — the
// set resolves by name but expands to zero members, leaving zero app terms.
func TestBuildDNATSnapshotEmptyApplicationSetFailsClosed(t *testing.T) {
	cfg := dnatAppRefConfig("empty-set")
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"empty-set": {Name: "empty-set"}, // no Applications members
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchSourcePorts
	if len(got) != 1 || got[0] != (NatPortRangeWire{Low: 1, High: 0}) {
		t.Fatalf("MatchSourcePorts = %+v, want one never-match sentinel {1,0} (fail-closed)", got)
	}
}

// Control: a DNAT rule with NO application configured (the explicit-match
// grammar) must keep its legitimate wildcard / explicit behavior — the fix
// must NOT clamp the no-app path. An IP-only DNAT carries an empty
// MatchSourcePorts (unconstrained source port) and a zero DestinationPort
// (any port, the #2396 IP-only path), NOT the never-match sentinel.
func TestBuildDNATSnapshotNoApplicationStillWildcards(t *testing.T) {
	cfg := dnatAppRefConfig("") // empty application = no app configured
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if len(snaps[0].MatchSourcePorts) != 0 {
		t.Fatalf("MatchSourcePorts = %+v, want empty (no app = unconstrained)", snaps[0].MatchSourcePorts)
	}
	if snaps[0].DestinationPort != 0 {
		t.Fatalf("DestinationPort = %d, want 0 (IP-only any-port DNAT)", snaps[0].DestinationPort)
	}
}
