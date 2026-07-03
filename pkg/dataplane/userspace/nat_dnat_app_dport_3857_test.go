// #3857: DNAT rule with BOTH `match application` AND `match destination-port`.
// The lenient / HA peer-sync snapshot builder must treat the explicit rule-level
// `match destination-port` as authoritative on the destination-port axis:
//
//	(a) an INVALID / unrepresentable rule destination-port present alongside an
//	    application must FAIL CLOSED (rule omitted) — it must NOT widen to the
//	    wildcard [0,0] port (which bypasses the #3446 dport guard, a fail-open);
//	(b) a VALID rule destination-port must be HONORED alongside the application
//	    (not dropped in favor of the application's own port or a wildcard);
//	(c) a MULTI-value rule destination-port list must keep EVERY port (not
//	    collapse to the singular first port).
//
// These exercise the lenient/peer-sync decode path by constructing the NATMatch
// directly (a crafted snapshot that skipped the strict commit gate), including
// the scalar-only DestinationPort a mixed-version peer may carry alone.
//
// RED-on-revert: restoring the pre-#3857 builder (application's port wins /
// singular-port switch case / [0,0] wildcard fallback) turns each of these RED.
package userspace

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dnatAppPortConfig builds a DNAT rule-set whose single rule references the
// named application AND carries the given rule-level NATMatch destination-port
// fields. The application is registered so ResolveApplication succeeds.
func dnatAppPortConfig(appName string, app *config.Application, match config.NATMatch) *config.Config {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{appName: app}
	if match.DestinationAddress == "" {
		match.DestinationAddress = "203.0.113.10"
	}
	match.Application = appName
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name:     "rs",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name:  "r1",
					Match: match,
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
				}},
			},
		},
	}
	return cfg
}

func snapDstPorts(snaps []DestinationNATRuleSnapshot) []int {
	out := make([]int, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, int(s.DestinationPort))
	}
	sort.Ints(out)
	return out
}

// (a) A port-less TCP application + an INVALID rule destination-port
// (non-numeric token preserved on InvalidDestinationPorts) must fail CLOSED:
// the rule is omitted. RED-on-revert: the removed [0,0] wildcard fallback
// emits one wildcard snapshot (DestinationPort=0) = match every port.
func TestBuildDNATSnapshotAppPlusInvalidDportFailsClosed_3857(t *testing.T) {
	cfg := dnatAppPortConfig("tcp-any", &config.Application{
		Name:     "tcp-any",
		Protocol: "tcp", // port-less: application does not pin a destination-port
	}, config.NATMatch{
		InvalidDestinationPorts: []string{"httpp"}, // configured but unparseable
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("invalid rule dest-port + application must match nothing, got %d snapshot(s): %+v",
			len(snaps), snaps)
	}
}

// (a') An out-of-range numeric rule destination-port alongside an application
// must also fail CLOSED (not wrap, not widen). RED-on-revert: the singular
// switch case rejected 70000 but the default branch then widened to [0,0].
func TestBuildDNATSnapshotAppPlusOutOfRangeDportFailsClosed_3857(t *testing.T) {
	cfg := dnatAppPortConfig("tcp-any", &config.Application{
		Name:     "tcp-any",
		Protocol: "tcp",
	}, config.NATMatch{
		DestinationPorts: []int{70000},
		DestinationPort:  70000,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("out-of-range rule dest-port + application must match nothing, got %d: %+v",
			len(snaps), snaps)
	}
}

// (b) A valid rule destination-port must be HONORED even when the application
// pins its OWN destination-port. RED-on-revert: the application's port (80) won
// and the operator's explicit `match destination-port 8080` was dropped.
func TestBuildDNATSnapshotRuleDportOverridesAppPort_3857(t *testing.T) {
	cfg := dnatAppPortConfig("http-80", &config.Application{
		Name:            "http-80",
		Protocol:        "tcp",
		DestinationPort: "80",
	}, config.NATMatch{
		DestinationPorts: []int{8080},
		DestinationPort:  8080,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].DestinationPort != 8080 {
		t.Fatalf("DestinationPort = %d, want 8080 (explicit rule dest-port honored, not the app's 80)",
			snaps[0].DestinationPort)
	}
}

// (b') Peer-sync / mixed-version path: a snapshot that carries ONLY the scalar
// DestinationPort (plural list empty) must still honor it over the app's port.
// RED-on-revert: with an app that pins its own port, the app's port won.
func TestBuildDNATSnapshotScalarOnlyRuleDportHonored_3857(t *testing.T) {
	cfg := dnatAppPortConfig("http-80", &config.Application{
		Name:            "http-80",
		Protocol:        "tcp",
		DestinationPort: "80",
	}, config.NATMatch{
		DestinationPort: 8080, // scalar only — plural list empty (older peer)
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].DestinationPort != 8080 {
		t.Fatalf("DestinationPort = %d, want 8080 (scalar-only rule dest-port honored)",
			snaps[0].DestinationPort)
	}
}

// (c) A multi-value rule destination-port list must keep EVERY port. Uses a
// port-less application so the ports come solely from the rule. RED-on-revert:
// the singular switch case emitted only the first port (8080).
func TestBuildDNATSnapshotMultiDportKeepsAllWithApp_3857(t *testing.T) {
	cfg := dnatAppPortConfig("tcp-any", &config.Application{
		Name:     "tcp-any",
		Protocol: "tcp",
	}, config.NATMatch{
		DestinationPorts: []int{8080, 8443},
		DestinationPort:  8080,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	got := snapDstPorts(snaps)
	want := []int{8080, 8443}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dest ports = %v, want %v (multi-port list must not collapse to first)", got, want)
	}
}

// (b+c) A valid multi-value rule destination-port overrides an application that
// ALSO pins its own port, keeping every rule port. RED-on-revert: the app's
// single port (80) won and the multi-value rule list was dropped.
func TestBuildDNATSnapshotMultiDportOverridesAppPort_3857(t *testing.T) {
	cfg := dnatAppPortConfig("http-80", &config.Application{
		Name:            "http-80",
		Protocol:        "tcp",
		DestinationPort: "80",
	}, config.NATMatch{
		DestinationPorts: []int{8080, 8443},
		DestinationPort:  8080,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	got := snapDstPorts(snaps)
	want := []int{8080, 8443}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dest ports = %v, want %v (rule dest-port overrides app port, keeps all)", got, want)
	}
}

// Regression guard: an application that pins its own destination-port with NO
// rule-level `match destination-port` is UNCHANGED — the app's port is honored
// and the fix must not over-reject or override it.
func TestBuildDNATSnapshotAppPortUnchangedWithoutRuleDport_3857(t *testing.T) {
	cfg := dnatAppPortConfig("http-80", &config.Application{
		Name:            "http-80",
		Protocol:        "tcp",
		DestinationPort: "80",
	}, config.NATMatch{}) // no rule-level destination-port
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].DestinationPort != 80 {
		t.Fatalf("DestinationPort = %d, want 80 (application port preserved)", snaps[0].DestinationPort)
	}
}
