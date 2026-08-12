package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #4983 F5: the detailed `show security flow session` output resolves the
// "In: ... If:" column from the session's RECORDED ingress identity, the same
// datum sessionFilter.resolveIngressIfaces selects on.
//
// Before this the column was derived from the ingress zone's FIRST configured
// interface (zoneIfaces[val.IngressZone]). Once the FILTER became exact, the
// two disagreed on exactly the sessions the feature exists for: `show security
// flow session interface lo.50` would select precisely the sessions that
// arrived on lo.50 and then print `If: ge-0/0/8.0` for every one of them. A
// filter and a column that answer the same question differently read as a bug
// in the filter.
//
// Harness note: buildSessionEgressIfaces resolves names through the real
// net.InterfaceByName, so the fixture's ingress interface has to be a netdev
// that exists on the test host. `lo` is the one name that is always present
// (the #5813 display tests use it for the same reason). Two UNITS of it —
// unit 0 and unit 50 — give the fixture its distinguishing property without
// needing a second real NIC: both units share one parent ifindex, so only the
// {ifindex, VLAN} pair separates them, which is precisely the identity under
// test.

const (
	ingressIfColumnTrustZoneID   uint16 = 1
	ingressIfColumnUntrustZoneID uint16 = 2
)

// ingressIfColumnCLIDP is a "loaded" dataplane serving exactly one v4 and one
// v6 forward session, both recorded as having arrived on {lo, VLAN 50}.
type ingressIfColumnCLIDP struct {
	*dataplane.Manager
	apply   *dataplane.ApplyResult
	ifindex uint32
}

func (d *ingressIfColumnCLIDP) IsLoaded() bool { return true }

func (d *ingressIfColumnCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *ingressIfColumnCLIDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	key := dataplane.SessionKey{Protocol: 6}
	copy(key.SrcIP[:], net.IPv4(10, 0, 62, 102).To4())
	copy(key.DstIP[:], net.IPv4(8, 8, 8, 8).To4())
	val := dataplane.SessionValue{
		IngressZone: ingressIfColumnTrustZoneID,
		EgressZone:  ingressIfColumnUntrustZoneID,
		// Arrived on lo.50. FibIfindex stays 0 so the EGRESS column falls back
		// to the untrust zone's own interface and cannot supply the name the
		// ingress assertion is looking for.
		IngressIfindex: d.ifindex,
		IngressVlanID:  50,
	}
	fn(key, val)
	return nil
}

func (d *ingressIfColumnCLIDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	key := dataplane.SessionKeyV6{Protocol: 6}
	copy(key.SrcIP[:], net.ParseIP("2001:559:8585:bf01::102").To16())
	copy(key.DstIP[:], net.ParseIP("2001:4860:4860::8888").To16())
	val := dataplane.SessionValueV6{
		IngressZone:    ingressIfColumnTrustZoneID,
		EgressZone:     ingressIfColumnUntrustZoneID,
		IngressIfindex: d.ifindex,
		IngressVlanID:  50,
	}
	fn(key, val)
	return nil
}

// ingressIfColumnCLI builds the CLI + config for the column test: a `trust`
// zone whose FIRST interface (ge-0/0/8.0, the zone-derived answer) is NOT the
// interface the session arrived on (lo.50, the recorded answer), and an
// `untrust` zone supplying a third distinct name for the egress column.
func ingressIfColumnCLI(t *testing.T) *CLI {
	t.Helper()
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/8 {
        unit 0 { family inet { address 10.20.31.40/24; } }
    }
    ge-0/0/9 {
        unit 0 { family inet { address 10.20.30.40/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/8.0; }
        }
        security-zone untrust {
            interfaces { ge-0/0/9.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		t.Fatalf("fixture missing active config")
	}
	// Add the ingress unit on a netdev that really resolves. Injected rather
	// than parsed because `lo` is not a Junos interface name; the shape
	// (parent + two units, one tagged) is what the code under test reads.
	cfg.Interfaces.Interfaces["lo"] = &config.InterfaceConfig{
		Name: "lo",
		Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			50: {Number: 50, VlanID: 50},
		},
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatalf("fixture missing trust zone")
	}
	// ge-0/0/8.0 stays FIRST: it is the name the retired zone-derived column
	// would print, so it must be a live candidate for the assertion to bind.
	trust.Interfaces = append(trust.Interfaces, "lo.50")

	return &CLI{
		store: store,
		dp: &ingressIfColumnCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
				"trust":   ingressIfColumnTrustZoneID,
				"untrust": ingressIfColumnUntrustZoneID,
			}},
			ifindex: uint32(loIface.Index),
		},
	}
}

// ingressIfColumnValues returns the `If:` value from every "In:" line of the
// captured output. Reading the In lines specifically keeps the Out line's own
// If: column from satisfying the assertion by accident.
func ingressIfColumnValues(t *testing.T, out string) []string {
	t.Helper()
	var got []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "In: ") {
			continue
		}
		idx := strings.Index(trimmed, "If: ")
		if idx < 0 {
			t.Fatalf("In line has no If: column: %q", trimmed)
		}
		rest := trimmed[idx+len("If: "):]
		if end := strings.Index(rest, ","); end >= 0 {
			rest = rest[:end]
		}
		got = append(got, rest)
	}
	return got
}

// TestShowFlowSessionIngressIfColumnUsesRecordedIdentity4983 is the
// fail-on-revert binding for the display column. Restoring
// `inIf := zoneIfaces[val.IngressZone]` at either print site makes the
// corresponding arm print the trust zone's FIRST interface and go RED.
func TestShowFlowSessionIngressIfColumnUsesRecordedIdentity4983(t *testing.T) {
	c := ingressIfColumnCLI(t)
	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	got := ingressIfColumnValues(t, out)
	if len(got) != 2 {
		t.Fatalf("want one In line for each of the v4 and v6 sessions, got %d: %q\n%s",
			len(got), got, out)
	}
	for i, name := range got {
		if name != "lo.50" {
			t.Errorf("In-line If: column %d = %q, want %q: the column is still derived "+
				"from the ingress ZONE's first interface instead of the session's "+
				"recorded ingress identity, so it disagrees with the interface filter "+
				"that now selects on that identity (#4983)", i, name, "lo.50")
		}
	}
}

// TestShowFlowSessionEgressIfColumnUnchanged4983 is the over-reach guard. The
// EGRESS column's rule is untouched by this change: with no FIB result it
// still falls back to the egress zone's interface. It must stay GREEN under
// the revert that turns the ingress test RED — otherwise the "ingress" test is
// just observing that some interface name appears somewhere.
func TestShowFlowSessionEgressIfColumnUnchanged4983(t *testing.T) {
	c := ingressIfColumnCLI(t)
	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	var outLines int
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Out: ") {
			continue
		}
		outLines++
		if !strings.Contains(trimmed, "If: ge-0/0/9.0,") {
			t.Errorf("Out-line If: column changed: %q — the egress resolver is "+
				"unchanged by #4983 and must still fall back to the egress zone's "+
				"interface when the session carries no FIB result", trimmed)
		}
	}
	if outLines != 2 {
		t.Fatalf("want one Out line for each of the v4 and v6 sessions, got %d\n%s", outLines, out)
	}
}
