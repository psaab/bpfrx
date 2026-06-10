package dhcpserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// testManager builds a Manager with recording seams. activeUnits maps
// unit name → is-active answer; calls records every runSystemctl
// invocation as a joined string ("restart kea-dhcp4-server").
func testManager(t *testing.T, activeUnits map[string]bool, failCmd string) (*Manager, *[]string) {
	t.Helper()
	dir := t.TempDir()
	calls := &[]string{}
	m := NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		func(args ...string) error {
			c := strings.Join(args, " ")
			*calls = append(*calls, c)
			if failCmd != "" && c == failCmd {
				return fmt.Errorf("systemctl %s: exit status 1", c)
			}
			return nil
		},
		func(unit string) bool { return activeUnits[unit] },
	)
	return m, calls
}

func v4Config(ifaces ...string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {
					Name:       "g0",
					Interfaces: ifaces,
					Pools: []*config.DHCPPool{{
						Name:     "p0",
						Subnet:   "10.0.1.0/24",
						RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200",
					}},
				},
			},
		},
	}
}

func calledWith(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// A stale Kea from a PREVIOUS daemon must be stopped when the new
// config has no dhcp-server stanza, even though this Manager never
// started it (#1778: reconcile against systemd state, not booleans).
func TestApplyNilStopsStaleActiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true, kea6Svc: true}, "")
	for _, p := range []string{m.confPath4, m.confPath6} {
		if err := os.WriteFile(p, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if !calledWith(*calls, "stop "+kea4Svc) || !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of both active units, got calls %v", *calls)
	}
	for _, p := range []string{m.confPath4, m.confPath6} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("config %s not removed", p)
		}
	}
}

// Removing one family from config stops that family's active unit
// while the other family restarts normally.
func TestApplyConfigRemovedFamilyStopsActiveUnit(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea6Svc: true}, "")

	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("expected restart of %s, got %v", kea4Svc, *calls)
	}
	if !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of active %s, got %v", kea6Svc, *calls)
	}
}

// Inactive units are not stopped — no systemctl churn on the common
// no-DHCP-config commit path.
func TestApplyClearSkipsInactiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no systemctl calls for inactive units, got %v", *calls)
	}
}

// Fail-closed (#1778): a Kea restart failure must fail Apply so the
// commit surfaces it, instead of logging Warn and returning nil.
func TestApplyRestartFailureFailsApply(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "restart "+kea4Svc)
	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("expected error from failed restart, got nil")
	}
	if !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
}

// Failing to stop an active unit that is no longer configured is also
// surfaced (the stale server would keep handing out old leases).
func TestApplyStopFailureFailsApply(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea4Svc: true}, "stop "+kea4Svc)
	err := m.Apply(nil)
	if err == nil {
		t.Fatal("expected error from failed stop, got nil")
	}
	if !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
}

// Clear is authoritative too: stops units systemd reports active even
// when this process never started them.
func TestClearStopsStaleActiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true, kea6Svc: true}, "")
	m.Clear()
	if !calledWith(*calls, "stop "+kea4Svc) || !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of both active units, got %v", *calls)
	}
}

// IsRunning reflects systemd state, surviving daemon restarts.
func TestIsRunningQueriesSystemd(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea6Svc: true}, "")
	if !m.IsRunning() {
		t.Error("IsRunning should be true when a unit is active")
	}
	m2, _ := testManager(t, map[string]bool{}, "")
	if m2.IsRunning() {
		t.Error("IsRunning should be false when no unit is active")
	}
}

// Apply must report a generate failure (unwritable config dir) for
// the broken family without masking it.
func TestApplyGenerateFailureFailsApply(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	// Point confPath4 inside a path that cannot be created (a file in
	// the way of the directory component).
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0644); err != nil {
		t.Fatal(err)
	}
	m.confPath4 = filepath.Join(blocker, "sub", "kea-dhcp4.conf")

	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("expected generate error, got nil")
	}
	if calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("must not restart kea4 after generate failure: %v", *calls)
	}
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Errorf("expected wrapped path error, got %v", err)
	}
}

func TestParseLeaseCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csv := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.100,aa:bb:cc:dd:ee:01,,86400,1707868800,1,0,0,client1,0,,0
10.0.1.101,aa:bb:cc:dd:ee:02,,86400,1707955200,1,0,0,client2,0,,0
`
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2", len(leases))
	}

	l := leases[0]
	if l.Address != "10.0.1.100" {
		t.Errorf("address: got %q", l.Address)
	}
	if l.HWAddress != "aa:bb:cc:dd:ee:01" {
		t.Errorf("hwaddr: got %q", l.HWAddress)
	}
	if l.Hostname != "client1" {
		t.Errorf("hostname: got %q", l.Hostname)
	}
	if l.ValidLife != "86400" {
		t.Errorf("valid_lifetime: got %q", l.ValidLife)
	}
	if l.SubnetID != "1" {
		t.Errorf("subnet_id: got %q", l.SubnetID)
	}
}

func TestParseLeaseCSV_NoFile(t *testing.T) {
	leases, err := parseLeaseCSV("/nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if leases != nil {
		t.Errorf("expected nil for nonexistent file, got %v", leases)
	}
}

func TestParseLeaseCSV_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	if err := os.WriteFile(path, []byte("address,hwaddr\n"), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Errorf("expected no leases, got %d", len(leases))
	}
}
