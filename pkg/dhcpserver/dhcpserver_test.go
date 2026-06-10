package dhcpserver

import (
	"encoding/json"
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

// Multi-interface groups: the per-subnet interface binding (which Kea
// limits to ONE interface) is omitted so address-based subnet
// selection serves every interface; single-interface groups keep the
// explicit binding. interfaces-config always lists all interfaces.
func TestGroupBindingAllInterfaces(t *testing.T) {
	type subnet struct {
		Subnet    string `json:"subnet"`
		Interface string `json:"interface"`
	}
	type dhcp4 struct {
		InterfacesConfig struct {
			Interfaces []string `json:"interfaces"`
		} `json:"interfaces-config"`
		Subnet4 []subnet `json:"subnet4"`
	}

	readConf := func(t *testing.T, m *Manager) dhcp4 {
		t.Helper()
		data, err := os.ReadFile(m.confPath4)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Dhcp4 dhcp4 `json:"Dhcp4"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out.Dhcp4
	}

	t.Run("multi-interface group omits subnet binding", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		if err := m.Apply(v4Config("ge-0-0-0", "ge-0-0-1")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		conf := readConf(t, m)
		if got := conf.InterfacesConfig.Interfaces; len(got) != 2 {
			t.Errorf("interfaces-config should list all group interfaces, got %v", got)
		}
		if len(conf.Subnet4) != 1 {
			t.Fatalf("want 1 subnet, got %d", len(conf.Subnet4))
		}
		if conf.Subnet4[0].Interface != "" {
			t.Errorf("multi-interface group must not bind subnet to %q (silent first-interface drop)",
				conf.Subnet4[0].Interface)
		}
	})

	t.Run("single-interface group binds explicitly", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		conf := readConf(t, m)
		if len(conf.Subnet4) != 1 || conf.Subnet4[0].Interface != "ge-0-0-0" {
			t.Errorf("single-interface group should bind subnet, got %+v", conf.Subnet4)
		}
	})
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

// Quoted fields containing commas must not shift columns (#1778:
// encoding/csv instead of strings.Split).
func TestParseLeaseCSV_QuotedHostname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csvData := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.100,aa:bb:cc:dd:ee:01,,86400,1707868800,1,0,0,"host, with comma",0,,0
`
	if err := os.WriteFile(path, []byte(csvData), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(leases))
	}
	if leases[0].Hostname != "host, with comma" {
		t.Errorf("hostname: got %q", leases[0].Hostname)
	}
	if leases[0].SubnetID != "1" {
		t.Errorf("subnet_id shifted: got %q", leases[0].SubnetID)
	}
}

// TestApplyStopsDeactivatingUnit pins the Codex finding on PR #1835:
// a unit reported "deactivating" can have a queued start behind it, so
// the reconcile must treat it as active-for-stop (unitIsActive returns
// true for it; here the seam simulates that directly).
func TestApplyStopsDeactivatingUnit(t *testing.T) {
	dir := t.TempDir()
	var stopped []string
	m := NewManagerForTesting(
		dir+"/kea4.conf", dir+"/kea6.conf",
		func(args ...string) error {
			if len(args) > 0 && args[0] == "stop" {
				stopped = append(stopped, args[len(args)-1])
			}
			return nil
		},
		func(unit string) bool { return true },
	)
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if len(stopped) != 2 {
		t.Fatalf("stopped = %v, want both kea units", stopped)
	}
}

// TestGenerateKea6RejectsMultiInterfaceGroup pins the second Codex
// finding on PR #1835: Kea v6 subnet selection cannot fall back to
// address matching (clients use link-local sources), so a
// multi-interface v6 group must be rejected loudly rather than
// silently losing its subnet6 interface selector.
func TestGenerateKea6RejectsMultiInterfaceGroup(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerForTesting(
		dir+"/kea4.conf", dir+"/kea6.conf",
		func(...string) error { return nil },
		func(string) bool { return false },
	)
	cfg := &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{},
	}
	cfg.DHCPv6LocalServer.Groups = map[string]*config.DHCPServerGroup{"lan": {
		Name:       "lan",
		Interfaces: []string{"ge-0/0/1", "ge-0/0/2"},
		Pools: []*config.DHCPPool{{
			Subnet: "2001:db8::/64", RangeLow: "2001:db8::100", RangeHigh: "2001:db8::200",
		}},
	}}
	err := m.Apply(cfg)
	if err == nil || !strings.Contains(err.Error(), "single interface selector") {
		t.Fatalf("want multi-interface v6 rejection, got %v", err)
	}
}

// TestWarnAmbiguousSubnetSelection pins #1835 F1: two groups whose
// pools share/overlap a subnet while at least one involved group emits
// no per-subnet interface selector (multi-interface group) must fire a
// warning at generate time — Kea's subnet selection is ambiguous. It
// must stay a warning, not an error (pre-existing accepted configs).
func TestWarnAmbiguousSubnetSelection(t *testing.T) {
	mkCfg := func(subnetA, subnetB string, ifacesA, ifacesB []string) *config.DHCPServerConfig {
		return &config.DHCPServerConfig{
			DHCPLocalServer: &config.DHCPLocalServerConfig{
				Groups: map[string]*config.DHCPServerGroup{
					"ga": {Name: "ga", Interfaces: ifacesA,
						Pools: []*config.DHCPPool{{Subnet: subnetA,
							RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200"}}},
					"gb": {Name: "gb", Interfaces: ifacesB,
						Pools: []*config.DHCPPool{{Subnet: subnetB,
							RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200"}}},
				},
			},
		}
	}

	run := func(t *testing.T, cfg *config.DHCPServerConfig) []string {
		t.Helper()
		m, _ := testManager(t, map[string]bool{}, "")
		var warned []string
		m.SetWarnForTesting(func(msg string, args ...any) {
			s := msg
			for _, a := range args {
				s += fmt.Sprintf(" %v", a)
			}
			warned = append(warned, s)
		})
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply must not error on ambiguous subnets: %v", err)
		}
		return warned
	}

	t.Run("same subnet, one multi-interface group warns", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.1.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		if len(warned) != 1 {
			t.Fatalf("want 1 warning, got %d: %v", len(warned), warned)
		}
		if !strings.Contains(warned[0], "ga") || !strings.Contains(warned[0], "gb") {
			t.Errorf("warning should name both groups: %q", warned[0])
		}
	})

	t.Run("overlapping subnets warn too", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.0.0/16", "10.0.1.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		if len(warned) != 1 {
			t.Fatalf("want 1 warning for overlapping prefixes, got %d: %v", len(warned), warned)
		}
	})

	t.Run("disjoint subnets do not warn", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.2.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		if len(warned) != 0 {
			t.Errorf("unexpected warning: %v", warned)
		}
	})

	t.Run("both groups with selectors do not warn", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.1.0/24",
			[]string{"ge-0-0-0"}, []string{"ge-0-0-2"}))
		if len(warned) != 0 {
			t.Errorf("unexpected warning when both subnets carry selectors: %v", warned)
		}
	})
}
