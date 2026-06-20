package dhcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// leaseTestNow is a fixed reference time BEFORE the 2024-02 expire
// epochs used by the legacy fixtures (1707868800 / 1707955200), so the
// expire filter added in #2085 keeps those (state=0) rows live and the
// pre-existing assertions still hold. New #2085 tests use their own now.
var leaseTestNow = time.Unix(1707800000, 0) // 2024-02-13 03:33:20 UTC

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

	leases, err := parseLeaseCSV(path, leaseTestNow)
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
	leases, err := parseLeaseCSV("/nonexistent/path", leaseTestNow)
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

	leases, err := parseLeaseCSV(path, leaseTestNow)
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

	leases, err := parseLeaseCSV(path, leaseTestNow)
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

// indexLeasesByAddr collapses a lease slice to an address→Lease map so
// the #2085 tests can assert per-address presence and field values; the
// expected lease count is asserted separately via len(leases).
func indexLeasesByAddr(leases []Lease) map[string]Lease {
	m := make(map[string]Lease, len(leases))
	for _, l := range leases {
		m[l.Address] = l
	}
	return m
}

// TestParseLeaseCSV_ExpiredAndDuplicate pins the core of #2085: Kea's
// memfile is append-only, so the SAME address appears multiple times
// (renewals) and lapsed leases linger until LFC. The display parser
// must collapse to one row per address (newest wins) and drop expired
// rows. Non-tautological: against the pre-#2085 parser this fixture
// returns FOUR rows (the duplicate twice + the expired one + the live
// one); the fix returns TWO (deduped live + the other live).
func TestParseLeaseCSV_ExpiredAndDuplicate(t *testing.T) {
	now := time.Unix(1707900000, 0) // 2024-02-14 06:40:00 UTC
	past := now.Unix() - 3600       // expired an hour ago
	future := now.Unix() + 3600     // valid for another hour
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	// Append order is chronological: the second 10.0.1.50 row (client1b,
	// newer expire) supersedes the first. 10.0.1.99 is expired. 10.0.1.60
	// is a normal single live lease.
	csv := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.50,aa:bb:cc:dd:ee:01,,86400,%d,1,0,0,client1a,0,,0
10.0.1.99,aa:bb:cc:dd:ee:99,,86400,%d,1,0,0,stale,0,,0
10.0.1.50,aa:bb:cc:dd:ee:01,,86400,%d,1,0,0,client1b,0,,0
10.0.1.60,aa:bb:cc:dd:ee:60,,86400,%d,1,0,0,client2,0,,0
`, future, past, future, future)
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2 (deduped + non-expired); pre-#2085 returned 4", len(leases))
	}
	byAddr := indexLeasesByAddr(leases)
	dup, ok := byAddr["10.0.1.50"]
	if !ok {
		t.Fatalf("deduped address 10.0.1.50 missing; got %+v", leases)
	}
	if dup.Hostname != "client1b" {
		t.Errorf("dedup must keep the NEWEST row: hostname got %q, want client1b", dup.Hostname)
	}
	if _, ok := byAddr["10.0.1.99"]; ok {
		t.Errorf("expired lease 10.0.1.99 must be dropped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.1.60"]; !ok {
		t.Errorf("live lease 10.0.1.60 must be present; got %+v", leases)
	}
	// Order is stable (first-appearance): 10.0.1.50 before 10.0.1.60.
	if leases[0].Address != "10.0.1.50" || leases[1].Address != "10.0.1.60" {
		t.Errorf("display order not stable first-appearance: %q, %q", leases[0].Address, leases[1].Address)
	}
}

// TestParseLeaseCSV_StateFiltered pins the second half of #2085: a
// released (state=2 expired-reclaimed) or declined (state=1) Kea lease
// is written with a non-default state but often a FUTURE expire epoch,
// so an expire-only filter would still show it as live. The display
// must drop non-default-state rows too, BEFORE the expire check. A
// later active (state=0) append must still reclaim the address.
// Non-tautological against an expire-only half-fix (which would emit the
// declined and reclaimed rows because their expire is in the future).
func TestParseLeaseCSV_StateFiltered(t *testing.T) {
	now := time.Unix(1707900000, 0)
	future := now.Unix() + 3600
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	// 10.0.1.10 declined (state=1, future expire) — must be hidden.
	// 10.0.1.11 expired-reclaimed (state=2, future expire) — must be hidden.
	// 10.0.1.12 reclaimed (state=2) then re-allocated live (state=0) —
	//   the later live append must reclaim the address.
	// 10.0.1.13 plain active — present.
	csv := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.10,aa:bb:cc:dd:ee:10,,86400,%d,1,0,0,declined,1,,0
10.0.1.11,aa:bb:cc:dd:ee:11,,86400,%d,1,0,0,reclaimed,2,,0
10.0.1.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,old,2,,0
10.0.1.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,reallocated,0,,0
10.0.1.13,aa:bb:cc:dd:ee:13,,86400,%d,1,0,0,active,0,,0
`, future, future, future, future, future)
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	byAddr := indexLeasesByAddr(leases)
	if _, ok := byAddr["10.0.1.10"]; ok {
		t.Errorf("declined lease (state=1, future expire) must be dropped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.1.11"]; ok {
		t.Errorf("expired-reclaimed lease (state=2, future expire) must be dropped; got %+v", leases)
	}
	reclaimed, ok := byAddr["10.0.1.12"]
	if !ok {
		t.Errorf("re-allocated address 10.0.1.12 must be shown live; got %+v", leases)
	} else if reclaimed.Hostname != "reallocated" {
		t.Errorf("reclaim must keep the live row: hostname got %q, want reallocated", reclaimed.Hostname)
	}
	if _, ok := byAddr["10.0.1.13"]; !ok {
		t.Errorf("plain active lease 10.0.1.13 must be present; got %+v", leases)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2 (reallocated + active); pre-fix/expire-only returns more", len(leases))
	}
}

// TestParseLeaseCSV_Lenient pins the display path's leniency: absent or
// unparseable state/expire columns must NOT hide a lease, and a header
// missing the state column entirely must degrade to today's behaviour
// (all addressed rows shown), never abort the show. This is what keeps
// the fix safe for older Kea / exotic headers.
func TestParseLeaseCSV_Lenient(t *testing.T) {
	now := time.Unix(1707900000, 0)
	dir := t.TempDir()

	// Garbage state + blank/garbage expire ⇒ rows kept.
	path := filepath.Join(dir, "garbage.csv")
	csv := `address,hwaddr,expire,state,hostname
10.0.2.10,aa:bb:cc:dd:ee:10,notanumber,xyz,a
10.0.2.11,aa:bb:cc:dd:ee:11,,,b
`
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Errorf("lenient: garbage/blank state+expire must keep rows; got %d, want 2 (%+v)", len(leases), leases)
	}

	// Header with NO state and NO expire column ⇒ all addressed rows shown.
	path2 := filepath.Join(dir, "nostate.csv")
	csv2 := `address,hwaddr,hostname
10.0.3.10,aa:bb:cc:dd:ee:10,a
10.0.3.11,aa:bb:cc:dd:ee:11,b
`
	if err := os.WriteFile(path2, []byte(csv2), 0644); err != nil {
		t.Fatal(err)
	}
	leases2, err := parseLeaseCSV(path2, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases2) != 2 {
		t.Errorf("lenient: missing state/expire columns must keep rows; got %d, want 2 (%+v)", len(leases2), leases2)
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

// asyncTestManager builds a Manager whose fake systemctl reports which
// v4 config was on disk when each restart ran (the worker writes the
// config before restarting, so this observes exactly which desired
// state the worker applied), and blocks until released.
func asyncTestManager(t *testing.T) (m *Manager, applied chan string, release chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	applied = make(chan string, 16)
	release = make(chan struct{}, 16)
	m = NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		nil, // set below; needs m for confPath4
		func(unit string) bool { return false },
	)
	m.runSystemctl = func(args ...string) error {
		data, _ := os.ReadFile(m.confPath4)
		applied <- string(data)
		<-release
		return nil
	}
	return m, applied, release
}

// TestApplyAsyncNeverBlocks pins #1835 F2: the VRRP event loop must
// never wait behind a (15s-bounded) systemctl — ApplyAsync returns
// immediately even while the worker is stuck inside a shell-out.
func TestApplyAsyncNeverBlocks(t *testing.T) {
	m, applied, release := asyncTestManager(t)
	defer close(release)

	m.ApplyAsync(v4Config("ge-0-0-0"), "test")
	<-applied // worker is now blocked inside the fake systemctl

	done := make(chan struct{})
	go func() {
		m.ApplyAsync(v4Config("ge-0-0-1"), "test")
		m.ApplyAsync(nil, "test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ApplyAsync blocked while the worker held systemctl")
	}
}

// TestApplyAsyncLatestWins pins the mailbox coalescing contract: with
// the worker busy, enqueueing B then C must apply only C — B is
// discarded, and the LAST desired state is the last one applied.
// Correct because Apply is an idempotent reconcile to desired state.
func TestApplyAsyncLatestWins(t *testing.T) {
	m, applied, release := asyncTestManager(t)

	m.ApplyAsync(v4Config("iface-A"), "a")
	gotA := <-applied // worker is executing A and blocked
	if !strings.Contains(gotA, "iface-A") {
		t.Fatalf("first apply should be A, got %q", gotA)
	}

	// Worker still blocked: B fills the slot, C overwrites B.
	m.ApplyAsync(v4Config("iface-B"), "b")
	m.ApplyAsync(v4Config("iface-C"), "c")

	release <- struct{}{} // finish A; worker picks up the slot
	gotNext := <-applied
	if !strings.Contains(gotNext, "iface-C") {
		t.Fatalf("expected latest state C applied next, got %q", gotNext)
	}
	release <- struct{}{} // finish C

	// B must have been coalesced away — no further applies.
	select {
	case extra := <-applied:
		t.Fatalf("unexpected extra apply (B not coalesced): %q", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestApplyAsyncSingleWorker pins the singleton contract: repeated
// ApplyAsync bursts start exactly one worker goroutine.
func TestApplyAsyncSingleWorker(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	for burst := 0; burst < 2; burst++ {
		for i := 0; i < 25; i++ {
			m.ApplyAsync(nil, "burst")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := m.asyncWorkerStarts.Load(); n != 1 {
		t.Fatalf("worker goroutine starts = %d, want 1", n)
	}
}

// TestApplyClusterCommit pins #1835 F3: a cluster-mode commit must
// always regenerate the Kea config and restart ONLY units that are
// currently active (active == this node is serving as VRRP MASTER);
// inactive units get the fresh config on disk for the next MASTER
// transition, with no restart.
func TestApplyClusterCommit(t *testing.T) {
	t.Run("active unit restarted with rewritten config", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
		if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("ApplyClusterCommit: %v", err)
		}
		if _, err := os.Stat(m.confPath4); err != nil {
			t.Errorf("config not regenerated: %v", err)
		}
		if !calledWith(*calls, "restart "+kea4Svc) {
			t.Errorf("active unit must restart on cluster commit, got %v", *calls)
		}
	})

	t.Run("inactive unit gets config only, no restart", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{}, "")
		if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("ApplyClusterCommit: %v", err)
		}
		if _, err := os.Stat(m.confPath4); err != nil {
			t.Errorf("config not regenerated: %v", err)
		}
		if len(*calls) != 0 {
			t.Errorf("inactive unit must not restart on cluster commit, got %v", *calls)
		}
	})

	t.Run("restart failure on active unit fails the commit", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{kea4Svc: true}, "restart "+kea4Svc)
		err := m.ApplyClusterCommit(v4Config("ge-0-0-0"))
		if err == nil || !strings.Contains(err.Error(), kea4Svc) {
			t.Fatalf("want fail-closed restart error naming the unit, got %v", err)
		}
	})

	t.Run("nil config clears active units", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
		if err := m.ApplyClusterCommit(nil); err != nil {
			t.Fatalf("ApplyClusterCommit(nil): %v", err)
		}
		if !calledWith(*calls, "stop "+kea4Svc) {
			t.Errorf("active unit must stop when config removed, got %v", *calls)
		}
	})
}

// waitForCondition polls cond until true or fails the test. Used for
// observing the async worker's gen-checked outcomes (skip counters,
// lastAppliedGen) without timing assumptions on the assertion itself.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSyncSupersedesQueuedAsync pins Codex hole 2 on PR #1835: a
// queued async request must NOT be applied over a newer synchronous
// ApplyClusterCommit. Choreographed deterministically via gens: the
// async producer allocates its gen at call entry, then "stalls" before
// reaching the mailbox (the worst-case interleaving), the sync commit
// lands with a higher gen, and the stale async — delivered through the
// real mailbox + worker — must be skipped by the shared apply body.
func TestSyncSupersedesQueuedAsync(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")

	// Async producer at call entry: gen allocated, enqueue delayed.
	oldGen := m.applyGen.Add(1)
	oldReq := &asyncApplyReq{gen: oldGen, cfg: v4Config("iface-OLD"), reason: "stale-vrrp"}

	// Sync cluster commit with a newer gen applies (unit active →
	// regenerates config and restarts).
	if err := m.ApplyClusterCommit(v4Config("iface-NEW")); err != nil {
		t.Fatalf("ApplyClusterCommit: %v", err)
	}

	// The stalled producer finally lands its stale request.
	m.enqueueAsync(oldReq)
	waitForCondition(t, "stale async skip", func() bool {
		return m.staleApplySkips.Load() == 1
	})

	data, err := os.ReadFile(m.confPath4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "iface-NEW") || strings.Contains(string(data), "iface-OLD") {
		t.Errorf("stale async overwrote the sync commit's config: %s", data)
	}
	restarts := 0
	for _, c := range *calls {
		if c == "restart "+kea4Svc {
			restarts++
		}
	}
	if restarts != 1 {
		t.Errorf("apply count: want exactly the sync commit's restart, got %d (%v)", restarts, *calls)
	}
}

// TestAsyncSupersedesOlderSync pins the other direction of the gen
// ordering: an async request allocated AFTER a sync apply lands over
// it (final state = async's), while a sync applier holding a stale gen
// skips and returns nil — being superseded is not a failure.
func TestAsyncSupersedesOlderSync(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")

	if err := m.Apply(v4Config("iface-SYNC")); err != nil { // gen 1
		t.Fatalf("Apply: %v", err)
	}
	m.ApplyAsync(v4Config("iface-ASYNC"), "newer") // gen 2 > 1 → applies
	waitForCondition(t, "async apply over older sync", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.lastAppliedGen == 2
	})
	data, _ := os.ReadFile(m.confPath4)
	if !strings.Contains(string(data), "iface-ASYNC") {
		t.Errorf("newer async must win, config: %s", data)
	}
	if got := len(*calls); got != 2 {
		t.Errorf("want 2 restarts (sync + newer async), got %d: %v", got, *calls)
	}

	// Inverse stale case: a sync applier whose gen lost the race to a
	// newer applier must skip, returning nil with no systemctl calls.
	if err := m.apply(1, v4Config("iface-STALE"), true); err != nil {
		t.Fatalf("superseded sync apply must return nil, got %v", err)
	}
	if m.staleApplySkips.Load() != 1 {
		t.Errorf("stale sync apply not skipped (skips=%d)", m.staleApplySkips.Load())
	}
	data, _ = os.ReadFile(m.confPath4)
	if strings.Contains(string(data), "iface-STALE") {
		t.Errorf("stale sync apply regenerated config: %s", data)
	}
	if got := len(*calls); got != 2 {
		t.Errorf("stale sync apply issued systemctl calls: %v", *calls)
	}
}

// TestApplyAsyncConcurrentProducersHighestGenWins pins Codex hole 1 on
// PR #1835 (ABA in the old send-after-drain loop): with the worker
// blocked, 10 concurrent producers race the mailbox; the pending slot
// must end up holding exactly the highest allocated gen (asserted via
// gens, not timing), and after release exactly that state is applied.
func TestApplyAsyncConcurrentProducersHighestGenWins(t *testing.T) {
	m, applied, release := asyncTestManager(t)

	m.ApplyAsync(v4Config("iface-prime"), "prime") // gen 1
	<-applied                                      // worker blocked in prime's restart

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.ApplyAsync(v4Config(fmt.Sprintf("iface-%d", i)), "racer")
		}(i)
	}
	wg.Wait()

	// All producers returned: the slot must hold the highest gen.
	m.asyncMu.Lock()
	pend := m.pendingAsync
	m.asyncMu.Unlock()
	if pend == nil {
		t.Fatal("no pending request after concurrent producers")
	}
	if want := m.applyGen.Load(); pend.gen != want {
		t.Fatalf("pending gen = %d, want highest allocated %d (ABA: an older producer overwrote a newer request)", pend.gen, want)
	}
	winner := pend.cfg.DHCPLocalServer.Groups["g0"].Interfaces[0]

	release <- struct{}{} // finish prime
	got := <-applied      // exactly one coalesced apply
	if !strings.Contains(got, winner) {
		t.Fatalf("applied %q, want highest-gen state %q", got, winner)
	}
	release <- struct{}{}

	select {
	case extra := <-applied:
		t.Fatalf("unexpected extra apply: %q", extra)
	case <-time.After(200 * time.Millisecond):
	}

	m.mu.Lock()
	last := m.lastAppliedGen
	m.mu.Unlock()
	if last != pend.gen {
		t.Fatalf("lastAppliedGen = %d, want %d", last, pend.gen)
	}
}
