package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #6492 fail-on-revert proofs for the SHARED cold-boot fence builder. Both
// findings are exercised through the PRODUCTION call path
// applyLo0Filter -> installLo0ColdBootFence -> InstallLo0ColdBootFence(spec),
// which is the path a cold-boot lo0 install failure actually takes (the boot
// apply logs+discards the error, so the fence is the only remaining protection).
// Revert dpuserspace.BuildFenceAddrSets out of applyLo0Filter — back to
// `BuildZoneHostInboundViews` + `BuildUnzonedHostInboundAddrs` — and both tests
// go RED.

// fenceScopeInstaller wires a failing real lo0 install to a capturing fence
// installer and returns the captured spec plus the fence call count.
func fenceScopeInstaller(t *testing.T, cfg *config.Config) (xnft.FenceSpec, int) {
	t.Helper()
	injected := errors.New("nftables: injected cold-boot lo0 failure")
	var spec xnft.FenceSpec
	calls := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { return injected },
		lo0ColdBootFence: func(s xnft.FenceSpec) error { spec = s; calls++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if d.lo0Enforced.Load() {
		t.Fatal("precondition: cold boot means lo0Enforced false")
	}
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("the real lo0 install failed; applyLo0Filter must surface an error")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected failure, got %v", err)
	}
	return spec, calls
}

// TestFenceWithholdsLifelineSharedAddress6492 is the Finding A proof. A
// management address configured on BOTH fxp0.0 (a lifeline) and a zoned data
// interface is a topology xpf explicitly accepts. The fence strips every
// per-service ACCEPT and its drop rule carries no `iifname`, so fencing that
// address renders `ip daddr 172.16.50.8 drop` — every NEW management connection
// to it dies for the whole fence window. The fence must WITHHOLD it.
//
// The second half is the anti-over-fix assertion: the REAL ruleset's views must
// still carry the address, because the real table's per-service accepts precede
// its catch-all DROP and admit the management session. A "fix" that subtracted
// the address inside BuildZoneHostInboundViews would relax the real table's
// default-deny (a fail-open) and makes that half RED.
func TestFenceWithholdsLifelineSharedAddress6492(t *testing.T) {
	cfg := lo0FenceTestConfig()
	// The mgmt zone's fxp0 now carries the SAME address as the wan zone's
	// reth0.50 (172.16.50.8). fxp0 is a lifeline; reth0.50 is not.
	cfg.Interfaces.Interfaces["fxp0"].Units[0] = &config.InterfaceUnit{
		Number:    0,
		Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"},
	}

	// The REAL ruleset still denies the shared address (its accepts protect it).
	realViews := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !viewsContainAddr(realViews, "172.16.50.8") {
		t.Fatal("the REAL host-inbound views must still scope the shared address; " +
			"withholding it there would relax the real table's default-deny (fail-open)")
	}

	spec, calls := fenceScopeInstaller(t, cfg)
	if calls != 1 {
		t.Fatalf("cold-boot fence install count = %d, want 1", calls)
	}
	if got := fenceViewAddrs(spec, false); sliceContains(got, "172.16.50.8") {
		t.Fatalf("FENCE must not drop 172.16.50.8: it is also configured on the fxp0 "+
			"lifeline, and the fence has no per-service accept to let management back "+
			"in. Fenced v4 = %v", got)
	}
	if got := fenceViewAddrs(spec, true); sliceContains(got, "2001:db8:50::8") {
		t.Fatalf("FENCE must not drop 2001:db8:50::8 (shared with the fxp0 lifeline). "+
			"Fenced v6 = %v", got)
	}
	// The fence must still be doing its job for the addresses that are NOT
	// shared — otherwise "withhold" degenerated into "fence nothing".
	if got := fenceViewAddrs(spec, false); !sliceContains(got, "10.0.61.1") {
		t.Fatalf("FENCE must still drop the unshared lan address 10.0.61.1, got %v", got)
	}
}

// TestFenceCoversZonelessRouter6492 is the Finding B proof. A router with an
// lo0 input filter but NO security zones is a valid config
// (compiler_filter_ref_3296_test): host-inbound / lo0 filters do not require
// the zone model. BuildZoneHostInboundViews and BuildUnzonedHostInboundAddrs
// both return nothing without zones, so a failed cold-boot lo0 install produced
// an accept-policy fence shell with ZERO drops — fail-OPEN, exactly what the
// fence exists to prevent. The fence's drop set must come from the
// firewall-local ADDRESSES, not from zone membership.
func TestFenceCoversZonelessRouter6492(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8:6492::1/64"}},
		}},
		// A lifeline keeps its exemption with or without zones.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.10.10.10/24"}},
		}},
	}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: "discard"},
		}},
	}

	// Precondition: this really is the zone-less shape the finding describes.
	if len(cfg.Security.Zones) != 0 {
		t.Fatal("precondition: the config must declare no security zone")
	}
	if v := dpuserspace.BuildZoneHostInboundViews(cfg); len(v) != 0 {
		t.Fatalf("precondition: the zone-model builder yields nothing without zones, got %+v", v)
	}
	if v4, v6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg); len(v4)+len(v6) != 0 {
		t.Fatalf("precondition: the unzoned builder yields nothing without zones, got %v %v", v4, v6)
	}

	spec, calls := fenceScopeInstaller(t, cfg)
	if calls != 1 {
		t.Fatalf("cold-boot fence install count = %d, want 1", calls)
	}
	gotV4 := fenceViewAddrs(spec, false)
	if !sliceContains(gotV4, "192.0.2.1") {
		t.Fatalf("FENCE on a zone-less router must drop the firewall-local address "+
			"192.0.2.1; a zero-drop `policy accept` shell is the fail-open this fence "+
			"exists to prevent. Fenced v4 = %v", gotV4)
	}
	if got := fenceViewAddrs(spec, true); !sliceContains(got, "2001:db8:6492::1") {
		t.Fatalf("FENCE on a zone-less router must drop 2001:db8:6492::1, got %v", got)
	}
	if sliceContains(gotV4, "10.10.10.10") {
		t.Fatalf("FENCE must never drop a lifeline (fxp0) address, got %v", gotV4)
	}
}

// viewsContainAddr reports whether any view scopes addr in either family.
func viewsContainAddr(views []dpuserspace.ZoneHostInboundView, addr string) bool {
	for _, v := range views {
		if sliceContains(v.V4Addrs, addr) || sliceContains(v.V6Addrs, addr) {
			return true
		}
	}
	return false
}
