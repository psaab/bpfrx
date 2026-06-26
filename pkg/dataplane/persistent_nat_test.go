package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestPersistentNATTable_SaveAndLookup(t *testing.T) {
	table := NewPersistentNATTable()

	srcIP := netip.MustParseAddr("192.168.1.100")
	natIP := netip.MustParseAddr("203.0.113.1")

	binding := &PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  12345,
		NatIP:    natIP,
		NatPort:  40000,
		PoolName: "pool1",
		LastSeen: time.Now(),
		Timeout:  300 * time.Second,
	}
	table.Save(binding)

	// Lookup should find the binding
	got := table.Lookup(srcIP, 12345, "pool1")
	if got == nil {
		t.Fatal("expected binding, got nil")
	}
	if got.NatIP != natIP {
		t.Errorf("NatIP = %s, want %s", got.NatIP, natIP)
	}
	if got.NatPort != 40000 {
		t.Errorf("NatPort = %d, want 40000", got.NatPort)
	}

	// Lookup with wrong pool should return nil
	if table.Lookup(srcIP, 12345, "other") != nil {
		t.Error("expected nil for wrong pool")
	}

	// Lookup with wrong port should return nil
	if table.Lookup(srcIP, 54321, "pool1") != nil {
		t.Error("expected nil for wrong port")
	}
}

func TestPersistentNATTable_SaveUpdatesLastSeen(t *testing.T) {
	table := NewPersistentNATTable()
	srcIP := netip.MustParseAddr("10.0.0.1")
	natIP := netip.MustParseAddr("203.0.113.1")

	before := time.Now().Add(-10 * time.Second)
	table.Save(&PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  1000,
		NatIP:    natIP,
		NatPort:  2000,
		PoolName: "p",
		LastSeen: before,
		Timeout:  60 * time.Second,
	})

	// Save again should update LastSeen
	table.Save(&PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  1000,
		NatIP:    natIP,
		NatPort:  2000,
		PoolName: "p",
		LastSeen: before,
		Timeout:  60 * time.Second,
	})

	got := table.Lookup(srcIP, 1000, "p")
	if got == nil {
		t.Fatal("expected binding")
	}
	if !got.LastSeen.After(before) {
		t.Error("LastSeen should have been updated to now")
	}
}

func TestPersistentNATTable_ExpiredBindingReturnsNil(t *testing.T) {
	table := NewPersistentNATTable()
	srcIP := netip.MustParseAddr("10.0.0.1")

	table.Save(&PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  1000,
		NatIP:    netip.MustParseAddr("1.2.3.4"),
		NatPort:  2000,
		PoolName: "p",
		LastSeen: time.Now().Add(-600 * time.Second),
		Timeout:  300 * time.Second,
	})

	if table.Lookup(srcIP, 1000, "p") != nil {
		t.Error("expected nil for expired binding")
	}
}

func TestPersistentNATTable_GCRemovesExpired(t *testing.T) {
	table := NewPersistentNATTable()

	// Add expired binding
	table.Save(&PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		SrcPort:  1000,
		NatIP:    netip.MustParseAddr("1.2.3.4"),
		NatPort:  2000,
		PoolName: "p",
		LastSeen: time.Now().Add(-600 * time.Second),
		Timeout:  300 * time.Second,
	})

	// Add live binding
	table.Save(&PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  1001,
		NatIP:    netip.MustParseAddr("1.2.3.4"),
		NatPort:  2001,
		PoolName: "p",
		LastSeen: time.Now(),
		Timeout:  300 * time.Second,
	})

	removed := table.GC()
	if removed != 1 {
		t.Errorf("GC removed %d, want 1", removed)
	}
	if table.Len() != 1 {
		t.Errorf("Len() = %d, want 1", table.Len())
	}
}

func TestPersistentNATTable_PoolConfig(t *testing.T) {
	table := NewPersistentNATTable()

	// Register pool config
	table.SetPoolConfig("snat-pool", PersistentNATPoolInfo{
		Timeout: 600 * time.Second,
		Permit:  config.PersistentNATPermitAnyRemoteHost,
	})

	natIP := netip.MustParseAddr("203.0.113.1")
	table.RegisterNATIP(natIP, "snat-pool")

	// Lookup pool by NAT IP
	poolName, cfg, ok := table.LookupPool(natIP)
	if !ok {
		t.Fatal("expected pool config")
	}
	if poolName != "snat-pool" {
		t.Errorf("pool name = %q, want snat-pool", poolName)
	}
	if cfg.Timeout != 600*time.Second {
		t.Errorf("timeout = %s, want 600s", cfg.Timeout)
	}
	if cfg.Permit != config.PersistentNATPermitAnyRemoteHost {
		t.Errorf("expected Permit = any-remote-host, got %q", cfg.Permit)
	}

	// Unknown IP should not find a pool
	_, _, ok = table.LookupPool(netip.MustParseAddr("10.10.10.10"))
	if ok {
		t.Error("expected no pool for unknown IP")
	}
}

func TestPersistentNATTable_ClearPoolConfigs(t *testing.T) {
	table := NewPersistentNATTable()

	table.SetPoolConfig("pool1", PersistentNATPoolInfo{Timeout: 300 * time.Second})
	ip := netip.MustParseAddr("1.2.3.4")
	table.RegisterNATIP(ip, "pool1")

	table.ClearPoolConfigs()

	_, _, ok := table.LookupPool(ip)
	if ok {
		t.Error("expected no pool after ClearPoolConfigs")
	}
}

func TestPersistentNATTable_InactivityTimeout(t *testing.T) {
	table := NewPersistentNATTable()

	// Register pool with custom timeout
	table.SetPoolConfig("custom-pool", PersistentNATPoolInfo{
		Timeout: 120 * time.Second,
	})
	natIP := netip.MustParseAddr("198.51.100.1")
	table.RegisterNATIP(natIP, "custom-pool")

	// Simulate saving a binding with pool's timeout
	_, poolCfg, ok := table.LookupPool(natIP)
	if !ok {
		t.Fatal("expected pool config")
	}

	table.Save(&PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.50"),
		SrcPort:  5000,
		NatIP:    natIP,
		NatPort:  30000,
		PoolName: "custom-pool",
		LastSeen: time.Now(),
		Timeout:  poolCfg.Timeout,
	})

	got := table.Lookup(netip.MustParseAddr("10.0.0.50"), 5000, "custom-pool")
	if got == nil {
		t.Fatal("expected binding")
	}
	if got.Timeout != 120*time.Second {
		t.Errorf("binding timeout = %s, want 120s", got.Timeout)
	}
}

func TestPersistentNATTable_PermitMode(t *testing.T) {
	table := NewPersistentNATTable()

	srcIP := netip.MustParseAddr("192.168.1.1")
	natIP := netip.MustParseAddr("203.0.113.5")

	table.Save(&PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  8080,
		NatIP:    natIP,
		NatPort:  40000,
		PoolName: "perm-pool",
		LastSeen: time.Now(),
		Timeout:  300 * time.Second,
		Permit:   config.PersistentNATPermitAnyRemoteHost,
	})

	got := table.Lookup(srcIP, 8080, "perm-pool")
	if got == nil {
		t.Fatal("expected binding")
	}
	if got.Permit != config.PersistentNATPermitAnyRemoteHost {
		t.Errorf("expected Permit = any-remote-host, got %q", got.Permit)
	}

	// #3193: PermitMode renders each three-way mode distinctly, and the
	// zero value resolves to the target-host-port default.
	cases := []struct {
		permit config.PersistentNATPermit
		want   string
	}{
		{config.PersistentNATPermitAnyRemoteHost, "any-remote-host"},
		{config.PersistentNATPermitTargetHost, "target-host"},
		{config.PersistentNATPermitTargetHostPort, "target-host-port"},
		{"", "target-host-port"},
	}
	for _, c := range cases {
		b := &PersistentNATBinding{Permit: c.permit}
		if got := b.PermitMode(); got != c.want {
			t.Errorf("PermitMode(%q) = %q, want %q", c.permit, got, c.want)
		}
	}
	if mode := (&PersistentNATBinding{Permit: config.PersistentNATPermitTargetHost}).PermitMode(); mode == (&PersistentNATBinding{Permit: config.PersistentNATPermitTargetHostPort}).PermitMode() {
		t.Fatalf("target-host and target-host-port must render distinctly, both = %q", mode)
	}
}

func TestPersistentNATTable_MultiplePoolIPs(t *testing.T) {
	table := NewPersistentNATTable()

	table.SetPoolConfig("multi-pool", PersistentNATPoolInfo{
		Timeout: 300 * time.Second,
	})

	ip1 := netip.MustParseAddr("203.0.113.1")
	ip2 := netip.MustParseAddr("203.0.113.2")
	ip3 := netip.MustParseAddr("203.0.113.3")

	table.RegisterNATIP(ip1, "multi-pool")
	table.RegisterNATIP(ip2, "multi-pool")
	table.RegisterNATIP(ip3, "multi-pool")

	// All IPs should resolve to same pool
	for _, ip := range []netip.Addr{ip1, ip2, ip3} {
		name, _, ok := table.LookupPool(ip)
		if !ok || name != "multi-pool" {
			t.Errorf("IP %s: pool = %q, ok = %v", ip, name, ok)
		}
	}
}

func TestPersistentNATTable_IPv6(t *testing.T) {
	table := NewPersistentNATTable()

	srcIP := netip.MustParseAddr("2001:db8::1")
	natIP := netip.MustParseAddr("2001:db8:ff::100")

	table.SetPoolConfig("v6pool", PersistentNATPoolInfo{
		Timeout: 600 * time.Second,
		Permit:  config.PersistentNATPermitAnyRemoteHost,
	})
	table.RegisterNATIP(natIP, "v6pool")

	table.Save(&PersistentNATBinding{
		SrcIP:    srcIP,
		SrcPort:  443,
		NatIP:    natIP,
		NatPort:  50000,
		PoolName: "v6pool",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
		Permit:   config.PersistentNATPermitAnyRemoteHost,
	})

	got := table.Lookup(srcIP, 443, "v6pool")
	if got == nil {
		t.Fatal("expected v6 binding")
	}
	if got.NatIP != natIP {
		t.Errorf("NatIP = %s, want %s", got.NatIP, natIP)
	}
	if got.Timeout != 600*time.Second {
		t.Errorf("timeout = %s, want 600s", got.Timeout)
	}
}
