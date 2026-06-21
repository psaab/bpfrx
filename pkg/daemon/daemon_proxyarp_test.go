package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// withFakeIfaceResolver replaces the proxyARPIfaceMap interface resolver with a
// fixed name→ifindex map so the RETH-resolution logic can be exercised without
// real interfaces, restoring the production resolver on cleanup.
func withFakeIfaceResolver(t *testing.T, byName map[string]int) {
	t.Helper()
	prev := ifaceIndexByName
	ifaceIndexByName = func(name string) (int, error) {
		if idx, ok := byName[name]; ok {
			return idx, nil
		}
		return 0, errors.New("no such device: " + name)
	}
	t.Cleanup(func() { ifaceIndexByName = prev })
}

// TestProxyARPIfaceMap_ResolvesRethToPhysical is the #2195/#2197 SMR F6
// regression guard: a proxy-arp entry on a RETH (sub-)interface must resolve to
// the PHYSICAL member ifindex (via cfg.RethToPhysical + config.LinuxIfName).
// Losing this resolution in the apply-path extraction would silently break
// proxy-arp on RETH interfaces (the NTF_PROXY entry / sysctl would land on the
// wrong — or no — link). The fake resolver only knows the physical member name,
// so a non-resolving extraction would drop the entry and fail this test.
func TestProxyARPIfaceMap_ResolvesRethToPhysical(t *testing.T) {
	// RethToPhysical is built from Interfaces with RedundantParent set; node 0
	// is local (slot-0 member preferred). reth0 → ge-0/0/2 (local member).
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0.50", Addresses: []string{"172.16.50.50/32"}},
	}

	// reth0 → ge-0/0/2 (local member) → Linux name ge-0-0-2.
	const wantIdx = 42
	linux := config.LinuxIfName("ge-0/0/2")
	withFakeIfaceResolver(t, map[string]int{linux: wantIdx})

	m := proxyARPIfaceMap(cfg)
	got, ok := m["reth0.50"]
	if !ok {
		t.Fatalf("reth0.50 not resolved; map=%v (RETH→physical resolution dropped?)", m)
	}
	if got != wantIdx {
		t.Fatalf("reth0.50 ifindex = %d, want %d (physical member %s)", got, wantIdx, linux)
	}
}

// TestProxyARPIfaceMap_DedupesAndSkipsUnresolvable verifies the helper dedupes
// repeated interface keys and best-effort skips an interface that does not
// resolve, without aborting the rest.
func TestProxyARPIfaceMap_DedupesAndSkipsUnresolvable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0/0/1", Addresses: []string{"10.0.0.1/32"}},
		{Interface: "ge-0/0/1", Addresses: []string{"10.0.0.2/32"}}, // dup key
		{Interface: "ge-0/0/9", Addresses: []string{"10.0.0.3/32"}}, // unresolvable
	}
	withFakeIfaceResolver(t, map[string]int{config.LinuxIfName("ge-0/0/1"): 5})

	m := proxyARPIfaceMap(cfg)
	if len(m) != 1 {
		t.Fatalf("map = %v, want exactly one resolved entry", m)
	}
	if m["ge-0/0/1"] != 5 {
		t.Fatalf("ge-0/0/1 ifindex = %d, want 5", m["ge-0/0/1"])
	}
}

// TestReconcileProxyARP_NoEntriesIsNoOp verifies the extracted daemon method is
// a no-op (no panic, no resolver call) when no proxy-arp entries are
// configured — the property that makes the always-on loop cheap on configs that
// do not use proxy-arp.
func TestReconcileProxyARP_NoEntriesIsNoOp(t *testing.T) {
	called := false
	prev := ifaceIndexByName
	ifaceIndexByName = func(name string) (int, error) { called = true; return 0, nil }
	t.Cleanup(func() { ifaceIndexByName = prev })

	d := &Daemon{}
	d.reconcileProxyARP(&config.Config{}) // empty config
	d.reconcileProxyARP(nil)              // nil config
	if called {
		t.Fatal("reconcileProxyARP resolved interfaces despite no proxy-arp entries")
	}
}

// TestProxyARPReassertLoop_DrivesReconcile verifies the always-on ticker drives
// reconcileProxyARP (#2197 item 2). On pre-fix code there is NO periodic
// re-assert loop at all, so this test (which asserts the loop invokes the
// reconcile against the active config) cannot pass — the loop does not exist.
// Here we substitute a counting reconcile fn and a short interval, then confirm
// the loop fires it with the store's active config.
func TestProxyARPReassertLoop_DrivesReconcile(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set security nat proxy-arp interface ge-0/0/1 address 10.0.2.50/32\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var calls int64
	var gotEntries int64
	prevFn := proxyARPReconcileFn
	proxyARPReconcileFn = func(_ *Daemon, cfg *config.Config) {
		atomic.AddInt64(&calls, 1)
		if cfg != nil && len(cfg.Security.NAT.ProxyARP) > 0 {
			atomic.StoreInt64(&gotEntries, 1)
		}
	}
	prevIvl := proxyARPReassertInterval
	proxyARPReassertInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		proxyARPReconcileFn = prevFn
		proxyARPReassertInterval = prevIvl
	})

	d := &Daemon{store: s}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.proxyARPReassertLoop(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt64(&calls) < 2 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("loop did not drive reconcile twice in time (calls=%d)", atomic.LoadInt64(&calls))
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if atomic.LoadInt64(&gotEntries) != 1 {
		t.Fatal("loop did not pass the active config (with proxy-arp entries) to the reconcile")
	}
}

// TestProxyARPReassertLoop_StopsOnContextCancel verifies the loop exits
// promptly when its context is cancelled (clean daemon shutdown).
func TestProxyARPReassertLoop_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	prevIvl := proxyARPReassertInterval
	proxyARPReassertInterval = time.Hour // never ticks during the test
	t.Cleanup(func() { proxyARPReassertInterval = prevIvl })

	d := &Daemon{store: s}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.proxyARPReassertLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not exit on context cancel")
	}
}
