package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

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
// regression guard: a proxy-arp entry on a base RETH interface must resolve to
// the PHYSICAL member ifindex (via cfg.ResolveKernelIfName → RethToPhysical).
// Losing this resolution in the apply-path extraction would silently break
// proxy-arp on RETH interfaces (the NTF_PROXY entry / sysctl would land on the
// wrong — or no — link). The fake resolver only knows the physical member name,
// so a non-resolving extraction would drop the entry and fail this test.
//
// The entry is on unit 0 (untagged, addresses on the base reth), which collapses
// onto the bare parent netdev — distinct from the VLAN sub-interface case in
// TestProxyARPIfaceMap_ResolvesVLANSubinterfaceToOwnNetdev (#3010).
func TestProxyARPIfaceMap_ResolvesRethToPhysical(t *testing.T) {
	// RethToPhysical is built from Interfaces with RedundantParent set; node 0
	// is local (slot-0 member preferred). reth0 → ge-0/0/2 (local member).
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, VlanID: 0},
				}},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
			},
		},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0.0", Addresses: []string{"172.16.50.50/32"}},
	}

	// reth0 → ge-0/0/2 (local member) → Linux name ge-0-0-2 (unit 0 collapse).
	const wantIdx = 42
	linux := config.LinuxIfName("ge-0/0/2")
	withFakeIfaceResolver(t, map[string]int{linux: wantIdx})

	m, _, _ := proxyARPIfaceMap(cfg)
	got, ok := m["reth0.0"]
	if !ok {
		t.Fatalf("reth0.0 not resolved; map=%v (RETH→physical resolution dropped?)", m)
	}
	if got != wantIdx {
		t.Fatalf("reth0.0 ifindex = %d, want %d (physical member %s)", got, wantIdx, linux)
	}
}

// TestProxyARPIfaceMap_ResolvesVLANSubinterfaceToOwnNetdev is the #3010
// fail-on-revert guard: a proxy-arp entry on a VLAN sub-interface must resolve
// to the SUB-INTERFACE's own VLAN netdev ifindex (ge-0-0-1.100), NOT the parent
// (ge-0-0-1). Linux proxy_arp/proxy_ndp are per-netdev, so storing the parent
// ifindex writes the sysctl on the parent and leaves the VLAN sub-interface
// silent — the bug this test pins.
//
// The fake resolver knows ONLY the VLAN netdev name (ge-0-0-1.100) and NOT the
// bare parent, so the old behavior (strip ".unit", resolve only the parent via
// RethToPhysical + LinuxIfName(base), store the parent ifindex) would call the
// resolver with "ge-0-0-1", get an error, log+skip, and produce an EMPTY map —
// failing this test. It also asserts the resolved ifindex is the VLAN netdev's,
// not the parent's, so a revert that resolved the parent (if the parent were
// resolvable) would still fail on the wrong-ifindex check.
//
// Note the VLAN ID (100) is intentionally DIFFERENT from the unit number (3):
// the kernel netdev is named by the 802.1Q VLAN ID, not the unit number, so a
// naive ".unit" re-append (the issue's first-cut suggestion) would resolve the
// wrong netdev name (ge-0-0-1.3) and also fail this test.
func TestProxyARPIfaceMap_ResolvesVLANSubinterfaceToOwnNetdev(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
					3: {Number: 3, VlanID: 100},
				}},
			},
		},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0/0/1.3", Addresses: []string{"10.0.100.50/32"}},
	}

	// The resolver knows ONLY the VLAN netdev (ge-0-0-1.100), so resolving the
	// parent (ge-0-0-1) or the wrong suffix (ge-0-0-1.3) yields no entry.
	const wantIdx = 77
	const parentIdx = 7
	vlanNetdev := config.LinuxIfName("ge-0/0/1") + ".100"
	withFakeIfaceResolver(t, map[string]int{
		vlanNetdev: wantIdx,
		// Deliberately also expose the bare parent so a parent-resolving revert
		// returns the WRONG (parent) ifindex and fails the equality check below,
		// rather than silently passing by absence.
		config.LinuxIfName("ge-0/0/1"): parentIdx,
	})

	m, _, _ := proxyARPIfaceMap(cfg)
	got, ok := m["ge-0/0/1.3"]
	if !ok {
		t.Fatalf("ge-0/0/1.3 not resolved; map=%v (VLAN sub-interface resolution dropped?)", m)
	}
	if got == parentIdx {
		t.Fatalf("ge-0/0/1.3 resolved to PARENT ifindex %d — proxy_arp would land on the parent netdev, leaving the VLAN sub-interface silent (#3010)", parentIdx)
	}
	if got != wantIdx {
		t.Fatalf("ge-0/0/1.3 ifindex = %d, want %d (VLAN netdev %s)", got, wantIdx, vlanNetdev)
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

	m, _, _ := proxyARPIfaceMap(cfg)
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

// TestDiffProxyResponders is the pure #2475 fail-on-revert anchor: the diff of
// the previously-enabled proxy responder set against the freshly-enabled set
// must yield exactly the (interface, family) pairs that DROPPED out, so the
// caller can disable their leaked proxy_arp / proxy_ndp sysctl. If the
// disable-on-removal logic is reverted (e.g. diffProxyResponders returns nil,
// or reconcileProxyARP stops calling it), the removed interface keeps its
// sysctl on — exactly the leak this issue fixes.
func TestDiffProxyResponders(t *testing.T) {
	v4 := map[int]struct{}{unix.AF_INET: {}}
	v4v6 := map[int]struct{}{unix.AF_INET: {}, unix.AF_INET6: {}}

	cases := []struct {
		name      string
		prev, cur map[string]map[int]struct{}
		want      map[string]map[int]struct{}
	}{
		{
			name: "interface fully removed",
			prev: map[string]map[int]struct{}{"ge-0-0-1": v4},
			cur:  nil,
			want: map[string]map[int]struct{}{"ge-0-0-1": v4},
		},
		{
			name: "steady config disables nothing",
			prev: map[string]map[int]struct{}{"ge-0-0-1": v4},
			cur:  map[string]map[int]struct{}{"ge-0-0-1": v4},
			want: map[string]map[int]struct{}{},
		},
		{
			name: "one family dropped, other kept",
			prev: map[string]map[int]struct{}{"ge-0-0-1": v4v6},
			cur:  map[string]map[int]struct{}{"ge-0-0-1": v4},
			want: map[string]map[int]struct{}{"ge-0-0-1": {unix.AF_INET6: {}}},
		},
		{
			name: "newly added interface disables nothing",
			prev: nil,
			cur:  map[string]map[int]struct{}{"ge-0-0-1": v4},
			want: nil,
		},
		{
			name: "one of two interfaces removed",
			prev: map[string]map[int]struct{}{"ge-0-0-1": v4, "ge-0-0-2": v4},
			cur:  map[string]map[int]struct{}{"ge-0-0-1": v4},
			want: map[string]map[int]struct{}{"ge-0-0-2": v4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffProxyResponders(tc.prev, tc.cur)
			if !sameProxySet(got, tc.want) {
				t.Fatalf("diffProxyResponders = %v, want %v", got, tc.want)
			}
		})
	}
}

// sameProxySet compares two (interface → family-set) maps for equality,
// treating nil and empty as equal (the diff returns nil when nothing is stale).
func sameProxySet(a, b map[string]map[int]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for iface, fams := range a {
		bf, ok := b[iface]
		if !ok || len(fams) != len(bf) {
			return false
		}
		for f := range fams {
			if _, ok := bf[f]; !ok {
				return false
			}
		}
	}
	return true
}

// TestReconcileProxyARP_DisablesOnRemoval is the integration #2475 fail-on-
// revert test: a commit that configures proxy-arp on an interface enables the
// per-interface sysctl; a follow-up commit that REMOVES proxy-arp must drive
// that sysctl back off via the disable sink. It drives the real
// reconcileProxyARP (resolving the loopback interface) and captures the
// teardown through the proxyARPDisableFn seam. On pre-fix code (no disable-on-
// removal) the second reconcile early-returns and never calls the sink, so the
// assertion that "lo" is disabled FAILS — and reverting the fix re-RED's it.
func TestReconcileProxyARP_DisablesOnRemoval(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}

	// Resolve any proxy-arp interface name to lo's ifindex so the dataplane
	// reconcile populates the enabled set keyed by "lo" (LinkByIndex(lo)).
	withFakeIfaceResolver(t, map[string]int{config.LinuxIfName("lo"): lo.Index})

	var disabled []map[string]map[int]struct{}
	prevDisable := proxyARPDisableFn
	proxyARPDisableFn = func(set map[string]map[int]struct{}) int {
		disabled = append(disabled, set)
		return 0
	}
	t.Cleanup(func() { proxyARPDisableFn = prevDisable })

	// The NTF_PROXY neighbor install on lo may need privileges; clean it up so
	// we leave no host state on a privileged runner.
	t.Cleanup(func() {
		_ = netlink.NeighDel(&netlink.Neigh{
			LinkIndex: lo.Index,
			IP:        net.ParseIP("10.0.2.50").To4(),
			Flags:     unix.NTF_PROXY,
			Family:    unix.AF_INET,
		})
	})

	d := &Daemon{}

	// Commit 1: proxy-arp configured on lo → sysctl enabled, state remembered.
	cfgOn := &config.Config{}
	cfgOn.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "lo", Addresses: []string{"10.0.2.50/32"}},
	}
	d.reconcileProxyARP(cfgOn)

	d.proxyARPEnabledMu.Lock()
	enabledLo := d.proxyARPEnabled["lo"]
	d.proxyARPEnabledMu.Unlock()
	if _, ok := enabledLo[unix.AF_INET]; !ok {
		t.Skipf("proxy-arp enable did not record lo (needs privileges for the "+
			"netlink install in this sandbox); enabled=%v", d.proxyARPEnabled)
	}
	if len(disabled) != 0 {
		t.Fatalf("disable sink called on the enable commit: %v", disabled)
	}

	// Commit 2: proxy-arp REMOVED → the leaked sysctl on lo must be disabled.
	d.reconcileProxyARP(&config.Config{})

	if len(disabled) != 1 {
		t.Fatalf("disable sink called %d times on removal, want 1 "+
			"(pre-#2475: sysctl leaks on — never driven back to 0)", len(disabled))
	}
	if _, ok := disabled[0]["lo"][unix.AF_INET]; !ok {
		t.Fatalf("removal disabled %v, want lo/AF_INET", disabled[0])
	}

	// State is now clear, so a third removal reconcile is a clean no-op.
	d.reconcileProxyARP(&config.Config{})
	if len(disabled) != 1 {
		t.Fatalf("disable sink fired again with empty prior state: %v", disabled)
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

	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1)}
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

	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1)}
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

// TestReassertProxyARPOnce_HoldsApplySem is the #4001 fail-on-revert guard: the
// periodic re-assert MUST run its reconcile under d.applySem — the same
// semaphore the commit/config-apply path holds across store.Commit +
// applyConfigLocked (reconcileProxyARP). Without it, a tick can interleave with
// a commit that removes a proxy-arp responder and re-install the removed
// responder from a stale pre-commit config snapshot (an HA blackhole for a
// moved VIP).
//
// The test substitutes the reconcile fn with a probe that, from inside the
// reconcile, tries a NON-BLOCKING acquire of the capacity-1 applySem. On the
// fixed code the re-assert already holds applySem, so TryAcquire FAILS
// (ranWithoutLock stays 0). Revert reassertProxyARPOnce to the old
// read-ActiveConfig-then-reconcile-without-the-lock form and TryAcquire
// succeeds → ranWithoutLock flips to 1 and this test goes RED.
func TestReassertProxyARPOnce_HoldsApplySem(t *testing.T) {
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

	var ranWithoutLock int64
	var called int64
	prevFn := proxyARPReconcileFn
	proxyARPReconcileFn = func(dd *Daemon, _ *config.Config) {
		atomic.AddInt64(&called, 1)
		// The re-assert must hold applySem while reconciling. A successful
		// non-blocking acquire proves it does NOT — the #4001 race is open.
		if dd.applySem.TryAcquire(1) {
			dd.applySem.Release(1)
			atomic.StoreInt64(&ranWithoutLock, 1)
		}
	}
	t.Cleanup(func() { proxyARPReconcileFn = prevFn })

	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1)}
	d.reassertProxyARPOnce(context.Background())

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("reconcile fn called %d times, want 1", atomic.LoadInt64(&called))
	}
	if atomic.LoadInt64(&ranWithoutLock) != 0 {
		t.Fatal("re-assert ran the proxy-ARP reconcile WITHOUT holding applySem (#4001): " +
			"a concurrent commit removing a responder could be undone by the re-assert")
	}
}

// TestReassertProxyARPOnce_SerializesWithCommit is the #4001 semantic
// fail-on-revert guard: a re-assert that fires while a commit holds applySem
// must BLOCK until the commit releases it, and must then reconcile the
// POST-commit ActiveConfig — never a stale pre-commit snapshot that still lists
// a just-removed responder.
//
// The test holds applySem (standing in for an in-flight commit), promotes a
// config with proxy-arp REMOVED into the store, launches reassertProxyARPOnce
// (which must block), asserts the reconcile has not run, then releases the
// semaphore and asserts the reconcile ran against the removed-responder config.
// On revert (no Acquire in the re-assert) the reconcile runs immediately and can
// observe the config while the commit is mid-flight — this test's blocked-until-
// release assertion goes RED.
func TestReassertProxyARPOnce_SerializesWithCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// Commit 1: proxy-arp configured (responder present).
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

	var sawEntries int64 // set to 1 if the reconcile ever saw a proxy-arp entry
	var called int64
	reconciled := make(chan struct{}, 1)
	prevFn := proxyARPReconcileFn
	proxyARPReconcileFn = func(_ *Daemon, cfg *config.Config) {
		if cfg != nil && len(cfg.Security.NAT.ProxyARP) > 0 {
			atomic.StoreInt64(&sawEntries, 1)
		}
		atomic.AddInt64(&called, 1)
		reconciled <- struct{}{}
	}
	t.Cleanup(func() { proxyARPReconcileFn = prevFn })

	d := &Daemon{store: s, applySem: semaphore.NewWeighted(1)}

	// Simulate an in-flight commit: hold applySem, then promote a config with
	// proxy-arp REMOVED so ActiveConfig() no longer lists the responder.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	// Still in configure mode after commit 1; remove proxy-arp and re-commit.
	if err := s.Delete([]string{"security", "nat", "proxy-arp"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit 2: %v", err)
	}

	done := make(chan struct{})
	go func() { d.reassertProxyARPOnce(context.Background()); close(done) }()

	// The re-assert must be blocked on applySem — the reconcile has not run.
	select {
	case <-reconciled:
		d.applySem.Release(1)
		t.Fatal("re-assert reconciled while the commit held applySem (#4001 race open)")
	case <-time.After(100 * time.Millisecond):
	}

	// Release the "commit" lock; the re-assert now proceeds against the
	// POST-commit ActiveConfig (proxy-arp removed).
	d.applySem.Release(1)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("re-assert did not run after applySem was released")
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("reconcile fn called %d times, want 1", atomic.LoadInt64(&called))
	}
	if atomic.LoadInt64(&sawEntries) != 0 {
		t.Fatal("re-assert reconciled a config that still listed the removed proxy-arp " +
			"responder — it read a stale pre-commit snapshot (#4001)")
	}
}
