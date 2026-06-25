package vrrp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #2528 — the VRRP advert source (localIP/localIPv6) was resolved once at
// openSocket() and never invalidated. When the interface's IPv4 or link-local
// IPv6 changed during operation (notably the RETH MAC reprogram cycle, which
// flushes all kernel addresses with a 30ms-1s window before networkd restores
// them), the instance kept sending from the stale source: the kernel silently
// rejects the send AND self-filtering misclassifies our own adverts as a
// peer's -> false master conflict / split-brain. The fix subscribes to netlink
// ADDRESS updates and re-resolves the source on any add/del affecting an
// interface a VRRP instance is bound to.
//
// These tests are the fail-on-revert gate: they assert the cached source is
// re-resolved to the NEW address after an address event and that the stale
// value is NOT retained. Reverting reresolveLocalAddrs to a no-op, or removing
// the addr-watcher wiring, leaves the stale source and fails them.

// errAddrSubscribeDisabled is injected by tests that never Stop the manager so
// runAddrWatcher returns immediately instead of leaking a goroutine. Also used
// by TestUpdateInstances_PreservesSyncHoldForExistingInstances in vrrp_test.go.
var errAddrSubscribeDisabled = errors.New("test: addr subscribe disabled")

// ipnetAddr builds a *net.IPNet host address (IP + mask) from a CIDR string.
// net.ParseCIDR returns the masked network address in the *IPNet, so we restore
// the host IP — matching what net.Interface.Addrs() yields per assigned
// address.
func ipnetAddr(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	n.IP = ip
	return n
}

// TestReresolveLocalAddrs_PicksUpChangedIPv4 is the core fail-on-revert: the
// cached IPv4 source is replaced when the interface address changes. Before the
// fix the cache was permanent; after, the addr-watcher's reresolveLocalAddrs
// adopts the new source (which sendPacket/self-filter then read via
// getLocalIP).
func TestReresolveLocalAddrs_PicksUpChangedIPv4(t *testing.T) {
	cur := []net.Addr{ipnetAddr(t, "172.16.50.8/24")}
	vi := newInstance(Instance{
		Interface: "reth0.50",
		GroupID:   1,
		Priority:  200,
	}, &net.Interface{Name: "reth0.50", Index: 42}, make(chan VRRPEvent, 16), nil)
	vi.addrsFn = func() ([]net.Addr, error) { return cur, nil }

	// Initial resolve (mirrors openSocket()).
	vi.reresolveLocalAddrs()
	if got := vi.getLocalIP(); got == nil || got.String() != "172.16.50.8" {
		t.Fatalf("initial localIP = %v, want 172.16.50.8", got)
	}

	// Interface address changes (e.g. post-MAC-reprogram re-add lands a
	// different/renumbered source). Without re-resolution the stale value
	// persists — demonstrate that, then prove the watcher path fixes it.
	cur = []net.Addr{ipnetAddr(t, "172.16.50.9/24")}
	if got := vi.getLocalIP(); got.String() != "172.16.50.8" {
		t.Fatalf("pre-reresolve localIP = %v, want the STALE 172.16.50.8 (cache is sticky)", got)
	}

	vi.reresolveLocalAddrs() // what the addr-watcher invokes on the event
	if got := vi.getLocalIP(); got == nil || got.String() != "172.16.50.9" {
		t.Fatalf("post-reresolve localIP = %v, want 172.16.50.9 (stale source must NOT be retained)", got)
	}
}

// TestReresolveLocalAddrs_IPv6PicksLinkLocal asserts the IPv6 re-resolve picks
// the LINK-LOCAL source (VRRP adverts use a fe80:: source), never a global
// IPv6, even when both are present.
func TestReresolveLocalAddrs_IPv6PicksLinkLocal(t *testing.T) {
	vi := newInstance(Instance{
		Interface:        "reth0.80",
		GroupID:          2,
		Priority:         200,
		VirtualAddresses: []string{"2001:559:8585:80::1/64"},
	}, &net.Interface{Name: "reth0.80", Index: 43}, make(chan VRRPEvent, 16), nil)
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			ipnetAddr(t, "2001:559:8585:80::8/64"), // global — must NOT be chosen
			ipnetAddr(t, "fe80::42/64"),            // link-local — the source
		}, nil
	}

	vi.reresolveLocalAddrs()
	got := vi.getLocalIPv6()
	if got == nil || !got.IsLinkLocalUnicast() {
		t.Fatalf("localIPv6 = %v, want a link-local (fe80::) source", got)
	}
	if got.String() != "fe80::42" {
		t.Fatalf("localIPv6 = %v, want fe80::42", got)
	}
}

// TestAddrWatcher_EventReresolvesBoundInstance drives the full manager path:
// inject the subscribeAddrs seam, deliver an AddrUpdate for the instance's
// ifindex, and assert the source is re-resolved. Fail-on-revert: removing the
// ensureAddrWatcherLocked wiring or the reresolveAddrFor body leaves the stale
// source and this test times out.
func TestAddrWatcher_EventReresolvesBoundInstance(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}

	cur := []net.Addr{ipnetAddr(t, "172.16.50.8/24")}
	vi := newInstance(Instance{Interface: "reth0.50", GroupID: 1, Priority: 200},
		&net.Interface{Name: "reth0.50", Index: 42}, m.eventCh, nil)
	vi.addrsFn = func() ([]net.Addr, error) { return cur, nil }
	vi.reresolveLocalAddrs() // seed the (soon-to-be-stale) source

	m.mu.Lock()
	m.instances[instanceKey{iface: "reth0.50", groupID: 1}] = vi
	m.ensureAddrWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	// Address renumbers, then the kernel emits the ADD event for our ifindex.
	cur = []net.Addr{ipnetAddr(t, "172.16.50.9/24")}
	ch <- netlink.AddrUpdate{
		LinkIndex:   42,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("172.16.50.9"), Mask: net.CIDRMask(24, 32)},
	}

	deadline := time.After(2 * time.Second)
	for {
		if got := vi.getLocalIP(); got != nil && got.String() == "172.16.50.9" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("localIP = %v, want 172.16.50.9 after addr event", vi.getLocalIP())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestAddrWatcher_IgnoresUnrelatedInterface asserts ifindex filtering: an
// address event for one interface re-resolves ONLY the instances bound to that
// ifindex, never an instance on a different interface. Two instances on
// distinct ifindexes; an event for the first must leave the second's cached
// source untouched.
func TestAddrWatcher_IgnoresUnrelatedInterface(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}

	curA := []net.Addr{ipnetAddr(t, "172.16.50.8/24")}
	viA := newInstance(Instance{Interface: "reth0.50", GroupID: 1, Priority: 200},
		&net.Interface{Name: "reth0.50", Index: 42}, m.eventCh, nil)
	viA.addrsFn = func() ([]net.Addr, error) { return curA, nil }
	viA.reresolveLocalAddrs()

	curB := []net.Addr{ipnetAddr(t, "10.0.61.1/24")}
	viB := newInstance(Instance{Interface: "reth1.0", GroupID: 2, Priority: 200},
		&net.Interface{Name: "reth1.0", Index: 99}, m.eventCh, nil)
	viB.addrsFn = func() ([]net.Addr, error) { return curB, nil }
	viB.reresolveLocalAddrs()

	m.mu.Lock()
	m.instances[instanceKey{iface: "reth0.50", groupID: 1}] = viA
	m.instances[instanceKey{iface: "reth1.0", groupID: 2}] = viB
	m.ensureAddrWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	// Renumber BOTH underlying address sets, but emit an event ONLY for viA's
	// ifindex (42). viA must adopt its new source; viB must NOT be re-resolved
	// (no event for ifindex 99), so it keeps its original source.
	curA = []net.Addr{ipnetAddr(t, "172.16.50.9/24")}
	curB = []net.Addr{ipnetAddr(t, "10.0.61.2/24")}
	ch <- netlink.AddrUpdate{
		LinkIndex:   42,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("172.16.50.9"), Mask: net.CIDRMask(24, 32)},
	}

	deadline := time.After(2 * time.Second)
	for {
		if got := viA.getLocalIP(); got != nil && got.String() == "172.16.50.9" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("viA localIP = %v, want 172.16.50.9", viA.getLocalIP())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// viA's event has been processed (single-consumer FIFO); viB never had an
	// event, so its source must be the ORIGINAL, not the renumbered 10.0.61.2.
	if got := viB.getLocalIP(); got == nil || got.String() != "10.0.61.1" {
		t.Fatalf("viB localIP = %v, want unchanged 10.0.61.1 (no event for its ifindex)", got)
	}
}

// TestAddrWatcher_RecreatedLinkNewIfindexSchedulesReconcile is the #2707
// fail-on-revert gate. A VLAN/GRE/WireGuard sub-interface is deleted and
// recreated, so the kernel assigns a NEW ifindex while the configured NAME is
// stable. An address event arrives on the NEW ifindex. The cached vi.iface.Index
// no longer matches, so the pre-#2707 cached-ifindex-only match dropped the
// event entirely and the instance waited up to ~2s for the reconcile to notice
// the drift. The fix resolves the event ifindex -> name, re-matches by the
// stable name, and triggers the immediate-reconcile lever (onEventDrop).
//
// Revert proof: with the old reresolveAddrFor (match only on cached ifindex),
// the ifindex-77 event matches nothing, onEventDrop never fires, and this test
// times out RED.
func TestAddrWatcher_RecreatedLinkNewIfindexSchedulesReconcile(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}
	// The recreated link's NEW ifindex (77) resolves back to the SAME name the
	// instance is configured with. This is the only syscall the watcher makes,
	// and only on a cached-ifindex miss.
	m.resolveLinkName = func(ifindex int) (string, error) {
		if ifindex == 77 {
			return "reth0.50", nil
		}
		return "", errors.New("test: no such ifindex")
	}
	reconciled := make(chan struct{}, 4)
	m.SetOnEventDrop(func() { reconciled <- struct{}{} })

	// Instance was built when the link had ifindex 42 (the pre-recreate value).
	cur := []net.Addr{ipnetAddr(t, "172.16.50.8/24")}
	vi := newInstance(Instance{Interface: "reth0.50", GroupID: 1, Priority: 200},
		&net.Interface{Name: "reth0.50", Index: 42}, m.eventCh, m.onEventDrop)
	vi.addrsFn = func() ([]net.Addr, error) { return cur, nil }
	vi.reresolveLocalAddrs()

	m.mu.Lock()
	m.instances[instanceKey{iface: "reth0.50", groupID: 1}] = vi
	m.ensureAddrWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	// Address comes up on the RECREATED link — new ifindex 77, same name.
	ch <- netlink.AddrUpdate{
		LinkIndex:   77,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("172.16.50.8"), Mask: net.CIDRMask(24, 32)},
	}

	select {
	case <-reconciled:
		// Immediate reconcile scheduled — the rebind happens event-driven, not
		// after the ~2s periodic reconcile.
	case <-time.After(2 * time.Second):
		t.Fatal("recreated-link addr event (new ifindex, same name) did not schedule a reconcile")
	}
}

// TestAddrWatcher_UnchangedIfindexUsesFastPath asserts the common case is
// unchanged: when the event ifindex still matches the cached vi.iface.Index the
// source is re-resolved IN PLACE (reresolveLocalAddrs) and NO reconcile is
// scheduled and NO link-name syscall is made. This guards the #2707 fix from
// regressing into a reconcile (or a syscall) on every routine address event.
func TestAddrWatcher_UnchangedIfindexUsesFastPath(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}
	var nameResolves int32
	m.resolveLinkName = func(ifindex int) (string, error) {
		atomic.AddInt32(&nameResolves, 1)
		return "reth0.50", nil
	}
	reconciled := make(chan struct{}, 4)
	m.SetOnEventDrop(func() { reconciled <- struct{}{} })

	cur := []net.Addr{ipnetAddr(t, "172.16.50.8/24")}
	vi := newInstance(Instance{Interface: "reth0.50", GroupID: 1, Priority: 200},
		&net.Interface{Name: "reth0.50", Index: 42}, m.eventCh, m.onEventDrop)
	vi.addrsFn = func() ([]net.Addr, error) { return cur, nil }
	vi.reresolveLocalAddrs()

	m.mu.Lock()
	m.instances[instanceKey{iface: "reth0.50", groupID: 1}] = vi
	m.ensureAddrWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	// Renumber + event on the SAME (cached) ifindex 42.
	cur = []net.Addr{ipnetAddr(t, "172.16.50.9/24")}
	ch <- netlink.AddrUpdate{
		LinkIndex:   42,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("172.16.50.9"), Mask: net.CIDRMask(24, 32)},
	}

	// Fast path re-resolves in place.
	deadline := time.After(2 * time.Second)
	for {
		if got := vi.getLocalIP(); got != nil && got.String() == "172.16.50.9" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("localIP = %v, want 172.16.50.9 (fast-path reresolve)", vi.getLocalIP())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// No reconcile and no link-name syscall on the fast path.
	select {
	case <-reconciled:
		t.Fatal("unchanged-ifindex event must NOT schedule a reconcile")
	case <-time.After(150 * time.Millisecond):
	}
	if n := atomic.LoadInt32(&nameResolves); n != 0 {
		t.Fatalf("resolveLinkName called %d times on the fast path, want 0 (no syscall on a cached-ifindex hit)", n)
	}
}

// TestAddrWatcher_LateAppearingInterfaceSchedulesReconcile is the #2788
// fail-on-revert gate. An instance is CONFIGURED (in the desired set, recorded
// via m.desiredIfaces) but its interface did not exist at the last
// UpdateInstances, so resolveIface failed and no instance was built — there is
// no entry in m.instances for it. The interface is later created and addressed,
// emitting an AddrUpdate on its fresh ifindex. The cached-ifindex match loop
// finds nothing (no instance), and the name-drift loop finds nothing (no
// instance bound to the name), so before the fix the event was dropped and the
// instance waited up to ~2s for the periodic reconcile. The fix recognises the
// resolved name as a desired-but-unbuilt interface and schedules an immediate
// reconcile.
//
// Revert proof: drop the m.desiredIfaces late-appearing branch (or stop
// populating m.desiredIfaces) and the event matches nothing, onEventDrop never
// fires, and this test times out RED.
func TestAddrWatcher_LateAppearingInterfaceSchedulesReconcile(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}
	// The freshly-created interface's ifindex (88) resolves to the configured
	// name. No instance is bound to it yet.
	m.resolveLinkName = func(ifindex int) (string, error) {
		if ifindex == 88 {
			return "reth0.50", nil
		}
		return "", errors.New("test: no such ifindex")
	}
	reconciled := make(chan struct{}, 4)
	m.SetOnEventDrop(func() { reconciled <- struct{}{} })

	// The interface is CONFIGURED (desired) but absent: resolveIface fails so
	// UpdateInstances builds no instance. Drive UpdateInstances so it records
	// the desired name in m.desiredIfaces (and starts the watcher).
	m.resolveIface = func(name string) (*net.Interface, error) {
		return nil, errors.New("test: interface not present yet")
	}
	desired := []*Instance{{Interface: "reth0.50", GroupID: 1, Priority: 200}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}
	m.mu.RLock()
	_, recorded := m.desiredIfaces["reth0.50"]
	_, built := m.instances[instanceKey{iface: "reth0.50", groupID: 1}]
	m.mu.RUnlock()
	if !recorded {
		t.Fatal("desiredIfaces must record the configured interface name")
	}
	if built {
		t.Fatal("no instance should be built when the interface is absent")
	}

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	// The interface is created and addressed — AddrUpdate on its new ifindex.
	ch <- netlink.AddrUpdate{
		LinkIndex:   88,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("172.16.50.8"), Mask: net.CIDRMask(24, 32)},
	}

	select {
	case <-reconciled:
		// Immediate reconcile scheduled — the build happens event-driven, not
		// after the ~2s periodic reconcile.
	case <-time.After(2 * time.Second):
		t.Fatal("late-appearing configured-interface addr event did not schedule a reconcile")
	}
}

// TestAddrWatcher_UnconfiguredInterfaceNoReconcile asserts the late-appearing
// branch does NOT fire for an interface that is not in the desired set: an
// address event for some unrelated netdev (not a VRRP interface) must be
// ignored, never triggering a spurious reconcile. Guards the #2788 fix from
// over-firing on every address event in the system.
func TestAddrWatcher_UnconfiguredInterfaceNoReconcile(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)

	updates := make(chan chan<- netlink.AddrUpdate, 1)
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}
	m.resolveLinkName = func(ifindex int) (string, error) {
		return "eth-unrelated0", nil // not a configured VRRP interface
	}
	reconciled := make(chan struct{}, 4)
	m.SetOnEventDrop(func() { reconciled <- struct{}{} })

	m.resolveIface = func(name string) (*net.Interface, error) {
		return nil, errors.New("test: absent")
	}
	// Only reth0.50 is desired; the event below is for eth-unrelated0.
	if err := m.UpdateInstances([]*Instance{{Interface: "reth0.50", GroupID: 1, Priority: 200}}); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	var ch chan<- netlink.AddrUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("addr watcher never subscribed")
	}

	ch <- netlink.AddrUpdate{
		LinkIndex:   55,
		NewAddr:     true,
		LinkAddress: net.IPNet{IP: net.ParseIP("10.1.1.1"), Mask: net.CIDRMask(24, 32)},
	}

	select {
	case <-reconciled:
		t.Fatal("address event for an unconfigured interface must NOT schedule a reconcile")
	case <-time.After(200 * time.Millisecond):
		// Correct: no reconcile.
	}
}

// TestUpdateInstances_StartsAddrWatcher asserts UpdateInstances lazily starts
// the singleton address watcher for ANY instance (not gated on
// TrackInterface), and that repeated churn never spawns a second goroutine.
func TestUpdateInstances_StartsAddrWatcher(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error { return nil }
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }
	// Resolve fails (interface absent) so no socket is opened, but the watcher
	// still latches from the desired loop.
	desired := []*Instance{{Interface: "no-such-iface-xyz0", GroupID: 101, Priority: 200}}
	for i := 0; i < 3; i++ {
		if err := m.UpdateInstances(desired); err != nil {
			t.Fatalf("UpdateInstances pass %d: %v", i, err)
		}
	}
	m.mu.RLock()
	starts := m.addrWatcherStarts
	running := m.addrWatcherRunning
	m.mu.RUnlock()
	if starts != 1 {
		t.Errorf("addrWatcherStarts = %d, want 1 (singleton)", starts)
	}
	if !running {
		t.Error("addrWatcherRunning should be latched")
	}
}
