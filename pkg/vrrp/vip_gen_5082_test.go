package vrrp

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
)

// #5082 — VRRP must not publish MASTER/advert/event before the required VIP set
// has actually actuated in the kernel, and ReconcileVIPs must not re-add VIPs
// (or force GARP) after a demotion raced it to BACKUP.
//
// Both tests inject the netlink seams (linkByNameFn/addrAddFn/addrDelFn) so the
// add/remove path is driven without a real interface. GARP is suppressed so the
// revert runs never perform real network I/O — garpEpoch (bumped immediately
// before the GARP send, on the success branch only) is the discriminator for
// "would have announced ownership".

func fiveZeroEightTwoLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// installFakeVIPNetlink wires the VIP netlink seams to a no-op SUCCESS path so a
// unit test that drives the state machine on a FAKE interface can still reach
// MASTER. becomeMaster is now fail-closed on VIP actuation (#5082): on an
// unresolvable interface (as used by the state-machine wiring tests) it would
// otherwise refuse to claim ownership and revert to BACKUP. State-machine tests
// (preempt gate / hold-time / owner-preempt) that don't exercise VIP actuation
// install this so the transition logic under test is isolated from netlink.
func installFakeVIPNetlink(vi *vrrpInstance) {
	vi.linkByNameFn = func(name string) (netlink.Link, error) {
		return fiveZeroEightTwoLink(name), nil
	}
	vi.addrAddFn = func(link netlink.Link, addr *netlink.Addr) error { return nil }
	vi.addrDelFn = func(link netlink.Link, addr *netlink.Addr) error { return nil }
}

// Test A (fail-closed publish): a transient netlink AddrAdd failure for a
// required VIP during becomeMaster must NOT publish ownership — no MASTER event,
// no advert, becomeMaster returns false and the instance reverts to BACKUP.
//
// Reverting the gate (advertise/emit regardless of the actuation result) turns
// this RED: becomeMaster returns true, emits a StateMaster event, and bumps
// garpEpoch.
func TestBecomeMaster_FailClosedOnVIPActuationFailure_5082(t *testing.T) {
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         "xpf-5082-a0",
		GroupID:           1,
		Priority:          100,
		Family:            "inet",
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: "xpf-5082-a0"}, eventCh, nil)
	vi.setState(StateBackup) // the state becomeMaster transitions FROM
	vi.suppressGARP.Store(true)

	// Interface resolves, but AddrAdd fails for the required VIP.
	vi.linkByNameFn = func(name string) (netlink.Link, error) {
		return fiveZeroEightTwoLink(name), nil
	}
	vi.addrAddFn = func(link netlink.Link, addr *netlink.Addr) error {
		return errors.New("injected netlink AddrAdd failure")
	}
	vi.addrDelFn = func(link netlink.Link, addr *netlink.Addr) error {
		return nil
	}

	owned := vi.becomeMaster()

	if owned {
		t.Fatal("becomeMaster returned true despite VIP actuation failure — " +
			"published an ownership it cannot back (fail-open)")
	}
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %v, want StateBackup after fail-closed becomeMaster", got)
	}
	if ep := vi.garpEpoch.Load(); ep != 0 {
		t.Fatalf("garpEpoch = %d, want 0 — GARP announced a VIP that never actuated", ep)
	}
	// No StateMaster event may have been published to the manager.
	for {
		select {
		case ev := <-eventCh:
			if ev.State == StateMaster {
				t.Fatal("emitted a StateMaster event despite VIP actuation " +
					"failure — peer/services trust a blackhole owner (fail-open)")
			}
		default:
			return
		}
	}
}

// Test B (reconcile race / generation guard): a demotion to BACKUP that races
// ReconcileVIPs between its state check and the netlink add must not leave the
// re-added VIPs in place or fire a forced GARP. The racing demotion is injected
// inside the addrAddFn (mimicking a concurrent becomeBackup whose setState bumps
// ownerGen while ReconcileVIPs holds vipMu). The generation revalidation after
// the add must roll back exactly the re-added VIPs and suppress GARP.
//
// Reverting the revalidation turns this RED: the re-added VIP is retained
// (deleted count < added count) and garpEpoch is bumped (forced GARP while
// BACKUP).
func TestReconcileVIPs_GenerationGuard_NoReaddWhileBackup_5082(t *testing.T) {
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         "xpf-5082-b0",
		GroupID:           1,
		Priority:          100,
		Family:            "inet",
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: "xpf-5082-b0"}, eventCh, nil)
	vi.setState(StateMaster) // reconcileVIP only acts while MASTER
	vi.suppressGARP.Store(true)

	vi.linkByNameFn = func(name string) (netlink.Link, error) {
		return fiveZeroEightTwoLink(name), nil
	}

	var mu sync.Mutex
	var added, deleted []string
	vi.addrAddFn = func(link netlink.Link, addr *netlink.Addr) error {
		mu.Lock()
		added = append(added, addr.String())
		mu.Unlock()
		// A superior advert transitions us to BACKUP mid-actuation. This is the
		// exact race the guard closes: setState bumps ownerGen (and flips state)
		// independently of vipMu, so the post-add revalidation observes it.
		vi.setState(StateBackup)
		return nil
	}
	vi.addrDelFn = func(link netlink.Link, addr *netlink.Addr) error {
		mu.Lock()
		deleted = append(deleted, addr.String())
		mu.Unlock()
		return nil
	}

	vi.reconcileVIP()

	mu.Lock()
	defer mu.Unlock()
	if len(added) == 0 {
		t.Fatal("addrAddFn never called — the test did not exercise the add path")
	}
	if len(deleted) != len(added) {
		t.Fatalf("rolled back %d of %d re-added VIPs — a BACKUP retains VIPs "+
			"re-added by a raced ReconcileVIPs (reconcile TOCTOU)",
			len(deleted), len(added))
	}
	if ep := vi.garpEpoch.Load(); ep != 0 {
		t.Fatalf("garpEpoch = %d, want 0 — forced GARP fired while BACKUP "+
			"(reconcile race announces a VIP we no longer own)", ep)
	}
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %v, want StateBackup", got)
	}
}
