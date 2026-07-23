package vrrp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #6177 — close the RETH VIP-removal sub-ms two-owner residual left by #5640.
//
// #5640 (#6174) withheld the remote-failover applied-ack until the demotion was
// ACTUATED. On the RETH-VRRP path ResignRG only SIGNALS the resign (priority-0 +
// resignCh) synchronously; the actual VIP removal (becomeBackup → removeVIPs)
// runs async on the run-loop. Releasing the ack on resign-signaled alone left a
// sub-ms window where the peer promoted while this node still owned the VIPs.
//
// The fix adds a per-instance resign-completion barrier: armResignBarrier
// registers a waiter BEFORE triggerResign, and markVIPsRemoved closes it once the
// VIPs are PHYSICALLY gone (becomeBackup succeeded, or the #5482 stale-VIP
// reconcile finally cleared a failed removal). The daemon waits on the barrier
// before releasing the applied-ack. These tests drive the netlink seams so the
// removal path runs without a real interface.

// newResignBarrierInstance builds a MASTER instance that already owns its VIP set
// (vipsHeld=true, as a successful becomeMaster would leave it) whose VIP removal
// is governed by delFn. fam/rgID let the manager-level test build a RETH instance
// (Family=="") in the right redundancy group (VRID = 100 + rgID).
func newResignBarrierInstance(t *testing.T, name, fam string, rgID int, delFn func(*netlink.Addr) error) (*vrrpInstance, chan VRRPEvent) {
	t.Helper()
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           100 + rgID,
		Priority:          200,
		Family:            fam,
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: name}, eventCh, nil)
	vi.linkByNameFn = func(n string) (netlink.Link, error) { return fiveZeroEightTwoLink(n), nil }
	vi.addrAddFn = func(netlink.Link, *netlink.Addr) error { return nil }
	vi.addrDelFn = func(_ netlink.Link, a *netlink.Addr) error { return delFn(a) }
	// Simulate the post-promotion state: MASTER, owning the VIP set.
	vi.setState(StateMaster)
	vi.markVIPsHeld()
	t.Cleanup(func() {
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	})
	return vi, eventCh
}

func isBarrierClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func awaitBarrierClosed(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("%s: resign barrier never closed within %s", what, within)
	}
}

// TestResignBarrier_ClosesOnBecomeBackupRemoval_6177 is the primary fail-on-revert
// guard: a barrier armed while the instance still owns its VIPs must stay OPEN
// until becomeBackup has removed them, then close. This is the difference between
// "resign signaled" and "VIPs physically removed" that #6177 closes.
//
// RED on revert: deleting the `vi.markVIPsRemoved()` call from becomeBackup's
// clean-removal branch (so the barrier is never signaled) leaves the armed
// channel open forever — awaitBarrierClosed then fails.
func TestResignBarrier_ClosesOnBecomeBackupRemoval_6177(t *testing.T) {
	vi, _ := newResignBarrierInstance(t, "xpf-6177-a0", "inet", 1, func(*netlink.Addr) error {
		return nil // clean removal
	})

	ch := vi.armResignBarrier()
	if isBarrierClosed(ch) {
		t.Fatal("resign barrier closed while the instance still owns its VIPs — the ack " +
			"would release before the RETH VIPs were removed (the #6177 window)")
	}

	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()
	vi.becomeBackup(mdt, adv)

	awaitBarrierClosed(t, ch, time.Second, "clean becomeBackup removal")
	vi.resignBarrierMu.Lock()
	held := vi.vipsHeld
	vi.resignBarrierMu.Unlock()
	if held {
		t.Fatal("vipsHeld must be cleared once becomeBackup removed the VIPs")
	}
}

// TestResignBarrier_AlreadyBackupShortCircuits_6177 pins the fast path: an
// instance that does NOT own the VIP set (already BACKUP / never promoted) has
// already actuated its demotion, so armResignBarrier must return an already-closed
// channel — the caller must not wait for a becomeBackup that will never run
// (otherwise the daemon's actuation wait would hang until its timeout).
//
// RED on revert: dropping the `if !vi.vipsHeld { ...closed... }` short-circuit in
// armResignBarrier (always returning a fresh open channel) leaves this channel
// open — the assertion below then fails.
func TestResignBarrier_AlreadyBackupShortCircuits_6177(t *testing.T) {
	vi, _ := newResignBarrierInstance(t, "xpf-6177-b0", "inet", 1, func(*netlink.Addr) error {
		return nil
	})
	// Not an owner: BACKUP, VIPs already gone.
	vi.setState(StateBackup)
	vi.markVIPsRemoved()

	ch := vi.armResignBarrier()
	if !isBarrierClosed(ch) {
		t.Fatal("armResignBarrier must return an already-closed channel when the instance " +
			"does not own the VIP set — a non-owner has nothing to wait for")
	}
}

// TestResignBarrier_FailedRemovalKeepsBarrierOpen_6177 pins the safe-direction on
// a netlink removal FAILURE: becomeBackup must NOT close the barrier while a stale
// VIP is still on the wire — the barrier stays open so the peer HOLDS rather than
// promotes over a VIP this node still answers for.
//
// RED on revert: removing the `if removeErr == nil` guard around
// `vi.markVIPsRemoved()` in becomeBackup (closing the barrier unconditionally)
// closes it despite the removal failure — the assertion below then fails.
func TestResignBarrier_FailedRemovalKeepsBarrierOpen_6177(t *testing.T) {
	vi, _ := newResignBarrierInstance(t, "xpf-6177-c0", "inet", 1, func(*netlink.Addr) error {
		return errors.New("injected netlink AddrDel failure")
	})
	// Keep the async reconcile from racing the assertion: a long backoff means
	// the first reconcile attempt fires well after this synchronous check.
	vi.vipReconcileBackoff = time.Hour

	ch := vi.armResignBarrier()
	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()
	vi.becomeBackup(mdt, adv)

	if isBarrierClosed(ch) {
		t.Fatal("resign barrier closed despite the VIP removal FAILING — the ack would " +
			"release while a stale VIP is still on the wire (two-owner hazard)")
	}
	if got := vi.vipRemoveFailures.Load(); got != 1 {
		t.Fatalf("expected the removal failure to be surfaced (vipRemoveFailures=1), got %d", got)
	}
}

// TestResignBarrier_ReconcileClosesBarrier_6177 pins the deferred close: when
// becomeBackup's synchronous removal fails, the #5482 stale-VIP reconcile that
// finally clears the VIP must release the barrier — so the gate is a true "VIPs
// physically removed" signal even across a transient netlink failure.
//
// RED on revert: removing the `vi.markVIPsRemoved()` added to the reconcile
// success path in scheduleVIPRemoveReconcile leaves the barrier open forever —
// awaitBarrierClosed then fails.
func TestResignBarrier_ReconcileClosesBarrier_6177(t *testing.T) {
	var calls atomic.Int32
	vi, _ := newResignBarrierInstance(t, "xpf-6177-d0", "inet", 1, func(*netlink.Addr) error {
		// Fail the synchronous becomeBackup removal, succeed on the reconcile.
		if calls.Add(1) == 1 {
			return errors.New("injected transient netlink AddrDel failure")
		}
		return nil
	})
	vi.vipReconcileBackoff = 5 * time.Millisecond

	ch := vi.armResignBarrier()
	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()
	vi.becomeBackup(mdt, adv)

	if isBarrierClosed(ch) {
		t.Fatal("barrier must not close on the failed synchronous removal")
	}
	// The async reconcile succeeds on its next attempt and must release the barrier.
	awaitBarrierClosed(t, ch, 2*time.Second, "stale-VIP reconcile success")
}

// TestResignRGWait_ArmsBarriersAndTriggersResign_6177 pins the manager-level
// contract: ResignRGWait sets priority-0, signals resignCh, and returns one open
// barrier per RETH instance that still owns its VIPs — the barrier that the
// daemon waits on before releasing the applied-ack. Only the target RG's
// instances are affected.
//
// RED on revert: if resignRGInstances armed the barrier AFTER triggerResign (or
// not at all), the returned barrier would be missing/already-forgotten; if
// ResignRGWait returned no barriers the daemon would signal immediately — the
// gating assertion (barrier closes only after becomeBackup) then regresses.
func TestResignRGWait_ArmsBarriersAndTriggersResign_6177(t *testing.T) {
	m := NewManager()
	// RETH instances (Family=="") — vi1 in RG1 owns VIPs, vi2 in RG2 must be
	// untouched by a RG1 resign.
	vi1, _ := newResignBarrierInstance(t, "eth0", "", 1, func(*netlink.Addr) error { return nil })
	vi2, _ := newResignBarrierInstance(t, "eth1", "", 2, func(*netlink.Addr) error { return nil })
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi1,
		{iface: "eth1", groupID: 102}: vi2,
	}
	m.mu.Unlock()

	barriers := m.ResignRGWait(1)
	if len(barriers) != 1 {
		t.Fatalf("ResignRGWait(1) returned %d barriers, want 1 (only the RG1 instance)", len(barriers))
	}
	if len(vi1.resignCh) != 1 {
		t.Error("vi1 (RG1) should have been signaled to resign")
	}
	if len(vi2.resignCh) != 0 {
		t.Error("vi2 (RG2) must NOT be signaled by a RG1 resign")
	}
	vi1.mu.Lock()
	pri := vi1.cfg.Priority
	vi1.mu.Unlock()
	if pri != 0 {
		t.Errorf("ResignRGWait must set priority 0 synchronously, got %d", pri)
	}

	// The barrier gates on VIP removal: open now, closes only after becomeBackup.
	if isBarrierClosed(barriers[0]) {
		t.Fatal("barrier closed before the RETH VIPs were removed — the ack would release early")
	}
	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()
	vi1.becomeBackup(mdt, adv)
	awaitBarrierClosed(t, barriers[0], time.Second, "ResignRGWait barrier after becomeBackup")
}

// TestResignRGWait_NonOwnerBarrierAlreadyClosed_6177 pins that ResignRGWait does
// not hang for an instance that never owned the VIPs: a BACKUP RETH instance
// yields an already-closed barrier so the daemon releases the ack immediately for
// that RG (no false hold).
func TestResignRGWait_NonOwnerBarrierAlreadyClosed_6177(t *testing.T) {
	m := NewManager()
	vi, _ := newResignBarrierInstance(t, "eth0", "", 3, func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)
	vi.markVIPsRemoved() // not an owner
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{{iface: "eth0", groupID: 103}: vi}
	m.mu.Unlock()

	barriers := m.ResignRGWait(3)
	if len(barriers) != 1 {
		t.Fatalf("want 1 barrier, got %d", len(barriers))
	}
	if !isBarrierClosed(barriers[0]) {
		t.Fatal("a non-owner instance must yield an already-closed barrier so the ack is not held")
	}
}
