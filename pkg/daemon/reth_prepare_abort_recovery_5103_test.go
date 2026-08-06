package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #5103 F4: aborting the link cycle on a failed worker join must not also abort
// the RECOVERY.
//
// PrepareLinkCycle is not a pure query. Before it can fail on stop_workers it
// has already disabled ctrl (and cleared every binding row if that disable could
// not be verified), so the abort leaves the dataplane half torn down. Nothing
// downstream re-arms it: the post-cycle rebind is gated on linkCycled (false —
// the cycle was aborted) and reapplyAfterDeferredMAC is gated on rethMACPending,
// which is computed BEFORE networkd.Apply and is false for a member that this
// same apply renamed into existence. Before the ordering fix the identical
// triple self-healed for the wrong reason — the cycle ran regardless, so
// linkCycled was true and NotifyLinkCycle rebound the sockets.
//
// The state these tests observe is that intermediate one: live set rejected,
// join failed, cycle aborted. A fixture that lets the MAC program complete
// cannot distinguish the fix, because then the ordinary post-cycle rebind runs
// and the rollback is indistinguishable from it.

// abortRecoveryLinkController counts both halves of the link-cycle protocol so a
// test can tell a rollback rebind from no rebind at all.
type abortRecoveryLinkController struct {
	prepareErr   error
	prepareCalls int
	notifyCalls  int
}

func (c *abortRecoveryLinkController) SetDeferWorkers(bool) {}

func (c *abortRecoveryLinkController) PrepareLinkCycle() error {
	c.prepareCalls++
	return c.prepareErr
}

func (c *abortRecoveryLinkController) NotifyLinkCycle() { c.notifyCalls++ }

// abortRecoveryTestDP is a RuntimeDataPlane whose only interesting surface is
// the link controller. It reuses deferredMACReapplyTestDP for the rest of the
// interface (#5134) and overrides Link.
type abortRecoveryTestDP struct {
	deferredMACReapplyTestDP
	link *abortRecoveryLinkController
}

func (d *abortRecoveryTestDP) Link() dataplane.LinkController { return d.link }

func newAbortRecoveryDaemon(prepareErr error) (*Daemon, *abortRecoveryLinkController) {
	lc := &abortRecoveryLinkController{prepareErr: prepareErr}
	return &Daemon{dp: &abortRecoveryTestDP{link: lc}}, lc
}

// TestRethMACAbortRebindsAfterFailedJoin_5103 is the F4 guard. The live MAC set
// is rejected (so the hook fires) and the join then fails (so the cycle aborts).
// The prepare has already disabled ctrl at that point, so the daemon must send
// the inverse — "rebind", via NotifyLinkCycle — rather than leave the dataplane
// mid-teardown with no owner.
//
// RED-on-revert: drop the NotifyLinkCycle rollback from
// programRethMACWithWorkerJoin and this fails at "AF_XDP sockets were never
// rebound after the aborted link cycle".
func TestRethMACAbortRebindsAfterFailedJoin_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1 — the fixture must reach the hook, "+
			"otherwise this test proves nothing about the abort", lc.prepareCalls)
	}
	if linkCycled {
		t.Error("linkCycled must be false when the cycle was aborted")
	}
	if lc.notifyCalls != 1 {
		t.Errorf("NotifyLinkCycle calls = %d, want 1: the AF_XDP sockets were never rebound "+
			"after the aborted link cycle. PrepareLinkCycle had already disabled ctrl, and no "+
			"other path re-arms it — linkCycled is false so the post-cycle rebind is skipped, "+
			"and rethMACPending is false for a member renamed into existence by this apply. "+
			"Forwarding stays down on this node (#5103 F4)", lc.notifyCalls)
	}
	// The rollback must not have been bought by cycling the link anyway.
	for _, e := range events {
		if e == "link-down" || e == "link-up" || e == "set-mac-cycled" {
			t.Fatalf("the link was MUTATED after the join failed (%q in %v)", e, events)
		}
	}
	if commitErr == nil {
		t.Fatal("a failed worker join must reach the commit: the node's dataplane was left " +
			"mid-teardown, so reporting commit SUCCESS hides a forwarding outage")
	}
	if !errors.Is(commitErr, errRethPrepareLinkCycle) {
		t.Errorf("commit error must carry errRethPrepareLinkCycle so the caller can fail the "+
			"commit closed on this class alone; got %v", commitErr)
	}
	if !strings.Contains(commitErr.Error(), "stop_workers") {
		t.Errorf("commit error should name the underlying cause; got %v", commitErr)
	}
}

// TestRethMACNoRollbackWhenJoinSucceeds_5103 is the over-reach guard for the
// rollback. When the join succeeds the cycle proceeds and step 2.6b2 owns the
// post-cycle rebind; a rollback here would rebind twice — the spurious rebind
// the call site's own comment warns gets EBUSY on mlx5 zero-copy queues.
func TestRethMACNoRollbackWhenJoinSucceeds_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))
	d, lc := newAbortRecoveryDaemon(nil)

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103)

	if lc.prepareCalls != 1 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 1", lc.prepareCalls)
	}
	if !linkCycled {
		t.Error("a successful join must let the cycle proceed and report linkCycled=true")
	}
	if lc.notifyCalls != 0 {
		t.Errorf("NotifyLinkCycle calls = %d, want 0: the rollback must fire on the ABORT "+
			"only. The caller rebinds once for a cycle that actually happened; rebinding here "+
			"too makes it twice", lc.notifyCalls)
	}
	if commitErr != nil {
		t.Errorf("a completed MAC program must not fail the commit; got %v", commitErr)
	}
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up" {
		t.Errorf("sequence = %v", events)
	}
}

// TestRethMACNoJoinOrRollbackOnLiveSet_5103 is the over-reach guard for the hook
// itself on the path the cluster's own NICs take. An IFF_LIVE_ADDR_CHANGE driver
// needs no cycle, so neither half of the protocol may run: joining workers here
// is a forwarding outage on every RETH MAC apply.
func TestRethMACNoJoinOrRollbackOnLiveSet_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, false /* live set works */))
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103)

	if linkCycled || commitErr != nil {
		t.Errorf("live set: linkCycled=%v commitErr=%v, want false/nil", linkCycled, commitErr)
	}
	if lc.prepareCalls != 0 || lc.notifyCalls != 0 {
		t.Errorf("prepare=%d notify=%d, want 0/0 — no cycle means no worker join and nothing "+
			"to roll back", lc.prepareCalls, lc.notifyCalls)
	}
}

// TestRethMACOrdinaryFailureStaysWarnOnly_5103 is the over-reach guard for the
// COMMIT error. Failing a MAC set has always been warn-only, and widening that to
// every programRethMAC error would fail commits that have always succeeded — a
// behaviour change well outside #5103. Only the failed-join class is escalated.
//
// The fixture is an ordinary failure that cannot involve the hook: the member is
// gone by the time programRethMAC looks it up, which is exactly what happens when
// an interface is renamed or removed between the caller's LinkByName and this
// call.
func TestRethMACOrdinaryFailureStaysWarnOnly_5103(t *testing.T) {
	withRethOps(t, rethLinkOps{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		byName: func(string) (netlink.Link, error) {
			return nil, errors.New("Link not found")
		},
		byIndex:         func(int) (netlink.Link, error) { return nil, errors.New("Link not found") },
		setDown:         func(netlink.Link) error { return nil },
		setUp:           func(netlink.Link) error { return nil },
		setName:         func(netlink.Link, string) error { return nil },
		setHardwareAddr: func(netlink.Link, net.HardwareAddr) error { return nil },
	})
	d, lc := newAbortRecoveryDaemon(errors.New("stop_workers: helper did not respond"))

	linkCycled, commitErr := d.programRethMACWithWorkerJoin("ge-0-0-1", virtMAC5103)

	if linkCycled {
		t.Error("a lookup failure cannot have cycled the link")
	}
	if commitErr != nil {
		t.Errorf("an ordinary MAC-program failure must stay warn-only, not fail the commit; "+
			"got %v", commitErr)
	}
	if lc.prepareCalls != 0 || lc.notifyCalls != 0 {
		t.Errorf("prepare=%d notify=%d, want 0/0 — the failure never reached the cycle path",
			lc.prepareCalls, lc.notifyCalls)
	}
}
