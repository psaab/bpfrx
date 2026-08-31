package vrrp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

// #7579: a rebooted higher-priority node intermittently claimed RG primacy from
// a healthy peer despite preempt=false, leaving a ~12.9s window in which both
// nodes held RG0 and had GARP'd for the same RETH VIPs.
//
// The promotion came through the masterDownTimer arm, which is UNGATED by
// preempt — correctly, because RFC 5798's preempt governs displacing a master
// you can HEAR, not filling an apparent vacancy. So the defect is not that a
// path ignores preempt; it is that the node believed no master existed while
// the peer was healthy and advertising.
//
// run() already extends the master-down timer at STARTUP for exactly this
// reason, and says so. That shield is one-shot: handleBackupRx drops the timer
// to the short interval on the first advert, so by sync-hold release —
// typically seconds later — it is spent. Release is the SECOND deafness window
// and is at least as predictable: it fires as bulk session sync completes, when
// a just-rebooted node is installing synced sessions and about to do VIP work.
//
// These cells bind the timer policy, which is a property of this state machine.
// They deliberately do NOT try to reproduce the race: at ~1-in-4 under load, a
// cluster run neither reliably observes it nor leaves a guard behind.

// TestStartupDeafnessShieldIsPinned7579 pins the PRE-EXISTING mitigation.
//
// Without it, a change to the release half is indistinguishable from having
// broken the startup half — both would show up only as "the suite is green".
func TestStartupDeafnessShieldIsPinned7579(t *testing.T) {
	noPreempt := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 1, Priority: 200, Preempt: false,
		AdvertiseInterval: 30,
	}}
	if got := noPreempt.initialMasterDownInterval(); got != deafMasterDownInterval {
		t.Fatalf("startup master-down interval with preempt=false = %v, want %v — the "+
			"original mitigation is gone, and a node whose AF_PACKET receiver is not "+
			"yet capturing promotes into a healthy peer", got, deafMasterDownInterval)
	}

	// The control: a preempting node must NOT get the extended interval, or
	// every ordinary failover is delayed by seconds.
	preempt := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 1, Priority: 200, Preempt: true,
		AdvertiseInterval: 30,
	}}
	short := preempt.masterDownInterval()
	if got := preempt.initialMasterDownInterval(); got != short {
		t.Fatalf("startup master-down interval with preempt=true = %v, want the normal "+
			"%v — extending it here delays every legitimate takeover", got, short)
	}
	// And the two must actually differ, or this cell proves nothing.
	if short >= deafMasterDownInterval {
		t.Fatalf("the normal interval %v is not shorter than the deaf interval %v; "+
			"the distinction this test is about does not exist", short, deafMasterDownInterval)
	}
}

// TestSyncHoldReleaseRearmsTheDeafInterval7579 is the DEFECT cell and the
// fail-on-revert guard.
//
// Before the fix the preemptNowCh case did nothing when the preempt gate
// declined, so the short (~97ms at a 30ms RETH interval) timer kept running
// through the release. Delete the re-arm and this goes RED.
func TestSyncHoldReleaseRearmsTheDeafInterval7579(t *testing.T) {
	vi := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 1, Priority: 200, Preempt: false,
		AdvertiseInterval: 30,
	}}
	d, rearm := vi.masterDownAfterSyncHoldRelease()
	if !rearm {
		t.Fatal("a sync-hold release that did NOT promote leaves the short master-down " +
			"timer running. The node is entering its second deafness window — bulk sync " +
			"has just completed and it is about to install sessions and add VIPs — and a " +
			"~97ms scheduling gap on the receiver promotes it into a healthy peer, " +
			"producing the #7579 dual-owner window")
	}
	if d != deafMasterDownInterval {
		t.Fatalf("re-armed interval = %v, want %v (the same interval the startup shield "+
			"uses; two different values here would drift)", d, deafMasterDownInterval)
	}
}

// TestPreemptingNodeIsNotDelayedByTheRearm7579 is the CONTROL, and it is the
// one a reviewer should look for.
//
// Without it, "re-arm at release" is indistinguishable from "always use the
// long interval", which is a real failover regression. A node that IS
// preempting — including the priority-255 address owner, for which getPreempt()
// is true irrespective of the no-preempt flag — must be left alone.
func TestPreemptingNodeIsNotDelayedByTheRearm7579(t *testing.T) {
	for _, tc := range []struct {
		name     string
		priority int
		preempt  bool
	}{
		{"preempt-enabled", 200, true},
		{"address-owner-despite-no-preempt", 255, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vi := &vrrpInstance{cfg: Instance{
				Interface: "ge-0-0-2", GroupID: 1,
				Priority: tc.priority, Preempt: tc.preempt,
				AdvertiseInterval: 30,
			}}
			if _, rearm := vi.masterDownAfterSyncHoldRelease(); rearm {
				t.Fatalf("a %s node had its master-down timer extended at sync-hold "+
					"release; it wants to preempt, and delaying it is a failover "+
					"regression", tc.name)
			}
		})
	}
}

// TestFirstAdvertReturnsToTheShortInterval7579 is what BOUNDS the cost of the
// re-arm, and it is the reason the fix is affordable.
//
// The extended interval applies only while nothing has been heard: the first
// peer advertisement resets the timer to the normal short interval, so a peer
// that is actually alive costs nothing. If handleBackupRx stopped doing that,
// the re-arm above would become a permanent 3s failover delay.
func TestFirstAdvertReturnsToTheShortInterval7579(t *testing.T) {
	vi := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 1, Priority: 100, Preempt: false,
		AdvertiseInterval: 30,
	}}
	// Arm the deaf interval, as a declined release does.
	mdt := time.NewTimer(deafMasterDownInterval)
	defer mdt.Stop()
	hold := time.NewTimer(time.Hour)
	defer hold.Stop()

	// A healthy peer advert at a HIGHER priority — accepted, stays BACKUP.
	vi.handleBackupRx(&VRRPPacket{VRID: 1, Priority: 200, MaxAdvertInt: 3}, mdt, hold)

	// The timer must now be the short interval. Measured by waiting slightly
	// longer than the short interval and much less than the deaf one: if the
	// deaf interval were still armed, nothing would fire.
	short := vi.masterDownInterval()
	if short >= deafMasterDownInterval {
		t.Fatalf("short interval %v is not shorter than deaf %v; cell asserts nothing",
			short, deafMasterDownInterval)
	}
	select {
	case <-mdt.C:
	case <-time.After(short + 500*time.Millisecond):
		t.Fatalf("the master-down timer did not fire within %v of an accepted peer "+
			"advert, so it is still on the extended interval. The #7579 re-arm would "+
			"then be a permanent failover delay rather than a bounded one", short)
	}
}

// TestSyncHoldReleasePathCallsTheRearm7579 is the WIRING cell.
//
// The cells above test two helpers. This one tests that the run loop's
// preemptNowCh case — the sync-hold release path — actually consults the
// release helper. Deleting that call restores the defect while every cell above
// stays green, because nothing they reach executes the run loop.
func TestSyncHoldReleasePathCallsTheRearm7579(t *testing.T) {
	const src = "instance.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var scanned, found bool
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name.Name != "stepBackup" {
			continue
		}
		scanned = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if se, ok := ce.Fun.(*ast.SelectorExpr); ok &&
				se.Sel.Name == "masterDownAfterSyncHoldRelease" {
				found = true
			}
			return true
		})
	}
	if !scanned {
		t.Fatalf("stepBackup not found in %s; this cell is scanning the wrong subject "+
			"and would pass over an empty set", src)
	}
	if !found {
		t.Fatal("stepBackup no longer calls masterDownAfterSyncHoldRelease, so a " +
			"sync-hold release that declines to promote leaves the short master-down " +
			"timer running — the #7579 defect, with the helper cells still green")
	}
}
