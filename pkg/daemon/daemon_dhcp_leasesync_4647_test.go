package daemon

import (
	"context"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// TestEnsureDHCPLeaseSyncLoop_KnobToggle is the #4647 BUG-B regression: a
// runtime `dhcp-lease-synchronization` toggle must (re)launch or stop the
// lease-sync push loop WITHOUT a daemon restart, and must be idempotent (no
// double-launch). Before the fix the loop was launched only from the
// connect-time block, so ensureDHCPLeaseSyncLoop did not exist and a knob-ON
// commit was a silent no-op.
func TestEnsureDHCPLeaseSyncLoop_KnobToggle(t *testing.T) {
	d := newTestDaemon()
	d.dhcpServer = &dhcpserver.Manager{}
	d.sessionSync = &cluster.SessionSync{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.clusterCommsCtx = ctx

	if d.dhcpLeaseSync.loopCancel != nil {
		t.Fatal("precondition: lease-sync loop must not be running")
	}

	// Knob ON (the apply-path reconcile) → loop launched without a restart.
	d.ensureDHCPLeaseSyncLoop(true)
	if d.dhcpLeaseSync.loopCancel == nil {
		t.Fatal("knob-ON toggle must (re)launch the lease-sync loop; loopCancel is nil (BUG-B RED)")
	}
	first := d.dhcpLeaseSync.loopCancel

	// Idempotent: a second ON toggle must NOT replace the running loop.
	d.ensureDHCPLeaseSyncLoop(true)
	if reflect.ValueOf(d.dhcpLeaseSync.loopCancel).Pointer() != reflect.ValueOf(first).Pointer() {
		t.Fatal("double-launch: second ON toggle replaced the running loop's cancel handle")
	}

	// Knob OFF → loop stopped, handle cleared.
	d.ensureDHCPLeaseSyncLoop(false)
	if d.dhcpLeaseSync.loopCancel != nil {
		t.Fatal("knob-OFF toggle must stop the loop; loopCancel still set")
	}
}

// TestEnsureDHCPLeaseSyncLoop_CommsDownNoLaunch verifies the loop is NOT started
// when cluster comms are not yet up (clusterCommsCtx nil) — that case is owned
// by the connect-time launch, so a premature apply-path call must be a no-op
// rather than leaking a loop bound to a nil/daemon context.
func TestEnsureDHCPLeaseSyncLoop_CommsDownNoLaunch(t *testing.T) {
	d := newTestDaemon()
	d.dhcpServer = &dhcpserver.Manager{}
	d.sessionSync = &cluster.SessionSync{}
	// clusterCommsCtx deliberately left nil (comms not established).

	d.ensureDHCPLeaseSyncLoop(true)
	if d.dhcpLeaseSync.loopCancel != nil {
		t.Fatal("ON toggle with comms down must not launch the loop (connect-time owns it)")
	}
}
