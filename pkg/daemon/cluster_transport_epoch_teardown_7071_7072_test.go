package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// cluster_transport_epoch_teardown_7071_7072_test.go — #7071 and #7072.
//
// Two halves of one asymmetry. #6290 folded activeClusterTransport into the
// comms epoch on the PUBLISH side; these close the two things that were left:
// the publish's drop signal was discarded by its caller (#7071), and the field
// was not cleared on the TEARDOWN side (#7072).
//
// A NOTE ON FIXTURES, because the obvious one is vacuous. clusterTransportFromConfig
// builds the key from ControlInterface / PeerAddress / the fabric fields. A
// fixture that sets NONE of them produces the ZERO key, so a value assertion
// against it is zero-equals-zero and passes with the write deleted. Every case
// below sets `control-interface` and ONLY that: it yields a non-zero key while
// starting no goroutines, because the heartbeat is gated on control-interface
// AND peer-address, and the sync path falls back to fabric and finds it empty.

func transportTestDaemon7071(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.cluster = &cluster.Manager{}
	d.daemonCtx = context.Background()
	return d
}

func clusterCfgCtl7071(ctl string) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: ctl}
	return cfg
}

// --- #7072: the field is torn down with the rest of the epoch ---------------

// TestStopClusterCommsClearsActiveTransport_7072 is the state claim: after a
// teardown the field must not name the transport that was just torn down.
//
// The fixture publishes a NON-ZERO key first, which is the whole difficulty —
// against a zero-key fixture this assertion holds whether or not the clear
// exists.
func TestStopClusterCommsClearsActiveTransport_7072(t *testing.T) {
	d := transportTestDaemon7071(t)
	_, gen, _ := d.beginClusterCommsEpoch(context.Background())
	if !d.setActiveTransportIfCurrent(gen, clusterTransportFromConfig(clusterCfgCtl7071("em0"))) {
		t.Fatal("precondition: the publish must be accepted for the current epoch")
	}
	if got := d.activeTransport(); got.ControlInterface != "em0" {
		t.Fatalf("precondition: active transport is %q, want em0 — a zero-key fixture "+
			"would make the assertion below vacuous", got.ControlInterface)
	}

	d.stopClusterComms()

	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Fatalf("after stopClusterComms the active transport is still %+v. The field "+
			"documents itself as the transport used by the comms CURRENTLY RUNNING, and "+
			"nothing is running after a teardown, so a non-zero value is false (#7072)", got)
	}
}

// TestStopOnlyTeardownDoesNotResurrectComms_7072 binds the CONSEQUENCE, and it
// is the cell a future reader needs.
//
// Apply-tail step 20 restarts comms on `active != zero && new != active`. With
// the stale key left in place, a commit landing after a stop-only teardown with
// a CHANGED transport passed both halves and restarted comms that were torn down
// deliberately. The one stop-only site is the bootstrap rollback
// (relinquishClusterForBootstrap -> stopClusterComms, no start), which stops them
// precisely so the peer stops seeing a healthy node whose dataplane is about to
// be detached — so the restart re-creates the hybrid that rollback exists to
// prevent.
//
// Both transports are exercised because only one of them could ever reach the
// restart: with an UNCHANGED key the second half of the guard already blocked it,
// so a same-key-only fixture passes with the clear deleted.
func TestStopOnlyTeardownDoesNotResurrectComms_7072(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{"changed_transport", "em0", "em1"},
		{"unchanged_transport", "em0", "em0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := transportTestDaemon7071(t)
			restarts := 0
			d.startClusterCommsFn = func(context.Context) { restarts++ }

			_, gen, _ := d.beginClusterCommsEpoch(context.Background())
			if !d.setActiveTransportIfCurrent(gen, clusterTransportFromConfig(clusterCfgCtl7071(tc.before))) {
				t.Fatal("precondition: publish must be accepted")
			}
			// The stop-only path: bootstrap rollback tears comms down and returns.
			d.stopClusterComms()

			if err := d.applyTailReconciles(clusterCfgCtl7071(tc.after),
				nil, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
				t.Fatalf("apply tail: %v", err)
			}
			if restarts != 0 {
				t.Fatalf("step 20 restarted cluster comms %d time(s) after a stop-only "+
					"teardown. The rollback stopped them deliberately; restarting puts the "+
					"node back to heartbeating and session-syncing with a dataplane the "+
					"rollback is detaching (#7072)", restarts)
			}
		})
	}
}

// --- #7071: the drop signal is consumed -------------------------------------

// TestSupersededStartClusterCommsReleasesItsContext_7071 is the half that made
// this worth doing beyond matching the siblings.
//
// When an epoch is superseded by ANOTHER beginClusterCommsEpoch rather than by a
// stopClusterComms, its context is ORPHANED: the newer epoch has overwritten
// clusterCommsCancel with its own, so no later stopClusterComms can cancel this
// one. startHAWatchdogHeartbeat binds a 500ms ticker goroutine to that context,
// so continuing past the dropped publish leaves it running for the life of the
// daemon, writing for an epoch nobody owns.
//
// The assertion is that the superseded context ends up CANCELLED, which is what
// makes the leak impossible rather than merely unlikely.
func TestSupersededStartClusterCommsReleasesItsContext_7071(t *testing.T) {
	d := transportTestDaemon7071(t)

	// Epoch N, as startClusterComms opens it.
	ctxN, genN, cancelN := d.beginClusterCommsEpoch(context.Background())
	// Epoch N+1 supersedes it WITHOUT a stopClusterComms, so cancelN is now
	// unreachable through the field — the shape that orphans the context.
	if _, genNext, _ := d.beginClusterCommsEpoch(context.Background()); genNext <= genN {
		t.Fatalf("precondition: the second epoch must supersede the first (%d <= %d)",
			genNext, genN)
	}
	select {
	case <-ctxN.Done():
		t.Fatal("precondition: the superseded context must still be live here; if it is " +
			"already cancelled this test cannot tell a released context from an orphaned one")
	default:
	}

	// What startClusterComms now does on a dropped publish.
	if d.setActiveTransportIfCurrent(genN, clusterTransportFromConfig(clusterCfgCtl7071("em0"))) {
		t.Fatal("precondition: the publish for a superseded epoch must be dropped")
	}
	cancelN()

	select {
	case <-ctxN.Done():
	case <-time.After(time.Second):
		t.Fatal("the superseded epoch's context is still live. Nothing else can cancel it " +
			"— the newer epoch overwrote clusterCommsCancel — so any goroutine bound to it " +
			"runs for the life of the daemon (#7071)")
	}
}

// TestSupersededStartClusterCommsPublishesNothing_7071 pins the drop itself: a
// superseded epoch must not leave its transport key behind as the live one.
func TestSupersededStartClusterCommsPublishesNothing_7071(t *testing.T) {
	d := transportTestDaemon7071(t)
	_, genLive, _ := d.beginClusterCommsEpoch(context.Background())
	if !d.setActiveTransportIfCurrent(genLive, clusterTransportFromConfig(clusterCfgCtl7071("em0"))) {
		t.Fatal("precondition: publish must be accepted for the live epoch")
	}
	stale := genLive - 1
	if d.setActiveTransportIfCurrent(stale, clusterTransportFromConfig(clusterCfgCtl7071("em9"))) {
		t.Fatal("a superseded epoch's publish was accepted")
	}
	if got := d.activeTransport(); got.ControlInterface != "em0" {
		t.Fatalf("the superseded publish overwrote the live transport: %q, want em0", got.ControlInterface)
	}
}
