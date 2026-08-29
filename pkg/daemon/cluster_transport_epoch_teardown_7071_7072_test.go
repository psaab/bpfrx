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

// commitClusterCfg7071 commits a cluster config so startClusterComms gets past
// its `d.store.ActiveConfig()` guard.
func commitClusterCfg7071(t *testing.T, d *Daemon, ctl string) {
	t.Helper()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// The auth key is required at commit (the control channel fails open
	// without one) and is deliberately NOT part of clusterTransportKey (#5078),
	// so it does not disturb what this fixture measures.
	sets := "set chassis cluster control-interface " + ctl + "\n" +
		"set chassis cluster authentication-key a-real-cluster-psk-7071\n"
	if _, err := d.store.LoadSet(sets); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if cfg := d.store.ActiveConfig(); cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("precondition: startClusterComms early-returns without a committed " +
			"cluster config, so the drop path would be unreachable")
	}
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

// TestSupersededStartClusterCommsReleasesItsContext_7071 drives the REAL
// startClusterComms through its drop path.
//
// It has to, and that is the point. An earlier version of this cell opened two
// epochs by hand and cancelled one — and stayed GREEN with both the early return
// and the cancel deleted, because it was asserting a property of
// context.WithCancel at a site production never executes. The supersession must
// land BETWEEN beginClusterCommsEpoch and the publish, a window no external
// caller can hit, which is what afterEpochBeginForTest exists for.
//
// The assertion is that the epoch's context ends up CANCELLED. When the
// supersession comes from another beginClusterCommsEpoch rather than a
// stopClusterComms, the newer epoch has overwritten clusterCommsCancel with its
// own, so nothing else can ever cancel this one — and startHAWatchdogHeartbeat
// binds a 500ms ticker goroutine to it. Leaving it live leaks that goroutine for
// the life of the daemon.
func TestSupersededStartClusterCommsReleasesItsContext_7071(t *testing.T) {
	d := transportTestDaemon7071(t)
	// startClusterComms early-returns unless a cluster config is COMMITTED, so
	// the drop path is unreachable without one. control-interface only: a
	// non-zero transport key that still starts no heartbeat (needs peer-address
	// too) and no session sync (falls back to fabric, which is empty).
	commitClusterCfg7071(t, d, "em0")

	var epochCtx context.Context
	d.afterEpochBeginForTest = func(ctx context.Context, gen uint64) {
		epochCtx = ctx
		// Supersede WITHOUT a stopClusterComms: that is the shape that orphans
		// the context, because stopClusterComms would have cancelled it.
		d.beginClusterCommsEpoch(context.Background())
	}

	d.startClusterComms(context.Background())

	if epochCtx == nil {
		t.Fatal("startClusterComms never opened an epoch — it early-returned before " +
			"the drop path, so this cell measured nothing")
	}
	select {
	case <-epochCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the superseded epoch's context is still live after startClusterComms " +
			"returned. Nothing else can cancel it — the newer epoch overwrote " +
			"clusterCommsCancel — so any goroutine bound to it, including the " +
			"watchdog's 500ms ticker, runs for the life of the daemon (#7071)")
	}
	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Fatalf("the superseded epoch published its transport key anyway: %+v", got)
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
