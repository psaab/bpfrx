package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// #6290: activeClusterTransport is written by startClusterComms and read by
// applyTailReconciles step 20. The issue filed it as "NOT a race today",
// reasoning that the boot startClusterComms completes before the gRPC/HTTP
// servers accept commits, so the write is visible before any reader runs.
//
// That accounts for the wrong readers. applyConfig's own doc lists its callers:
// DHCP callbacks, config-poll, dynamic feeds, event engine, in-process CLI
// commits, CLI auto-rollback, cluster sync recv — none of which are the gRPC or
// HTTP servers. The DHCP one is live before the write:
//
//	daemon_run_bringup.go  dhcp.New(..., d.onDHCPAddressChange, ...)  callback wired
//	daemon_run_bringup.go  boot d.applyConfig(cfg)
//	 -> daemon_apply_routing.go  reconcileDHCPClients(cfg)            client goroutines START
//	daemon_run.go          d.startClusterComms(ctx)                   the WRITE happens here
//
// A lease arriving in that window runs onDHCPAddressChange -> applyConfig ->
// applyConfigLocked -> applyTailReconciles step 20, which READS the field. That
// goroutine was created BEFORE the write, so goroutine creation orders them the
// wrong way and establishes no happens-before. applySem does not help: the
// reader takes it, the boot writer does not, and a semaphore only excludes
// participants that take it.
//
// So the race is real on master, and it is the mirror of #5113 on
// mgmtVRFInterfaces (written under applySem, read by this same callback without
// it), which daemon.go already calls "a real Go data race".
//
// This test drives BOTH sides through production symbols — startClusterComms
// for the write, activeTransport for the read — so it is the actual pair of
// accesses, not a test-local restatement of them. It asserts nothing itself:
// the assertion is the race detector, so it is only meaningful under -race.
//
// RED on revert: drop the two mutex guards, i.e. make
// setActiveTransportIfCurrent's body a bare `d.activeClusterTransport = k` and
// activeTransport's a bare `return d.activeClusterTransport` — master's exact
// shape — and `go test -race -run
// TestActiveClusterTransportIsMutexGuarded_6290 ./pkg/daemon/` reports a
// WARNING: DATA RACE naming both functions.
func TestActiveClusterTransportIsMutexGuarded_6290(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// A clustered active is the precondition for startClusterComms to get past
	// its `cfg.Chassis.Cluster == nil` early return and reach the write.
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		// #6611: an unkeyed chassis cluster is a hard reject at commit.
		"chassis cluster authentication-key test-cluster-psk-6290",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit clustered active: %v", err)
	}
	if active := store.ActiveConfig(); active == nil || active.Chassis.Cluster == nil {
		t.Fatal("precondition: active config must carry a cluster stanza")
	}

	// dp nil and no control/fabric endpoints, so startClusterComms takes the
	// write and then starts NO goroutines: the HA watchdog is gated on d.dp,
	// the heartbeat on ControlInterface+PeerAddress, and the sync constructor
	// on a resolvable sync endpoint. The write is the second statement of the
	// function and runs regardless.
	d := &Daemon{
		store: store,
		opts:  Options{NoDataplane: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.startClusterComms(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = d.activeTransport()
		}
	}()
	wg.Wait()
}

// TestSetActiveTransportDropsStaleEpoch is the deterministic half, mirroring
// TestStartClusterCommsPublishDropsStaleEpoch (#4958). The race detector is
// probabilistic and only runs under -race, so the epoch gate needs an assertion
// that does not depend on either.
//
// The same boot window that makes #6290 reachable admits two concurrent
// startClusterComms calls — the boot one and a DHCP-callback-driven restart
// from step 20. Both bump the epoch and both publish a transport key. Without
// the generation gate the loser of that ordering can land LAST, leaving
// activeClusterTransport describing a superseded epoch while clusterCommsGen
// names the live one; step 20 then compares the next commit against the wrong
// baseline and either skips a needed comms restart or performs a spurious one.
//
// RED on revert: delete the `gen != d.clusterCommsGen` check in
// setActiveTransportIfCurrent and the stale publish wins — independent of the
// race detector.
func TestSetActiveTransportDropsStaleEpoch(t *testing.T) {
	d := &Daemon{opts: Options{NoDataplane: true}}

	fresh := clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.0.2"}
	stale := clusterTransportKey{ControlInterface: "STALE", PeerAddress: "10.99.9.9"}

	// Open an epoch and publish under it: the live state.
	_, gen := d.beginClusterCommsEpoch(context.Background())
	if !d.setActiveTransportIfCurrent(gen, fresh) {
		t.Fatal("publish under the CURRENT epoch must be accepted")
	}
	if got := d.activeTransport(); got != fresh {
		t.Fatalf("current-epoch publish did not land: got %+v want %+v", got, fresh)
	}

	// A restart supersedes it. The prior epoch's publish must now be dropped.
	_, newGen := d.beginClusterCommsEpoch(context.Background())
	if newGen == gen {
		t.Fatal("precondition: beginClusterCommsEpoch must advance the generation")
	}
	if d.setActiveTransportIfCurrent(gen, stale) {
		t.Fatal("a SUPERSEDED epoch's transport publish must be dropped, not accepted")
	}
	if got := d.activeTransport(); got != fresh {
		t.Fatalf("stale publish clobbered the live epoch's transport: got %+v want %+v", got, fresh)
	}

	// The new epoch can still publish.
	if !d.setActiveTransportIfCurrent(newGen, stale) {
		t.Fatal("publish under the NEW current epoch must be accepted")
	}
	if got := d.activeTransport(); got != stale {
		t.Fatalf("new-epoch publish did not land: got %+v want %+v", got, stale)
	}
}
