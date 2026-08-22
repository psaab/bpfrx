package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6031 — the cold-prime bulk window is sourced from the userspace helper's
// TABLE-TRUTH export (export_owner_rg_sessions), not from the best-effort BPF
// display mirror pkg/cluster's BulkSync used to walk.

// errExportRefused models the helper refusing the export — control socket down,
// unsupported verb, protocol mismatch.
var errExportRefused = errors.New("helper refused export_owner_rg_sessions")

type failingUserspaceSessionExporter struct{ err error }

func (f *failingUserspaceSessionExporter) ExportOwnerRGSessions(_ []int, _ uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	return nil, dpuserspace.ProcessStatus{}, f.err
}

func bulkSnapshotConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}
	return cfg
}

func bulkSnapshotDaemon() *Daemon {
	return &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return true },
			IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
		},
	}
}

// TestBuildUserspaceBulkSnapshotCollectsTableTruth_6031 pins the core of the
// snapshot builder: the export's records become window entries, and a record
// for a redundancy group this node is NOT primary for is filtered out by the
// same per-session owner-RG rule the incremental stream applies — the accuracy
// the zone-level ShouldSyncZone approximation could not deliver.
func TestBuildUserspaceBulkSnapshotCollectsTableTruth_6031(t *testing.T) {
	mine := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 39906, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 1,
		EgressIfindex: 12, TXIfindex: 11, NeighborMAC: "aa:bb:cc:dd:ee:ff",
	}
	peers := mine
	peers.SrcPort = 39907
	peers.OwnerRGID = 2 // this node is primary for RG1 only
	v6 := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet6, Protocol: 6,
		SrcIP: "2001:559:8585:bf01::102", DstIP: "2001:559:8585:80::200",
		SrcPort: 40000, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 1,
		EgressIfindex: 12, TXIfindex: 11, NeighborMAC: "aa:bb:cc:dd:ee:ff",
	}

	exporter := &fakeUserspaceSessionExporter{deltas: []dpuserspace.SessionDeltaInfo{mine, peers, v6}}
	d := bulkSnapshotDaemon()

	snap, err := d.buildUserspaceBulkSnapshotWithConfig(exporter, bulkSnapshotConfig(), []int{1})
	if err != nil {
		t.Fatalf("buildUserspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if exporter.calls != 1 {
		t.Fatalf("export calls = %d, want exactly 1 per window", exporter.calls)
	}
	if got := len(snap.V4); got != 1 {
		t.Fatalf("snapshot V4 = %d entries, want 1 — a session owned by a redundancy group "+
			"this node is not primary for must not ride our authoritative window", got)
	}
	if got := len(snap.V6); got != 1 {
		t.Fatalf("snapshot V6 = %d entries, want 1", got)
	}
	if got := snap.Len(); got != 2 {
		t.Fatalf("snapshot Len() = %d, want 2", got)
	}
	if snap.V4[0].Value.IngressZone == 0 {
		t.Fatal("snapshot entry lost its ingress zone — the receiver's reconcile keys on it")
	}
}

// TestBuildUserspaceBulkSnapshotCarriesFabricWireAlias_6031 pins that the
// snapshot expands a fabric-redirected session into BOTH wire keys, exactly as
// the incremental path does. Dropping the alias would leave the peer's copy
// absent from the authoritative window on the very next bulk, so the peer would
// reconcile away a session it is actively forwarding for.
func TestBuildUserspaceBulkSnapshotCarriesFabricWireAlias_6031(t *testing.T) {
	exporter := &fakeUserspaceSessionExporter{deltas: []dpuserspace.SessionDeltaInfo{{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 39906, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 1,
		EgressIfindex: 12, TXIfindex: 11, TXVLANID: 80,
		NeighborMAC: "aa:bb:cc:dd:ee:ff", SrcMAC: "02:bf:72:00:50:08",
		NATSrcIP: "172.16.80.8", NATSrcPort: 39906,
		FabricRedirect: true,
	}}}
	d := bulkSnapshotDaemon()

	snap, err := d.buildUserspaceBulkSnapshotWithConfig(exporter, bulkSnapshotConfig(), []int{1})
	if err != nil {
		t.Fatalf("buildUserspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if got := len(snap.V4); got != 2 {
		t.Fatalf("snapshot V4 = %d entries, want 2 (session + #4090 forward wire alias)", got)
	}
	if snap.V4[0].Key == snap.V4[1].Key {
		t.Fatal("the forward wire alias must be a DISTINCT key from the session it aliases")
	}
}

// TestBuildUserspaceBulkSnapshotPropagatesExportError_6031 pins the error
// posture at the source: a failed export must surface as an error, never as an
// empty-but-successful snapshot. An empty snapshot is authoritative — it would
// tell the peer to reconcile away every session we own.
func TestBuildUserspaceBulkSnapshotPropagatesExportError_6031(t *testing.T) {
	d := bulkSnapshotDaemon()
	snap, err := d.buildUserspaceBulkSnapshotWithConfig(
		&failingUserspaceSessionExporter{err: errExportRefused}, bulkSnapshotConfig(), []int{1})
	if err == nil {
		t.Fatal("#6031: a FAILED table-truth export returned no error — an empty snapshot is " +
			"authoritative and would reconcile away every session this node owns")
	}
	if !errors.Is(err, errExportRefused) {
		t.Fatalf("error = %v, want it to carry the export failure", err)
	}
	if snap != nil {
		t.Fatalf("snapshot = %+v, want nil alongside the error", snap)
	}
}

// TestBuildUserspaceBulkSnapshotNoOwnedRGsIsEmptyNotNil_6031 pins the
// distinction the whole three-case source contract turns on. A node that is
// primary for NO redundancy group owns nothing to sync — that is an
// authoritative statement, and returning nil would instead be read as "no
// source available" and silently fall back to the mirror, re-pushing the peer's
// own imports back at it.
func TestBuildUserspaceBulkSnapshotNoOwnedRGsIsEmptyNotNil_6031(t *testing.T) {
	exporter := &fakeUserspaceSessionExporter{deltas: []dpuserspace.SessionDeltaInfo{{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 39906, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 1,
	}}}
	d := bulkSnapshotDaemon()

	snap, err := d.buildUserspaceBulkSnapshotWithConfig(exporter, bulkSnapshotConfig(), nil)
	if err != nil {
		t.Fatalf("buildUserspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if snap == nil {
		t.Fatal("#6031: a node primary for no redundancy group must return an EMPTY " +
			"authoritative snapshot, not nil — nil falls back to the display mirror")
	}
	if snap.Len() != 0 {
		t.Fatalf("snapshot Len() = %d, want 0", snap.Len())
	}
	if exporter.calls != 0 {
		t.Fatalf("export calls = %d, want 0 — there is nothing to export", exporter.calls)
	}
}

// TestUserspaceBulkSessionSnapshotFallsBackWhenNoRuntime_6031 pins the
// compatibility arm of the resolver: with no published runtime (or a runtime
// that is not the userspace exporter) there is no table-truth to consult, so it
// must report "no source" and leave the pre-#6031 store walk in place rather
// than sending an empty window that deletes live sessions.
func TestUserspaceBulkSessionSnapshotFallsBackWhenNoRuntime_6031(t *testing.T) {
	d := bulkSnapshotDaemon()
	snap, err := d.userspaceBulkSessionSnapshot()
	if err != nil {
		t.Fatalf("userspaceBulkSessionSnapshot() error = %v", err)
	}
	if snap != nil {
		t.Fatalf("snapshot = %+v, want nil (fall back to the session-store walk) with no runtime", snap)
	}
}

// TestBuildUserspaceBulkSnapshotSkipsNonOpenRecords_6031 pins that a
// close-shaped record in a live-table export is not framed as a live session.
func TestBuildUserspaceBulkSnapshotSkipsNonOpenRecords_6031(t *testing.T) {
	exporter := &fakeUserspaceSessionExporter{deltas: []dpuserspace.SessionDeltaInfo{{
		Event: "close", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 39906, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 1,
	}}}
	d := bulkSnapshotDaemon()

	snap, err := d.buildUserspaceBulkSnapshotWithConfig(exporter, bulkSnapshotConfig(), []int{1})
	if err != nil {
		t.Fatalf("buildUserspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if snap.Len() != 0 {
		t.Fatalf("snapshot Len() = %d, want 0 — a close record is not a live session", snap.Len())
	}
}

// bulkSourceWiringDP is a RuntimeDataPlane whose only live surface is the
// table-truth export, so the production-wired source can be invoked for real.
type bulkSourceWiringDP struct {
	dataplane.RuntimeDataPlane
	exporter *fakeUserspaceSessionExporter
}

func (d *bulkSourceWiringDP) ExportOwnerRGSessions(rgIDs []int, max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	return d.exporter.ExportOwnerRGSessions(rgIDs, max)
}

func (d *bulkSourceWiringDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceStrict }

// Sessions/Telemetry are reached by SessionSync.SetRuntime. Nil is the
// "no store wired" case the sync layer already guards for, which is what this
// test wants: the assertion is about the SOURCE, not the store walk.
func (d *bulkSourceWiringDP) Sessions() dataplane.SessionStore { return nil }

func (d *bulkSourceWiringDP) Telemetry() dataplane.Telemetry { return nil }

// TestStartClusterCommsWiresTableTruthBulkSource_6031 is the WIRING guard. The
// two halves of this change are independently useless: pkg/cluster consults
// SessionSync.BulkSessionSource, and pkg/daemon can build a table-truth
// snapshot — but the residual only closes if the production startup actually
// installs the one into the other. So this drives the real
// startClusterComms and then INVOKES the source it published, asserting the
// entry that comes back is the exported one. Asserting merely that the field is
// non-nil would pass with any function wired there.
//
// RED on revert: delete the `ss.BulkSessionSource = d.userspaceBulkSessionSnapshot`
// line from startClusterComms and the nil-source assertion fires; wire some
// other producer and the round-trip assertion fires.
func TestStartClusterCommsWiresTableTruthBulkSource_6031(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// A clustered active whose sync endpoint RESOLVES: lo carries 127.0.0.1/8,
	// which selectClusterBindAddr matches against the 127.0.0.2 peer, so the
	// sync constructor goroutine gets past its address retry loop and reaches
	// the callback wiring.
	//
	// The endpoint is the FABRIC transport, not control-link, deliberately:
	// startClusterComms only starts the heartbeat when control-interface AND
	// peer-address are both set, and cluster.Manager.StartHeartbeat /
	// StopHeartbeat race on the manager's heartbeat fields (heartbeat_manager.go
	// :116 vs :163) — a PRE-EXISTING race this test has no business exposing.
	// The sync constructor takes the fabric fall-back and reaches the same
	// wiring block. TestActiveClusterTransportIsMutexGuarded_6290 avoids the
	// same hazard the same way (it configures no sync endpoint at all).
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster fabric-interface lo",
		"chassis cluster fabric-peer-address 127.0.0.2",
		"chassis cluster redundancy-group 0 node 0 priority 200",
		"chassis cluster redundancy-group 0 node 1 priority 100",
		"chassis cluster authentication-key test-cluster-psk-6031",
		"security zones security-zone lan",
		"security zones security-zone wan",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	exported := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 39906, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", OwnerRGID: 0,
		EgressIfindex: 12, TXIfindex: 11, NeighborMAC: "aa:bb:cc:dd:ee:ff",
	}
	exporter := &fakeUserspaceSessionExporter{deltas: []dpuserspace.SessionDeltaInfo{exported}}

	d := &Daemon{
		store:    store,
		opts:     Options{NoDataplane: true},
		cluster:  newClusterManager(true),
		rgStates: make(map[int]*rgStateMachine),
	}
	// Publish the export-capable runtime BEFORE comms start: startClusterComms
	// only wires the ownership predicates (IsPrimaryFn / IsPrimaryForRGFn) when
	// a runtime is published, and the sync filter the snapshot builder applies
	// consults them.
	d.setDataplane(&bulkSourceWiringDP{exporter: exporter})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)
	t.Cleanup(d.stopClusterComms)

	var ss *cluster.SessionSync
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if ss = d.getSessionSync(); ss != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ss == nil {
		t.Fatal("setup: startClusterComms never published a SessionSync")
	}
	if ss.BulkSessionSource == nil {
		t.Fatal("#6031: startClusterComms published a SessionSync with NO BulkSessionSource — " +
			"the bulk window still comes from the best-effort BPF display mirror")
	}

	// Invoke the wired source: the snapshot must carry the EXPORTED session,
	// which identifies the wired function as the table-truth resolver rather
	// than any other producer that could have been assigned to the field.
	snap, err := ss.BulkSessionSource()
	if err != nil {
		t.Fatalf("wired BulkSessionSource() error = %v", err)
	}
	if snap == nil {
		t.Fatal("#6031: the wired source reported NO authoritative snapshot with an " +
			"export-capable runtime published — BulkSync would fall back to the mirror")
	}
	if exporter.calls != 1 {
		t.Fatalf("export_owner_rg_sessions calls = %d, want 1 — the wired source is not the "+
			"table-truth resolver", exporter.calls)
	}
	if got := snap.Len(); got != 1 {
		t.Fatalf("wired source snapshot Len() = %d, want 1 (the exported session)", got)
	}
}
