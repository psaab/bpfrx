package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #1387 inc-2 daemon-level tests: the node-level HA gate (plan §4.3) and the
// reconcile loop's gate enforcement. The gate is the single decision for
// "should this node publish DDNS now": OPEN when standalone, or MASTER for
// >=1 RG in cluster mode; CLOSED (BACKUP for all RGs) means STOP WRITING —
// never withdraw (plan risk R3).

// recordingUpdater records every upsert/delete the manager drives.
type recordingUpdater struct {
	mu      sync.Mutex
	upserts []dhcpserver.LeaseDNSRecord
	deletes []dhcpserver.LeaseDNSRecord
}

func (r *recordingUpdater) UpsertLease(_ context.Context, rec dhcpserver.LeaseDNSRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upserts = append(r.upserts, rec)
	return nil
}

func (r *recordingUpdater) DeleteLease(_ context.Context, rec dhcpserver.LeaseDNSRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deletes = append(r.deletes, rec)
	return nil
}

func (r *recordingUpdater) counts() (up, del int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.upserts), len(r.deletes)
}

// ddnsTestDaemon builds a daemon with a real store committing the given
// DDNS config, plus a DDNS manager whose live backend is replaced by the
// recording updater (resolve-per-Reconcile factory returns it when enabled).
func ddnsTestDaemon(t *testing.T, up *recordingUpdater) (*Daemon, *config.DHCPServerConfig) {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// A minimal config with DDNS enabled + a DHCP server group.
	if _, err := s.LoadSet(
		"set system services dhcp-local-server group g1 interface ge-0/0/1.0\n" +
			"set system services dhcp-local-server dynamic-dns enable\n" +
			"set system services dhcp-local-server dynamic-dns domain example.com\n" +
			"set system services dhcp-local-server dynamic-dns backend rfc2136\n" +
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	mgr := dhcpserver.NewDDNSManagerForTesting(
		dhcpserver.DNSUpdater(up),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
		func(c *config.DHCPDynamicDNSConfig) (dhcpserver.DNSUpdater, error) {
			// Resolve to the recording updater whenever the policy would
			// otherwise build a live backend (enabled rfc2136 + update-server).
			if c == nil || c.UpdateServer == "" {
				return up, nil
			}
			return up, nil
		},
	)
	d := &Daemon{
		store:              s,
		applySem:           semaphore.NewWeighted(1),
		rgStates:           make(map[int]*rgStateMachine),
		ddns:               mgr,
		ddnsReconcileNowCh: make(chan struct{}, 1),
	}
	cfg := s.ActiveConfig()
	return d, &cfg.System.DHCPServer
}

func writeLeaseFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDDNSWriterGateStandaloneAlwaysOpen(t *testing.T) {
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	// No cluster manager → standalone → gate always open.
	if !d.ddnsWriterGateOpen() {
		t.Fatal("standalone node must always be the DDNS writer (gate open)")
	}
}

func TestDDNSWriterGateClusterMasterForOneRGOpen(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	// RG 1 BACKUP, RG 2 MASTER → MASTER for >=1 RG → gate open.
	d.getOrCreateRGState(1).SetCluster(false)
	d.getOrCreateRGState(2).SetCluster(true)
	if !d.ddnsWriterGateOpen() {
		t.Fatal("a node MASTER for >=1 RG must have the DDNS gate OPEN")
	}
}

func TestDDNSWriterGateClusterBackupForAllClosed(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	d.getOrCreateRGState(1).SetCluster(false)
	d.getOrCreateRGState(2).SetCluster(false)
	if d.ddnsWriterGateOpen() {
		t.Fatal("a node BACKUP for ALL RGs must have the DDNS gate CLOSED")
	}
}

func TestReconcileDDNSOnceMasterPublishes(t *testing.T) {
	up := &recordingUpdater{}
	d, _ := ddnsTestDaemon(t, up)
	d.cluster = cluster.NewManager(0, 1)
	d.getOrCreateRGState(1).SetCluster(true) // MASTER → gate open

	p4, p6 := d.ddns.DDNSLeasePaths()
	writeLeaseFile(t, p4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n"+
		"10.0.1.5,aa,,3600,1900000000,1,laptop,0\n")
	writeLeaseFile(t, p6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")

	d.reconcileDDNSOnce(context.Background())
	upN, delN := up.counts()
	if upN == 0 {
		t.Errorf("MASTER node must publish: upserts = %d, want >0", upN)
	}
	if delN != 0 {
		t.Errorf("a fresh MASTER reconcile must not delete: deletes = %d", delN)
	}
}

func TestReconcileDDNSOnceBackupDoesNothing(t *testing.T) {
	up := &recordingUpdater{}
	d, _ := ddnsTestDaemon(t, up)
	d.cluster = cluster.NewManager(0, 1)
	d.getOrCreateRGState(1).SetCluster(false) // BACKUP for all → gate closed

	p4, p6 := d.ddns.DDNSLeasePaths()
	// Even with active leases in the memfile, a BACKUP node must NOT write.
	writeLeaseFile(t, p4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n"+
		"10.0.1.5,aa,,3600,1900000000,1,laptop,0\n")
	writeLeaseFile(t, p6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")

	d.reconcileDDNSOnce(context.Background())
	upN, delN := up.counts()
	if upN != 0 || delN != 0 {
		t.Errorf("BACKUP-for-all node must issue ZERO ops (stop-writing, not withdraw): upserts=%d deletes=%d", upN, delN)
	}
}

func TestReconcileDDNSOnceEarlyNudgeZeroDeletes(t *testing.T) {
	// Async-takeover ordering (plan §4.3 M-r2-2): a nudge fired before Kea
	// repopulates the memfile sees NO leases and must issue ZERO deletes
	// (it only ADDs on a later cycle once the store/leases catch up).
	up := &recordingUpdater{}
	d, _ := ddnsTestDaemon(t, up)
	d.cluster = cluster.NewManager(0, 1)
	d.getOrCreateRGState(1).SetCluster(true) // MASTER → gate open

	p4, p6 := d.ddns.DDNSLeasePaths()
	// Empty memfiles (Kea has not repopulated yet).
	writeLeaseFile(t, p4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	writeLeaseFile(t, p6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")

	d.reconcileDDNSOnce(context.Background())
	upN, delN := up.counts()
	if delN != 0 {
		t.Errorf("early-nudge against an empty memfile must issue ZERO deletes, got %d", delN)
	}
	if upN != 0 {
		t.Errorf("no leases yet → no upserts, got %d", upN)
	}
}

func TestNudgeDDNSReconcileCoalesces(t *testing.T) {
	d := &Daemon{ddnsReconcileNowCh: make(chan struct{}, 1)}
	// Multiple nudges coalesce into one pending wakeup (non-blocking depth-1).
	d.nudgeDDNSReconcile()
	d.nudgeDDNSReconcile()
	d.nudgeDDNSReconcile()
	select {
	case <-d.ddnsReconcileNowCh:
	default:
		t.Fatal("expected one pending nudge")
	}
	select {
	case <-d.ddnsReconcileNowCh:
		t.Fatal("nudges must coalesce — only one pending wakeup")
	default:
	}
}

func TestDDNSStatsNilWhenNoManager(t *testing.T) {
	d := &Daemon{}
	if d.DDNSStats() != nil {
		t.Error("DDNSStats() must be nil when the manager is absent")
	}
	if d.OwnedDDNSRecords() != nil {
		t.Error("OwnedDDNSRecords() must be nil when the manager is absent")
	}
}
