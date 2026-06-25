package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #2456: the DHCP-relay master-state gate. On a shared client segment both the
// cluster MASTER and the BACKUP node receive the client broadcast; only the
// MASTER for the relay interface's redundancy group may forward it upstream.
// These tests cover the daemon-side gate (relayMasterGateOpen) and its
// interface→RG resolver (relayInterfaceRG).

func TestRelayInterfaceRG(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0":    {Name: "reth0", RedundancyGroup: 1},
		"reth1":    {Name: "reth1", RedundancyGroup: 2},
		"ge-0/0/3": {Name: "ge-0/0/3", RedundancyGroup: 0}, // non-HA
	}
	cases := []struct {
		iface string
		want  int
	}{
		{"reth0.0", 1},    // unit suffix stripped → base reth0 → RG 1
		{"reth0", 1},      // bare base name
		{"reth1.5", 2},    // VLAN unit
		{"ge-0/0/3.0", 0}, // non-RG interface
		{"unknown.0", 0},  // not in config
	}
	for _, tc := range cases {
		if got := relayInterfaceRG(cfg, tc.iface); got != tc.want {
			t.Errorf("relayInterfaceRG(%q) = %d, want %d", tc.iface, got, tc.want)
		}
	}
	// nil config and nil interface table are both safe (→ 0).
	if got := relayInterfaceRG(nil, "reth0.0"); got != 0 {
		t.Errorf("relayInterfaceRG(nil,...) = %d, want 0", got)
	}
}

// TestRelayMasterGateStandaloneAlwaysRelays: no cluster manager → standalone →
// gate always open (relay every request), without touching the store.
func TestRelayMasterGateStandaloneAlwaysRelays(t *testing.T) {
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	if !d.relayMasterGateOpen("reth0.0") {
		t.Fatal("standalone node must always relay (gate open)")
	}
}

// gateTestDaemon builds a cluster-mode Daemon whose active config maps reth0 to
// RG 1 and reth1 to RG 2, with a relay group on reth0.0. It is the substrate
// for the master/backup branch tests.
func gateTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces reth0 unit 0 family inet address 10.0.61.1/24\n" +
			"set interfaces reth1 redundant-ether-options redundancy-group 2\n" +
			"set interfaces ge-0/0/3 unit 0 family inet address 10.0.30.1/24\n" +
			"set forwarding-options dhcp-relay server-group sg 192.0.2.1\n" +
			"set forwarding-options dhcp-relay group g active-server-group sg\n" +
			"set forwarding-options dhcp-relay group g interface reth0.0\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{
		store:    s,
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
}

// TestRelayMasterGateMasterRelays: cluster MASTER for the relay interface's RG
// (reth0 → RG 1) → gate open.
func TestRelayMasterGateMasterRelays(t *testing.T) {
	d := gateTestDaemon(t)
	// All VRRP instances MASTER for RG 1 → rg active. isRethMasterState reads
	// AllVRRPMaster; with no per-instance entries SetCluster(true) drives
	// active via the cluster-primary path used by the other HA gates.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	if !d.relayMasterGateOpen("reth0.0") {
		t.Fatal("MASTER for the relay RG must relay (gate open)")
	}
}

// TestRelayMasterGateBackupDrops: cluster BACKUP for the relay interface's RG
// → gate closed (drop, do not duplicate-relay).
func TestRelayMasterGateBackupDrops(t *testing.T) {
	d := gateTestDaemon(t)
	d.getOrCreateRGState(1).SetVRRP("reth0", false) // BACKUP for RG 1
	if d.relayMasterGateOpen("reth0.0") {
		t.Fatal("BACKUP for the relay RG must NOT relay (gate closed)")
	}
}

// TestRelayMasterGateFailoverReevaluates: the gate is re-read live, so a node
// that transitions BACKUP→MASTER for the relay RG starts relaying with no
// restart (mirrors the established per-RG gate re-evaluation).
func TestRelayMasterGateFailoverReevaluates(t *testing.T) {
	d := gateTestDaemon(t)
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	if d.relayMasterGateOpen("reth0.0") {
		t.Fatal("pre-failover BACKUP must have gate closed")
	}
	// Failover: become MASTER for RG 1.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	if !d.relayMasterGateOpen("reth0.0") {
		t.Fatal("post-failover MASTER must have gate open (live re-eval, no restart)")
	}
}

// TestRelayMasterGateNonRGInterfaceRelays: a relay on a non-RG-owned interface
// (RG 0) is not a duplicate-relay hazard → always relays, even in cluster mode.
func TestRelayMasterGateNonRGInterfaceRelays(t *testing.T) {
	d := gateTestDaemon(t)
	// This node is BACKUP for RG 1, but ge-0/0/3 is not RG-owned.
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	if !d.relayMasterGateOpen("ge-0/0/3.0") {
		t.Fatal("non-RG-owned relay interface must always relay")
	}
}
