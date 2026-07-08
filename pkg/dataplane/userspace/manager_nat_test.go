package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestBuildSourceNATSnapshotsPopulatesPoolFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.AddressPersistent = true
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:          "pool-a",
			Addresses:     []string{"203.0.113.10/32", "203.0.113.11/32", "2001:db8:80::10/128"},
			PortLow:       40000,
			PortHigh:      40100,
			PersistentNAT: &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 900},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "snat-pool",
			Match: config.NATMatch{
				SourceAddresses:      []string{"10.0.0.0/8"},
				DestinationAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{
				Type:     config.NATSource,
				PoolName: "pool-a",
			},
		}},
	}}

	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0]
	if got.PoolName != "pool-a" || got.InterfaceMode || got.Off {
		t.Fatalf("snapshot action fields = %+v", got)
	}
	if !got.AddressPersistent {
		t.Fatalf("AddressPersistent = false, want true")
	}
	if got.PortLow != 40000 || got.PortHigh != 40100 {
		t.Fatalf("port range = %d-%d, want 40000-40100", got.PortLow, got.PortHigh)
	}
	if !got.PersistentNAT {
		t.Fatalf("PersistentNAT = false, want true")
	}
	if !got.PersistentNATPermitAnyRemoteHost {
		t.Fatalf("PersistentNATPermitAnyRemoteHost = false, want true")
	}
	if got.PersistentNATInactivityTimeout != 900 {
		t.Fatalf("PersistentNATInactivityTimeout = %d, want 900", got.PersistentNATInactivityTimeout)
	}
	if got.PersistentNATPermit != "any-remote-host" {
		t.Fatalf("PersistentNATPermit = %q, want any-remote-host", got.PersistentNATPermit)
	}
	wantAddrs := []string{"203.0.113.10/32", "203.0.113.11/32", "2001:db8:80::10/128"}
	if !reflect.DeepEqual(got.PoolAddresses, wantAddrs) {
		t.Fatalf("PoolAddresses = %#v, want %#v", got.PoolAddresses, wantAddrs)
	}
}

func TestBuildSourceNATSnapshotsMarksUnsafePoolModeRules(t *testing.T) {
	tests := []struct {
		name       string
		pools      map[string]*config.NATPool
		wantReason string
	}{
		{
			name:       "missing pool",
			pools:      map[string]*config.NATPool{},
			wantReason: "missing_pool",
		},
		{
			name: "nil pool",
			pools: map[string]*config.NATPool{
				"pool-a": nil,
			},
			wantReason: "missing_pool",
		},
		{
			name: "empty pool",
			pools: map[string]*config.NATPool{
				"pool-a": {Name: "pool-a", PortLow: 1024, PortHigh: 65535},
			},
			wantReason: "empty_pool",
		},
		{
			name: "port low overflow",
			pools: map[string]*config.NATPool{
				"pool-a": {Name: "pool-a", Addresses: []string{"203.0.113.10/32"}, PortLow: 65536, PortHigh: 65535},
			},
			wantReason: "invalid_port_range",
		},
		{
			name: "port high overflow",
			pools: map[string]*config.NATPool{
				"pool-a": {Name: "pool-a", Addresses: []string{"203.0.113.10/32"}, PortLow: 1024, PortHigh: 70000},
			},
			wantReason: "invalid_port_range",
		},
		{
			name: "port range reversed",
			pools: map[string]*config.NATPool{
				"pool-a": {Name: "pool-a", Addresses: []string{"203.0.113.10/32"}, PortLow: 40000, PortHigh: 39999},
			},
			wantReason: "invalid_port_range",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := sourceNATPoolTestConfig()
			cfg.Security.NAT.SourcePools = tt.pools
			snaps := buildSourceNATSnapshots(cfg, nil)
			if len(snaps) != 1 {
				t.Fatalf("len(snaps) = %d, want 1; snaps=%+v", len(snaps), snaps)
			}
			if !snaps[0].PoolUnusable {
				t.Fatalf("PoolUnusable = false, want true; snap=%+v", snaps[0])
			}
			if snaps[0].PoolUnusableReason != tt.wantReason {
				t.Fatalf("PoolUnusableReason = %q, want %q", snaps[0].PoolUnusableReason, tt.wantReason)
			}
			if snaps[0].PoolName != "pool-a" {
				t.Fatalf("PoolName = %q, want pool-a", snaps[0].PoolName)
			}
		})
	}
}

func sourceNATPoolTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:      "pool-a",
			Addresses: []string{"203.0.113.10/32"},
			PortLow:   1024,
			PortHigh:  65535,
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "snat-pool",
			Match: config.NATMatch{
				SourceAddresses:      []string{"10.0.0.0/8"},
				DestinationAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{
				Type:     config.NATSource,
				PoolName: "pool-a",
			},
		}},
	}}
	return cfg
}

// TestClearNATRuleCountersSendsHelperIPCAndIsDurable is the #2218 fail-on-
// revert guard for the MAJOR clear-durability bug. The operator NAT-counter
// clear must reset BOTH the Go offset map AND the helper's cumulative
// NatCounterStore (via the clear_nat_counters IPC); otherwise the next 1/s
// status poll re-mirrors the helper's cumulative total over the cleared offset
// (SetNATRuleCounterOffset overwrites absolutely) and the cleared value snaps
// back within <=1s.
//
// The fake helper models exactly that: a `status` request reports the
// cumulative total UNTIL it has received a `clear_nat_counters` request, after
// which it reports 0 (the real helper's NatCounterStore.clear()). The test:
//  1. seeds the offset map with a cumulative total (a prior poll),
//  2. clears via Manager.ClearNATRuleCounters,
//  3. asserts the clear_nat_counters IPC was sent,
//  4. runs a follow-up status poll through the real syncBPFCountersLocked and
//     asserts the offset stays 0 (not restored to the cumulative).
//
// Pre-fix (Manager.ClearNATRuleCounters only zeroes the offset / the embedded
// bpfShim method runs and no IPC is sent): the helper still reports the
// cumulative, step 4's poll overwrites the offset back to it, and the final
// assertion fails (counter snaps back).
func TestClearNATRuleCountersSendsHelperIPCAndIsDurable(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	const counterID = uint32(1)
	const cumPackets = uint64(42)
	const cumBytes = uint64(4200)

	reqCh := make(chan string, 8)
	// Helper state: once cleared, status reports 0 for the NAT counter.
	cleared := make(chan struct{})
	go func() {
		clearedFlag := false
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req.Type
			var natCounters []NATRuleCounterStatus
			switch req.Type {
			case "clear_nat_counters":
				if !clearedFlag {
					clearedFlag = true
					close(cleared)
				}
				natCounters = []NATRuleCounterStatus{{CounterID: counterID, Packets: 0, Bytes: 0}}
			case "status":
				if clearedFlag {
					natCounters = []NATRuleCounterStatus{{CounterID: counterID, Packets: 0, Bytes: 0}}
				} else {
					natCounters = []NATRuleCounterStatus{{CounterID: counterID, Packets: cumPackets, Bytes: cumBytes}}
				}
			}
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{NATRuleCounters: natCounters},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// Step 1: a prior poll mirrored the helper's cumulative total into the
	// bpfShim offset map. ReadNATRuleCounter should report it.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		NATRuleCounters: []NATRuleCounterStatus{{CounterID: counterID, Packets: cumPackets, Bytes: cumBytes}},
	})
	m.mu.Unlock()
	if got, _ := m.bpfShim.ReadNATRuleCounter(uint32(counterID)); got != (dataplane.CounterValue{Packets: cumPackets, Bytes: cumBytes}) {
		t.Fatalf("pre-clear ReadNATRuleCounter = %+v, want packets=%d bytes=%d", got, cumPackets, cumBytes)
	}

	// Step 2: operator clear.
	if err := m.ClearNATRuleCounters(); err != nil {
		t.Fatalf("ClearNATRuleCounters: %v", err)
	}

	// Step 3: the clear_nat_counters IPC must have been sent (load-bearing
	// half — revert the IPC send and this never fires).
	select {
	case <-cleared:
	case <-time.After(2 * time.Second):
		t.Fatal("helper never received clear_nat_counters IPC")
	}
	// Offset must be zeroed immediately after clear.
	if got, _ := m.bpfShim.ReadNATRuleCounter(uint32(counterID)); got != (dataplane.CounterValue{}) {
		t.Fatalf("ReadNATRuleCounter right after clear = %+v, want zero", got)
	}

	// Step 4: simulate the next 1/s status poll. The helper (now cleared)
	// reports 0, so syncBPFCountersLocked overwrites the offset with 0 and the
	// cleared value DOES NOT snap back. Without the IPC the helper would still
	// report the cumulative here and this overwrite would restore it.
	m.mu.Lock()
	var status ProcessStatus
	err = m.requestLocked(ControlRequest{Type: "status"}, &status)
	if err == nil {
		m.syncBPFCountersLocked(&status)
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("status poll: %v", err)
	}
	if got, _ := m.bpfShim.ReadNATRuleCounter(uint32(counterID)); got != (dataplane.CounterValue{}) {
		t.Fatalf("ReadNATRuleCounter after post-clear poll = %+v, want zero (counter snapped back — clear_nat_counters IPC missing?)", got)
	}

	// Drain to confirm the sequence included the clear IPC.
	var sawClear bool
	for {
		select {
		case typ := <-reqCh:
			if typ == "clear_nat_counters" {
				sawClear = true
			}
			continue
		default:
		}
		break
	}
	if !sawClear {
		t.Fatal("clear_nat_counters request not observed in helper request log")
	}
}

// TestClearNATRuleCountersZerosCachedHelperCountersWithoutHelper covers the
// no-live-helper path (#2218): with no helper process the cached
// m.lastStatus.NATRuleCounters are zeroed directly so a clear still takes
// effect (parity with clearHelperPolicyCountersLocked's without-helper branch).
func TestClearNATRuleCountersZerosCachedHelperCountersWithoutHelper(t *testing.T) {
	m := New()
	m.proc = nil // no live helper
	m.lastStatus = ProcessStatus{
		NATRuleCounters: []NATRuleCounterStatus{{CounterID: 1, Packets: 9, Bytes: 900}},
	}
	if err := m.ClearNATRuleCounters(); err != nil {
		t.Fatalf("ClearNATRuleCounters: %v", err)
	}
	if got := m.lastStatus.NATRuleCounters[0]; got.Packets != 0 || got.Bytes != 0 {
		t.Fatalf("cached helper NAT counter after clear = %+v, want zero packets/bytes", got)
	}
}
