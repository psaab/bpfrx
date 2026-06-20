package userspace

import (
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2079: AppliedNATView is the generation-coherent source for the NAT
// pool-utilization-alarm monitor. These tests pin the r10 fixed point: the
// view's coherency is keyed off m.appliedSnapshot.Generation (the helper's
// last-applied generation echoed as status.LastSnapshotGeneration), NOT
// m.lastSnapshot.Generation (which FIB/neighbor bumps advance without a full
// apply) and NOT m.publishedSnapshot (which content-dedup no-ops advance).

func selfProc(t *testing.T) *exec.Cmd {
	t.Helper()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	return &exec.Cmd{Process: p}
}

func TestAppliedNATViewUnavailableWhenNoProc(t *testing.T) {
	m := New()
	if v := m.AppliedNATView(); v.Available {
		t.Fatal("nil proc must be Available:false")
	}
}

func TestAppliedNATViewUnavailableBeforeFirstApply(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	// No appliedSnapshot captured yet.
	if v := m.AppliedNATView(); v.Available {
		t.Fatal("no applied snapshot must be Available:false")
	}
}

func TestAppliedNATViewCoherent(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 7}
	m.markAppliedSnapshotLocked() // appliedSnapshot = {cfg, 7}
	m.lastStatus = ProcessStatus{
		LastSnapshotGeneration: 7,
		SourceNATPools: []SourceNATPoolStatus{
			{PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100, UsedPorts: 42},
		},
	}
	v := m.AppliedNATView()
	if !v.Available || !v.HelperCoherent {
		t.Fatalf("expected available+coherent, got %+v", v)
	}
	if v.Config != cfg || v.AppliedGeneration != 7 {
		t.Fatalf("config/gen wrong: %+v", v)
	}
	p, ok := v.Pools["p1"]
	if !ok || p.UsedPorts != 42 || p.AddressCount != 1 || p.PortHigh != 100 {
		t.Fatalf("pool sample wrong: %+v", v.Pools)
	}
}

func TestAppliedNATViewNotCoherentMidApply(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 8}
	m.markAppliedSnapshotLocked() // applied gen = 8
	// Helper still reports the previous generation (apply in flight).
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 7}
	v := m.AppliedNATView()
	if !v.Available {
		t.Fatal("should be available")
	}
	if v.HelperCoherent {
		t.Fatal("status gen 7 != applied gen 8 must be HelperCoherent:false")
	}
}

// TestAppliedNATViewFIBBumpStaysCoherent is the r10 fixed point: a
// FIB-generation bump that advances m.lastSnapshot.Generation WITHOUT a full
// apply must NOT change appliedSnapshot.Generation, so the view stays coherent
// against the helper's still-current last_snapshot_generation. Mutation:
// sourcing the view's generation from lastSnapshot.Generation (the r9 bug)
// makes this gate coherency off.
func TestAppliedNATViewFIBBumpStaysCoherent(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.generation = 9
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 9}
	m.markAppliedSnapshotLocked() // applied gen = 9
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 9}

	// Simulate a FIB-generation bump: lastSnapshot.Generation advances, but
	// the helper records it as last_fib_generation only — last_snapshot_generation
	// stays 9, and appliedSnapshot is NOT touched.
	m.generation = 10
	m.lastSnapshot.Generation = 10
	// (no markAppliedSnapshotLocked — the FIB bump path does not call it)

	v := m.AppliedNATView()
	if !v.Available || !v.HelperCoherent {
		t.Fatalf("FIB bump must keep the view coherent (applied gen unchanged), got %+v", v)
	}
	if v.AppliedGeneration != 9 {
		t.Fatalf("applied generation must remain 9 after a FIB bump, got %d", v.AppliedGeneration)
	}
}

// TestAppliedNATViewDedup: two status entries for the same pool report
// identical UsedPorts (shared allocator); the view takes one entry, never sums.
func TestAppliedNATViewDedup(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	cfg := &config.Config{}
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 3}
	m.markAppliedSnapshotLocked()
	m.lastStatus = ProcessStatus{
		LastSnapshotGeneration: 3,
		SourceNATPools: []SourceNATPoolStatus{
			{RuleName: "r1", PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100, UsedPorts: 50},
			{RuleName: "r2", PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100, UsedPorts: 50},
		},
	}
	v := m.AppliedNATView()
	if len(v.Pools) != 1 {
		t.Fatalf("expected 1 deduped pool, got %d", len(v.Pools))
	}
	if v.Pools["p1"].UsedPorts != 50 {
		t.Fatalf("deduped pool must keep one value (50), got %d", v.Pools["p1"].UsedPorts)
	}
}
