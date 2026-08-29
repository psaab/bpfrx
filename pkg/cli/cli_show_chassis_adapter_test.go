package cli

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type forwardingStatusCLITestDP struct {
	dataplane.DataPlane

	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *forwardingStatusCLITestDP) IsLoaded() bool {
	return f.loaded
}

func (f *forwardingStatusCLITestDP) GetMapStats() []dataplane.MapStats {
	return f.mapStats
}

type forwardingStatusCLIUserspaceTestDP struct {
	*forwardingStatusCLITestDP

	status      dpuserspace.ProcessStatus
	statusCalls int
}

func (f *forwardingStatusCLIUserspaceTestDP) Status() (dpuserspace.ProcessStatus, error) {
	f.statusCalls++
	return f.status, nil
}

func TestForwardingStatusDataplaneProjectsMapStats(t *testing.T) {
	dp := &forwardingStatusCLITestDP{
		loaded: true,
		mapStats: []dataplane.MapStats{
			{
				Name:       "sessions",
				Type:       "Hash",
				MaxEntries: 128,
				UsedCount:  32,
				KeySize:    16,
				ValueSize:  64,
			},
			{
				Name:       "zone_configs",
				Type:       "Array",
				MaxEntries: 4,
				UsedCount:  4,
				KeySize:    4,
				ValueSize:  32,
			},
		},
	}
	c := &CLI{dp: dp}

	accessor := c.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got := accessor.GetMapStats()
	want := []fwdstatus.MapStats{
		{Type: "Hash", MaxEntries: 128, UsedCount: 32},
		{Type: "Array", MaxEntries: 4, UsedCount: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMapStats() = %#v, want %#v", got, want)
	}
}

func TestForwardingStatusDataplaneUsesUserspaceStatusAdapter(t *testing.T) {
	dp := &forwardingStatusCLIUserspaceTestDP{
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{loaded: true},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 123,
				WallNS:      456,
			}},
		},
	}
	c := &CLI{dp: dp}

	accessor := c.forwardingStatusDataplane()
	statusAccessor, ok := accessor.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		t.Fatalf("forwardingStatusDataplane() = %T, want userspace Status adapter", accessor)
	}

	got, err := statusAccessor.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if dp.statusCalls != 1 {
		t.Fatalf("Status() calls = %d, want 1", dp.statusCalls)
	}
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 123 {
		t.Fatalf("Status() = %#v, want injected userspace status", got)
	}
}

// --- #7250: the crash accessor must be WIRED, not merely implemented -------
//
// pkg/fwdstatus's own cells exercise Build + Format directly, so every one of
// them stays green if this adapter loses its HelperCrashState method — they
// assert a property of the renderer, not of the wiring. This is the cell that
// reds on that deletion.

type forwardingStatusCLICrashTestDP struct {
	*forwardingStatusCLIUserspaceTestDP

	rec        dpuserspace.HelperCrashRecord
	known      bool
	crashCalls int
}

func (f *forwardingStatusCLICrashTestDP) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	f.crashCalls++
	return f.rec, f.known
}

func TestForwardingStatusCLIAdapterExposesTheCrashAccessor7250(t *testing.T) {
	base := &forwardingStatusCLITestDP{loaded: true}
	dp := &forwardingStatusCLICrashTestDP{
		forwardingStatusCLIUserspaceTestDP: &forwardingStatusCLIUserspaceTestDP{
			forwardingStatusCLITestDP: base,
		},
		known: true,
		rec: dpuserspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			ExitCode:         101,
			PID:              4242,
			Restarts:         3,
		},
	}

	c := &CLI{dp: dp}
	acc := c.forwardingStatusDataplane()
	if acc == nil {
		t.Fatal("forwardingStatusDataplane returned nil for a userspace backend")
	}

	// The accessor fwdstatus.Build probes for. If the adapter does not satisfy
	// this, Build silently leaves HelperCrashKnown false and the crash block
	// never renders — with no compile error anywhere.
	probe, ok := acc.(interface {
		HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
	})
	if !ok {
		t.Fatal("the CLI forwarding-status adapter does not expose HelperCrashState, so " +
			"fwdstatus.Build's probe misses and `show chassis forwarding` renders no " +
			"crash block however healthy the renderer is (#7250)")
	}

	got, known := probe.HelperCrashState()
	if !known {
		t.Fatal("adapter reported the crash state as unknown for a backend that answers it")
	}
	if got.ExitCode != 101 || got.PID != 4242 || got.Restarts != 3 {
		t.Errorf("adapter did not pass the record through unchanged: %+v", got)
	}
	if dp.crashCalls == 0 {
		t.Error("adapter never called through to the backend")
	}
}
