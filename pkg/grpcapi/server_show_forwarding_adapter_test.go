package grpcapi

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type forwardingStatusServerTestDP struct {
	dataplane.DataPlane

	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *forwardingStatusServerTestDP) IsLoaded() bool {
	return f.loaded
}

func (f *forwardingStatusServerTestDP) GetMapStats() []dataplane.MapStats {
	return f.mapStats
}

type forwardingStatusServerUserspaceTestDP struct {
	*forwardingStatusServerTestDP

	status      dpuserspace.ProcessStatus
	statusCalls int
}

func (f *forwardingStatusServerUserspaceTestDP) Status() (dpuserspace.ProcessStatus, error) {
	f.statusCalls++
	return f.status, nil
}

func TestForwardingStatusDataplaneProjectsMapStats(t *testing.T) {
	dp := &forwardingStatusServerTestDP{
		loaded: true,
		mapStats: []dataplane.MapStats{
			{
				Name:       "sessions",
				Type:       "Hash",
				MaxEntries: 256,
				UsedCount:  64,
				KeySize:    16,
				ValueSize:  64,
			},
			{
				Name:       "lpm_trie",
				Type:       "LPMTrie",
				MaxEntries: 1024,
				UsedCount:  7,
				KeySize:    8,
				ValueSize:  8,
			},
		},
	}
	s := &Server{dp: dp}

	accessor := s.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got := accessor.GetMapStats()
	want := []fwdstatus.MapStats{
		{Type: "Hash", MaxEntries: 256, UsedCount: 64},
		{Type: "LPMTrie", MaxEntries: 1024, UsedCount: 7},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMapStats() = %#v, want %#v", got, want)
	}
}

func TestForwardingStatusDataplaneUsesUserspaceStatusAdapter(t *testing.T) {
	dp := &forwardingStatusServerUserspaceTestDP{
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{loaded: true},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 321,
				WallNS:      654,
			}},
		},
	}
	s := &Server{dp: dp}

	accessor := s.forwardingStatusDataplane()
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
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 321 {
		t.Fatalf("Status() = %#v, want injected userspace status", got)
	}
}

// --- #7250: the crash accessor must be WIRED on the gRPC side too ---------
//
// The remote `cli` binary lands here, not on pkg/cli. Two frontends render the
// same fact from one implementation (the pkg/bootstrapshow rule), so both
// adapters need the method and both need a cell — binding one would leave the
// other free to regress silently.

type forwardingStatusServerCrashTestDP struct {
	*forwardingStatusServerUserspaceTestDP

	rec        dpuserspace.HelperCrashRecord
	known      bool
	crashCalls int
}

func (f *forwardingStatusServerCrashTestDP) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	f.crashCalls++
	return f.rec, f.known
}

func TestForwardingStatusServerAdapterExposesTheCrashAccessor7250(t *testing.T) {
	base := &forwardingStatusServerTestDP{loaded: true}
	dp := &forwardingStatusServerCrashTestDP{
		forwardingStatusServerUserspaceTestDP: &forwardingStatusServerUserspaceTestDP{
			forwardingStatusServerTestDP: base,
		},
		known: true,
		rec: dpuserspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			Signal:           "killed",
			ExitCode:         -1,
			Restarts:         7,
		},
	}

	s := &Server{dp: dp}
	acc := s.forwardingStatusDataplane()
	if acc == nil {
		t.Fatal("forwardingStatusDataplane returned nil for a userspace backend")
	}

	probe, ok := acc.(interface {
		HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
	})
	if !ok {
		t.Fatal("the gRPC forwarding-status adapter does not expose HelperCrashState, so " +
			"the remote `cli` binary renders no crash block for `show chassis " +
			"forwarding` (#7250)")
	}

	got, known := probe.HelperCrashState()
	if !known {
		t.Fatal("adapter reported the crash state as unknown for a backend that answers it")
	}
	if got.Signal != "killed" || got.Restarts != 7 {
		t.Errorf("adapter did not pass the record through unchanged: %+v", got)
	}
	if dp.crashCalls == 0 {
		t.Error("adapter never called through to the backend")
	}
}
