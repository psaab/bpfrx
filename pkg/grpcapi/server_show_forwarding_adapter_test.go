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
