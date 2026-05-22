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
