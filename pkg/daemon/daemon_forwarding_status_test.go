package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type forwardingStatusDaemonTestDP struct {
	runtimeOnlyApplyTestDP
	dataplane.DataPlane

	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *forwardingStatusDaemonTestDP) IsLoaded() bool {
	return f.loaded
}

func (f *forwardingStatusDaemonTestDP) Close() error {
	return nil
}

func (f *forwardingStatusDaemonTestDP) Teardown() error {
	return nil
}

func (f *forwardingStatusDaemonTestDP) GetMapStats() []dataplane.MapStats {
	return f.mapStats
}

type forwardingStatusDaemonUserspaceTestDP struct {
	*forwardingStatusDaemonTestDP

	status      dpuserspace.ProcessStatus
	statusCalls int
}

func (f *forwardingStatusDaemonUserspaceTestDP) Status() (dpuserspace.ProcessStatus, error) {
	f.statusCalls++
	return f.status, nil
}

func TestForwardingStatusDataplaneProjectsMapStats(t *testing.T) {
	dp := &forwardingStatusDaemonTestDP{
		loaded: true,
		mapStats: []dataplane.MapStats{
			{
				Name:       "sessions",
				Type:       "Hash",
				MaxEntries: 512,
				UsedCount:  128,
				KeySize:    16,
				ValueSize:  64,
			},
			{
				Name:       "policy",
				Type:       "PerCPUArray",
				MaxEntries: 8,
				UsedCount:  8,
				KeySize:    4,
				ValueSize:  128,
			},
		},
	}
	d := &Daemon{dp: dp}

	accessor := d.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got := accessor.GetMapStats()
	want := []fwdstatus.MapStats{
		{Type: "Hash", MaxEntries: 512, UsedCount: 128},
		{Type: "PerCPUArray", MaxEntries: 8, UsedCount: 8},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMapStats() = %#v, want %#v", got, want)
	}
}

func TestForwardingStatusDataplaneUsesUserspaceStatusAdapter(t *testing.T) {
	dp := &forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{loaded: true},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 987,
				WallNS:      654,
			}},
		},
	}
	d := &Daemon{dp: dp}

	accessor := d.forwardingStatusDataplane()
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
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 987 {
		t.Fatalf("Status() = %#v, want injected userspace status", got)
	}
}
