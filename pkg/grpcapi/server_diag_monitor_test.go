package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/monitoriface"
)

type monitorInterfaceServerTestDP struct {
	dataplane.DataPlane

	loaded     bool
	counters   dataplane.InterfaceCounterValue
	gotIfindex int
}

func (f *monitorInterfaceServerTestDP) IsLoaded() bool {
	return f.loaded
}

func (f *monitorInterfaceServerTestDP) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	f.gotIfindex = ifindex
	return f.counters, nil
}

func TestMonitorInterfaceDataplaneProjectsCounters(t *testing.T) {
	dp := &monitorInterfaceServerTestDP{
		loaded: true,
		counters: dataplane.InterfaceCounterValue{
			RxPackets: 100,
			RxBytes:   200,
			TxPackets: 300,
			TxBytes:   400,
		},
	}
	s := &Server{dp: dp}

	accessor := s.monitorInterfaceDataplane()
	if accessor == nil {
		t.Fatal("monitorInterfaceDataplane() returned nil")
	}
	if _, ok := accessor.(monitoriface.RuntimeDataPlane); !ok {
		t.Fatalf("monitorInterfaceDataplane() = %T, want monitoriface.RuntimeDataPlane", accessor)
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got, err := accessor.ReadInterfaceCounters(84)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters() error = %v", err)
	}
	if dp.gotIfindex != 84 {
		t.Fatalf("ReadInterfaceCounters ifindex = %d, want 84", dp.gotIfindex)
	}
	if got != (monitoriface.InterfaceCounters{RxPackets: 100, RxBytes: 200, TxPackets: 300, TxBytes: 400}) {
		t.Fatalf("ReadInterfaceCounters() = %+v, want projected monitor counters", got)
	}
}
