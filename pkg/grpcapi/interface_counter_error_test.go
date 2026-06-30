// #3464: gRPC GetInterfaces must surface a per-interface counter-read failure
// with an explicit InterfaceInfo.unavailable flag, not a misleading clean 0 —
// the same uniform contract as REST /stats/interfaces, REST /interfaces, and
// the Prometheus xpf_interface_counter_read_errors_total counter. Without the
// flag, an operator cannot tell "interface idle" (real 0) from "counter bridge
// unavailable" (read failed).
//
// FAIL-ON-REVERT: dropping the `else { ii.Unavailable = true }` in
// GetInterfaces leaves the resolved row at Unavailable=false -> the assertion
// below goes RED.
package grpcapi

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// ifaceCounterErrGRPCDP is a loaded grpcRuntime whose per-interface counter
// reads always fail.
type ifaceCounterErrGRPCDP struct {
	*dataplane.Manager
}

func (d *ifaceCounterErrGRPCDP) IsLoaded() bool { return true }

func (d *ifaceCounterErrGRPCDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, errors.New("counter bridge degraded")
}

// newLoopbackZoneStore binds the loopback (lo.0) to a security zone so
// GetInterfaces resolves net.InterfaceByName("lo") and reaches the
// ReadInterfaceCounters read.
func newLoopbackZoneStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo {
        unit 0 {
            family inet;
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces lo.0;
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetInterfacesFlagsUnavailableOnReadError(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(\"lo\") unavailable in this environment (%v)", err)
	}
	s := &Server{
		store: newLoopbackZoneStore(t),
		dp:    &ifaceCounterErrGRPCDP{Manager: dataplane.New()},
	}

	resp, err := s.GetInterfaces(context.Background(), &pb.GetInterfacesRequest{})
	if err != nil {
		t.Fatalf("GetInterfaces error = %v", err)
	}

	var sawResolved bool
	for _, ii := range resp.Interfaces {
		if ii.Ifindex > 0 {
			sawResolved = true
			if !ii.Unavailable {
				t.Errorf("resolved interface %q reported counters as a clean 0 on a read "+
					"failure (unavailable=false) — must be flagged degraded (#3464). info=%+v",
					ii.Name, ii)
			}
			if ii.RxPackets != 0 || ii.TxPackets != 0 {
				t.Errorf("unavailable interface %q carried nonzero counters; want 0. info=%+v", ii.Name, ii)
			}
		}
	}
	if !sawResolved {
		t.Fatalf("no resolved interface row present; fixture/loopback not wired. resp=%+v", resp.Interfaces)
	}
}
