// #3345: GetGlobalStats must fail with codes.Internal when a global-counter
// read fails, rather than returning a zero-valued response that is
// indistinguishable from "no events".
//
// FAIL-ON-REVERT: restoring `v, _ := s.dp.ReadGlobalCounter(idx)` (dropping
// the readErr capture + the status.Errorf return) makes GetGlobalStats return
// a non-error zero response and the want-Internal assertion goes RED.
package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// counterFaultGRPCDP is a loaded grpcRuntime whose global-counter reads fail.
type counterFaultGRPCDP struct {
	*dataplane.Manager
}

func (d *counterFaultGRPCDP) IsLoaded() bool { return true }

func (d *counterFaultGRPCDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, errors.New("counter bridge degraded")
}

func TestGetGlobalStatsFailsOnCounterReadError(t *testing.T) {
	dp := &counterFaultGRPCDP{Manager: dataplane.New()}
	s := newViewServer(t, dp)

	_, err := s.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err == nil {
		t.Fatal("GetGlobalStats returned nil error on counter read failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetGlobalStats error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

// lateCounterFaultGRPCDP fails ONLY GlobalCtrRxPackets, which GetGlobalStats
// reads AFTER the screen-counter loop. This pins the H1 ordering fix: the
// readErr check must run AFTER the full response struct is built, or a
// failure on a late read returns a nil-error zero-valued field.
type lateCounterFaultGRPCDP struct {
	*dataplane.Manager
}

func (d *lateCounterFaultGRPCDP) IsLoaded() bool { return true }

func (d *lateCounterFaultGRPCDP) ReadGlobalCounter(idx uint32) (uint64, error) {
	if idx == dataplane.GlobalCtrRxPackets {
		return 0, errors.New("counter bridge degraded")
	}
	return 0, nil
}

func TestGetGlobalStatsFailsOnLateCounterReadError(t *testing.T) {
	dp := &lateCounterFaultGRPCDP{Manager: dataplane.New()}
	s := newViewServer(t, dp)

	_, err := s.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err == nil {
		t.Fatal("GetGlobalStats returned nil error on a LATE (post-screen-loop) " +
			"counter read failure; want codes.Internal (H1 ordering)")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetGlobalStats error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}
