// #2469: the gRPC session VIEW RPCs (GetSessions legacy path and
// GetSessionSummary) must fail with codes.Internal when the backend
// session iterator errors, rather than returning a partial/zero result
// as a successful response. The cursor GetSessions path already did
// this; these tests pin the legacy + summary paths.
//
// FAIL-ON-REVERT: restoring `_ = s.dp.IterateSessions(...)` in
// getSessionsLegacy / GetSessionSummary makes both RPCs return a
// non-error empty response and the want-Internal assertions go RED.
package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// viewFaultGRPCDP fails the session iterators to model a backend
// (helper) error mid-scan. It embeds *dataplane.Manager only for the
// methods the view paths do not reach before the iterator error.
type viewFaultGRPCDP struct {
	*dataplane.Manager
	iterErr   error
	iterV6Err error
}

func (d *viewFaultGRPCDP) IsLoaded() bool { return true }

func (d *viewFaultGRPCDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.iterErr
}

func (d *viewFaultGRPCDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterV6Err
}

func newViewServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
		// cluster nil -> standalone.
	}
}

func TestGetSessionsLegacyFailsOnIteratorError(t *testing.T) {
	dp := &viewFaultGRPCDP{
		Manager: dataplane.New(),
		iterErr: errors.New("helper restart: session map closed"),
	}
	s := newViewServer(t, dp)

	// Legacy path: PageSize == 0 (no cursor pagination).
	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if err == nil {
		t.Fatal("GetSessions returned nil error on iterator failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetSessions error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

func TestGetSessionSummaryFailsOnIteratorError(t *testing.T) {
	dp := &viewFaultGRPCDP{
		Manager: dataplane.New(),
		iterErr: errors.New("helper restart: session map closed"),
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err == nil {
		t.Fatal("GetSessionSummary returned nil error on iterator failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetSessionSummary error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}
