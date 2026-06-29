package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// newCompareServer returns a gRPC server whose store is in configuration
// mode with one staged candidate change, so ShowCompare has a candidate
// to diff on the success path.
func newCompareServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system host-name compare-fixture"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	return &Server{store: store}
}

// TestShowCompareRejectsNegativeRollback asserts the gRPC ShowCompare RPC
// returns codes.InvalidArgument on a negative rollback_n instead of
// falling through to the candidate-vs-active compare with a success
// response. #3443 M6. RED-on-revert: dropping the `RollbackN < 0` guard
// lets rollback_n=-1 reach s.store.ShowCompare() and return a successful
// candidate-vs-active diff, which fails these assertions.
func TestShowCompareRejectsNegativeRollback(t *testing.T) {
	s := newCompareServer(t)

	for _, n := range []int32{-1, -5} {
		resp, err := s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: n})
		if err == nil {
			t.Errorf("rollback_n=%d: err = nil (resp=%v), want InvalidArgument", n, resp)
			continue
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Errorf("rollback_n=%d: error is not a *status.Status: %T (%v)", n, err, err)
			continue
		}
		if got := st.Code(); got != codes.InvalidArgument {
			t.Errorf("rollback_n=%d: code = %v, want %v", n, got, codes.InvalidArgument)
		}
		if !strings.Contains(st.Message(), "must be non-negative") {
			t.Errorf("rollback_n=%d: message = %q, want substring %q", n, st.Message(), "must be non-negative")
		}
	}
}

// TestShowCompareZeroRollbackComparesCandidate asserts rollback_n=0 still
// performs the candidate-vs-active compare and succeeds (the reserved
// default semantics are preserved).
func TestShowCompareZeroRollbackComparesCandidate(t *testing.T) {
	s := newCompareServer(t)

	if _, err := s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: 0}); err != nil {
		t.Fatalf("rollback_n=0: err = %v, want nil", err)
	}
}
