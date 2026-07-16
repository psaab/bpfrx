package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// emptyWalkGRPCDP is a minimal loaded dataplane whose session walk is empty, so
// GetSessions reaches (and returns from) the limiter-gated walk without needing
// a real conntrack table. It embeds *dataplane.Manager to satisfy the rest of
// grpcRuntime (unused methods return the Manager's not-loaded/not-found errors).
type emptyWalkGRPCDP struct{ *dataplane.Manager }

func (emptyWalkGRPCDP) IsLoaded() bool { return true }
func (emptyWalkGRPCDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}
func (emptyWalkGRPCDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// TestGetSessions_InProcessLeaseReuse_5880 proves the gRPC session service reuses
// an in-process admission lease instead of re-acquiring the shared limiter: at
// capacity 1, a nested in-process call (carrying the lease a REST boundary
// stamped) SUCCEEDS, while a direct external gRPC call (no lease) is still
// bounded with ResourceExhausted.
//
// FAIL-ON-REVERT: restore the unconditional gRPC re-acquire (sessionWalkLimiter
// .Acquire() instead of .AcquireCtx(ctx)) → at capacity 1 the leased in-process
// call self-rejects with ResourceExhausted → the first assertion goes RED.
func TestGetSessions_InProcessLeaseReuse_5880(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	defer func() { sessionWalkLimiter = orig }()

	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	s := &Server{dp: emptyWalkGRPCDP{dataplane.New()}, store: store}

	// Model the REST external trust boundary: acquire the single slot and obtain
	// the lease-stamped context it would delegate on.
	release, leasedCtx, err := sessionWalkLimiter.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("boundary acquire: %v", err)
	}
	defer release()
	if got := sessionWalkLimiter.InFlight(); got != 1 {
		t.Fatalf("after boundary acquire InFlight=%d, want 1", got)
	}

	// The nested in-process gRPC call carrying the lease MUST reuse the slot, not
	// self-reject at capacity 1.
	if _, err := s.GetSessions(leasedCtx, &pb.GetSessionsRequest{}); err != nil {
		t.Fatalf("in-process GetSessions self-rejected at cap 1 (lease not honored — "+
			"the #5880 double-acquire): %v", err)
	}

	// A DIRECT external gRPC call (no lease) at capacity 1 is still bounded.
	_, err = s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("external gRPC GetSessions at cap 1: err=%v, want ResourceExhausted "+
			"(the lease must not globally disable the limiter)", err)
	}
}
