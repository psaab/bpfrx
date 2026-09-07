package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9143: the gRPC FRR status RPCs forked a `vtysh` child per request with no
// admission bound and discarded their request context (`_ context.Context`).
//
// The two surfaces must classify the SAME event the same way — the lesson #9142
// wrote down on the session-clear surface, where an admission refusal answered
// 429 standalone and 500 clustered. REST renders frr.ErrVtyshBusy as 429; gRPC
// must render it as codes.ResourceExhausted, the code every other admission
// refusal in this process already uses.
//
// As on REST, this is additive: an ordinary FRR failure still yields
// codes.Internal, unchanged.

type stubFRRExec9143g struct{ frr.RecordingExecutor }

type failingFRRExec9143g struct{ frr.RecordingExecutor }

func (failingFRRExec9143g) Vtysh(context.Context, string) (string, error) {
	return "", errors.New("vtysh: exit status 1: zebra unreachable")
}

func withFreshVtyshLimiter9143g(t *testing.T, n int) {
	t.Helper()
	orig := diagcmd.VtyshLimiter
	diagcmd.VtyshLimiter = diagcmd.NewLimiter(n)
	t.Cleanup(func() { diagcmd.VtyshLimiter = orig })
}

func TestGRPCFRRStatusOverCapIsResourceExhausted9143(t *testing.T) {
	calls := map[string]func(*Server, context.Context) error{
		"GetOSPFStatus/neighbors": func(s *Server, c context.Context) error {
			_, e := s.GetOSPFStatus(c, &pb.GetOSPFStatusRequest{})
			return e
		},
		"GetOSPFStatus/database": func(s *Server, c context.Context) error {
			_, e := s.GetOSPFStatus(c, &pb.GetOSPFStatusRequest{Type: "database"})
			return e
		},
		"GetBGPStatus/summary": func(s *Server, c context.Context) error {
			_, e := s.GetBGPStatus(c, &pb.GetBGPStatusRequest{})
			return e
		},
		"GetBGPStatus/routes": func(s *Server, c context.Context) error {
			_, e := s.GetBGPStatus(c, &pb.GetBGPStatusRequest{Type: "routes"})
			return e
		},
		"GetRIPStatus": func(s *Server, c context.Context) error {
			_, e := s.GetRIPStatus(c, &pb.GetRIPStatusRequest{})
			return e
		},
		"GetISISStatus": func(s *Server, c context.Context) error {
			_, e := s.GetISISStatus(c, &pb.GetISISStatusRequest{})
			return e
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			// Control: with a free slot the RPC succeeds, so the refusal
			// below is measured against an admitted case.
			withFreshVtyshLimiter9143g(t, 1)
			s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &stubFRRExec9143g{})}
			if err := call(s, context.Background()); err != nil {
				t.Fatalf("with a free slot %s failed: %v", name, err)
			}

			release, err := diagcmd.VtyshLimiter.Acquire()
			if err != nil {
				t.Fatalf("pre-acquire: %v", err)
			}
			defer release()

			err = call(s, context.Background())
			if err == nil {
				t.Fatalf("%s succeeded while the vtysh budget was saturated", name)
			}
			if got := status.Code(err); got != codes.ResourceExhausted {
				t.Fatalf("%s over-cap -> %v, want codes.ResourceExhausted (REST renders the same "+
					"event as 429; the two surfaces must not disagree — #9142)", name, got)
			}
		})
	}
}

func TestGRPCFRROrdinaryErrorStaysInternal9143(t *testing.T) {
	withFreshVtyshLimiter9143g(t, 4)
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &failingFRRExec9143g{})}

	_, err := s.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: "database"})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("ordinary FRR failure -> %v, want codes.Internal (unchanged from before #9143)", got)
	}
}

// The gRPC handlers used to discard their context entirely (`_ context.Context`).
// A cancelled RPC must now abort the shell-out.
func TestGRPCFRRCancelledRPCAbortsTheRead9143(t *testing.T) {
	withFreshVtyshLimiter9143g(t, 4)
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &ctxWatchExec9143g{})}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.GetOSPFStatus(ctx, &pb.GetOSPFStatusRequest{Type: "database"})
	if err == nil {
		t.Fatal("a cancelled RPC still ran the FRR read to completion — the request context is not propagated")
	}
}

type ctxWatchExec9143g struct{ frr.RecordingExecutor }

func (ctxWatchExec9143g) Vtysh(ctx context.Context, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "ok", nil
}
