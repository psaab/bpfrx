package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// bigConfigServer returns a ShowConfig response whose Output is sized on
// request, so the test can drive a payload larger than grpc-Go's 4 MiB default
// receive cap without buffering the whole configstore machinery.
type bigConfigServer struct {
	pb.UnimplementedBpfrxServiceServer
	payload string
}

func (s *bigConfigServer) ShowConfig(context.Context, *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	return &pb.ShowConfigResponse{Output: s.payload}, nil
}

// TestCLIReceivesLargeConfig pins #5321: the configstore accepts a
// configuration up to configstore.MaxConfigSize (16 MiB), so a `show
// configuration` for such a config produces a ShowConfig response well over
// grpc-Go's 4 MiB default MaxCallRecvMsgSize. The CLI client must raise the
// receive cap (dialOpts) or the response fails with ResourceExhausted and the
// operator loses config inspection on a large appliance.
//
// RED-on-revert: drop grpc.WithDefaultCallOptions(MaxCallRecvMsgSize) from
// dialOpts and this test fails — the >4 MiB payload trips the 4 MiB default
// with codes.ResourceExhausted.
func TestCLIReceivesLargeConfig(t *testing.T) {
	const grpcDefaultRecv = 4 << 20 // grpc-Go defaultClientMaxReceiveMessageSize

	// Payload above the 4 MiB default but within the store ceiling: a config
	// the store would legitimately accept yet the un-tuned client cannot read.
	payloadLen := grpcDefaultRecv + (2 << 20) // 6 MiB
	if payloadLen > configstore.MaxConfigSize {
		t.Fatalf("test payload %d exceeds configstore.MaxConfigSize %d", payloadLen, configstore.MaxConfigSize)
	}
	payload := strings.Repeat("a", payloadLen)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, &bigConfigServer{payload: payload})
	go srv.Serve(lis)
	defer srv.Stop()

	dialer := grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})

	// Dial with the exact production client construction plus the bufconn dialer.
	conn, err := grpc.NewClient("passthrough:///bufnet", dialOpts(dialer)...)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)

	resp, err := client.ShowConfig(context.Background(), &pb.ShowConfigRequest{
		Format: pb.ConfigFormat_HIERARCHICAL,
		Target: pb.ConfigTarget_ACTIVE,
	})
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			t.Fatalf("CLI client rejected a %d-byte config with ResourceExhausted; "+
				"MaxCallRecvMsgSize not raised to configstore.MaxConfigSize (#5321): %v", payloadLen, err)
		}
		t.Fatalf("ShowConfig: %v", err)
	}
	if len(resp.Output) != payloadLen {
		t.Fatalf("ShowConfig Output len = %d, want %d", len(resp.Output), payloadLen)
	}
}

// TestDialOptsCapMatchesStoreCeiling guards the bound itself: the CLI receive
// cap tracks configstore.MaxConfigSize (plus framing headroom) so the client
// can always display a config the store accepts. A weaker but direct guard
// against the two bounds drifting.
func TestDialOptsCapMatchesStoreCeiling(t *testing.T) {
	if maxConfigRecvBytes < configstore.MaxConfigSize {
		t.Fatalf("maxConfigRecvBytes (%d) < configstore.MaxConfigSize (%d): CLI cannot display a config the store accepts",
			maxConfigRecvBytes, configstore.MaxConfigSize)
	}
	if maxConfigRecvBytes != configstore.MaxConfigSize+(1<<20) {
		t.Fatalf("maxConfigRecvBytes = %d, want MaxConfigSize+1MiB (%d)",
			maxConfigRecvBytes, configstore.MaxConfigSize+(1<<20))
	}
}
