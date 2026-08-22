package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestServeUntilDoneBoundedByStuckMonitorStream_4910 proves that an active,
// unbounded MonitorInterface stream cannot block gRPC shutdown forever. The
// server-lifetime context is cancelled while a client holds a MonitorInterface
// stream open; serveUntilDone (the shared Run / RunFabricListener shutdown
// path) must still return within the bounded grpcStopTimeout because
// stopGRPCServer force-Stop()'s the server after the grace period.
//
// RED-on-revert: replacing the bounded stopGRPCServer with a plain
// srv.GracefulStop() makes serveUntilDone hang here (the stream keeps
// stream.Context() live), and the test times out.
func TestServeUntilDoneBoundedByStuckMonitorStream_4910(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name fw; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The PRODUCTION primary-listener construction, not a hand-rolled copy of
	// it: #5849's connection-scoped config-lock lifecycle AND the #5278
	// login-class chain. The peer resolver is injected to report uid 0 because
	// this runs over a bufconn, which authz.LookupPeer correctly refuses to
	// attribute (it is not a TCP peer) — and a denied MonitorInterface would
	// leave no open stream, quietly removing the very thing this test bounds.
	s := &Server{
		store: store,
		addr:  "bufnet",
		peerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return authz.PeerIdentity{UID: 0, OK: true, Local: true}
		},
	}

	lis := bufconn.Listen(1 << 20)
	srv := s.buildPrimaryServer()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serveUntilDone(ctx, srv, lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)

	// Hold a MonitorInterface stream open (summary mode). We deliberately do
	// NOT cancel this client context: a client keeping the stream open is
	// exactly what blocks GracefulStop.
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	stream, err := client.MonitorInterface(streamCtx, &pb.MonitorInterfaceRequest{})
	if err != nil {
		t.Fatalf("MonitorInterface: %v", err)
	}
	// Receive the first frame so the handler is inside its streaming loop and
	// the RPC is genuinely in-flight against GracefulStop.
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first stream.Recv: %v", err)
	}

	// Cancel the server lifetime. serveUntilDone must return within the bounded
	// grace period despite the still-open stream.
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilDone returned error: %v", err)
		}
	case <-time.After(grpcStopTimeout + 5*time.Second):
		t.Fatalf("serveUntilDone did not return within %v of ctx cancel — an open "+
			"MonitorInterface stream blocked shutdown", grpcStopTimeout+5*time.Second)
	}
}

// TestStopGRPCServerIdleReturnsPromptly_4910 confirms the bounded stop does not
// impose the timeout on a clean, RPC-idle shutdown: with no in-flight RPC,
// GracefulStop completes immediately and stopGRPCServer returns well under the
// grace period (so a normal client disconnect drops nothing and shutdown stays
// fast).
func TestStopGRPCServerIdleReturnsPromptly_4910(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()

	start := time.Now()
	stopGRPCServer(srv, grpcStopTimeout)
	if elapsed := time.Since(start); elapsed >= grpcStopTimeout {
		t.Fatalf("idle stopGRPCServer took %v (>= %v) — it should return as soon as GracefulStop completes",
			elapsed, grpcStopTimeout)
	}
}
