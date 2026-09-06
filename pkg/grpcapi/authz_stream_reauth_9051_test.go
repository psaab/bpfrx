package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// fakeServerStream9051 is the minimum grpc.ServerStream the interceptor needs:
// it only ever reads Context().
type fakeServerStream9051 struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream9051) Context() context.Context { return f.ctx }

// authzConfigRevoked9051 is authzConfig5278 with the read-only user's class
// removed — the revocation. Keeping every other user identical is what makes
// the difference attributable: only opsuser's authority changed.
const authzConfigRevoked9051 = `
system {
    host-name authz-grpc-test;
    login {
        user opuser {
            class operator;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

func shortenStreamReauth9051(t *testing.T) {
	t.Helper()
	old := streamReauthInterval9051
	streamReauthInterval9051 = 15 * time.Millisecond
	t.Cleanup(func() { streamReauthInterval9051 = old })
}

// revokeInStore9051 commits a config in which the streaming principal has no
// class. This is the real revocation path: a class edit committed while the
// stream is open.
func revokeInStore9051(t *testing.T, s *Server) {
	t.Helper()
	store := s.store
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(authzConfigRevoked9051); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
}

// #9051: a stream adjudicated only at open outlives its own verdict.
//
// principalStreamInterceptor called authorizeRPC once and then handed the
// stream to a handler that loops until the client disconnects. A principal
// demoted mid-stream kept its PermView feed for the life of the connection,
// while unary RPCs on the SAME connection were re-adjudicated every call.
func TestStreamIsTerminatedWhenThePrincipalIsRevoked9051(t *testing.T) {
	usePasswdFixture5278(t)
	shortenStreamReauth9051(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/MonitorInterface"

	entered := make(chan struct{})
	// The handler shape every streaming RPC here actually has: block until the
	// context is done. Nothing about this handler knows re-authorization
	// exists, which is the point of putting it in the interceptor.
	handler := func(_ any, stream grpc.ServerStream) error {
		close(entered)
		<-stream.Context().Done()
		return nil
	}

	errc := make(chan error, 1)
	go func() {
		errc <- s.principalStreamInterceptor(nil,
			fakeServerStream9051{ctx: ctxWithPeerUID(authzUIDReadOnly)},
			&grpc.StreamServerInfo{FullMethod: full}, handler)
	}()

	// REFERENCE ARM: the stream must be ADMITTED first. Without this, a fix
	// that denied every stream at open would satisfy the assertion below while
	// breaking the feature.
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("the stream was refused at open, so nothing is being measured: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}

	revokeInStore9051(t, s)

	select {
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("a revoked stream must end with PermissionDenied, got %v (code %v). "+
				"A bare cancellation is indistinguishable from an ordinary shutdown, "+
				"so the client cannot tell it was revoked", err, status.Code(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream outlived the revocation: the principal keeps its feed " +
			"until it disconnects, which is #9051")
	}
}

// NARROWNESS. An authorized principal's stream must NOT be terminated. Without
// this row, "terminate the stream" is satisfied by terminating every stream —
// which passes the test above and deletes the feature.
func TestAnAuthorizedStreamIsNotTerminated9051(t *testing.T) {
	usePasswdFixture5278(t)
	shortenStreamReauth9051(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/MonitorInterface"

	ctx, cancel := context.WithCancel(ctxWithPeerUID(authzUIDReadOnly))
	defer cancel()

	entered := make(chan struct{})
	handler := func(_ any, stream grpc.ServerStream) error {
		close(entered)
		<-stream.Context().Done()
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		errc <- s.principalStreamInterceptor(nil,
			fakeServerStream9051{ctx: ctx},
			&grpc.StreamServerInfo{FullMethod: full}, handler)
	}()
	<-entered

	// Many re-auth ticks pass with no revocation.
	select {
	case err := <-errc:
		t.Fatalf("an authorized stream was terminated after %v: %v",
			streamReauthInterval9051, err)
	case <-time.After(20 * streamReauthInterval9051):
	}

	// And an ordinary client hangup still ends it cleanly, with no error — the
	// revocation path must not have replaced the normal one.
	cancel()
	select {
	case err := <-errc:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("a client hangup must not report a revocation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end when the client hung up")
	}
}
