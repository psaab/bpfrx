package grpcapi

import (
	"context"
	"log/slog"
	"net"
	"syscall"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// dialPeer establishes a gRPC connection to the cluster peer via the fabric link.
// Tries fab0 first, then fab1 if dual-fabric is configured and fab0 fails.
// Returns the connection or an error if not in cluster mode / all addresses fail.
func (s *Server) dialPeer() (*grpc.ClientConn, error) {
	if s.fabricPeerAddrFn == nil {
		return nil, status.Error(codes.Unavailable, "not in cluster mode")
	}
	peerIPs := s.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil, status.Error(codes.Unavailable, "cluster peer address not available")
	}

	// #4107: authenticate every RPC we dial on the peer's fabric listener with
	// the control-link PSK. GetRequestMetadata is read per RPC, so the token
	// rotates with the auth window and a not-yet-keyed node dials tokenless
	// (dual-accept). This covers the GetStatus health probe below too.
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(fabricAuthCreds{keyFn: s.fabricAuthKey}),
	}
	if s.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					var err error
					c.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, s.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	// Try each fabric address; return first successful connection.
	var lastErr error
	for _, ip := range peerIPs {
		// #8597 (muse-004 K29): net.JoinHostPort, not "%s:port". An IPv6
		// fabric literal formatted the old way yields `2001:db8::2:50051`,
		// which grpc.NewClient parses as a bogus host:port — so an IPv6-only
		// fabric never dials its peer and the failure looks like the peer being
		// unreachable. #4909 fixed the identical shape in `pkg/cli/peer.go`,
		// whose comment documents this exact string; this site and the two
		// fabric LISTENER addresses in `daemon_ha_comms_wiring.go` were the
		// rest of that class.
		peerAddr := net.JoinHostPort(ip, "50051")
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			lastErr = err
			continue
		}
		// Verify the connection is usable with a short deadline.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		client := pb.NewBpfrxServiceClient(conn)
		_, err = client.GetStatus(ctx, &pb.GetStatusRequest{})
		cancel()
		if err != nil {
			conn.Close()
			lastErr = err
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		return conn, nil
	}
	return nil, status.Errorf(codes.Unavailable, "cannot connect to peer on any fabric address: %v", lastErr)
}
