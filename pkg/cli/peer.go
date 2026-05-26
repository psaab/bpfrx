// Cluster peer dialing for cluster-wide CLI queries. The CLI uses the
// fabric link to reach the other chassis node so that `show ...`
// commands can aggregate state across the pair without requiring the
// operator to log in to both nodes.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// dialPeer establishes a gRPC connection to the cluster peer, trying fab0
// then fab1 if dual-fabric is configured. Returns nil if not in cluster mode.
func (c *CLI) dialPeer() *grpc.ClientConn {
	if c.fabricPeerAddrFn == nil {
		return nil
	}
	peerIPs := c.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if c.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, rc syscall.RawConn) error {
					var err error
					rc.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	for _, ip := range peerIPs {
		peerAddr := fmt.Sprintf("%s:50051", ip)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			continue
		}
		// Quick TCP probe to verify the address is reachable.
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c.fabricVRFDevice != "" {
			d.Control = func(network, address string, rc syscall.RawConn) error {
				var err error
				rc.Control(func(fd uintptr) {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
				})
				return err
			}
		}
		tc, err := d.DialContext(context.Background(), "tcp", peerAddr)
		if err != nil {
			conn.Close()
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		tc.Close()
		return conn
	}
	slog.Warn("failed to dial peer on any fabric address")
	return nil
}

// requestPeerSystemAction asks the peer to perform a system-level action
// (reboot, shutdown, etc.) via the fabric gRPC link. When peerSystemActionFn
// is set, the request is satisfied locally without a fabric dial.
func (c *CLI) requestPeerSystemAction(ctx context.Context, action string) (string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	if c.peerSystemActionFn != nil {
		return c.peerSystemActionFn(ctx, action)
	}
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()

	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, &pb.SystemActionRequest{Action: action})
	if err != nil {
		return "", err
	}
	return resp.Message, nil
}
