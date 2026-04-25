package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

// showChassisForwarding renders the `show chassis forwarding` Junos-
// style one-screen view.  Uses the shared pkg/fwdstatus package so
// the gRPC handler and this local TTY path produce identical output.
//
// #877: local-node MVP.
// #879: cluster mode renders both node0:/node1: blocks via peer dial.
func (c *CLI) showChassisForwarding() error {
	localBuf, err := c.buildLocalForwarding()
	if err != nil {
		return err
	}

	if c.cluster == nil {
		fmt.Print(localBuf)
		return nil
	}

	// Cluster mode — compose two blocks with node0:/node1: headers.
	localNodeID := c.cluster.NodeID()
	fmt.Printf("node%d:\n%s\n%s",
		localNodeID, chassisForwardingSeparator, localBuf)

	peerBuf, peerErr := c.dialAndShowForwarding()
	peerNodeID := c.cluster.PeerNodeID()
	fmt.Printf("\nnode%d:\n%s\n", peerNodeID, chassisForwardingSeparator)
	if peerErr != nil {
		fmt.Printf("FWDD status:\n  (peer unreachable: %s)\n", peerErr)
	} else {
		fmt.Print(peerBuf)
	}
	return nil
}

const chassisForwardingSeparator = "--------------------------------------------------------------------------"

// buildLocalForwarding renders a single-node FWDD-status block for
// the local node.
func (c *CLI) buildLocalForwarding() (string, error) {
	var snap fwdstatus.SamplerSnapshot
	if c.fwdSampler != nil {
		snap = c.fwdSampler.Snapshot()
	}
	fs, err := fwdstatus.Build(
		c.dp,
		fwdstatus.OSProcReader{},
		c.startTime,
		snap,
	)
	if err != nil {
		return "", fmt.Errorf("build forwarding status: %w", err)
	}
	return fwdstatus.Format(fs), nil
}

// dialAndShowForwarding queries the cluster peer for its single-node
// FWDD-status block.  Injects xpf-no-peer:1 to prevent recursion.
func (c *CLI) dialAndShowForwarding() (string, error) {
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return "", err
	}
	return resp.Output, nil
}
