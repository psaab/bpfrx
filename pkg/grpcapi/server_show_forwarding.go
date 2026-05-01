package grpcapi

import (
	"context"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

func (s *Server) buildLocalForwarding() string {
	var snap fwdstatus.SamplerSnapshot
	if s.fwdSampler != nil {
		snap = s.fwdSampler.Snapshot()
	}
	fs, err := fwdstatus.Build(
		s.dp,
		fwdstatus.OSProcReader{},
		s.startTime,
		snap,
	)
	if err != nil {
		return fmt.Sprintf("FWDD status:\n  (build failed: %s)\n", err)
	}
	return fwdstatus.Format(fs)
}

func (s *Server) dialAndShowForwarding(ctx context.Context) (string, error) {
	conn, err := s.dialPeer()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return "", err
	}
	return resp.Output, nil
}
