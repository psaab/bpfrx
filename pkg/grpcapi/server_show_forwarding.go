package grpcapi

import (
	"context"
	"fmt"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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
		s.forwardingStatusDataplane(),
		fwdstatus.OSProcReader{},
		s.startTime,
		snap,
	)
	if err != nil {
		return fmt.Sprintf("FWDD status:\n  (build failed: %s)\n", err)
	}
	return fwdstatus.Format(fs)
}

type forwardingStatusServerDataPlane struct {
	server *Server
}

func (a forwardingStatusServerDataPlane) IsLoaded() bool {
	return a.server != nil && a.server.dp != nil && a.server.dp.IsLoaded()
}

func (a forwardingStatusServerDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.server == nil || a.server.dp == nil {
		return nil
	}
	stats := a.server.dp.GetMapStats()
	out := make([]fwdstatus.MapStats, 0, len(stats))
	for _, ms := range stats {
		out = append(out, fwdstatus.MapStats{
			Type:       ms.Type,
			MaxEntries: ms.MaxEntries,
			UsedCount:  ms.UsedCount,
		})
	}
	return out
}

type forwardingStatusServerUserspaceDataPlane struct {
	forwardingStatusServerDataPlane
}

func (a forwardingStatusServerUserspaceDataPlane) Status() (dpuserspace.ProcessStatus, error) {
	return a.server.userspaceDataplaneStatus()
}

func (s *Server) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if s == nil || s.dp == nil {
		return nil
	}
	base := forwardingStatusServerDataPlane{server: s}
	if _, ok := s.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		return forwardingStatusServerUserspaceDataPlane{forwardingStatusServerDataPlane: base}
	}
	return base
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
