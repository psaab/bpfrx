package grpcapi

import (
	"context"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/nat"
)

// appliedNATView projects the userspace manager's last-applied NAT snapshot
// into a nat.AppliedView for the deterministic-mapping lookup. It reads only
// cached in-memory state (no control-socket I/O) and returns an
// unavailable view when the dataplane is not the userspace manager, is not
// running, or has not applied any configuration yet (#5794 invariant 3 —
// query the APPLIED generation, never the candidate config).
// appliedNATViewProvider is the narrow seam the deterministic-mapping
// lookup reads: the production userspace adapter implements it (delegating
// to its manager) and tests can implement it directly without a live
// helper. Kept package-private, asserted from s.dp.
type appliedNATViewProvider interface {
	AppliedNATView() dpuserspace.AppliedNATView
}

func (s *Server) appliedNATView() nat.AppliedView {
	provider, ok := s.dpProbe().(appliedNATViewProvider)
	if !ok {
		return nat.AppliedView{Available: false}
	}
	v := provider.AppliedNATView()
	if !v.Available || v.Config == nil {
		return nat.AppliedView{Available: false}
	}
	return nat.AppliedView{Config: v.Config, Generation: v.AppliedGeneration, Available: true}
}

// GetNATDeterministic resolves a deterministic source-NAT forward
// (subscriber -> translated) or reverse (translated -> subscriber) mapping
// against the last-applied NAT generation (#5794). Lookup failures are
// returned in the response body with a stable machine-readable error_code
// (found=false), not as a gRPC status error, so every surface renders the
// same typed result.
func (s *Server) GetNATDeterministic(_ context.Context, req *pb.GetNATDeterministicRequest) (*pb.GetNATDeterministicResponse, error) {
	view := s.appliedNATView()

	switch req.GetDirection() {
	case pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD:
		res, lerr := nat.LookupForward(view, req.GetPool(), req.GetInternalHost())
		if lerr != nil {
			return natDeterministicError(lerr), nil
		}
		return &pb.GetNATDeterministicResponse{
			Found:             true,
			AppliedGeneration: res.AppliedGeneration,
			Pool:              res.Pool,
			Mode:              uint32(res.Mode),
			InternalHost:      res.InternalHost,
			ExternalIp:        res.ExternalIP,
			PortLow:           uint32(res.PortLow),
			PortHigh:          uint32(res.PortHigh),
			BlockSize:         uint32(res.BlockSize),
			BlockIndex:        res.BlockIndex,
		}, nil

	case pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE:
		if req.GetNatPort() > 65535 {
			return &pb.GetNATDeterministicResponse{
				Found:       false,
				ErrorCode:   nat.ErrCodeMalformedInput,
				ErrorDetail: "translated port must be 1-65535",
			}, nil
		}
		res, lerr := nat.LookupReverse(view, req.GetPool(), req.GetNatIp(), uint16(req.GetNatPort()))
		if lerr != nil {
			return natDeterministicError(lerr), nil
		}
		return &pb.GetNATDeterministicResponse{
			Found:             true,
			AppliedGeneration: res.AppliedGeneration,
			Pool:              res.Pool,
			Mode:              uint32(res.Mode),
			InternalHost:      res.InternalHost,
			// #9070: the deterministic UNIT length for the recovered base.
			InternalPrefixLen: uint32(res.InternalPrefixLen),
			ExternalIp:        res.ExternalIP,
			NatPort:           uint32(res.NATPort),
			PortLow:           uint32(res.PortLow),
			PortHigh:          uint32(res.PortHigh),
			BlockSize:         uint32(res.BlockSize),
			BlockIndex:        res.BlockIndex,
		}, nil

	default:
		return &pb.GetNATDeterministicResponse{
			Found:       false,
			ErrorCode:   nat.ErrCodeMalformedInput,
			ErrorDetail: "direction must be forward or reverse",
		}, nil
	}
}

func natDeterministicError(lerr *nat.LookupError) *pb.GetNATDeterministicResponse {
	return &pb.GetNATDeterministicResponse{
		Found:       false,
		ErrorCode:   lerr.Code,
		ErrorDetail: lerr.Detail,
	}
}
