package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetRoutes(_ context.Context, _ *pb.GetRoutesRequest) (*pb.GetRoutesResponse, error) {
	if s.routing == nil {
		return &pb.GetRoutesResponse{}, nil
	}

	entries, err := s.routing.GetRoutes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get routes: %v", err)
	}

	resp := &pb.GetRoutesResponse{}
	for _, e := range entries {
		resp.Routes = append(resp.Routes, &pb.RouteInfo{
			Destination: e.Destination,
			NextHop:     e.NextHop,
			Interface:   e.Interface,
			Preference:  int32(e.Preference),
			Protocol:    e.Protocol,
		})
	}
	return resp, nil
}

func (s *Server) GetOSPFStatus(_ context.Context, req *pb.GetOSPFStatusRequest) (*pb.GetOSPFStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetOSPFStatusResponse{Output: "FRR not available"}, nil
	}
	var output string
	var err error
	switch req.Type {
	case "neighbor-detail":
		output, err = s.frr.GetOSPFNeighborDetail()
	case "database":
		output, err = s.frr.GetOSPFDatabase()
	case "interface":
		output, err = s.frr.GetOSPFInterface()
	case "routes":
		output, err = s.frr.GetOSPFRoutes()
	default:
		neighbors, nerr := s.frr.GetOSPFNeighbors()
		if nerr != nil {
			return nil, status.Errorf(codes.Internal, "%v", nerr)
		}
		var b strings.Builder
		for _, n := range neighbors {
			fmt.Fprintf(&b, "%-18s %-10s %-16s %-18s %s\n",
				n.NeighborID, n.Priority, n.State, n.Address, n.Interface)
		}
		output = b.String()
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.GetOSPFStatusResponse{Output: output}, nil
}

func (s *Server) GetBGPStatus(_ context.Context, req *pb.GetBGPStatusRequest) (*pb.GetBGPStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetBGPStatusResponse{Output: "FRR not available"}, nil
	}
	var b strings.Builder
	switch req.Type {
	case "routes":
		routes, err := s.frr.GetBGPRoutes()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		for _, r := range routes {
			fmt.Fprintf(&b, "%-24s %-20s %s\n", r.Network, r.NextHop, r.Path)
		}
	case "groups":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) == 0 {
			b.WriteString("No BGP groups configured\n")
		} else {
			// Group neighbors by GroupName
			groups := make(map[string][]*config.BGPNeighbor)
			for _, n := range cfg.Protocols.BGP.Neighbors {
				name := n.GroupName
				if name == "" {
					name = "(ungrouped)"
				}
				groups[name] = append(groups[name], n)
			}
			names := make([]string, 0, len(groups))
			for name := range groups {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				neighbors := groups[name]
				var peerAS uint32
				var exports []string
				if len(neighbors) > 0 {
					peerAS = neighbors[0].PeerAS
					exports = neighbors[0].Export
				}
				fmt.Fprintf(&b, "Group: %s  Peer-AS: %d  Neighbors: %d\n", name, peerAS, len(neighbors))
				if len(exports) > 0 {
					fmt.Fprintf(&b, "  Export: %s\n", strings.Join(exports, ", "))
				}
				for _, n := range neighbors {
					desc := ""
					if n.Description != "" {
						desc = " (" + n.Description + ")"
					}
					fmt.Fprintf(&b, "  Neighbor: %s%s\n", n.Address, desc)
				}
				b.WriteString("\n")
			}
		}
	default:
		// "received-routes:<ip>" for neighbor received routes
		if strings.HasPrefix(req.Type, "received-routes:") {
			ip := strings.TrimPrefix(req.Type, "received-routes:")
			output, err := s.frr.GetBGPNeighborReceivedRoutes(ip)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%v", err)
			}
			return &pb.GetBGPStatusResponse{Output: output}, nil
		}
		// "advertised-routes:<ip>" for neighbor advertised routes
		if strings.HasPrefix(req.Type, "advertised-routes:") {
			ip := strings.TrimPrefix(req.Type, "advertised-routes:")
			output, err := s.frr.GetBGPNeighborAdvertisedRoutes(ip)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%v", err)
			}
			return &pb.GetBGPStatusResponse{Output: output}, nil
		}
		// "neighbor" or "neighbor:<ip>" for detailed neighbor info
		if req.Type == "neighbor" || strings.HasPrefix(req.Type, "neighbor:") {
			ip := ""
			if strings.HasPrefix(req.Type, "neighbor:") {
				ip = strings.TrimPrefix(req.Type, "neighbor:")
			}
			output, err := s.frr.GetBGPNeighborDetail(ip)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%v", err)
			}
			return &pb.GetBGPStatusResponse{Output: output}, nil
		}
		peers, err := s.frr.GetBGPSummary()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-8s %-10s %-10s %-12s %s\n",
				p.Neighbor, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State)
		}
	}
	return &pb.GetBGPStatusResponse{Output: b.String()}, nil
}

func (s *Server) GetRIPStatus(_ context.Context, _ *pb.GetRIPStatusRequest) (*pb.GetRIPStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetRIPStatusResponse{Output: "FRR not available"}, nil
	}
	routes, err := s.frr.GetRIPRoutes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	var b strings.Builder
	if len(routes) == 0 {
		b.WriteString("No RIP routes\n")
	} else {
		fmt.Fprintf(&b, "  %-20s %-18s %-8s %s\n", "Network", "Next Hop", "Metric", "Interface")
		for _, r := range routes {
			fmt.Fprintf(&b, "  %-20s %-18s %-8s %s\n", r.Network, r.NextHop, r.Metric, r.Interface)
		}
	}
	return &pb.GetRIPStatusResponse{Output: b.String()}, nil
}

func (s *Server) GetISISStatus(_ context.Context, req *pb.GetISISStatusRequest) (*pb.GetISISStatusResponse, error) {
	if s.frr == nil {
		return &pb.GetISISStatusResponse{Output: "FRR not available"}, nil
	}
	var b strings.Builder
	switch req.Type {
	case "adjacency-detail":
		output, err := s.frr.GetISISAdjacencyDetail()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		b.WriteString(output)
	case "routes":
		output, err := s.frr.GetISISRoutes()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		b.WriteString(output)
	case "database":
		output, err := s.frr.GetISISDatabase()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		b.WriteString(output)
	default:
		adjs, err := s.frr.GetISISAdjacency()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		if len(adjs) == 0 {
			b.WriteString("No IS-IS adjacencies\n")
		} else {
			fmt.Fprintf(&b, "  %-20s %-14s %-10s %-10s %s\n",
				"System ID", "Interface", "Level", "State", "Hold Time")
			for _, a := range adjs {
				fmt.Fprintf(&b, "  %-20s %-14s %-10s %-10s %s\n",
					a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)
			}
		}
	}
	return &pb.GetISISStatusResponse{Output: b.String()}, nil
}

func (s *Server) GetIPsecSA(_ context.Context, _ *pb.GetIPsecSARequest) (*pb.GetIPsecSAResponse, error) {
	if s.ipsec == nil {
		return &pb.GetIPsecSAResponse{Output: "IPsec not available"}, nil
	}
	sas, err := s.ipsec.GetSAStatus()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	var b strings.Builder
	for _, sa := range sas {
		fmt.Fprintf(&b, "SA: %s  State: %s", sa.Name, sa.State)
		if sa.LocalAddr != "" {
			fmt.Fprintf(&b, "  Local: %s", sa.LocalAddr)
		}
		if sa.RemoteAddr != "" {
			fmt.Fprintf(&b, "  Remote: %s", sa.RemoteAddr)
		}
		b.WriteString("\n")
	}
	return &pb.GetIPsecSAResponse{Output: b.String()}, nil
}
