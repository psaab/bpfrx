package grpcapi

import (
	"context"
	"fmt"
	"time"

	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

func (s *Server) GetDHCPLeases(_ context.Context, _ *pb.GetDHCPLeasesRequest) (*pb.GetDHCPLeasesResponse, error) {
	if s.dhcp == nil {
		return &pb.GetDHCPLeasesResponse{}, nil
	}

	resp := &pb.GetDHCPLeasesResponse{}
	for _, l := range s.dhcp.Leases() {
		family := "inet"
		if l.Family == 6 {
			family = "inet6"
		}
		info := &pb.DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
			Obtained:  l.Obtained.Format(time.RFC3339),
		}
		if l.Gateway.IsValid() {
			info.Gateway = l.Gateway.String()
		}
		for _, dns := range l.DNS {
			info.Dns = append(info.Dns, dns.String())
		}
		if info.Dns == nil {
			info.Dns = []string{}
		}
		resp.Leases = append(resp.Leases, info)
	}

	// Add delegated prefixes
	for _, dp := range s.dhcp.DelegatedPrefixes() {
		pdInfo := &pb.DHCPDelegatedPrefix{
			Interface:         dp.Interface,
			Prefix:            dp.Prefix.String(),
			PreferredLifetime: dp.PreferredLifetime.String(),
			ValidLifetime:     dp.ValidLifetime.String(),
			Obtained:          dp.Obtained.Format(time.RFC3339),
		}
		// Attach PD to the matching lease, or add to first inet6 lease
		attached := false
		for _, lease := range resp.Leases {
			if lease.Interface == dp.Interface && lease.Family == "inet6" {
				lease.DelegatedPrefixes = append(lease.DelegatedPrefixes, pdInfo)
				attached = true
				break
			}
		}
		if !attached && len(resp.Leases) > 0 {
			// Create a standalone lease entry for PD-only
			resp.Leases = append(resp.Leases, &pb.DHCPLeaseInfo{
				Interface:         dp.Interface,
				Family:            "inet6",
				Dns:               []string{},
				DelegatedPrefixes: []*pb.DHCPDelegatedPrefix{pdInfo},
			})
		}
	}

	return resp, nil
}

func (s *Server) GetDHCPClientIdentifiers(_ context.Context, _ *pb.GetDHCPClientIdentifiersRequest) (*pb.GetDHCPClientIdentifiersResponse, error) {
	if s.dhcp == nil {
		return &pb.GetDHCPClientIdentifiersResponse{}, nil
	}

	resp := &pb.GetDHCPClientIdentifiersResponse{}
	for _, d := range s.dhcp.DUIDs() {
		resp.Identifiers = append(resp.Identifiers, &pb.DHCPClientIdentifierInfo{
			Interface: d.Interface,
			Type:      d.Type,
			Display:   d.Display,
			Hex:       d.HexBytes,
		})
	}
	return resp, nil
}

func (s *Server) ClearDHCPClientIdentifier(_ context.Context, req *pb.ClearDHCPClientIdentifierRequest) (*pb.ClearDHCPClientIdentifierResponse, error) {
	if s.dhcp == nil {
		return &pb.ClearDHCPClientIdentifierResponse{Message: "No DHCP clients running"}, nil
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
			return nil, fmt.Errorf("clear DUID: %w", err)
		}
		return &pb.ClearDHCPClientIdentifierResponse{
			Message: fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface),
		}, nil
	}

	s.dhcp.ClearAllDUIDs()
	return &pb.ClearDHCPClientIdentifierResponse{Message: "All DHCPv6 DUIDs cleared"}, nil
}
