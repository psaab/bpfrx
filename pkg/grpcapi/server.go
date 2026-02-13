// Package grpcapi implements the gRPC API server for bpfrx.
package grpcapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vishvananda/netlink"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/frr"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/rpm"
	"github.com/psaab/bpfrx/pkg/vrrp"
)

// Config configures the gRPC server.
type Config struct {
	Store    *configstore.Store
	DP       *dataplane.Manager
	EventBuf *logging.EventBuffer
	GC       *conntrack.GC
	Routing  *routing.Manager
	FRR      *frr.Manager
	IPsec    *ipsec.Manager
	DHCP         *dhcp.Manager
	DHCPServer   *dhcpserver.Manager
	RPMResultsFn func() []*rpm.ProbeResult // returns live RPM results
	ApplyFn      func(*config.Config)      // daemon's applyConfig callback
	Version      string                    // software version string
}

// Server implements the BpfrxService gRPC service.
type Server struct {
	pb.UnimplementedBpfrxServiceServer
	store        *configstore.Store
	dp           *dataplane.Manager
	eventBuf     *logging.EventBuffer
	gc           *conntrack.GC
	routing      *routing.Manager
	frr          *frr.Manager
	ipsec        *ipsec.Manager
	dhcp         *dhcp.Manager
	dhcpServer   *dhcpserver.Manager
	rpmResultsFn func() []*rpm.ProbeResult
	applyFn      func(*config.Config)
	startTime    time.Time
	addr         string
	version      string
}

// NewServer creates a new gRPC server.
func NewServer(addr string, cfg Config) *Server {
	return &Server{
		store:        cfg.Store,
		dp:           cfg.DP,
		eventBuf:     cfg.EventBuf,
		gc:           cfg.GC,
		routing:      cfg.Routing,
		frr:          cfg.FRR,
		ipsec:        cfg.IPsec,
		dhcp:         cfg.DHCP,
		dhcpServer:   cfg.DHCPServer,
		rpmResultsFn: cfg.RPMResultsFn,
		applyFn:      cfg.ApplyFn,
		startTime:    time.Now(),
		addr:         addr,
		version:      cfg.Version,
	}
}

// Run starts the gRPC server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, s)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("gRPC server listening", "addr", s.addr)
		if err := srv.Serve(lis); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	srv.GracefulStop()
	return nil
}

// --- Config lifecycle RPCs ---

func (s *Server) EnterConfigure(_ context.Context, _ *pb.EnterConfigureRequest) (*pb.EnterConfigureResponse, error) {
	if err := s.store.EnterConfigure(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.EnterConfigureResponse{}, nil
}

func (s *Server) ExitConfigure(_ context.Context, _ *pb.ExitConfigureRequest) (*pb.ExitConfigureResponse, error) {
	s.store.ExitConfigure()
	return &pb.ExitConfigureResponse{}, nil
}

func (s *Server) GetConfigModeStatus(_ context.Context, _ *pb.GetConfigModeStatusRequest) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	}, nil
}

func (s *Server) Set(_ context.Context, req *pb.SetRequest) (*pb.SetResponse, error) {
	if err := s.store.SetFromInput(req.Input); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) Delete(_ context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	if err := s.store.DeleteFromInput(req.Input); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.DeleteResponse{}, nil
}

func (s *Server) Load(_ context.Context, req *pb.LoadRequest) (*pb.LoadResponse, error) {
	switch req.Mode {
	case "override":
		if err := s.store.LoadOverride(req.Content); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	case "merge", "":
		if err := s.store.LoadMerge(req.Content); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown load mode: %s (use 'override' or 'merge')", req.Mode)
	}
	return &pb.LoadResponse{}, nil
}

func (s *Server) Commit(_ context.Context, _ *pb.CommitRequest) (*pb.CommitResponse, error) {
	// If a confirmed commit is pending, confirm it
	if s.store.IsConfirmPending() {
		if err := s.store.ConfirmCommit(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.CommitResponse{}, nil
	}

	compiled, err := s.store.Commit()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if s.applyFn != nil {
		s.applyFn(compiled)
	}
	return &pb.CommitResponse{}, nil
}

func (s *Server) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest) (*pb.CommitCheckResponse, error) {
	if _, err := s.store.CommitCheck(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.CommitCheckResponse{}, nil
}

func (s *Server) CommitConfirmed(_ context.Context, req *pb.CommitConfirmedRequest) (*pb.CommitConfirmedResponse, error) {
	compiled, err := s.store.CommitConfirmed(int(req.Minutes))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if s.applyFn != nil {
		s.applyFn(compiled)
	}
	return &pb.CommitConfirmedResponse{}, nil
}

func (s *Server) ConfirmCommit(_ context.Context, _ *pb.ConfirmCommitRequest) (*pb.ConfirmCommitResponse, error) {
	if err := s.store.ConfirmCommit(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.ConfirmCommitResponse{}, nil
}

func (s *Server) Rollback(_ context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	if err := s.store.Rollback(int(req.N)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.RollbackResponse{}, nil
}

func (s *Server) ShowConfig(_ context.Context, req *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	var output string
	switch {
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowActiveJSON()
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowActiveSet()
	case req.Target == pb.ConfigTarget_ACTIVE:
		if len(req.Path) > 0 {
			output = s.store.ShowActivePath(req.Path)
		} else {
			output = s.store.ShowActive()
		}
	case req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowCandidateJSON()
	case req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowCandidateSet()
	default:
		output = s.store.ShowCandidate()
	}
	return &pb.ShowConfigResponse{Output: output}, nil
}

func (s *Server) ShowCompare(_ context.Context, req *pb.ShowCompareRequest) (*pb.ShowCompareResponse, error) {
	if req.RollbackN > 0 {
		diff, err := s.store.ShowCompareRollback(int(req.RollbackN))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	return &pb.ShowCompareResponse{Output: s.store.ShowCompare()}, nil
}

func (s *Server) ShowRollback(_ context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
	var output string
	var err error
	if req.Format == pb.ConfigFormat_SET {
		output, err = s.store.ShowRollbackSet(int(req.N))
	} else {
		output, err = s.store.ShowRollback(int(req.N))
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.ShowRollbackResponse{Output: output}, nil
}

func (s *Server) ListHistory(_ context.Context, _ *pb.ListHistoryRequest) (*pb.ListHistoryResponse, error) {
	entries := s.store.ListHistory()
	resp := &pb.ListHistoryResponse{}
	for i, e := range entries {
		resp.Entries = append(resp.Entries, &pb.HistoryEntry{
			Index:     int32(i + 1),
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		})
	}
	return resp, nil
}

// --- Operational show RPCs ---

func (s *Server) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	resp := &pb.GetStatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = int32(len(cfg.Security.Zones))
	}
	if s.gc != nil {
		stats := s.gc.Stats()
		resp.SessionCount = int32(stats.TotalEntries)
	}
	return resp, nil
}

func (s *Server) GetGlobalStats(_ context.Context, _ *pb.GetGlobalStatsRequest) (*pb.GetGlobalStatsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	ctrMap := s.dp.Map("global_counters")
	if ctrMap == nil {
		return nil, status.Error(codes.Internal, "global_counters map not found")
	}

	readCounter := func(idx uint32) uint64 {
		var perCPU []uint64
		if err := ctrMap.Lookup(idx, &perCPU); err != nil {
			return 0
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total
	}

	// Collect per-screen-type drop counters
	screenDetails := make(map[string]uint64)
	screenCounters := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrScreenSynFlood, "syn-flood"},
		{dataplane.GlobalCtrScreenICMPFlood, "icmp-flood"},
		{dataplane.GlobalCtrScreenUDPFlood, "udp-flood"},
		{dataplane.GlobalCtrScreenPortScan, "port-scan"},
		{dataplane.GlobalCtrScreenIPSweep, "ip-sweep"},
		{dataplane.GlobalCtrScreenLandAttack, "land-attack"},
		{dataplane.GlobalCtrScreenPingOfDeath, "ping-of-death"},
		{dataplane.GlobalCtrScreenTearDrop, "tear-drop"},
		{dataplane.GlobalCtrScreenTCPSynFin, "tcp-syn-fin"},
		{dataplane.GlobalCtrScreenTCPNoFlag, "tcp-no-flag"},
		{dataplane.GlobalCtrScreenTCPFinNoAck, "tcp-fin-no-ack"},
		{dataplane.GlobalCtrScreenWinNuke, "winnuke"},
		{dataplane.GlobalCtrScreenIPSrcRoute, "ip-source-route"},
		{dataplane.GlobalCtrScreenSynFrag, "syn-fragment"},
	}
	for _, sc := range screenCounters {
		v := readCounter(sc.idx)
		if v > 0 {
			screenDetails[sc.name] = v
		}
	}

	return &pb.GetGlobalStatsResponse{
		RxPackets:           readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:           readCounter(dataplane.GlobalCtrTxPackets),
		Drops:               readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated:     readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:      readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:         readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:        readCounter(dataplane.GlobalCtrPolicyDeny),
		NatAllocFailures:    readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDenies:   readCounter(dataplane.GlobalCtrHostInboundDeny),
		TcEgressPackets:     readCounter(dataplane.GlobalCtrTCEgressPackets),
		Nat64Translations:   readCounter(dataplane.GlobalCtrNAT64Xlate),
		HostInboundAllowed:  readCounter(dataplane.GlobalCtrHostInbound),
		ScreenDropDetails:   screenDetails,
	}, nil
}

func (s *Server) GetZones(_ context.Context, _ *pb.GetZonesRequest) (*pb.GetZonesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetZonesResponse{}, nil
	}

	var cr *dataplane.CompileResult
	if s.dp != nil {
		cr = s.dp.LastCompileResult()
	}

	resp := &pb.GetZonesResponse{}
	for zoneName, zone := range cfg.Security.Zones {
		zi := &pb.ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			Interfaces:  zone.Interfaces,
			TcpRst:      zone.TCPRst,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}
		if zone.HostInboundTraffic != nil {
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.Protocols...)
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}
		if zi.HostInboundServices == nil {
			zi.HostInboundServices = []string{}
		}

		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.Id = uint32(id)
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		resp.Zones = append(resp.Zones, zi)
	}
	sort.Slice(resp.Zones, func(i, j int) bool { return resp.Zones[i].Name < resp.Zones[j].Name })
	return resp, nil
}

func (s *Server) GetPolicies(_ context.Context, _ *pb.GetPoliciesRequest) (*pb.GetPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetPoliciesResponse{}, nil
	}

	resp := &pb.GetPoliciesResponse{}
	var policyID uint32
	for _, zpp := range cfg.Security.Policies {
		pi := &pb.PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for _, rule := range zpp.Policies {
			pr := &pb.PolicyRule{
				Name:         rule.Name,
				Description:  rule.Description,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				}
			}
			policyID++
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
	}
	return resp, nil
}

func (s *Server) GetSessions(_ context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}
	offset := int(req.Offset)
	zoneFilter := uint16(req.Zone)
	protoFilter := req.Protocol
	srcPort := uint16(req.SourcePort)
	dstPort := uint16(req.DestinationPort)
	natOnly := req.NatOnly

	// Parse CIDR prefix filters
	var srcNet, dstNet *net.IPNet
	if req.SourcePrefix != "" {
		cidr := req.SourcePrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, srcNet, _ = net.ParseCIDR(cidr)
	}
	if req.DestinationPrefix != "" {
		cidr := req.DestinationPrefix
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, dstNet, _ = net.ParseCIDR(cidr)
	}

	now := monotonicSeconds()
	var all []*pb.SessionEntry
	idx := 0

	// Build reverse zone ID → name map
	zoneNames := make(map[uint16]string)
	if cr := s.dp.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if srcPort != 0 && ntohs(key.SrcPort) != srcPort {
			return true
		}
		if dstPort != 0 && ntohs(key.DstPort) != dstPort {
			return true
		}
		if natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
			return true
		}
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV4(key, val, now, zoneNames))
		}
		idx++
		return true
	})

	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if srcPort != 0 && ntohs(key.SrcPort) != srcPort {
			return true
		}
		if dstPort != 0 && ntohs(key.DstPort) != dstPort {
			return true
		}
		if natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
			return true
		}
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV6(key, val, now, zoneNames))
		}
		idx++
		return true
	})

	return &pb.GetSessionsResponse{
		Total:    int32(idx),
		Limit:    int32(limit),
		Offset:   int32(offset),
		Sessions: all,
	}, nil
}

func (s *Server) GetSessionSummary(_ context.Context, _ *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	resp := &pb.GetSessionSummaryResponse{}

	_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		resp.TotalEntries++
		if val.IsReverse == 0 {
			resp.ForwardOnly++
			resp.Ipv4Sessions++
			if val.State == dataplane.SessStateEstablished {
				resp.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				resp.SnatSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				resp.DnatSessions++
			}
		}
		return true
	})

	_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		resp.TotalEntries++
		if val.IsReverse == 0 {
			resp.ForwardOnly++
			resp.Ipv6Sessions++
			if val.State == dataplane.SessStateEstablished {
				resp.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				resp.SnatSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				resp.DnatSessions++
			}
		}
		return true
	})

	return resp, nil
}

func (s *Server) GetNATSource(_ context.Context, _ *pb.GetNATSourceRequest) (*pb.GetNATSourceResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATSourceResponse{}, nil
	}

	resp := &pb.GetNATSourceResponse{}
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := &pb.NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			resp.Rules = append(resp.Rules, info)
		}
	}
	return resp, nil
}

func (s *Server) GetNATDestination(_ context.Context, _ *pb.GetNATDestinationRequest) (*pb.GetNATDestinationResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return &pb.GetNATDestinationResponse{}, nil
	}

	resp := &pb.GetNATDestinationResponse{}
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := &pb.NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint32(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIp = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint32(pool.Port)
				}
			}
			resp.Rules = append(resp.Rules, info)
		}
	}
	return resp, nil
}

func (s *Server) GetScreen(_ context.Context, _ *pb.GetScreenRequest) (*pb.GetScreenResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetScreenResponse{}, nil
	}

	resp := &pb.GetScreenResponse{}
	for name, profile := range cfg.Security.Screen {
		si := &pb.ScreenInfo{
			Name:   name,
			Checks: screenChecks(profile),
		}
		if si.Checks == nil {
			si.Checks = []string{}
		}
		resp.Screens = append(resp.Screens, si)
	}
	sort.Slice(resp.Screens, func(i, j int) bool { return resp.Screens[i].Name < resp.Screens[j].Name })
	return resp, nil
}

func (s *Server) GetEvents(_ context.Context, req *pb.GetEventsRequest) (*pb.GetEventsResponse, error) {
	if s.eventBuf == nil {
		return &pb.GetEventsResponse{}, nil
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Zone:     uint16(req.Zone),
		Action:   req.Action,
		Protocol: req.Protocol,
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	// Build reverse zone ID → name map
	evZoneNames := make(map[uint16]string)
	if cr := s.dp.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}

	resp := &pb.GetEventsResponse{}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.EventEntry{
			Time:            ev.Time.Format(time.RFC3339),
			Type:            ev.Type,
			SrcAddr:         ev.SrcAddr,
			DstAddr:         ev.DstAddr,
			Protocol:        ev.Protocol,
			Action:          ev.Action,
			PolicyId:        ev.PolicyID,
			IngressZone:     uint32(ev.InZone),
			EgressZone:      uint32(ev.OutZone),
			IngressZoneName: evZoneNames[ev.InZone],
			EgressZoneName:  evZoneNames[ev.OutZone],
			ScreenCheck:     ev.ScreenCheck,
			SessionPackets:  ev.SessionPkts,
			SessionBytes:    ev.SessionBytes,
		})
	}
	return resp, nil
}

func (s *Server) GetInterfaces(_ context.Context, _ *pb.GetInterfacesRequest) (*pb.GetInterfacesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetInterfacesResponse{}, nil
	}

	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	resp := &pb.GetInterfacesResponse{}
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		ii := &pb.InterfaceInfo{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			ii.Ifindex = int32(iface.Index)
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					ii.RxPackets = ctrs.RxPackets
					ii.RxBytes = ctrs.RxBytes
					ii.TxPackets = ctrs.TxPackets
					ii.TxBytes = ctrs.TxBytes
				}
			}
		}
		resp.Interfaces = append(resp.Interfaces, ii)
	}
	sort.Slice(resp.Interfaces, func(i, j int) bool { return resp.Interfaces[i].Name < resp.Interfaces[j].Name })
	return resp, nil
}

func (s *Server) ShowInterfacesDetail(_ context.Context, req *pb.ShowInterfacesDetailRequest) (*pb.ShowInterfacesDetailResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.ShowInterfacesDetailResponse{Output: "no active configuration\n"}, nil
	}

	filterName := req.Filter

	if req.Terse {
		return s.showInterfacesTerse(cfg, filterName)
	}

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZone[ifName] = zone
			ifaceZoneName[ifName] = name
		}
	}

	// Collect logical interfaces
	type logicalIface struct {
		zoneName string
		zone     *config.ZoneConfig
		physName string
		unitNum  int
		vlanID   int
	}
	var logicals []logicalIface

	for ifName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &unitNum)
		}
		vlanID := 0
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if unit, ok := ifCfg.Units[unitNum]; ok {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifName],
			zone:     zone,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	if len(logicals) == 0 && filterName != "" {
		return &pb.ShowInterfacesDetailResponse{Output: fmt.Sprintf("interface %s not found in configuration\n", filterName)}, nil
	}

	// Group by physical interface
	physGroups := make(map[string][]logicalIface)
	var physOrder []string
	for _, li := range logicals {
		if _, seen := physGroups[li.physName]; !seen {
			physOrder = append(physOrder, li.physName)
		}
		physGroups[li.physName] = append(physGroups[li.physName], li)
	}
	sort.Strings(physOrder)

	var buf strings.Builder
	for _, physName := range physOrder {
		group := physGroups[physName]

		iface, ifErr := net.InterfaceByName(physName)
		if ifErr != nil {
			fmt.Fprintf(&buf, "Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state
		linkUp := "Down"
		enabled := "Enabled"
		if iface.Flags&net.FlagUp != 0 {
			linkUp = "Up"
		}
		if iface.Flags&net.FlagUp == 0 {
			enabled = "Disabled"
		}
		// Try /sys/class/net for operstate
		if data, err := os.ReadFile("/sys/class/net/" + physName + "/operstate"); err == nil {
			state := strings.TrimSpace(string(data))
			if state == "up" {
				linkUp = "Up"
			} else if state == "down" {
				linkUp = "Down"
			}
		}

		fmt.Fprintf(&buf, "Physical interface: %s, %s, Physical link is %s\n", physName, enabled, linkUp)

		// Link-level details
		mtu := iface.MTU
		linkType := "Ethernet"
		speedStr := ""
		if raw, err := os.ReadFile("/sys/class/net/" + physName + "/speed"); err == nil {
			var mbps int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &mbps); err == nil && mbps > 0 {
				if mbps >= 1000 {
					speedStr = fmt.Sprintf(", Speed: %dGbps", mbps/1000)
				} else {
					speedStr = fmt.Sprintf(", Speed: %dMbps", mbps)
				}
			}
		}
		fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d%s\n", linkType, mtu, speedStr)

		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&buf, "  Current address: %s, Hardware address: %s\n", iface.HardwareAddr, iface.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if linkUp == "Up" {
			flags = append(flags, "Running")
		}
		if linkUp == "Down" {
			flags = append(flags, "Down")
		}
		fmt.Fprintf(&buf, "  Device flags   : %s\n", strings.Join(flags, " "))

		// VLAN tagging
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.VlanTagging {
			fmt.Fprintln(&buf, "  VLAN tagging: Enabled")
		}

		// Kernel link statistics via /sys/class/net
		s.writeKernelStats(&buf, physName)

		// BPF traffic counters
		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintln(&buf, "  BPF statistics:")
				fmt.Fprintf(&buf, "    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&buf, "    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Fprintf(&buf, "\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Fprintf(&buf, " VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Fprintln(&buf)

			fmt.Fprintf(&buf, "    Security: Zone: %s\n", li.zoneName)

			// Host-inbound traffic services
			if li.zone != nil && li.zone.HostInboundTraffic != nil {
				hit := li.zone.HostInboundTraffic
				if len(hit.SystemServices) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound traffic : %s\n", strings.Join(hit.SystemServices, " "))
				}
				if len(hit.Protocols) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound protocols: %s\n", strings.Join(hit.Protocols, " "))
				}
			}

			// DHCP annotations
			var unit *config.InterfaceUnit
			if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
				if u, ok := ifCfg.Units[li.unitNum]; ok {
					unit = u
				}
			}
			if unit != nil {
				if unit.DHCP {
					fmt.Fprintln(&buf, "    DHCPv4: enabled")
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Fprintf(&buf, "    DHCPv6: enabled%s\n", duidInfo)
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet6); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
			}

			// Addresses grouped by protocol
			liface, _ := net.InterfaceByName(lookupName)
			if liface == nil {
				liface = iface
			}
			if liface != nil {
				addrs, err := liface.Addrs()
				if err == nil && len(addrs) > 0 {
					var v4Addrs, v6Addrs []string
					for _, addr := range addrs {
						a := addr.String()
						ip, _, err := net.ParseCIDR(a)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							v4Addrs = append(v4Addrs, a)
						} else {
							v6Addrs = append(v6Addrs, a)
						}
					}
					if len(v4Addrs) > 0 {
						fmt.Fprintf(&buf, "    Protocol inet, MTU: %d\n", mtu)
						for _, a := range v4Addrs {
							fmt.Fprintln(&buf, "      Addresses, Flags: Is-Preferred Is-Primary")
							fmt.Fprintf(&buf, "        Local: %s\n", a)
						}
					}
					if len(v6Addrs) > 0 {
						fmt.Fprintf(&buf, "    Protocol inet6, MTU: %d\n", mtu)
						for _, a := range v6Addrs {
							fl := "Is-Preferred Is-Primary"
							if strings.HasPrefix(a, "fe80:") {
								fl = "Is-Preferred"
							}
							fmt.Fprintf(&buf, "      Addresses, Flags: %s\n", fl)
							fmt.Fprintf(&buf, "        Local: %s\n", a)
						}
					}
				}
			}
		}

		fmt.Fprintln(&buf)
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) showInterfacesTerse(cfg *config.Config, filterName string) (*pb.ShowInterfacesDetailResponse, error) {
	// Build zone mapping: interface name -> zone name
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	// Collect all configured interfaces with units
	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit
	seen := make(map[string]bool)
	for physName, ifCfg := range cfg.Interfaces.Interfaces {
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		seen[physName] = true
		for unitNum, unit := range ifCfg.Units {
			units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
		}
	}
	// Also include zone-only interfaces not in interfaces config
	for ifName := range ifaceZoneName {
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		if !seen[physName] {
			seen[physName] = true
			unitNum := 0
			if len(parts) == 2 {
				fmt.Sscanf(parts[1], "%d", &unitNum)
			}
			units = append(units, ifUnit{physName: physName, unitNum: unitNum})
		}
	}

	// Sort by physical name then unit number
	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	// Track which physical interfaces we've printed
	printedPhys := make(map[string]bool)

	for _, u := range units {
		// Print the physical interface line if not printed yet
		if !printedPhys[u.physName] {
			printedPhys[u.physName] = true
			admin := "up"
			link := "up"
			iface, err := net.InterfaceByName(u.physName)
			if err != nil {
				link = "down"
			} else {
				if iface.Flags&net.FlagUp == 0 {
					admin = "down"
				}
				// Read operstate from sysfs
				data, err := os.ReadFile("/sys/class/net/" + u.physName + "/operstate")
				if err == nil {
					state := strings.TrimSpace(string(data))
					if state != "up" {
						link = "down"
					}
				}
			}
			fmt.Fprintf(&buf, "%-24s%-6s%-6s\n", u.physName, admin, link)
		}

		// Determine the logical interface name
		logicalName := fmt.Sprintf("%s.%d", u.physName, u.unitNum)
		lookupName := u.physName
		if u.vlanID > 0 {
			lookupName = fmt.Sprintf("%s.%d", u.physName, u.vlanID)
		}

		// Get addresses for this logical interface
		var v4Addrs, v6Addrs []string
		liface, err := net.InterfaceByName(lookupName)
		if err != nil {
			// Try the physical interface for unit 0
			liface, err = net.InterfaceByName(u.physName)
		}
		if err == nil {
			addrs, _ := liface.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				addrStr := fmt.Sprintf("%s/%d", ipNet.IP, ones)
				if ipNet.IP.To4() != nil {
					v4Addrs = append(v4Addrs, addrStr)
				} else {
					v6Addrs = append(v6Addrs, addrStr)
				}
			}
		}

		admin := "up"
		link := "up"
		if liface == nil {
			link = "down"
		} else {
			if liface.Flags&net.FlagUp == 0 {
				admin = "down"
			}
		}

		// Print logical interface with first protocol/address
		firstProto := ""
		firstAddr := ""
		if len(v4Addrs) > 0 {
			firstProto = "inet"
			firstAddr = v4Addrs[0]
		} else if len(v6Addrs) > 0 {
			firstProto = "inet6"
			firstAddr = v6Addrs[0]
		}

		fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		// Print remaining v4 addresses
		if len(v4Addrs) > 1 {
			for _, a := range v4Addrs[1:] {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet", a)
			}
		}

		// Print v6 addresses (if v4 was first)
		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		if firstProto == "inet" {
			startIdx = 0
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) writeKernelStats(buf *strings.Builder, ifaceName string) {
	readStat := func(name string) uint64 {
		data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/%s", ifaceName, name))
		if err != nil {
			return 0
		}
		var v uint64
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
		return v
	}
	rxPkts := readStat("rx_packets")
	rxBytes := readStat("rx_bytes")
	txPkts := readStat("tx_packets")
	txBytes := readStat("tx_bytes")
	fmt.Fprintf(buf, "  Input rate     : %d packets, %d bytes\n", rxPkts, rxBytes)
	fmt.Fprintf(buf, "  Output rate    : %d packets, %d bytes\n", txPkts, txBytes)
	rxErr := readStat("rx_errors")
	txErr := readStat("tx_errors")
	if rxErr > 0 || txErr > 0 {
		fmt.Fprintf(buf, "  Errors         : %d input, %d output\n", rxErr, txErr)
	}
	rxDrop := readStat("rx_dropped")
	txDrop := readStat("tx_dropped")
	if rxDrop > 0 || txDrop > 0 {
		fmt.Fprintf(buf, "  Drops          : %d input, %d output\n", rxDrop, txDrop)
	}
}

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
	case "database":
		output, err = s.frr.GetOSPFDatabase()
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
	case "routes":
		output, err := s.frr.GetISISRoutes()
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

// --- Diagnostic RPCs ---

func (s *Server) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	if req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target required")
	}
	count := int(req.Count)
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}
	args := []string{"-c", fmt.Sprintf("%d", count)}
	if req.Source != "" {
		args = append(args, "-I", req.Source)
	}
	if req.Size > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", req.Size))
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		cmd = append(cmd, "ip", "vrf", "exec", req.RoutingInstance)
	}
	cmd = append(cmd, "ping")
	cmd = append(cmd, args...)

	out, err := execDiagCmd(ctx, cmd)
	if err != nil {
		return &pb.PingResponse{Output: out + "\n" + err.Error()}, nil
	}
	return &pb.PingResponse{Output: out}, nil
}

func (s *Server) Traceroute(ctx context.Context, req *pb.TracerouteRequest) (*pb.TracerouteResponse, error) {
	if req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target required")
	}
	args := []string{}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		cmd = append(cmd, "ip", "vrf", "exec", req.RoutingInstance)
	}
	cmd = append(cmd, "traceroute")
	cmd = append(cmd, args...)

	out, err := execDiagCmd(ctx, cmd)
	if err != nil {
		return &pb.TracerouteResponse{Output: out + "\n" + err.Error()}, nil
	}
	return &pb.TracerouteResponse{Output: out}, nil
}

func execDiagCmd(ctx context.Context, cmd []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// --- Mutation RPCs ---

func (s *Server) ClearSessions(_ context.Context, _ *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	v4, v6, err := s.dp.ClearAllSessions()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.ClearSessionsResponse{
		Ipv4Cleared: int32(v4),
		Ipv6Cleared: int32(v6),
	}, nil
}

func (s *Server) ClearCounters(_ context.Context, _ *pb.ClearCountersRequest) (*pb.ClearCountersResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	if err := s.dp.ClearAllCounters(); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.ClearCountersResponse{}, nil
}

// --- Completion RPC ---

func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
	text := req.Line
	if int(req.Pos) < len(text) {
		text = text[:req.Pos]
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var candidates []string
	if req.ConfigMode {
		candidates = s.completeConfig(words, partial)
	} else {
		candidates = s.completeOperational(words, partial)
	}

	sort.Strings(candidates)
	return &pb.CompleteResponse{Candidates: candidates}, nil
}

func (s *Server) completeOperational(words []string, partial string) []string {
	cfg := s.store.ActiveConfig()
	return completeFromTree(operationalTree, words, partial, cfg)
}

func (s *Server) completeConfig(words []string, partial string) []string {
	if len(words) == 0 {
		return filterPrefix(keysOf(configTopLevel), partial)
	}

	switch words[0] {
	case "set", "delete":
		schemaCompletions := config.CompleteSetPathWithValues(words[1:], s.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		return filterPrefix(schemaCompletions, partial)
	case "run":
		cfg := s.store.ActiveConfig()
		return completeFromTree(operationalTree, words[1:], partial, cfg)
	case "commit":
		if len(words) == 1 {
			return filterPrefix([]string{"check", "confirmed"}, partial)
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) valueProvider(hint config.ValueHint) []string {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		names := make([]string, 0, len(cfg.Security.Zones))
		for name := range cfg.Security.Zones {
			names = append(names, name)
		}
		return names
	case config.ValueHintAddressName:
		var names []string
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				names = append(names, addr.Name)
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				names = append(names, as.Name)
			}
		}
		return names
	case config.ValueHintAppName:
		var names []string
		for _, app := range cfg.Applications.Applications {
			names = append(names, app.Name)
		}
		for _, as := range cfg.Applications.ApplicationSets {
			names = append(names, as.Name)
		}
		for name := range config.PredefinedApplications {
			names = append(names, name)
		}
		return names
	case config.ValueHintAppSetName:
		var names []string
		for _, as := range cfg.Applications.ApplicationSets {
			names = append(names, as.Name)
		}
		return names
	case config.ValueHintPoolName:
		var names []string
		for name := range cfg.Security.NAT.SourcePools {
			names = append(names, name)
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				names = append(names, name)
			}
		}
		return names
	case config.ValueHintScreenProfile:
		names := make([]string, 0, len(cfg.Security.Screen))
		for name := range cfg.Security.Screen {
			names = append(names, name)
		}
		return names
	case config.ValueHintStreamName:
		names := make([]string, 0, len(cfg.Security.Log.Streams))
		for name := range cfg.Security.Log.Streams {
			names = append(names, name)
		}
		return names
	case config.ValueHintInterfaceName:
		var names []string
		for _, zone := range cfg.Security.Zones {
			names = append(names, zone.Interfaces...)
		}
		return names
	}
	return nil
}

// --- shared command trees (same as cli.go) ---

type completionNode struct {
	desc      string
	children  map[string]*completionNode
	dynamicFn func(cfg *config.Config) []string
}

var operationalTree = map[string]*completionNode{
	"configure": {desc: "Enter configuration mode"},
	"ping":       {desc: "Ping remote host"},
	"traceroute": {desc: "Trace route to remote host"},
	"show": {desc: "Show information", children: map[string]*completionNode{
		"configuration": {desc: "Show active configuration"},
		"dhcp": {desc: "Show DHCP information", children: map[string]*completionNode{
			"leases":            {desc: "Show DHCP leases"},
			"client-identifier": {desc: "Show DHCPv6 DUID(s)"},
			"relay":             {desc: "Show DHCP relay status"},
		}},
		"route": {desc: "Show routing table", children: map[string]*completionNode{
			"instance": {desc: "Show routes for a routing instance", dynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.RoutingInstances))
				for _, ri := range cfg.RoutingInstances {
					names = append(names, ri.Name)
				}
				return names
			}},
		}},
		"schedulers": {desc: "Show policy schedulers"},
		"snmp":       {desc: "Show SNMP statistics"},
		"security": {desc: "Show security information", children: map[string]*completionNode{
			"zones": {desc: "Show security zones", dynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}},
			"policies": {desc: "Show security policies", children: map[string]*completionNode{
				"brief": {desc: "Show brief policy summary"},
			}},
			"screen": {desc: "Show screen/IDS profiles"},
			"flow": {desc: "Show flow information", children: map[string]*completionNode{
				"session": {desc: "Show active sessions"},
			}},
			"nat": {desc: "Show NAT information", children: map[string]*completionNode{
				"source":      {desc: "Show source NAT"},
				"destination": {desc: "Show destination NAT"},
				"static":      {desc: "Show static NAT"},
			}},
			"address-book":   {desc: "Show address book entries"},
			"applications":   {desc: "Show application definitions"},
			"alg":            {desc: "Show ALG status"},
			"dynamic-address": {desc: "Show dynamic address feeds"},
			"log":            {desc: "Show recent security events"},
			"statistics":     {desc: "Show global statistics"},
			"ipsec": {desc: "Show IPsec status", children: map[string]*completionNode{
				"security-associations": {desc: "Show IPsec SAs"},
			}},
			"vrrp":           {desc: "Show VRRP high availability status"},
			"match-policies": {desc: "Match 5-tuple against policies"},
		}},
		"interfaces": {desc: "Show interface status", dynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, children: map[string]*completionNode{
			"tunnel": {desc: "Show tunnel interfaces"},
		}},
		"protocols": {desc: "Show protocol information", children: map[string]*completionNode{
			"ospf": {desc: "Show OSPF information", children: map[string]*completionNode{
				"neighbor": {desc: "Show OSPF neighbors"},
				"database": {desc: "Show OSPF database"},
			}},
			"bgp": {desc: "Show BGP information", children: map[string]*completionNode{
				"summary": {desc: "Show BGP peer summary"},
				"routes":  {desc: "Show BGP routes"},
			}},
			"rip":  {desc: "Show RIP routes"},
			"isis": {desc: "Show IS-IS information", children: map[string]*completionNode{
				"adjacency": {desc: "Show IS-IS adjacencies"},
				"routes":    {desc: "Show IS-IS routes"},
			}},
		}},
		"flow-monitoring": {desc: "Show flow monitoring/NetFlow configuration"},
		"firewall":        {desc: "Show firewall filters"},
		"dhcp-relay":      {desc: "Show DHCP relay status"},
		"system": {desc: "Show system information", children: map[string]*completionNode{
			"alarms":              {desc: "Show system alarms"},
			"internet-options":    {desc: "Show internet options"},
			"login":              {desc: "Show configured login users"},
			"ntp":                {desc: "Show NTP server status"},
			"rollback":           {desc: "Show rollback history"},
			"root-authentication": {desc: "Show root authentication"},
			"services":           {desc: "Show system services"},
			"storage":            {desc: "Show filesystem usage"},
			"syslog":             {desc: "Show system syslog configuration"},
			"uptime":             {desc: "Show system uptime"},
			"memory":             {desc: "Show memory usage"},
			"processes":          {desc: "Show running processes"},
			"license":            {desc: "Show system license"},
		}},
	}},
	"request": {desc: "Perform system operations", children: map[string]*completionNode{
		"system": {desc: "System operations", children: map[string]*completionNode{
			"reboot": {desc: "Reboot the system"},
			"halt":   {desc: "Halt the system"},
		}},
	}},
	"clear": {desc: "Clear information", children: map[string]*completionNode{
		"security": {desc: "Clear security information", children: map[string]*completionNode{
			"flow": {desc: "Clear flow information", children: map[string]*completionNode{
				"session": {desc: "Clear all sessions"},
			}},
			"counters": {desc: "Clear all counters"},
			"nat": {desc: "Clear NAT information", children: map[string]*completionNode{
				"source": {desc: "Clear source NAT", children: map[string]*completionNode{
					"persistent-nat-table": {desc: "Clear persistent NAT bindings"},
				}},
			}},
		}},
		"dhcp": {desc: "Clear DHCP information", children: map[string]*completionNode{
			"client-identifier": {desc: "Clear DHCPv6 DUID(s)"},
		}},
	}},
	"quit": {desc: "Exit CLI"},
	"exit": {desc: "Exit CLI"},
}

var configTopLevel = map[string]*completionNode{
	"set":    {desc: "Set a configuration value"},
	"delete": {desc: "Delete a configuration element"},
	"show":   {desc: "Show candidate configuration"},
	"commit": {desc: "Commit configuration", children: map[string]*completionNode{
		"check":     {desc: "Validate without applying"},
		"confirmed": {desc: "Auto-rollback if not confirmed"},
	}},
	"rollback": {desc: "Revert to previous configuration"},
	"run":      {desc: "Run operational command"},
	"exit":     {desc: "Exit configuration mode"},
	"quit":     {desc: "Exit configuration mode"},
}

func completeFromTree(tree map[string]*completionNode, words []string, partial string, cfg *config.Config) []string {
	current := tree
	var currentNode *completionNode
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil // dynamic value typed — no further completions
		}
		currentNode = node
		if node.children == nil {
			// Leaf node — only offer dynamic values if present.
			if node.dynamicFn != nil && cfg != nil {
				return filterPrefix(node.dynamicFn(cfg), partial)
			}
			return nil
		}
		current = node.children
	}
	candidates := keysOf(current)
	if currentNode != nil && currentNode.dynamicFn != nil && cfg != nil {
		candidates = append(candidates, currentNode.dynamicFn(cfg)...)
	}
	return filterPrefix(candidates, partial)
}

func keysOf(m map[string]*completionNode) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func filterPrefix(items []string, prefix string) []string {
	if prefix == "" {
		return items
	}
	var result []string
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return result
}

// --- helpers ---

func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			names[ifName] = true
		}
	}
	return names
}

func policyActionStr(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, v)
	return ip
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, zoneNames map[uint16]string) *pb.SessionEntry {
	se := &pb.SessionEntry{
		SrcAddr:         net.IP(key.SrcIP[:]).String(),
		DstAddr:         net.IP(key.DstIP[:]).String(),
		SrcPort:         uint32(ntohs(key.SrcPort)),
		DstPort:         uint32(ntohs(key.DstPort)),
		Protocol:        protoName(key.Protocol),
		State:           sessionStateName(val.State),
		PolicyId:        val.PolicyID,
		IngressZone:     uint32(val.IngressZone),
		EgressZone:      uint32(val.EgressZone),
		IngressZoneName: zoneNames[val.IngressZone],
		EgressZoneName:  zoneNames[val.EgressZone],
		FwdPackets:     val.FwdPackets,
		FwdBytes:       val.FwdBytes,
		RevPackets:     val.RevPackets,
		RevBytes:       val.RevBytes,
		TimeoutSeconds: val.Timeout,
	}
	if val.Created > 0 && now > val.Created {
		se.AgeSeconds = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.IdleSeconds = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.Nat = fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.Nat = fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort))
	}
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, zoneNames map[uint16]string) *pb.SessionEntry {
	se := &pb.SessionEntry{
		SrcAddr:         net.IP(key.SrcIP[:]).String(),
		DstAddr:         net.IP(key.DstIP[:]).String(),
		SrcPort:         uint32(ntohs(key.SrcPort)),
		DstPort:         uint32(ntohs(key.DstPort)),
		Protocol:        protoName(key.Protocol),
		State:           sessionStateName(val.State),
		PolicyId:        val.PolicyID,
		IngressZone:     uint32(val.IngressZone),
		EgressZone:      uint32(val.EgressZone),
		IngressZoneName: zoneNames[val.IngressZone],
		EgressZoneName:  zoneNames[val.EgressZone],
		FwdPackets:     val.FwdPackets,
		FwdBytes:       val.FwdBytes,
		RevPackets:     val.RevPackets,
		RevBytes:       val.RevBytes,
		TimeoutSeconds: val.Timeout,
	}
	if val.Created > 0 && now > val.Created {
		se.AgeSeconds = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.IdleSeconds = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.Nat = fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.Nat = fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort))
	}
	return se
}

func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

func screenChecks(p *config.ScreenProfile) []string {
	var checks []string
	if p.TCP.SynFlood != nil {
		checks = append(checks, "syn-flood")
	}
	if p.TCP.Land {
		checks = append(checks, "land")
	}
	if p.TCP.WinNuke {
		checks = append(checks, "winnuke")
	}
	if p.TCP.SynFrag {
		checks = append(checks, "syn-frag")
	}
	if p.TCP.SynFin {
		checks = append(checks, "syn-fin")
	}
	if p.TCP.NoFlag {
		checks = append(checks, "tcp-no-flag")
	}
	if p.TCP.FinNoAck {
		checks = append(checks, "fin-no-ack")
	}
	if p.ICMP.PingDeath {
		checks = append(checks, "ping-death")
	}
	if p.ICMP.FloodThreshold > 0 {
		checks = append(checks, "icmp-flood")
	}
	if p.UDP.FloodThreshold > 0 {
		checks = append(checks, "udp-flood")
	}
	if p.IP.SourceRouteOption {
		checks = append(checks, "source-route-option")
	}
	if p.IP.TearDrop {
		checks = append(checks, "tear-drop")
	}
	return checks
}

func (s *Server) GetNATPoolStats(_ context.Context, _ *pb.GetNATPoolStatsRequest) (*pb.GetNATPoolStatsResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATPoolStatsResponse{}, nil
	}

	resp := &pb.GetNATPoolStatsResponse{}

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := int32((portHigh - portLow + 1) * len(pool.Addresses))
		used := int32(0)

		if s.dp != nil && s.dp.IsLoaded() {
			if cr := s.dp.LastCompileResult(); cr != nil {
				if id, ok := cr.PoolIDs[name]; ok {
					cnt, err := s.dp.ReadNATPortCounter(uint32(id))
					if err == nil {
						used = int32(cnt)
					}
				}
			}
		}

		avail := totalPorts - used
		if avail < 0 {
			avail = 0
		}
		util := "0.0%"
		if totalPorts > 0 {
			util = fmt.Sprintf("%.1f%%", float64(used)/float64(totalPorts)*100)
		}

		resp.Pools = append(resp.Pools, &pb.NATPoolStats{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     totalPorts,
			UsedPorts:      used,
			AvailablePorts: avail,
			Utilization:    util,
		})
	}

	// Interface-mode pools
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				used := int32(0)
				if s.dp != nil && s.dp.IsLoaded() {
					_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
						if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
							used++
						}
						return true
					})
				}
				resp.Pools = append(resp.Pools, &pb.NATPoolStats{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   used,
					IsInterface: true,
				})
			}
		}
	}

	return resp, nil
}

func (s *Server) GetNATRuleStats(_ context.Context, req *pb.GetNATRuleStatsRequest) (*pb.GetNATRuleStatsResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATRuleStatsResponse{}, nil
	}

	resp := &pb.GetNATRuleStatsResponse{}
	for _, rs := range cfg.Security.NAT.Source {
		if req.RuleSet != "" && rs.Name != req.RuleSet {
			continue
		}
		for _, rule := range rs.Rules {
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			var hitPkts, hitBytes uint64
			if s.dp != nil && s.dp.IsLoaded() {
				if cr := s.dp.LastCompileResult(); cr != nil {
					ruleKey := rs.Name + "/" + rule.Name
					if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
						cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
						if err == nil {
							hitPkts = cnt.Packets
							hitBytes = cnt.Bytes
						}
					}
				}
			}

			resp.Rules = append(resp.Rules, &pb.NATRuleStats{
				RuleSet:          rs.Name,
				RuleName:         rule.Name,
				FromZone:         rs.FromZone,
				ToZone:           rs.ToZone,
				Action:           action,
				SourceMatch:      srcMatch,
				DestinationMatch: dstMatch,
				HitPackets:       hitPkts,
				HitBytes:         hitBytes,
			})
		}
	}

	return resp, nil
}

func (s *Server) GetVRRPStatus(_ context.Context, _ *pb.GetVRRPStatusRequest) (*pb.GetVRRPStatusResponse, error) {
	cfg := s.store.ActiveConfig()
	resp := &pb.GetVRRPStatusResponse{}

	if cfg != nil {
		instances := vrrp.CollectInstances(cfg)
		runtimeStates := vrrp.RuntimeStates(instances)
		for _, inst := range instances {
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
			state := runtimeStates[key]
			if state == "" {
				state = "INIT"
			}
			resp.Instances = append(resp.Instances, &pb.VRRPInstanceInfo{
				Interface:        inst.Interface,
				GroupId:          int32(inst.GroupID),
				State:            state,
				Priority:         int32(inst.Priority),
				VirtualAddresses: inst.VirtualAddresses,
				Preempt:          inst.Preempt,
			})
		}
	}

	status, _ := vrrp.Status()
	resp.ServiceStatus = status

	return resp, nil
}

func (s *Server) MatchPolicies(_ context.Context, req *pb.MatchPoliciesRequest) (*pb.MatchPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.MatchPoliciesResponse{}, nil
	}

	parsedSrc := net.ParseIP(req.SourceIp)
	parsedDst := net.ParseIP(req.DestinationIp)
	dstPort := int(req.DestinationPort)

	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != req.FromZone || zpp.ToZone != req.ToZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
				continue
			}
			if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
				continue
			}
			if !matchPolicyApp(pol.Match.Applications, req.Protocol, dstPort, cfg) {
				continue
			}

			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}

			return &pb.MatchPoliciesResponse{
				Matched:      true,
				PolicyName:   pol.Name,
				Action:       action,
				SrcAddresses: pol.Match.SourceAddresses,
				DstAddresses: pol.Match.DestinationAddresses,
				Applications: pol.Match.Applications,
			}, nil
		}
	}

	return &pb.MatchPoliciesResponse{
		Matched: false,
		Action:  "deny (default)",
	}, nil
}

// --- ShowText RPC ---

func (s *Server) ShowText(_ context.Context, req *pb.ShowTextRequest) (*pb.ShowTextResponse, error) {
	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	switch req.Topic {
	case "schedulers":
		if cfg == nil || len(cfg.Schedulers) == 0 {
			buf.WriteString("No schedulers configured\n")
		} else {
			for name, sched := range cfg.Schedulers {
				fmt.Fprintf(&buf, "Scheduler: %s\n", name)
				if sched.StartTime != "" {
					fmt.Fprintf(&buf, "  Start time: %s\n", sched.StartTime)
				}
				if sched.StopTime != "" {
					fmt.Fprintf(&buf, "  Stop time:  %s\n", sched.StopTime)
				}
				if sched.StartDate != "" {
					fmt.Fprintf(&buf, "  Start date: %s\n", sched.StartDate)
				}
				if sched.StopDate != "" {
					fmt.Fprintf(&buf, "  Stop date:  %s\n", sched.StopDate)
				}
				if sched.Daily {
					buf.WriteString("  Recurrence: daily\n")
				}
				buf.WriteString("\n")
			}
		}

	case "snmp":
		if cfg == nil || cfg.System.SNMP == nil {
			buf.WriteString("No SNMP configured\n")
		} else {
			snmpCfg := cfg.System.SNMP
			if snmpCfg.Location != "" {
				fmt.Fprintf(&buf, "Location:    %s\n", snmpCfg.Location)
			}
			if snmpCfg.Contact != "" {
				fmt.Fprintf(&buf, "Contact:     %s\n", snmpCfg.Contact)
			}
			if snmpCfg.Description != "" {
				fmt.Fprintf(&buf, "Description: %s\n", snmpCfg.Description)
			}
			if len(snmpCfg.Communities) > 0 {
				buf.WriteString("Communities:\n")
				for name, comm := range snmpCfg.Communities {
					fmt.Fprintf(&buf, "  %s: %s\n", name, comm.Authorization)
				}
			}
			if len(snmpCfg.TrapGroups) > 0 {
				buf.WriteString("Trap groups:\n")
				for name, tg := range snmpCfg.TrapGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
				}
			}
		}

	case "dhcp-server":
		if s.dhcpServer == nil || !s.dhcpServer.IsRunning() {
			buf.WriteString("DHCP server not running\n")
		} else {
			leases4, _ := s.dhcpServer.GetLeases4()
			leases6, _ := s.dhcpServer.GetLeases6()
			if len(leases4) == 0 && len(leases6) == 0 {
				buf.WriteString("No active leases\n")
			}
			if len(leases4) > 0 {
				buf.WriteString("DHCPv4 Leases:\n")
				fmt.Fprintf(&buf, "  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
				for _, l := range leases4 {
					fmt.Fprintf(&buf, "  %-18s %-20s %-15s %-12s %s\n",
						l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
				}
			}
			if len(leases6) > 0 {
				buf.WriteString("DHCPv6 Leases:\n")
				fmt.Fprintf(&buf, "  %-40s %-20s %-15s %-12s %s\n", "Address", "DUID", "Hostname", "Lifetime", "Expires")
				for _, l := range leases6 {
					fmt.Fprintf(&buf, "  %-40s %-20s %-15s %-12s %s\n",
						l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
				}
			}
		}

	case "dhcp-relay":
		if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
			buf.WriteString("No DHCP relay configured\n")
		} else {
			relay := cfg.ForwardingOptions.DHCPRelay
			if len(relay.ServerGroups) > 0 {
				buf.WriteString("Server groups:\n")
				for name, sg := range relay.ServerGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
				}
			}
			if len(relay.Groups) > 0 {
				buf.WriteString("Relay groups:\n")
				for name, g := range relay.Groups {
					fmt.Fprintf(&buf, "  %s:\n", name)
					fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
					fmt.Fprintf(&buf, "    Active server group: %s\n", g.ActiveServerGroup)
				}
			}
		}

	case "firewall":
		hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
		if !hasFilters {
			buf.WriteString("No firewall filters configured\n")
		} else {
			printFilters := func(family string, filters map[string]*config.FirewallFilter) {
				names := make([]string, 0, len(filters))
				for name := range filters {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					filter := filters[name]
					fmt.Fprintf(&buf, "Filter: %s (family %s)\n", name, family)
					for _, term := range filter.Terms {
						fmt.Fprintf(&buf, "  Term: %s\n", term.Name)
						if term.DSCP != "" {
							fmt.Fprintf(&buf, "    from dscp %s\n", term.DSCP)
						}
						if term.Protocol != "" {
							fmt.Fprintf(&buf, "    from protocol %s\n", term.Protocol)
						}
						for _, addr := range term.SourceAddresses {
							fmt.Fprintf(&buf, "    from source-address %s\n", addr)
						}
						for _, pl := range term.SourcePrefixLists {
							if pl.Except {
								fmt.Fprintf(&buf, "    from source-prefix-list %s except\n", pl.Name)
							} else {
								fmt.Fprintf(&buf, "    from source-prefix-list %s\n", pl.Name)
							}
						}
						for _, addr := range term.DestAddresses {
							fmt.Fprintf(&buf, "    from destination-address %s\n", addr)
						}
						for _, pl := range term.DestPrefixLists {
							if pl.Except {
								fmt.Fprintf(&buf, "    from destination-prefix-list %s except\n", pl.Name)
							} else {
								fmt.Fprintf(&buf, "    from destination-prefix-list %s\n", pl.Name)
							}
						}
						if len(term.SourcePorts) > 0 {
							fmt.Fprintf(&buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
						}
						if len(term.DestinationPorts) > 0 {
							fmt.Fprintf(&buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
						}
						if term.ICMPType >= 0 {
							fmt.Fprintf(&buf, "    from icmp-type %d\n", term.ICMPType)
						}
						if term.ICMPCode >= 0 {
							fmt.Fprintf(&buf, "    from icmp-code %d\n", term.ICMPCode)
						}
						if term.RoutingInstance != "" {
							fmt.Fprintf(&buf, "    then routing-instance %s\n", term.RoutingInstance)
						}
						if term.Log {
							buf.WriteString("    then log\n")
						}
						if term.Count != "" {
							fmt.Fprintf(&buf, "    then count %s\n", term.Count)
						}
						if term.ForwardingClass != "" {
							fmt.Fprintf(&buf, "    then forwarding-class %s\n", term.ForwardingClass)
						}
						if term.LossPriority != "" {
							fmt.Fprintf(&buf, "    then loss-priority %s\n", term.LossPriority)
						}
						action := term.Action
						if action == "" {
							action = "accept"
						}
						fmt.Fprintf(&buf, "    then %s\n", action)
					}
					buf.WriteString("\n")
				}
			}
			printFilters("inet", cfg.Firewall.FiltersInet)
			printFilters("inet6", cfg.Firewall.FiltersInet6)
		}

	case "alg":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			alg := cfg.Security.ALG
			fmt.Fprintf(&buf, "SIP:  %s\n", boolStatus(!alg.SIPDisable))
			fmt.Fprintf(&buf, "FTP:  %s\n", boolStatus(!alg.FTPDisable))
			fmt.Fprintf(&buf, "TFTP: %s\n", boolStatus(!alg.TFTPDisable))
			fmt.Fprintf(&buf, "DNS:  %s\n", boolStatus(!alg.DNSDisable))
		}

	case "dynamic-address":
		if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
			buf.WriteString("No dynamic address feeds configured\n")
		} else {
			for name, feed := range cfg.Security.DynamicAddress.FeedServers {
				fmt.Fprintf(&buf, "Feed server: %s\n", name)
				fmt.Fprintf(&buf, "  URL: %s\n", feed.URL)
				if feed.FeedName != "" {
					fmt.Fprintf(&buf, "  Feed name: %s\n", feed.FeedName)
				}
				if feed.UpdateInterval > 0 {
					fmt.Fprintf(&buf, "  Update interval: %ds\n", feed.UpdateInterval)
				}
				if feed.HoldInterval > 0 {
					fmt.Fprintf(&buf, "  Hold interval: %ds\n", feed.HoldInterval)
				}
				buf.WriteString("\n")
			}
		}

	case "address-book":
		if cfg == nil || cfg.Security.AddressBook == nil {
			buf.WriteString("No address book configured\n")
		} else {
			ab := cfg.Security.AddressBook
			if len(ab.Addresses) > 0 {
				buf.WriteString("Addresses:\n")
				for name, addr := range ab.Addresses {
					fmt.Fprintf(&buf, "  %-20s %s\n", name, addr.Value)
				}
			}
			if len(ab.AddressSets) > 0 {
				buf.WriteString("Address sets:\n")
				for name, as := range ab.AddressSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
				}
			}
		}

	case "applications":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			if len(cfg.Applications.Applications) > 0 {
				buf.WriteString("Applications:\n")
				for name, app := range cfg.Applications.Applications {
					fmt.Fprintf(&buf, "  %-20s proto=%-6s", name, app.Protocol)
					if app.DestinationPort != "" {
						fmt.Fprintf(&buf, " dst-port=%s", app.DestinationPort)
					}
					buf.WriteString("\n")
				}
			}
			if len(cfg.Applications.ApplicationSets) > 0 {
				buf.WriteString("Application sets:\n")
				for name, as := range cfg.Applications.ApplicationSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Applications, ", "))
				}
			}
		}

	case "flow-monitoring":
		if cfg == nil || cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
			buf.WriteString("No flow monitoring configured\n")
		} else {
			v9 := cfg.Services.FlowMonitoring.Version9
			buf.WriteString("Flow monitoring (NetFlow v9):\n")
			for name, tmpl := range v9.Templates {
				fmt.Fprintf(&buf, "  Template: %s\n", name)
				if tmpl.FlowActiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
				}
				if tmpl.FlowInactiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
				}
				if tmpl.TemplateRefreshRate > 0 {
					fmt.Fprintf(&buf, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
				}
			}
		}

	case "flow-timeouts":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			flow := cfg.Security.Flow
			buf.WriteString("Flow session timeouts:\n")
			if flow.TCPSession != nil {
				fmt.Fprintf(&buf, "  TCP established:      %ds\n", flow.TCPSession.EstablishedTimeout)
				fmt.Fprintf(&buf, "  TCP initial:          %ds\n", flow.TCPSession.InitialTimeout)
				fmt.Fprintf(&buf, "  TCP closing:          %ds\n", flow.TCPSession.ClosingTimeout)
				fmt.Fprintf(&buf, "  TCP time-wait:        %ds\n", flow.TCPSession.TimeWaitTimeout)
			}
			fmt.Fprintf(&buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
			fmt.Fprintf(&buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
			if flow.TCPMSSIPsecVPN > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (IPsec VPN):  %d\n", flow.TCPMSSIPsecVPN)
			}
			if flow.TCPMSSGre > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE):        %d\n", flow.TCPMSSGre)
			}
			if flow.AllowDNSReply {
				buf.WriteString("  Allow DNS reply:      enabled\n")
			}
			if flow.AllowEmbeddedICMP {
				buf.WriteString("  Allow embedded ICMP:  enabled\n")
			}
			if flow.GREPerformanceAcceleration {
				buf.WriteString("  GRE acceleration:     enabled\n")
			}
			if flow.PowerModeDisable {
				buf.WriteString("  Power mode:           disabled\n")
			}
		}

	case "flow-statistics":
		if s.dp == nil || !s.dp.IsLoaded() {
			buf.WriteString("Flow statistics: dataplane not loaded\n")
		} else {
			ctrMap := s.dp.Map("global_counters")
			if ctrMap == nil {
				buf.WriteString("Flow statistics: global_counters map not found\n")
			} else {
				readCtr := func(idx uint32) uint64 {
					var perCPU []uint64
					if err := ctrMap.Lookup(idx, &perCPU); err != nil {
						return 0
					}
					var total uint64
					for _, v := range perCPU {
						total += v
					}
					return total
				}
				sessNew := readCtr(dataplane.GlobalCtrSessionsNew)
				sessClosed := readCtr(dataplane.GlobalCtrSessionsClosed)
				buf.WriteString("Flow statistics:\n")
				fmt.Fprintf(&buf, "  %-30s %d\n", "Current sessions:", sessNew-sessClosed)
				fmt.Fprintf(&buf, "  %-30s %d\n", "Sessions created:", sessNew)
				fmt.Fprintf(&buf, "  %-30s %d\n", "Sessions closed:", sessClosed)
				buf.WriteString("\n")
				fmt.Fprintf(&buf, "  %-30s %d\n", "Packets received:", readCtr(dataplane.GlobalCtrRxPackets))
				fmt.Fprintf(&buf, "  %-30s %d\n", "Packets transmitted:", readCtr(dataplane.GlobalCtrTxPackets))
				fmt.Fprintf(&buf, "  %-30s %d\n", "Packets dropped:", readCtr(dataplane.GlobalCtrDrops))
				fmt.Fprintf(&buf, "  %-30s %d\n", "TC egress packets:", readCtr(dataplane.GlobalCtrTCEgressPackets))
				buf.WriteString("\n")
				fmt.Fprintf(&buf, "  %-30s %d\n", "Policy deny:", readCtr(dataplane.GlobalCtrPolicyDeny))
				fmt.Fprintf(&buf, "  %-30s %d\n", "NAT allocation failures:", readCtr(dataplane.GlobalCtrNATAllocFail))
				fmt.Fprintf(&buf, "  %-30s %d\n", "Screen drops:", readCtr(dataplane.GlobalCtrScreenDrops))
				fmt.Fprintf(&buf, "  %-30s %d\n", "Host-inbound denies:", readCtr(dataplane.GlobalCtrHostInboundDeny))
				fmt.Fprintf(&buf, "  %-30s %d\n", "Host-inbound allowed:", readCtr(dataplane.GlobalCtrHostInbound))
				fmt.Fprintf(&buf, "  %-30s %d\n", "NAT64 translations:", readCtr(dataplane.GlobalCtrNAT64Xlate))
			}
		}

	case "flow-traceoptions":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			opts := cfg.Security.Flow.Traceoptions
			if opts == nil || opts.File == "" {
				buf.WriteString("Flow traceoptions: not configured\n")
			} else {
				buf.WriteString("Flow traceoptions:\n")
				fmt.Fprintf(&buf, "  File:           %s\n", opts.File)
				if opts.FileSize > 0 {
					fmt.Fprintf(&buf, "  File size:      %d bytes\n", opts.FileSize)
				}
				if opts.FileCount > 0 {
					fmt.Fprintf(&buf, "  File count:     %d\n", opts.FileCount)
				}
				if len(opts.Flags) > 0 {
					fmt.Fprintf(&buf, "  Flags:          %s\n", strings.Join(opts.Flags, ", "))
				}
				if len(opts.PacketFilters) > 0 {
					buf.WriteString("  Packet filters:\n")
					for _, pf := range opts.PacketFilters {
						fmt.Fprintf(&buf, "    %s:", pf.Name)
						if pf.SourcePrefix != "" {
							fmt.Fprintf(&buf, " src=%s", pf.SourcePrefix)
						}
						if pf.DestinationPrefix != "" {
							fmt.Fprintf(&buf, " dst=%s", pf.DestinationPrefix)
						}
						buf.WriteString("\n")
					}
				}
			}
		}

	case "nat-static":
		if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
			buf.WriteString("No static NAT rules configured.\n")
		} else {
			for _, rs := range cfg.Security.NAT.Static {
				fmt.Fprintf(&buf, "Static NAT rule-set: %s\n", rs.Name)
				fmt.Fprintf(&buf, "  From zone: %s\n", rs.FromZone)
				for _, rule := range rs.Rules {
					fmt.Fprintf(&buf, "  Rule: %s\n", rule.Name)
					fmt.Fprintf(&buf, "    Match destination-address: %s\n", rule.Match)
					fmt.Fprintf(&buf, "    Then static-nat prefix:    %s\n", rule.Then)
				}
				buf.WriteString("\n")
			}
		}

	case "persistent-nat":
		if s.dp == nil || s.dp.PersistentNAT == nil {
			buf.WriteString("Persistent NAT table not available\n")
		} else {
			bindings := s.dp.PersistentNAT.All()
			if len(bindings) == 0 {
				buf.WriteString("No persistent NAT bindings\n")
			} else {
				fmt.Fprintf(&buf, "Total persistent NAT bindings: %d\n\n", len(bindings))
				fmt.Fprintf(&buf, "%-20s %-8s %-20s %-8s %-15s %-10s\n",
					"Source IP", "SrcPort", "NAT IP", "NATPort", "Pool", "Timeout")
				for _, b := range bindings {
					remaining := time.Until(b.LastSeen.Add(b.Timeout))
					if remaining < 0 {
						remaining = 0
					}
					fmt.Fprintf(&buf, "%-20s %-8d %-20s %-8d %-15s %-10s\n",
						b.SrcIP, b.SrcPort, b.NatIP, b.NatPort, b.PoolName,
						remaining.Truncate(time.Second))
				}
			}
		}

	case "tunnels":
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			tunnels, err := s.routing.GetTunnelStatus()
			if err != nil {
				fmt.Fprintf(&buf, "Error: %v\n", err)
			} else if len(tunnels) == 0 {
				buf.WriteString("No tunnel interfaces configured\n")
			} else {
				for _, t := range tunnels {
					fmt.Fprintf(&buf, "Tunnel %s:\n", t.Name)
					fmt.Fprintf(&buf, "  State:       %s\n", t.State)
					fmt.Fprintf(&buf, "  Source:      %s\n", t.Source)
					fmt.Fprintf(&buf, "  Destination: %s\n", t.Destination)
					for _, addr := range t.Addresses {
						fmt.Fprintf(&buf, "  Address:     %s\n", addr)
					}
					buf.WriteString("\n")
				}
			}
		}

	case "rpm":
		if s.rpmResultsFn == nil {
			buf.WriteString("RPM probes not available\n")
		} else {
			results := s.rpmResultsFn()
			if len(results) == 0 {
				buf.WriteString("No RPM probes configured\n")
			} else {
				buf.WriteString("RPM Probe Results:\n")
				for _, r := range results {
					fmt.Fprintf(&buf, "  Probe: %s, Test: %s\n", r.ProbeName, r.TestName)
					fmt.Fprintf(&buf, "    Type: %s, Target: %s\n", r.ProbeType, r.Target)
					fmt.Fprintf(&buf, "    Status: %s", r.LastStatus)
					if r.LastRTT > 0 {
						fmt.Fprintf(&buf, ", RTT: %s", r.LastRTT)
					}
					buf.WriteString("\n")
					fmt.Fprintf(&buf, "    Sent: %d, Received: %d", r.TotalSent, r.TotalRecv)
					if r.TotalSent > 0 {
						loss := float64(r.TotalSent-r.TotalRecv) / float64(r.TotalSent) * 100
						fmt.Fprintf(&buf, ", Loss: %.1f%%", loss)
					}
					buf.WriteString("\n")
					if !r.LastProbeAt.IsZero() {
						fmt.Fprintf(&buf, "    Last probe: %s\n", r.LastProbeAt.Format("2006-01-02 15:04:05"))
					}
				}
			}
		}

	case "version":
		ver := s.version
		if ver == "" {
			ver = "dev"
		}
		fmt.Fprintf(&buf, "bpfrx eBPF firewall %s\n", ver)
		var uts unix.Utsname
		if err := unix.Uname(&uts); err == nil {
			sysname := strings.TrimRight(string(uts.Sysname[:]), "\x00")
			release := strings.TrimRight(string(uts.Release[:]), "\x00")
			machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
			nodename := strings.TrimRight(string(uts.Nodename[:]), "\x00")
			fmt.Fprintf(&buf, "Hostname: %s\n", nodename)
			fmt.Fprintf(&buf, "Kernel: %s %s (%s)\n", sysname, release, machine)
		}
		fmt.Fprintf(&buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))

	case "chassis":
		// CPU info
		cpuData, _ := os.ReadFile("/proc/cpuinfo")
		cpuModel := ""
		cpuCount := 0
		for _, line := range strings.Split(string(cpuData), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					cpuModel = strings.TrimSpace(parts[1])
				}
				cpuCount++
			}
		}
		if cpuModel != "" {
			fmt.Fprintf(&buf, "CPU: %s (%d cores)\n", cpuModel, cpuCount)
		}
		// Memory
		memData, _ := os.ReadFile("/proc/meminfo")
		for _, line := range strings.Split(string(memData), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						fmt.Fprintf(&buf, "Memory: %.1f GB total\n", float64(kb)/(1024*1024))
					}
				}
				break
			}
		}
		// Memory — include free/available
		memFree := uint64(0)
		memAvail := uint64(0)
		for _, line := range strings.Split(string(memData), "\n") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			if strings.HasPrefix(line, "MemFree:") {
				if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					memFree = kb
				}
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					memAvail = kb
				}
			}
		}
		if memAvail > 0 {
			fmt.Fprintf(&buf, "Memory available: %.1f GB\n", float64(memAvail)/(1024*1024))
		} else if memFree > 0 {
			fmt.Fprintf(&buf, "Memory free: %.1f GB\n", float64(memFree)/(1024*1024))
		}
		// Load average
		var sysinfo unix.Sysinfo_t
		if err := unix.Sysinfo(&sysinfo); err == nil {
			loads := [3]float64{
				float64(sysinfo.Loads[0]) / 65536.0,
				float64(sysinfo.Loads[1]) / 65536.0,
				float64(sysinfo.Loads[2]) / 65536.0,
			}
			fmt.Fprintf(&buf, "Load average: %.2f, %.2f, %.2f\n", loads[0], loads[1], loads[2])
			days := sysinfo.Uptime / 86400
			hours := (sysinfo.Uptime % 86400) / 3600
			mins := (sysinfo.Uptime % 3600) / 60
			fmt.Fprintf(&buf, "System uptime: %d days, %d:%02d\n", days, hours, mins)
		}
		// Kernel
		var uts unix.Utsname
		if err := unix.Uname(&uts); err == nil {
			release := strings.TrimRight(string(uts.Release[:]), "\x00")
			machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
			fmt.Fprintf(&buf, "Kernel: %s (%s)\n", release, machine)
		}

	case "storage":
		var stat unix.Statfs_t
		mounts := []struct{ path, name string }{
			{"/", "Root (/)"},
			{"/var", "/var"},
			{"/tmp", "/tmp"},
		}
		fmt.Fprintf(&buf, "%-20s %12s %12s %12s %6s\n", "Filesystem", "Size", "Used", "Avail", "Use%")
		for _, m := range mounts {
			if err := unix.Statfs(m.path, &stat); err != nil {
				continue
			}
			total := stat.Blocks * uint64(stat.Bsize)
			free := stat.Bavail * uint64(stat.Bsize)
			used := total - (stat.Bfree * uint64(stat.Bsize))
			pct := float64(0)
			if total > 0 {
				pct = float64(used) / float64(total) * 100
			}
			fmt.Fprintf(&buf, "%-20s %11.1fG %11.1fG %11.1fG %5.0f%%\n",
				m.name,
				float64(total)/float64(1<<30),
				float64(used)/float64(1<<30),
				float64(free)/float64(1<<30),
				pct)
		}

	case "alarms":
		// Compile current config to check for warnings
		cfg := s.store.ActiveConfig()
		if cfg != nil {
			warnings := config.ValidateConfig(cfg)
			if len(warnings) == 0 {
				buf.WriteString("No alarms currently active\n")
			} else {
				fmt.Fprintf(&buf, "%d active alarm(s):\n", len(warnings))
				for _, w := range warnings {
					fmt.Fprintf(&buf, "  WARNING: %s\n", w)
				}
			}
		} else {
			buf.WriteString("No active configuration loaded\n")
		}

	case "route-summary":
		if s.routing == nil {
			fmt.Fprintln(&buf, "Routing manager not available")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			byProto := make(map[string]int)
			var v4Count, v6Count int
			for _, e := range entries {
				byProto[e.Protocol]++
				if strings.Contains(e.Destination, ":") {
					v6Count++
				} else {
					v4Count++
				}
			}
			fmt.Fprintf(&buf, "inet.0: %d destinations\n", v4Count)
			fmt.Fprintf(&buf, "inet6.0: %d destinations\n\n", v6Count)
			fmt.Fprintf(&buf, "Route summary by protocol:\n")
			fmt.Fprintf(&buf, "  %-14s %s\n", "Protocol", "Routes")
			protos := make([]string, 0, len(byProto))
			for p := range byProto {
				protos = append(protos, p)
			}
			sort.Strings(protos)
			for _, p := range protos {
				fmt.Fprintf(&buf, "  %-14s %d\n", p, byProto[p])
			}
			fmt.Fprintf(&buf, "  %-14s %d\n", "Total", len(entries))
		}

	case "interfaces-extensive":
		linksList, err := netlink.LinkList()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing interfaces: %v", err)
		}
		sort.Slice(linksList, func(i, j int) bool {
			return linksList[i].Attrs().Name < linksList[j].Attrs().Name
		})
		// Build config lookup for description/speed/duplex/zone
		ifCfgMap := make(map[string]*config.InterfaceConfig)
		ifZoneMap := make(map[string]string)
		if cfg != nil {
			for _, ifc := range cfg.Interfaces.Interfaces {
				ifCfgMap[ifc.Name] = ifc
			}
			for _, z := range cfg.Security.Zones {
				for _, ifName := range z.Interfaces {
					ifZoneMap[ifName] = z.Name
				}
			}
		}
		for _, link := range linksList {
			attrs := link.Attrs()
			if attrs.Name == "lo" {
				continue
			}
			adminUp := attrs.Flags&net.FlagUp != 0
			operUp := attrs.OperState == netlink.OperUp
			adminStr := "Disabled"
			if adminUp {
				adminStr = "Enabled"
			}
			linkStr := "Down"
			if operUp {
				linkStr = "Up"
			}
			fmt.Fprintf(&buf, "Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
			if ifCfg, ok := ifCfgMap[attrs.Name]; ok {
				if ifCfg.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", ifCfg.Description)
				}
				if ifCfg.Speed != "" {
					fmt.Fprintf(&buf, "  Speed: %s\n", ifCfg.Speed)
				}
				if ifCfg.Duplex != "" {
					fmt.Fprintf(&buf, "  Duplex: %s\n", ifCfg.Duplex)
				}
			}
			if zone, ok := ifZoneMap[attrs.Name]; ok {
				fmt.Fprintf(&buf, "  Security zone: %s\n", zone)
			}
			fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d\n", attrs.EncapType, attrs.MTU)
			if len(attrs.HardwareAddr) > 0 {
				fmt.Fprintf(&buf, "  Current address: %s\n", attrs.HardwareAddr)
			}
			fmt.Fprintf(&buf, "  Interface index: %d\n", attrs.Index)
			if st := attrs.Statistics; st != nil {
				fmt.Fprintf(&buf, "  Traffic statistics:\n")
				fmt.Fprintf(&buf, "    Input:  %d bytes, %d packets\n", st.RxBytes, st.RxPackets)
				fmt.Fprintf(&buf, "    Output: %d bytes, %d packets\n", st.TxBytes, st.TxPackets)
				fmt.Fprintf(&buf, "  Input errors:\n")
				fmt.Fprintf(&buf, "    Errors: %d, Drops: %d, Overruns: %d, Frame: %d\n",
					st.RxErrors, st.RxDropped, st.RxOverErrors, st.RxFrameErrors)
				fmt.Fprintf(&buf, "  Output errors:\n")
				fmt.Fprintf(&buf, "    Errors: %d, Drops: %d, Carrier: %d, Collisions: %d\n",
					st.TxErrors, st.TxDropped, st.TxCarrierErrors, st.Collisions)
			}
			addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
			for _, a := range addrs {
				fmt.Fprintf(&buf, "  Address: %s\n", a.IPNet)
			}
			fmt.Fprintln(&buf)
		}

	case "policies-hit-count":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		fmt.Fprintf(&buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
			"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
		fmt.Fprintln(&buf, strings.Repeat("-", 88))
		policySetID := uint32(0)
		var totalPkts, totalBytes uint64
		for _, zpp := range cfg.Security.Policies {
			for i, pol := range zpp.Policies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				var pkts, bytes uint64
				if s.dp != nil && s.dp.IsLoaded() {
					if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
						pkts = counters.Packets
						bytes = counters.Bytes
					}
				}
				totalPkts += pkts
				totalBytes += bytes
				fmt.Fprintf(&buf, "%-12s %-12s %-24s %-8s %12d %16d\n",
					zpp.FromZone, zpp.ToZone, pol.Name, action, pkts, bytes)
			}
			policySetID++
		}
		fmt.Fprintln(&buf, strings.Repeat("-", 88))
		fmt.Fprintf(&buf, "%-48s %8s %12d %16d\n", "Total", "", totalPkts, totalBytes)

	case "chassis-cluster":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.Chassis.Cluster == nil {
			fmt.Fprintln(&buf, "Cluster not configured")
			break
		}
		cluster := cfg.Chassis.Cluster
		fmt.Fprintf(&buf, "Chassis cluster status:\n")
		fmt.Fprintf(&buf, "  RETH count: %d\n\n", cluster.RethCount)
		for _, rg := range cluster.RedundancyGroups {
			fmt.Fprintf(&buf, "Redundancy group: %d\n", rg.ID)
			for nodeID, priority := range rg.NodePriorities {
				fmt.Fprintf(&buf, "  Node %d priority: %d\n", nodeID, priority)
			}
			if rg.GratuitousARPCount > 0 {
				fmt.Fprintf(&buf, "  Gratuitous ARP count: %d\n", rg.GratuitousARPCount)
			}
			if len(rg.InterfaceMonitors) > 0 {
				fmt.Fprintln(&buf, "  Interface monitors:")
				for _, mon := range rg.InterfaceMonitors {
					fmt.Fprintf(&buf, "    %-20s weight %d\n", mon.Interface, mon.Weight)
				}
			}
			fmt.Fprintln(&buf)
		}

	case "chassis-environment":
		thermalZones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
		if len(thermalZones) > 0 {
			fmt.Fprintln(&buf, "Temperature:")
			for _, tz := range thermalZones {
				data, err := os.ReadFile(tz)
				if err != nil {
					continue
				}
				millideg, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
				if err != nil {
					continue
				}
				typeFile := filepath.Join(filepath.Dir(tz), "type")
				name := filepath.Base(filepath.Dir(tz))
				if typeData, err := os.ReadFile(typeFile); err == nil {
					name = strings.TrimSpace(string(typeData))
				}
				fmt.Fprintf(&buf, "  %-30s %d.%d C\n", name, millideg/1000, (millideg%1000)/100)
			}
			fmt.Fprintln(&buf)
		}
		var sysinfo unix.Sysinfo_t
		if err := unix.Sysinfo(&sysinfo); err == nil {
			days := sysinfo.Uptime / 86400
			hours := (sysinfo.Uptime % 86400) / 3600
			mins := (sysinfo.Uptime % 3600) / 60
			fmt.Fprintf(&buf, "System uptime: %d days, %d:%02d\n", days, hours, mins)
			fmt.Fprintf(&buf, "Load average: %.2f %.2f %.2f\n",
				float64(sysinfo.Loads[0])/65536.0,
				float64(sysinfo.Loads[1])/65536.0,
				float64(sysinfo.Loads[2])/65536.0)
		}

	case "system-services":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		fmt.Fprintln(&buf, "System services:")
		fmt.Fprintln(&buf, "  gRPC:           127.0.0.1:50051 (always on)")
		fmt.Fprintln(&buf, "  HTTP REST:      127.0.0.1:8080 (always on)")
		if cfg.System.Services != nil {
			if cfg.System.Services.SSH != nil {
				rootLogin := cfg.System.Services.SSH.RootLogin
				if rootLogin == "" {
					rootLogin = "deny"
				}
				fmt.Fprintf(&buf, "  SSH:            enabled (root-login: %s)\n", rootLogin)
			}
			if cfg.System.Services.WebManagement != nil {
				wm := cfg.System.Services.WebManagement
				if wm.HTTP {
					iface := "all"
					if wm.HTTPInterface != "" {
						iface = wm.HTTPInterface
					}
					fmt.Fprintf(&buf, "  Web HTTP:       enabled (interface: %s)\n", iface)
				}
				if wm.HTTPS {
					iface := "all"
					if wm.HTTPSInterface != "" {
						iface = wm.HTTPSInterface
					}
					cert := ""
					if wm.SystemGeneratedCert {
						cert = ", system-generated-certificate"
					}
					fmt.Fprintf(&buf, "  Web HTTPS:      enabled (interface: %s%s)\n", iface, cert)
				}
			}
			if cfg.System.Services.DNSEnabled {
				fmt.Fprintln(&buf, "  DNS:            enabled")
			}
		}
		if len(cfg.System.NameServers) > 0 {
			fmt.Fprintf(&buf, "  DNS servers:    %s\n", strings.Join(cfg.System.NameServers, ", "))
		}
		if len(cfg.System.NTPServers) > 0 {
			fmt.Fprintf(&buf, "  NTP servers:    %s\n", strings.Join(cfg.System.NTPServers, ", "))
		}
		if len(cfg.Security.Log.Streams) > 0 {
			fmt.Fprintf(&buf, "  Syslog:         %d stream(s)\n", len(cfg.Security.Log.Streams))
		}
		if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
			fmt.Fprintf(&buf, "  NetFlow v9:     %d template(s)\n", len(cfg.Services.FlowMonitoring.Version9.Templates))
		}
		if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
			fmt.Fprintf(&buf, "  IPFIX:          %d template(s)\n", len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates))
		}
		if cfg.Services.ApplicationIdentification {
			fmt.Fprintln(&buf, "  AppID:          enabled")
		}
		if cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
			total := 0
			for _, probe := range cfg.Services.RPM.Probes {
				total += len(probe.Tests)
			}
			fmt.Fprintf(&buf, "  RPM probes:     %d probe(s), %d test(s)\n", len(cfg.Services.RPM.Probes), total)
		}

	case "ntp":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		if len(cfg.System.NTPServers) == 0 {
			fmt.Fprintln(&buf, "No NTP servers configured")
			break
		}
		fmt.Fprintln(&buf, "NTP servers:")
		for _, server := range cfg.System.NTPServers {
			fmt.Fprintf(&buf, "  %s\n", server)
		}
		if out, err := exec.Command("chronyc", "-n", "sources").CombinedOutput(); err == nil {
			fmt.Fprintf(&buf, "\nChrony sources:\n%s\n", string(out))
		} else if out, err := exec.Command("ntpq", "-p").CombinedOutput(); err == nil {
			fmt.Fprintf(&buf, "\nNTP peers:\n%s\n", string(out))
		} else if out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").CombinedOutput(); err == nil {
			fmt.Fprintf(&buf, "\nNTP synchronized: %s\n", strings.TrimSpace(string(out)))
		}

	case "system-syslog":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		if cfg.System.Syslog == nil {
			fmt.Fprintln(&buf, "No system syslog configuration")
			break
		}
		sys := cfg.System.Syslog
		if len(sys.Hosts) > 0 {
			fmt.Fprintln(&buf, "Syslog hosts:")
			for _, h := range sys.Hosts {
				fmt.Fprintf(&buf, "  %-20s", h.Address)
				if h.AllowDuplicates {
					fmt.Fprint(&buf, " allow-duplicates")
				}
				fmt.Fprintln(&buf)
				for _, f := range h.Facilities {
					fmt.Fprintf(&buf, "    %-20s %s\n", f.Facility, f.Severity)
				}
			}
		}
		if len(sys.Files) > 0 {
			fmt.Fprintln(&buf, "Syslog files:")
			for _, f := range sys.Files {
				fmt.Fprintf(&buf, "  %-20s %s %s\n", f.Name, f.Facility, f.Severity)
			}
		}
		if len(sys.Users) > 0 {
			fmt.Fprintln(&buf, "Syslog users:")
			for _, u := range sys.Users {
				fmt.Fprintf(&buf, "  %-20s %s %s\n", u.User, u.Facility, u.Severity)
			}
		}

	case "policy-options":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			po := &cfg.PolicyOptions
			if len(po.PrefixLists) > 0 {
				buf.WriteString("Prefix lists:\n")
				for name, pl := range po.PrefixLists {
					fmt.Fprintf(&buf, "  %-30s %d prefixes\n", name, len(pl.Prefixes))
					for _, p := range pl.Prefixes {
						fmt.Fprintf(&buf, "    %s\n", p)
					}
				}
			}
			if len(po.PolicyStatements) > 0 {
				if len(po.PrefixLists) > 0 {
					buf.WriteString("\n")
				}
				buf.WriteString("Policy statements:\n")
				for name, ps := range po.PolicyStatements {
					fmt.Fprintf(&buf, "  %s", name)
					if ps.DefaultAction != "" {
						fmt.Fprintf(&buf, " (default: %s)", ps.DefaultAction)
					}
					buf.WriteString("\n")
					for _, t := range ps.Terms {
						fmt.Fprintf(&buf, "    term %s:", t.Name)
						if t.FromProtocol != "" {
							fmt.Fprintf(&buf, " from %s", t.FromProtocol)
						}
						if t.PrefixList != "" {
							fmt.Fprintf(&buf, " prefix-list %s", t.PrefixList)
						}
						if t.Action != "" {
							fmt.Fprintf(&buf, " then %s", t.Action)
						}
						if t.LoadBalance != "" {
							fmt.Fprintf(&buf, " load-balance %s", t.LoadBalance)
						}
						buf.WriteString("\n")
					}
				}
			}
			if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
				buf.WriteString("No policy-options configured\n")
			}
		}

	case "backup-router":
		if cfg == nil || cfg.System.BackupRouter == "" {
			buf.WriteString("No backup router configured\n")
		} else {
			fmt.Fprintf(&buf, "Backup router: %s\n", cfg.System.BackupRouter)
			if cfg.System.BackupRouterDst != "" {
				fmt.Fprintf(&buf, "  Destination: %s\n", cfg.System.BackupRouterDst)
			} else {
				buf.WriteString("  Destination: 0.0.0.0/0 (default)\n")
			}
		}

	case "nat64":
		if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
			buf.WriteString("No NAT64 rule-sets configured\n")
		} else {
			for _, rs := range cfg.Security.NAT.NAT64 {
				fmt.Fprintf(&buf, "NAT64 rule-set: %s\n", rs.Name)
				if rs.Prefix != "" {
					fmt.Fprintf(&buf, "  Prefix:      %s\n", rs.Prefix)
				}
				if rs.SourcePool != "" {
					fmt.Fprintf(&buf, "  Source pool:  %s\n", rs.SourcePool)
				}
				buf.WriteString("\n")
			}
		}

	case "ike":
		if cfg == nil || len(cfg.Security.IPsec.Gateways) == 0 {
			buf.WriteString("No IKE gateways configured\n")
		} else {
			names := make([]string, 0, len(cfg.Security.IPsec.Gateways))
			for name := range cfg.Security.IPsec.Gateways {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				gw := cfg.Security.IPsec.Gateways[name]
				fmt.Fprintf(&buf, "IKE gateway: %s\n", name)
				if gw.Address != "" {
					fmt.Fprintf(&buf, "  Remote address:     %s\n", gw.Address)
				}
				if gw.DynamicHostname != "" {
					fmt.Fprintf(&buf, "  Dynamic hostname:   %s\n", gw.DynamicHostname)
				}
				if gw.LocalAddress != "" {
					fmt.Fprintf(&buf, "  Local address:      %s\n", gw.LocalAddress)
				}
				if gw.ExternalIface != "" {
					fmt.Fprintf(&buf, "  External interface: %s\n", gw.ExternalIface)
				}
				if gw.IKEPolicy != "" {
					fmt.Fprintf(&buf, "  IKE policy:         %s\n", gw.IKEPolicy)
					if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
						fmt.Fprintf(&buf, "    Mode:     %s\n", pol.Mode)
						fmt.Fprintf(&buf, "    Proposal: %s\n", pol.Proposals)
					}
				}
				ver := gw.Version
				if ver == "" {
					ver = "v1+v2"
				}
				fmt.Fprintf(&buf, "  IKE version:        %s\n", ver)
				if gw.DeadPeerDetect != "" {
					fmt.Fprintf(&buf, "  DPD:                %s\n", gw.DeadPeerDetect)
				}
				if gw.NoNATTraversal {
					buf.WriteString("  NAT-T:              disabled\n")
				}
				if gw.LocalIDValue != "" {
					fmt.Fprintf(&buf, "  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
				}
				if gw.RemoteIDValue != "" {
					fmt.Fprintf(&buf, "  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
				}
				buf.WriteString("\n")
			}
			// IKE proposals
			if len(cfg.Security.IPsec.IKEProposals) > 0 {
				pNames := make([]string, 0, len(cfg.Security.IPsec.IKEProposals))
				for name := range cfg.Security.IPsec.IKEProposals {
					pNames = append(pNames, name)
				}
				sort.Strings(pNames)
				buf.WriteString("IKE proposals:\n")
				for _, name := range pNames {
					p := cfg.Security.IPsec.IKEProposals[name]
					fmt.Fprintf(&buf, "  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
					if p.LifetimeSeconds > 0 {
						fmt.Fprintf(&buf, " lifetime=%ds", p.LifetimeSeconds)
					}
					buf.WriteString("\n")
				}
			}
		}

	case "event-options":
		if cfg == nil || len(cfg.EventOptions) == 0 {
			buf.WriteString("No event-options configured\n")
		} else {
			for _, ep := range cfg.EventOptions {
				fmt.Fprintf(&buf, "Policy: %s\n", ep.Name)
				if len(ep.Events) > 0 {
					fmt.Fprintf(&buf, "  Events: %s\n", strings.Join(ep.Events, ", "))
				}
				for _, w := range ep.WithinClauses {
					fmt.Fprintf(&buf, "  Within: %d seconds", w.Seconds)
					if w.TriggerOn > 0 {
						fmt.Fprintf(&buf, ", trigger on %d", w.TriggerOn)
					}
					if w.TriggerUntil > 0 {
						fmt.Fprintf(&buf, ", trigger until %d", w.TriggerUntil)
					}
					buf.WriteString("\n")
				}
				if len(ep.AttributesMatch) > 0 {
					buf.WriteString("  Attributes match:\n")
					for _, am := range ep.AttributesMatch {
						fmt.Fprintf(&buf, "    %s\n", am)
					}
				}
				if len(ep.ThenCommands) > 0 {
					buf.WriteString("  Then commands:\n")
					for _, cmd := range ep.ThenCommands {
						fmt.Fprintf(&buf, "    %s\n", cmd)
					}
				}
				buf.WriteString("\n")
			}
		}

	case "routing-options":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			ro := &cfg.RoutingOptions
			hasContent := false
			if ro.AutonomousSystem > 0 {
				fmt.Fprintf(&buf, "Autonomous system: %d\n\n", ro.AutonomousSystem)
				hasContent = true
			}
			if ro.ForwardingTableExport != "" {
				fmt.Fprintf(&buf, "Forwarding-table export: %s\n\n", ro.ForwardingTableExport)
				hasContent = true
			}
			if len(ro.StaticRoutes) > 0 {
				buf.WriteString("Static routes (inet.0):\n")
				fmt.Fprintf(&buf, "  %-24s %-20s %s\n", "Destination", "Next-Hop", "Pref")
				for _, sr := range ro.StaticRoutes {
					if sr.Discard {
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
						continue
					}
					for i, nh := range sr.NextHops {
						dest := sr.Destination
						if i > 0 {
							dest = ""
						}
						nhStr := nh.Address
						if nh.Interface != "" {
							nhStr += " via " + nh.Interface
						}
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", dest, nhStr, fmtPref(sr.Preference))
					}
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if len(ro.Inet6StaticRoutes) > 0 {
				buf.WriteString("Static routes (inet6.0):\n")
				fmt.Fprintf(&buf, "  %-40s %-30s %s\n", "Destination", "Next-Hop", "Pref")
				for _, sr := range ro.Inet6StaticRoutes {
					if sr.Discard {
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
						continue
					}
					for i, nh := range sr.NextHops {
						dest := sr.Destination
						if i > 0 {
							dest = ""
						}
						nhStr := nh.Address
						if nh.Interface != "" {
							nhStr += " via " + nh.Interface
						}
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", dest, nhStr, fmtPref(sr.Preference))
					}
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if len(ro.RibGroups) > 0 {
				buf.WriteString("RIB groups:\n")
				for name, rg := range ro.RibGroups {
					fmt.Fprintf(&buf, "  %-20s import-rib: %s\n", name, strings.Join(rg.ImportRibs, ", "))
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if !hasContent {
				buf.WriteString("No routing-options configured\n")
			}
		}

	case "forwarding-options":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			fo := &cfg.ForwardingOptions
			hasContent := false
			if fo.FamilyInet6Mode != "" {
				fmt.Fprintf(&buf, "Family inet6 mode: %s\n", fo.FamilyInet6Mode)
				hasContent = true
			}
			if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
				buf.WriteString("Sampling:\n")
				for name, inst := range fo.Sampling.Instances {
					fmt.Fprintf(&buf, "  Instance: %s\n", name)
					if inst.InputRate > 0 {
						fmt.Fprintf(&buf, "    Input rate: 1/%d\n", inst.InputRate)
					}
					for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
						if fam == nil {
							continue
						}
						for _, fs := range fam.FlowServers {
							fmt.Fprintf(&buf, "    Flow server: %s:%d\n", fs.Address, fs.Port)
							if fs.Version9Template != "" {
								fmt.Fprintf(&buf, "      Version 9 template: %s\n", fs.Version9Template)
							}
						}
						if fam.SourceAddress != "" {
							fmt.Fprintf(&buf, "    Source address: %s\n", fam.SourceAddress)
						}
						if fam.InlineJflow {
							buf.WriteString("    Inline jflow: enabled\n")
						}
						if fam.InlineJflowSourceAddress != "" {
							fmt.Fprintf(&buf, "    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
						}
					}
				}
				hasContent = true
			}
			if fo.DHCPRelay != nil {
				buf.WriteString("DHCP relay: (see 'show dhcp-relay' for details)\n")
				hasContent = true
			}
			if !hasContent {
				buf.WriteString("No forwarding-options configured\n")
			}
		}

	case "routing-instances":
		if cfg == nil || len(cfg.RoutingInstances) == 0 {
			buf.WriteString("No routing instances configured\n")
		} else {
			fmt.Fprintf(&buf, "%-20s %-16s %-6s %s\n", "Instance", "Type", "Table", "Interfaces")
			for _, ri := range cfg.RoutingInstances {
				tableID := "-"
				if ri.TableID > 0 {
					tableID = fmt.Sprintf("%d", ri.TableID)
				}
				ifaces := "-"
				if len(ri.Interfaces) > 0 {
					ifaces = strings.Join(ri.Interfaces, ", ")
				}
				fmt.Fprintf(&buf, "%-20s %-16s %-6s %s\n", ri.Name, ri.InstanceType, tableID, ifaces)
			}
			buf.WriteString("\n")
			// Per-instance details
			for _, ri := range cfg.RoutingInstances {
				fmt.Fprintf(&buf, "Instance: %s\n", ri.Name)
				fmt.Fprintf(&buf, "  Type: %s\n", ri.InstanceType)
				if ri.TableID > 0 {
					fmt.Fprintf(&buf, "  Table ID: %d\n", ri.TableID)
				}
				if len(ri.Interfaces) > 0 {
					fmt.Fprintf(&buf, "  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
				}
				if len(ri.StaticRoutes) > 0 {
					buf.WriteString("  Static routes:\n")
					for _, sr := range ri.StaticRoutes {
						if sr.Discard {
							fmt.Fprintf(&buf, "    %s -> discard\n", sr.Destination)
							continue
						}
						for _, nh := range sr.NextHops {
							nhStr := nh.Address
							if nh.Interface != "" {
								nhStr += " via " + nh.Interface
							}
							fmt.Fprintf(&buf, "    %s -> %s\n", sr.Destination, nhStr)
						}
					}
				}
				if ri.OSPF != nil {
					buf.WriteString("  Protocols: OSPF\n")
				}
				if ri.BGP != nil {
					buf.WriteString("  Protocols: BGP\n")
				}
				if ri.RIP != nil {
					buf.WriteString("  Protocols: RIP\n")
				}
				buf.WriteString("\n")
			}
		}

	case "login":
		if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
			buf.WriteString("No login users configured\n")
		} else {
			fmt.Fprintf(&buf, "%-16s %-6s %-14s %s\n", "User", "UID", "Class", "SSH Keys")
			for _, u := range cfg.System.Login.Users {
				uid := "-"
				if u.UID > 0 {
					uid = strconv.Itoa(u.UID)
				}
				class := u.Class
				if class == "" {
					class = "-"
				}
				keys := strconv.Itoa(len(u.SSHKeys))
				fmt.Fprintf(&buf, "%-16s %-6s %-14s %s\n", u.Name, uid, class, keys)
			}
		}

	case "screen":
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			// Build reverse map: profile name -> zones
			zonesByProfile := make(map[string][]string)
			for name, zone := range cfg.Security.Zones {
				if zone.ScreenProfile != "" {
					zonesByProfile[zone.ScreenProfile] = append(zonesByProfile[zone.ScreenProfile], name)
				}
			}
			var names []string
			for name := range cfg.Security.Screen {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				profile := cfg.Security.Screen[name]
				fmt.Fprintf(&buf, "Screen profile: %s\n", name)
				if profile.TCP.Land {
					buf.WriteString("  TCP LAND attack detection: enabled\n")
				}
				if profile.TCP.SynFin {
					buf.WriteString("  TCP SYN+FIN detection: enabled\n")
				}
				if profile.TCP.NoFlag {
					buf.WriteString("  TCP no-flag detection: enabled\n")
				}
				if profile.TCP.FinNoAck {
					buf.WriteString("  TCP FIN-no-ACK detection: enabled\n")
				}
				if profile.TCP.WinNuke {
					buf.WriteString("  TCP WinNuke detection: enabled\n")
				}
				if profile.TCP.SynFrag {
					buf.WriteString("  TCP SYN fragment detection: enabled\n")
				}
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  TCP SYN flood protection: attack-threshold %d\n",
						profile.TCP.SynFlood.AttackThreshold)
				}
				if profile.ICMP.PingDeath {
					buf.WriteString("  ICMP ping-of-death detection: enabled\n")
				}
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  ICMP flood protection: threshold %d\n",
						profile.ICMP.FloodThreshold)
				}
				if profile.IP.SourceRouteOption {
					buf.WriteString("  IP source-route option detection: enabled\n")
				}
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  UDP flood protection: threshold %d\n",
						profile.UDP.FloodThreshold)
				}
				if zones, ok := zonesByProfile[name]; ok {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "  Applied to zones: %s\n", strings.Join(zones, ", "))
				}
				buf.WriteString("\n")
			}
			// Per-type drop counters
			if s.dp != nil && s.dp.IsLoaded() {
				ctrMap := s.dp.Map("global_counters")
				if ctrMap != nil {
					readCtr := func(idx uint32) uint64 {
						var perCPU []uint64
						if err := ctrMap.Lookup(idx, &perCPU); err == nil {
							var total uint64
							for _, v := range perCPU {
								total += v
							}
							return total
						}
						return 0
					}
					totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
					fmt.Fprintf(&buf, "Total screen drops: %d\n", totalDrops)
					if totalDrops > 0 {
						screenCounters := []struct {
							idx  uint32
							name string
						}{
							{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
							{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
							{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
							{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
							{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
							{dataplane.GlobalCtrScreenTearDrop, "Teardrop"},
							{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
							{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
							{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
							{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
							{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
							{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
						}
						for _, sc := range screenCounters {
							v := readCtr(sc.idx)
							if v > 0 {
								fmt.Fprintf(&buf, "  %-25s %d\n", sc.name+":", v)
							}
						}
					}
				}
			}
		}

	case "log":
		out, err := exec.Command("journalctl", "-u", "bpfrxd", "-n", "50", "--no-pager").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "journalctl: %v", err)
		}
		buf.Write(out)

	case "internet-options":
		if cfg == nil || cfg.System.InternetOptions == nil {
			buf.WriteString("No internet-options configured\n")
		} else {
			io := cfg.System.InternetOptions
			buf.WriteString("Internet options:\n")
			fmt.Fprintf(&buf, "  no-ipv6-reject-zero-hop-limit: %s\n", boolStatus(io.NoIPv6RejectZeroHopLimit))
		}

	case "root-authentication":
		if cfg == nil || cfg.System.RootAuthentication == nil {
			buf.WriteString("No root authentication configured\n")
		} else {
			ra := cfg.System.RootAuthentication
			if ra.EncryptedPassword != "" {
				buf.WriteString("Root password: configured (encrypted)\n")
			}
			if len(ra.SSHKeys) > 0 {
				fmt.Fprintf(&buf, "Root SSH keys: %d\n", len(ra.SSHKeys))
				for _, key := range ra.SSHKeys {
					// Show key type and fingerprint prefix
					parts := strings.Fields(key)
					if len(parts) >= 2 {
						comment := ""
						if len(parts) >= 3 {
							comment = " " + parts[2]
						}
						fmt.Fprintf(&buf, "  %s%s\n", parts[0], comment)
					}
				}
			}
		}

	default:
		// Handle "log:<filename>[:<count>]" for syslog file destinations
		if strings.HasPrefix(req.Topic, "log:") {
			parts := strings.SplitN(req.Topic, ":", 3)
			filename := filepath.Base(parts[1]) // sanitize path
			n := "50"
			if len(parts) >= 3 {
				if _, err := strconv.Atoi(parts[2]); err == nil {
					n = parts[2]
				}
			}
			logPath := filepath.Join("/var/log", filename)
			out, err := exec.Command("tail", "-n", n, logPath).CombinedOutput()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "read %s: %v", logPath, err)
			}
			buf.Write(out)
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unknown topic: %s", req.Topic)
		}
	}

	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

func boolStatus(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// --- GetSystemInfo RPC ---

func (s *Server) GetSystemInfo(_ context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	var buf strings.Builder

	switch req.Type {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading uptime: %v", err)
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			return nil, status.Error(codes.Internal, "unexpected /proc/uptime format")
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&buf, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&buf, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&buf, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading meminfo: %v", err)
		}
		info := make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				info[key] = val
			}
		}
		total := info["MemTotal"]
		free := info["MemFree"]
		buffers := info["Buffers"]
		cached := info["Cached"]
		available := info["MemAvailable"]
		used := total - free - buffers - cached

		fmt.Fprintf(&buf, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&buf, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&buf, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	case "processes":
		cmd := exec.Command("ps", "aux", "--sort=-rss")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running ps: %v", err)
		}
		buf.Write(out)

	case "storage":
		cmd := exec.Command("df", "-h")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running df: %v", err)
		}
		buf.Write(out)

	case "arp":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V4)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing ARP entries: %v", err)
		}
		fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n", "MAC Address", "Address", "Interface", "State")
		for _, n := range neighbors {
			if n.IP == nil || n.HardwareAddr == nil {
				continue
			}
			ifName := ""
			if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
				ifName = link.Attrs().Name
			}
			fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n",
				n.HardwareAddr, n.IP, ifName, neighStateStr(n.State))
		}

	case "ipv6-neighbors":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing IPv6 neighbors: %v", err)
		}
		fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n", "MAC Address", "IPv6 Address", "Interface", "State")
		for _, n := range neighbors {
			if n.IP == nil || n.HardwareAddr == nil {
				continue
			}
			ifName := ""
			if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
				ifName = link.Attrs().Name
			}
			fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n",
				n.HardwareAddr, n.IP, ifName, neighStateStr(n.State))
		}

	case "connections":
		cmd := exec.Command("ss", "-tnp")
		out, err := cmd.Output()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "running ss: %v", err)
		}
		buf.Write(out)

	case "users":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
			fmt.Fprintln(&buf, "No login users configured")
		} else {
			fmt.Fprintf(&buf, "%-20s %-8s %-20s %s\n", "Username", "UID", "Class", "SSH Keys")
			for _, u := range cfg.System.Login.Users {
				uid := "-"
				if u.UID > 0 {
					uid = strconv.Itoa(u.UID)
				}
				class := u.Class
				if class == "" {
					class = "-"
				}
				fmt.Fprintf(&buf, "%-20s %-8s %-20s %d\n", u.Name, uid, class, len(u.SSHKeys))
			}
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown system info type: %s", req.Type)
	}

	return &pb.GetSystemInfoResponse{Output: buf.String()}, nil
}

func neighStateStr(state int) string {
	switch state {
	case netlink.NUD_REACHABLE:
		return "reachable"
	case netlink.NUD_STALE:
		return "stale"
	case netlink.NUD_DELAY:
		return "delay"
	case netlink.NUD_PROBE:
		return "probe"
	case netlink.NUD_FAILED:
		return "failed"
	case netlink.NUD_PERMANENT:
		return "permanent"
	case netlink.NUD_INCOMPLETE:
		return "incomplete"
	case netlink.NUD_NOARP:
		return "noarp"
	default:
		return "unknown"
	}
}

// --- SystemAction RPC ---

func (s *Server) SystemAction(_ context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	switch req.Action {
	case "reboot":
		slog.Warn("system reboot requested via gRPC")
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "reboot").Run()
		}()
		return &pb.SystemActionResponse{Message: "System going down for reboot NOW!"}, nil

	case "halt":
		slog.Warn("system halt requested via gRPC")
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "halt").Run()
		}()
		return &pb.SystemActionResponse{Message: "System halting NOW!"}, nil

	case "zeroize":
		slog.Warn("system zeroize requested via gRPC")
		// Remove configs
		configDir := "/etc/bpfrx"
		files, _ := os.ReadDir(configDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
				os.Remove(configDir + "/" + f.Name())
			}
		}
		// Remove BPF pins
		os.RemoveAll("/sys/fs/bpf/bpfrx")
		// Remove managed networkd files
		ndFiles, _ := os.ReadDir("/etc/systemd/network")
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-bpfrx-") {
				os.Remove("/etc/systemd/network/" + f.Name())
			}
		}
		return &pb.SystemActionResponse{Message: "System zeroized. Configuration erased. Reboot to complete factory reset."}, nil

	case "dhcp-renew":
		if s.dhcp == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "DHCP manager not available")
		}
		if req.Target == "" {
			return nil, status.Errorf(codes.InvalidArgument, "dhcp-renew requires target interface")
		}
		if err := s.dhcp.Renew(req.Target); err != nil {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("DHCP renewal initiated on %s", req.Target),
		}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown action: %s", req.Action)
	}
}

// matchPolicyAddr checks if an IP matches a list of address-book references.
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchPolicyApp checks if a protocol/port matches application references.
func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}
