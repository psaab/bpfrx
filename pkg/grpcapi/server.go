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

	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/feeds"
	"github.com/psaab/bpfrx/pkg/frr"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/lldp"
	"github.com/psaab/bpfrx/pkg/rpm"
	"github.com/psaab/bpfrx/pkg/vrrp"
)

// Config configures the gRPC server.
type Config struct {
	Store    *configstore.Store
	DP       dataplane.DataPlane
	EventBuf *logging.EventBuffer
	GC       *conntrack.GC
	Routing  *routing.Manager
	FRR      *frr.Manager
	IPsec    *ipsec.Manager
	DHCP         *dhcp.Manager
	DHCPServer   *dhcpserver.Manager
	RPMResultsFn    func() []*rpm.ProbeResult      // returns live RPM results
	FeedsFn         func() map[string]feeds.FeedInfo // returns live feed status
	LLDPNeighborsFn func() []*lldp.Neighbor         // returns live LLDP neighbors
	ApplyFn         func(*config.Config)             // daemon's applyConfig callback
	Version      string                    // software version string
}

// Server implements the BpfrxService gRPC service.
type Server struct {
	pb.UnimplementedBpfrxServiceServer
	store        *configstore.Store
	dp           dataplane.DataPlane
	eventBuf     *logging.EventBuffer
	gc           *conntrack.GC
	routing      *routing.Manager
	frr          *frr.Manager
	ipsec        *ipsec.Manager
	dhcp         *dhcp.Manager
	dhcpServer   *dhcpserver.Manager
	rpmResultsFn    func() []*rpm.ProbeResult
	feedsFn         func() map[string]feeds.FeedInfo
	lldpNeighborsFn func() []*lldp.Neighbor
	applyFn         func(*config.Config)
	startTime    time.Time
	addr         string
	version      string
}

// NewServer creates a new gRPC server.
// NOTE: gRPC is local-only (127.0.0.1) so all RPCs are inherently trusted.
// Login class RBAC enforcement could be added here via per-RPC interceptors if
// gRPC is ever exposed on non-loopback addresses.
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
		rpmResultsFn:    cfg.RPMResultsFn,
		feedsFn:         cfg.FeedsFn,
		lldpNeighborsFn: cfg.LLDPNeighborsFn,
		applyFn:         cfg.ApplyFn,
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

	// Capture diff summary before commit (active will change)
	summary := s.store.CommitDiffSummary()

	compiled, err := s.store.Commit()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if s.applyFn != nil {
		s.applyFn(compiled)
	}
	return &pb.CommitResponse{Summary: summary}, nil
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
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowActiveXML()
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
	case req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowCandidateXML()
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
	readCounter := func(idx uint32) uint64 {
		v, _ := s.dp.ReadGlobalCounter(idx)
		return v
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

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := &pb.PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
		}
		for _, rule := range cfg.Security.GlobalPolicies {
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
	appFilter := req.Application
	cfg := s.store.ActiveConfig()

	// Resolve application filter to proto+port for efficient matching
	var appProto uint8
	var appPort uint16
	if appFilter != "" {
		var ok bool
		appProto, appPort, ok = lookupAppFilter(appFilter, cfg)
		if !ok {
			return &pb.GetSessionsResponse{}, nil // unknown app, no matches
		}
	}

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
		if appFilter != "" && (key.Protocol != appProto || ntohs(key.DstPort) != appPort) {
			return true
		}
		if idx >= offset && len(all) < limit {
			se := sessionEntryV4(key, val, now, zoneNames)
			se.Application = resolveAppName(key.Protocol, ntohs(key.DstPort), cfg)
			all = append(all, se)
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
		if appFilter != "" && (key.Protocol != appProto || ntohs(key.DstPort) != appPort) {
			return true
		}
		if idx >= offset && len(all) < limit {
			se := sessionEntryV6(key, val, now, zoneNames)
			se.Application = resolveAppName(key.Protocol, ntohs(key.DstPort), cfg)
			all = append(all, se)
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

	// Count active DNAT sessions and per-rule-set breakdown
	if s.dp != nil && s.dp.IsLoaded() {
		type rsKey struct{ from, to string }
		rsSessions := make(map[rsKey]int32)
		var zoneByID map[uint16]string
		if cr := s.dp.LastCompileResult(); cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		totalDNAT := int32(0)
		_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				if zoneByID != nil {
					rsSessions[rsKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				if zoneByID != nil {
					rsSessions[rsKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		resp.TotalActiveTranslations = totalDNAT
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			key := rsKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				resp.RuleSetSessions = append(resp.RuleSetSessions, &pb.NATRuleSetSessions{
					FromZone: rs.FromZone,
					ToZone:   rs.ToZone,
					Sessions: cnt,
				})
			}
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

		// Show configured speed/duplex from config
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if ifCfg.Speed != "" {
				fmt.Fprintf(&buf, "  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Fprintf(&buf, "  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Link-level details
		mtu := iface.MTU
		linkType := "Ethernet"
		var linkExtras []string
		if raw, err := os.ReadFile("/sys/class/net/" + physName + "/speed"); err == nil {
			var mbps int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &mbps); err == nil && mbps > 0 {
				if mbps >= 1000 {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dGbps", mbps/1000))
				} else {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dMbps", mbps))
				}
			}
		}
		if raw, err := os.ReadFile("/sys/class/net/" + physName + "/duplex"); err == nil {
			d := strings.TrimSpace(string(raw))
			if d == "full" {
				linkExtras = append(linkExtras, "Link-mode: Full-duplex")
			} else if d == "half" {
				linkExtras = append(linkExtras, "Link-mode: Half-duplex")
			}
		}
		speedStr := ""
		if len(linkExtras) > 0 {
			speedStr = ", " + strings.Join(linkExtras, ", ")
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

func (s *Server) ClearSessions(_ context.Context, req *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}

	// If no filters, clear all
	if req.SourcePrefix == "" && req.DestinationPrefix == "" &&
		req.Protocol == "" && req.Zone == "" &&
		req.SourcePort == 0 && req.DestinationPort == 0 &&
		req.Application == "" {
		v4, v6, err := s.dp.ClearAllSessions()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.ClearSessionsResponse{
			Ipv4Cleared: int32(v4),
			Ipv6Cleared: int32(v6),
		}, nil
	}

	// Build filter
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

	var proto uint8
	switch strings.ToLower(req.Protocol) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	case "icmp":
		proto = 1
	}

	var clearAppProto uint8
	var clearAppPort uint16
	if req.Application != "" {
		clearCfg := s.store.ActiveConfig()
		var ok bool
		clearAppProto, clearAppPort, ok = lookupAppFilter(req.Application, clearCfg)
		if !ok {
			return &pb.ClearSessionsResponse{}, nil
		}
	}

	var zoneID uint16
	if req.Zone != "" {
		if cr := s.dp.LastCompileResult(); cr != nil {
			zoneID = cr.ZoneIDs[req.Zone]
		}
	}

	// Clear matching IPv4 sessions
	v4Deleted := 0
	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if proto != 0 && key.Protocol != proto {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if zoneID != 0 && val.IngressZone != zoneID && val.EgressZone != zoneID {
			return true
		}
		if req.SourcePort != 0 && key.SrcPort != uint16(req.SourcePort) {
			return true
		}
		if req.DestinationPort != 0 && key.DstPort != uint16(req.DestinationPort) {
			return true
		}
		if req.Application != "" && (key.Protocol != clearAppProto || ntohs(key.DstPort) != clearAppPort) {
			return true
		}
		v4Keys = append(v4Keys, key)
		v4RevKeys = append(v4RevKeys, dataplane.SessionKey{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, dataplane.DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v4Keys {
		if err := s.dp.DeleteSession(key); err == nil {
			v4Deleted++
		}
	}
	for _, key := range v4RevKeys {
		s.dp.DeleteSession(key)
	}
	for _, dk := range snatDNATKeys {
		s.dp.DeleteDNATEntry(dk)
	}

	// Clear matching IPv6 sessions
	v6Deleted := 0
	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if proto != 0 && key.Protocol != proto {
			return true
		}
		if srcNet != nil && !srcNet.Contains(net.IP(key.SrcIP[:])) {
			return true
		}
		if dstNet != nil && !dstNet.Contains(net.IP(key.DstIP[:])) {
			return true
		}
		if zoneID != 0 && val.IngressZone != zoneID && val.EgressZone != zoneID {
			return true
		}
		if req.SourcePort != 0 && key.SrcPort != uint16(req.SourcePort) {
			return true
		}
		if req.DestinationPort != 0 && key.DstPort != uint16(req.DestinationPort) {
			return true
		}
		if req.Application != "" && (key.Protocol != clearAppProto || ntohs(key.DstPort) != clearAppPort) {
			return true
		}
		v6Keys = append(v6Keys, key)
		v6RevKeys = append(v6RevKeys, dataplane.SessionKeyV6{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, dataplane.DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v6Keys {
		if err := s.dp.DeleteSessionV6(key); err == nil {
			v6Deleted++
		}
	}
	for _, key := range v6RevKeys {
		s.dp.DeleteSessionV6(key)
	}
	for _, dk := range snatDNATKeysV6 {
		s.dp.DeleteDNATEntryV6(dk)
	}

	return &pb.ClearSessionsResponse{
		Ipv4Cleared: int32(v4Deleted),
		Ipv6Cleared: int32(v6Deleted),
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
	return cmdtree.CompleteFromTree(cmdtree.OperationalTree, words, partial, cfg)
}

func (s *Server) completeConfig(words []string, partial string) []string {
	if len(words) == 0 {
		return cmdtree.FilterPrefix(cmdtree.KeysOf(cmdtree.ConfigTopLevel), partial)
	}

	switch words[0] {
	case "set", "delete":
		schemaCompletions := config.CompleteSetPathWithValues(words[1:], s.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		return cmdtree.FilterPrefix(schemaCompletions, partial)
	case "run":
		cfg := s.store.ActiveConfig()
		return cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
	case "commit":
		if len(words) == 1 {
			return cmdtree.FilterPrefix([]string{"check", "confirmed"}, partial)
		}
		return nil
	case "load":
		if len(words) == 1 {
			return cmdtree.FilterPrefix([]string{"override", "merge"}, partial)
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

// Command trees are defined in pkg/cmdtree (single source of truth).
// gRPC completion uses cmdtree.CompleteFromTree directly.

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

type builtinApp struct {
	proto uint8
	port  uint16
}

var builtinApps = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			var appProto uint8
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				appProto = 6
			case "udp":
				appProto = 17
			case "icmp":
				appProto = 1
			default:
				continue
			}
			if appProto != proto {
				continue
			}
			portStr := app.DestinationPort
			if portStr == "" {
				continue
			}
			if strings.Contains(portStr, "-") {
				parts := strings.SplitN(portStr, "-", 2)
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi {
					return name
				}
			} else {
				if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
					return name
				}
			}
		}
	}
	for name, ba := range builtinApps {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

func lookupAppFilter(appName string, cfg *config.Config) (proto uint8, port uint16, ok bool) {
	if ba, found := builtinApps[appName]; found {
		return ba.proto, ba.port, true
	}
	if cfg != nil {
		if app, found := cfg.Applications.Applications[appName]; found {
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				proto = 6
			case "udp":
				proto = 17
			case "icmp":
				proto = 1
			default:
				return 0, 0, false
			}
			if app.DestinationPort != "" {
				if v, err := strconv.Atoi(app.DestinationPort); err == nil {
					return proto, uint16(v), true
				}
			}
		}
	}
	return 0, 0, false
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

	// Count active SNAT sessions and per-rule-set breakdown
	totalSNAT := int32(0)
	type rsKey struct{ from, to string }
	rsSessions := make(map[rsKey]int32)
	if s.dp != nil && s.dp.IsLoaded() {
		var zoneByID map[uint16]string
		if cr := s.dp.LastCompileResult(); cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[rsKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[rsKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
	}
	resp.TotalActiveTranslations = totalSNAT

	// Interface-mode pools
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				resp.Pools = append(resp.Pools, &pb.NATPoolStats{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   totalSNAT,
					IsInterface: true,
				})
			}
		}
	}

	// Per-rule-set session counts
	for _, rs := range cfg.Security.NAT.Source {
		key := rsKey{rs.FromZone, rs.ToZone}
		if cnt, ok := rsSessions[key]; ok {
			resp.RuleSetSessions = append(resp.RuleSetSessions, &pb.NATRuleSetSessions{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
				Sessions: cnt,
			})
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

	// Helper to read NAT rule counters
	readCounter := func(rsName, ruleName string) (uint64, uint64) {
		if s.dp != nil && s.dp.IsLoaded() {
			if cr := s.dp.LastCompileResult(); cr != nil {
				ruleKey := rsName + "/" + ruleName
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						return cnt.Packets, cnt.Bytes
					}
				}
			}
		}
		return 0, 0
	}

	// Source NAT rules (default when nat_type is empty or "source")
	if req.NatType == "" || req.NatType == "source" {
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
				hitPkts, hitBytes := readCounter(rs.Name, rule.Name)
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
	}

	// Destination NAT rules
	if req.NatType == "destination" {
		if dnat := cfg.Security.NAT.Destination; dnat != nil {
			for _, rs := range dnat.RuleSets {
				if req.RuleSet != "" && rs.Name != req.RuleSet {
					continue
				}
				for _, rule := range rs.Rules {
					action := "off"
					if rule.Then.PoolName != "" {
						action = "pool " + rule.Then.PoolName
					}
					dstMatch := "0.0.0.0/0"
					if rule.Match.DestinationAddress != "" {
						dstMatch = rule.Match.DestinationAddress
					}
					if rule.Match.DestinationPort != 0 {
						dstMatch += fmt.Sprintf(":%d", rule.Match.DestinationPort)
					}
					hitPkts, hitBytes := readCounter(rs.Name, rule.Name)
					resp.Rules = append(resp.Rules, &pb.NATRuleStats{
						RuleSet:          rs.Name,
						RuleName:         rule.Name,
						FromZone:         rs.FromZone,
						ToZone:           rs.ToZone,
						Action:           action,
						DestinationMatch: dstMatch,
						HitPackets:       hitPkts,
						HitBytes:         hitBytes,
					})
				}
			}
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

	// Handle parameterized topics (prefix:value format)
	if strings.HasPrefix(req.Topic, "route-table:") {
		vrfName := strings.TrimPrefix(req.Topic, "route-table:")
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			entries, err := s.routing.GetVRFRoutes(vrfName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get VRF routes: %v", err)
			}
			if len(entries) == 0 {
				fmt.Fprintf(&buf, "No routes in table %s\n", vrfName)
			} else {
				fmt.Fprintf(&buf, "Routing table: %s\n", vrfName)
				fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
				for _, e := range entries {
					fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
						e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "route-protocol:") {
		proto := strings.ToLower(strings.TrimPrefix(req.Topic, "route-protocol:"))
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			fmt.Fprintf(&buf, "Routes matching protocol: %s\n", proto)
			fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
			count := 0
			for _, e := range entries {
				if strings.ToLower(e.Protocol) == proto {
					fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
						e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
					count++
				}
			}
			if count == 0 {
				buf.WriteString("  (no routes)\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "route-prefix:") {
		prefix := strings.TrimPrefix(req.Topic, "route-prefix:")
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			// Parse as CIDR for subnet matching
			filterCIDR := prefix
			if !strings.Contains(filterCIDR, "/") {
				if strings.Contains(filterCIDR, ":") {
					filterCIDR += "/128"
				} else {
					filterCIDR += "/32"
				}
			}
			_, filterNet, filterErr := net.ParseCIDR(filterCIDR)
			fmt.Fprintf(&buf, "Routes matching %s:\n", prefix)
			fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
			count := 0
			for _, e := range entries {
				if routePrefixMatch(e.Destination, filterNet, filterErr) {
					fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
						e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
					count++
				}
			}
			if count == 0 {
				buf.WriteString("  (no matching routes)\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option:") {
		profileName := strings.TrimPrefix(req.Topic, "screen-ids-option:")
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			profile, ok := cfg.Security.Screen[profileName]
			if !ok {
				fmt.Fprintf(&buf, "Screen profile '%s' not found\n", profileName)
			} else {
				fmt.Fprintf(&buf, "Screen object status:\n\n")
				fmt.Fprintf(&buf, "  Name                                        Value\n")
				if profile.TCP.Land {
					fmt.Fprintf(&buf, "  TCP land attack                             enabled\n")
				}
				if profile.TCP.SynFin {
					fmt.Fprintf(&buf, "  TCP SYN+FIN                                 enabled\n")
				}
				if profile.TCP.NoFlag {
					fmt.Fprintf(&buf, "  TCP no-flag                                 enabled\n")
				}
				if profile.TCP.FinNoAck {
					fmt.Fprintf(&buf, "  TCP FIN-no-ACK                              enabled\n")
				}
				if profile.TCP.WinNuke {
					fmt.Fprintf(&buf, "  TCP WinNuke                                 enabled\n")
				}
				if profile.TCP.SynFrag {
					fmt.Fprintf(&buf, "  TCP SYN fragment                            enabled\n")
				}
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  TCP SYN flood attack threshold              %d\n",
						profile.TCP.SynFlood.AttackThreshold)
					if profile.TCP.SynFlood.SourceThreshold > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood source threshold              %d\n",
							profile.TCP.SynFlood.SourceThreshold)
					}
					if profile.TCP.SynFlood.DestinationThreshold > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood destination threshold          %d\n",
							profile.TCP.SynFlood.DestinationThreshold)
					}
					if profile.TCP.SynFlood.Timeout > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood timeout                       %d\n",
							profile.TCP.SynFlood.Timeout)
					}
				}
				if profile.ICMP.PingDeath {
					fmt.Fprintf(&buf, "  ICMP ping of death                          enabled\n")
				}
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  ICMP flood threshold                        %d\n",
						profile.ICMP.FloodThreshold)
				}
				if profile.IP.SourceRouteOption {
					fmt.Fprintf(&buf, "  IP source route option                      enabled\n")
				}
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  UDP flood threshold                         %d\n",
						profile.UDP.FloodThreshold)
				}
				// Show which zones use this profile
				var zones []string
				for name, zone := range cfg.Security.Zones {
					if zone.ScreenProfile == profileName {
						zones = append(zones, name)
					}
				}
				if len(zones) > 0 {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-statistics:") {
		zoneName := strings.TrimPrefix(req.Topic, "screen-statistics:")
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if s.dp == nil || !s.dp.IsLoaded() {
			buf.WriteString("Dataplane not loaded\n")
		} else {
			cr := s.dp.LastCompileResult()
			if cr == nil {
				buf.WriteString("No compile result available\n")
			} else {
				zoneID, ok := cr.ZoneIDs[zoneName]
				if !ok {
					fmt.Fprintf(&buf, "Zone '%s' not found\n", zoneName)
				} else {
					fs, err := s.dp.ReadFloodCounters(zoneID)
					if err != nil {
						fmt.Fprintf(&buf, "Error reading flood counters: %v\n", err)
					} else {
						screenProfile := ""
						if z, ok := cfg.Security.Zones[zoneName]; ok {
							screenProfile = z.ScreenProfile
						}
						fmt.Fprintf(&buf, "Screen statistics for zone '%s':\n", zoneName)
						if screenProfile != "" {
							fmt.Fprintf(&buf, "  Screen profile: %s\n", screenProfile)
						}
						fmt.Fprintf(&buf, "  %-30s %s\n", "Counter", "Value")
						fmt.Fprintf(&buf, "  %-30s %d\n", "SYN flood events", fs.SynCount)
						fmt.Fprintf(&buf, "  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
						fmt.Fprintf(&buf, "  %-30s %d\n", "UDP flood events", fs.UDPCount)
					}
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option-detail:") {
		profileName := strings.TrimPrefix(req.Topic, "screen-ids-option-detail:")
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			profile, ok := cfg.Security.Screen[profileName]
			if !ok {
				fmt.Fprintf(&buf, "Screen profile '%s' not found\n", profileName)
			} else {
				fmt.Fprintf(&buf, "Screen object status (detail):\n\n")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "Name", "Value", "Default")
				enabledS := func(v bool) string {
					if v {
						return "enabled"
					}
					return "disabled"
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP land attack", enabledS(profile.TCP.Land), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN+FIN", enabledS(profile.TCP.SynFin), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP no-flag", enabledS(profile.TCP.NoFlag), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP FIN-no-ACK", enabledS(profile.TCP.FinNoAck), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP WinNuke", enabledS(profile.TCP.WinNuke), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN fragment", enabledS(profile.TCP.SynFrag), "disabled")
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Attack threshold", profile.TCP.SynFlood.AttackThreshold, "200")
					if profile.TCP.SynFlood.AlarmThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Alarm threshold", profile.TCP.SynFlood.AlarmThreshold, "512")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
					}
					if profile.TCP.SynFlood.SourceThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Source threshold", profile.TCP.SynFlood.SourceThreshold, "4000")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
					}
					if profile.TCP.SynFlood.DestinationThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Destination threshold", profile.TCP.SynFlood.DestinationThreshold, "4000")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
					}
					if profile.TCP.SynFlood.Timeout > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Timeout (seconds)", profile.TCP.SynFlood.Timeout, "20")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
					}
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "ICMP ping of death", enabledS(profile.ICMP.PingDeath), "disabled")
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "ICMP flood threshold", profile.ICMP.FloodThreshold, "1000")
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "IP source route option", enabledS(profile.IP.SourceRouteOption), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "IP teardrop", enabledS(profile.IP.TearDrop), "disabled")
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "UDP flood threshold", profile.UDP.FloodThreshold, "1000")
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
				}
				var zones []string
				for name, zone := range cfg.Security.Zones {
					if zone.ScreenProfile == profileName {
						zones = append(zones, name)
					}
				}
				if len(zones) > 0 {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
				} else {
					fmt.Fprintf(&buf, "\n  Bound to zones: (none)\n")
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test policy: "test-policy:from=X,to=Y,src=A,dst=B,port=P,proto=TCP"
	if strings.HasPrefix(req.Topic, "test-policy:") {
		params := strings.TrimPrefix(req.Topic, "test-policy:")
		var fromZone, toZone, srcIP, dstIP, proto string
		var dstPort int
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "from":
				fromZone = parts[1]
			case "to":
				toZone = parts[1]
			case "src":
				srcIP = parts[1]
			case "dst":
				dstIP = parts[1]
			case "port":
				dstPort, _ = strconv.Atoi(parts[1])
			case "proto":
				proto = parts[1]
			}
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if fromZone == "" || toZone == "" {
			buf.WriteString("Missing from/to zone parameters\n")
		} else {
			parsedSrc := net.ParseIP(srcIP)
			parsedDst := net.ParseIP(dstIP)
			found := false
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone != fromZone || zpp.ToZone != toZone {
					continue
				}
				for _, pol := range zpp.Policies {
					if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
						continue
					}
					if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
						continue
					}
					if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
						continue
					}
					action := policyActionName(pol.Action)
					fmt.Fprintf(&buf, "Policy match:\n")
					fmt.Fprintf(&buf, "  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
					fmt.Fprintf(&buf, "  Policy:    %s\n", pol.Name)
					fmt.Fprintf(&buf, "  Action:    %s\n", action)
					found = true
					break
				}
				if found {
					break
				}
			}
			if !found {
				// Check global policies
				for _, pol := range cfg.Security.GlobalPolicies {
					if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
						continue
					}
					if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
						continue
					}
					if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
						continue
					}
					action := policyActionName(pol.Action)
					fmt.Fprintf(&buf, "Policy match (global):\n")
					fmt.Fprintf(&buf, "  Policy:    %s\n", pol.Name)
					fmt.Fprintf(&buf, "  Action:    %s\n", action)
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(&buf, "Default deny (no matching policy for %s -> %s)\n", fromZone, toZone)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test routing: "test-routing:dest=10.0.0.0/24" or "test-routing:dest=10.0.0.0/24,instance=dmz-vr"
	if strings.HasPrefix(req.Topic, "test-routing:") {
		params := strings.TrimPrefix(req.Topic, "test-routing:")
		var dest, instance string
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "dest":
				dest = parts[1]
			case "instance":
				instance = parts[1]
			}
		}
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else if dest == "" {
			buf.WriteString("Missing dest parameter\n")
		} else {
			var entries []routing.RouteEntry
			var err error
			if instance != "" {
				entries, err = s.routing.GetVRFRoutes(instance)
			} else {
				entries, err = s.routing.GetRoutes()
			}
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			filterCIDR := dest
			if !strings.Contains(filterCIDR, "/") {
				if strings.Contains(filterCIDR, ":") {
					filterCIDR += "/128"
				} else {
					filterCIDR += "/32"
				}
			}
			filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
			if filterErr != nil {
				filterIP = net.ParseIP(dest)
			}
			var best *routing.RouteEntry
			bestLen := -1
			for i := range entries {
				_, rNet, err := net.ParseCIDR(entries[i].Destination)
				if err != nil {
					continue
				}
				if filterIP != nil && rNet.Contains(filterIP) {
					ones, _ := rNet.Mask.Size()
					if ones > bestLen {
						bestLen = ones
						best = &entries[i]
					}
				}
			}
			if instance != "" {
				fmt.Fprintf(&buf, "Routing lookup in instance %s for %s:\n", instance, dest)
			} else {
				fmt.Fprintf(&buf, "Routing lookup for %s:\n", dest)
			}
			if best == nil {
				buf.WriteString("  No matching route found\n")
			} else {
				fmt.Fprintf(&buf, "  Destination: %s\n", best.Destination)
				fmt.Fprintf(&buf, "  Next-hop:    %s\n", best.NextHop)
				fmt.Fprintf(&buf, "  Interface:   %s\n", best.Interface)
				fmt.Fprintf(&buf, "  Protocol:    %s\n", best.Protocol)
				fmt.Fprintf(&buf, "  Preference:  %d\n", best.Preference)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test security-zone: "test-zone:interface=trust0"
	if strings.HasPrefix(req.Topic, "test-zone:") {
		params := strings.TrimPrefix(req.Topic, "test-zone:")
		var ifName string
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 && parts[0] == "interface" {
				ifName = parts[1]
			}
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if ifName == "" {
			buf.WriteString("Missing interface parameter\n")
		} else {
			found := false
			for zoneName, zone := range cfg.Security.Zones {
				for _, iface := range zone.Interfaces {
					if iface == ifName {
						fmt.Fprintf(&buf, "Interface %s belongs to zone: %s\n", ifName, zoneName)
						if zone.Description != "" {
							fmt.Fprintf(&buf, "  Description: %s\n", zone.Description)
						}
						if zone.ScreenProfile != "" {
							fmt.Fprintf(&buf, "  Screen:      %s\n", zone.ScreenProfile)
						}
						if zone.HostInboundTraffic != nil {
							if len(zone.HostInboundTraffic.SystemServices) > 0 {
								fmt.Fprintf(&buf, "  Host-inbound services: %s\n", strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
							}
							if len(zone.HostInboundTraffic.Protocols) > 0 {
								fmt.Fprintf(&buf, "  Host-inbound protocols: %s\n", strings.Join(zone.HostInboundTraffic.Protocols, ", "))
							}
						}
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				fmt.Fprintf(&buf, "Interface %s is not assigned to any security zone\n", ifName)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "firewall-filter:") {
		filterName := strings.TrimPrefix(req.Topic, "firewall-filter:")
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			var filter *config.FirewallFilter
			var family string
			if f, ok := cfg.Firewall.FiltersInet[filterName]; ok {
				filter = f
				family = "inet"
			} else if f, ok := cfg.Firewall.FiltersInet6[filterName]; ok {
				filter = f
				family = "inet6"
			}
			if filter == nil {
				fmt.Fprintf(&buf, "Filter not found: %s\n", filterName)
			} else {
				var filterIDs map[string]uint32
				if s.dp != nil && s.dp.IsLoaded() {
					if cr := s.dp.LastCompileResult(); cr != nil {
						filterIDs = cr.FilterIDs
					}
				}
				var ruleStart uint32
				var hasCounters bool
				if filterIDs != nil {
					if fid, ok := filterIDs[family+":"+filterName]; ok {
						if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
							ruleStart = fcfg.RuleStart
							hasCounters = true
						}
					}
				}
				fmt.Fprintf(&buf, "Filter: %s (family %s)\n", filterName, family)
				ruleOffset := ruleStart
				for _, term := range filter.Terms {
					fmt.Fprintf(&buf, "\n  Term: %s\n", term.Name)
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
					if term.ForwardingClass != "" {
						fmt.Fprintf(&buf, "    then forwarding-class %s\n", term.ForwardingClass)
					}
					if term.LossPriority != "" {
						fmt.Fprintf(&buf, "    then loss-priority %s\n", term.LossPriority)
					}
					if term.Log {
						buf.WriteString("    then log\n")
					}
					if term.Count != "" {
						fmt.Fprintf(&buf, "    then count %s\n", term.Count)
					}
					action := term.Action
					if action == "" {
						action = "accept"
					}
					fmt.Fprintf(&buf, "    then %s\n", action)
					if hasCounters {
						nSrc := len(term.SourceAddresses)
						for _, ref := range term.SourcePrefixLists {
							if !ref.Except {
								if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
									nSrc += len(pl.Prefixes)
								}
							}
						}
						if nSrc == 0 {
							nSrc = 1
						}
						nDst := len(term.DestAddresses)
						for _, ref := range term.DestPrefixLists {
							if !ref.Except {
								if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
									nDst += len(pl.Prefixes)
								}
							}
						}
						if nDst == 0 {
							nDst = 1
						}
						nDstPorts := len(term.DestinationPorts)
						if nDstPorts == 0 {
							nDstPorts = 1
						}
						nSrcPorts := len(term.SourcePorts)
						if nSrcPorts == 0 {
							nSrcPorts = 1
						}
						numRules := uint32(nSrc * nDst * nDstPorts * nSrcPorts)
						var totalPkts, totalBytes uint64
						for i := uint32(0); i < numRules; i++ {
							if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
								totalPkts += ctrs.Packets
								totalBytes += ctrs.Bytes
							}
						}
						fmt.Fprintf(&buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
						ruleOffset += numRules
					}
				}
				buf.WriteString("\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	switch req.Topic {
	case "zones-detail":
		if cfg == nil || len(cfg.Security.Zones) == 0 {
			buf.WriteString("No security zones configured\n")
		} else {
			zoneNames := make([]string, 0, len(cfg.Security.Zones))
			for name := range cfg.Security.Zones {
				zoneNames = append(zoneNames, name)
			}
			sort.Strings(zoneNames)
			for _, name := range zoneNames {
				zone := cfg.Security.Zones[name]
				var zoneID uint16
				if s.dp != nil {
					if cr := s.dp.LastCompileResult(); cr != nil {
						zoneID = cr.ZoneIDs[name]
					}
				}
				if zoneID > 0 {
					fmt.Fprintf(&buf, "Zone: %s (id: %d)\n", name, zoneID)
				} else {
					fmt.Fprintf(&buf, "Zone: %s\n", name)
				}
				if zone.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", zone.Description)
				}
				fmt.Fprintf(&buf, "  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
				if zone.TCPRst {
					buf.WriteString("  TCP RST: enabled\n")
				}
				if zone.ScreenProfile != "" {
					fmt.Fprintf(&buf, "  Screen: %s\n", zone.ScreenProfile)
				}
				if zone.HostInboundTraffic != nil {
					if len(zone.HostInboundTraffic.SystemServices) > 0 {
						fmt.Fprintf(&buf, "  Host-inbound system-services: %s\n",
							strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
					}
					if len(zone.HostInboundTraffic.Protocols) > 0 {
						fmt.Fprintf(&buf, "  Host-inbound protocols: %s\n",
							strings.Join(zone.HostInboundTraffic.Protocols, ", "))
					}
				}
				// Traffic counters
				if s.dp != nil && s.dp.IsLoaded() && zoneID > 0 {
					ingress, errIn := s.dp.ReadZoneCounters(zoneID, 0)
					egress, errOut := s.dp.ReadZoneCounters(zoneID, 1)
					if errIn == nil && errOut == nil {
						buf.WriteString("  Traffic statistics:\n")
						fmt.Fprintf(&buf, "    Input:  %d packets, %d bytes\n", ingress.Packets, ingress.Bytes)
						fmt.Fprintf(&buf, "    Output: %d packets, %d bytes\n", egress.Packets, egress.Bytes)
					}
				}
				// Policies referencing this zone
				var policyRefs []string
				for _, zpp := range cfg.Security.Policies {
					if zpp.FromZone == name || zpp.ToZone == name {
						dir := "from"
						peer := zpp.ToZone
						if zpp.ToZone == name {
							dir = "to"
							peer = zpp.FromZone
						}
						policyRefs = append(policyRefs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(zpp.Policies)))
					}
				}
				if len(policyRefs) > 0 {
					fmt.Fprintf(&buf, "  Policies: %s\n", strings.Join(policyRefs, ", "))
				}
				// Detail: per-interface info
				if len(zone.Interfaces) > 0 {
					buf.WriteString("  Interface details:\n")
					for _, ifName := range zone.Interfaces {
						fmt.Fprintf(&buf, "    %s:\n", ifName)
						if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
							for _, unit := range ifc.Units {
								for _, addr := range unit.Addresses {
									fmt.Fprintf(&buf, "      Address: %s\n", addr)
								}
								if unit.DHCP {
									buf.WriteString("      DHCPv4: enabled\n")
								}
								if unit.DHCPv6 {
									buf.WriteString("      DHCPv6: enabled\n")
								}
							}
						}
					}
				}
				// Screen profile detail
				if zone.ScreenProfile != "" {
					if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok {
						fmt.Fprintf(&buf, "  Screen profile details (%s):\n", zone.ScreenProfile)
						var checks []string
						if profile.TCP.Land {
							checks = append(checks, "land")
						}
						if profile.TCP.SynFin {
							checks = append(checks, "syn-fin")
						}
						if profile.TCP.NoFlag {
							checks = append(checks, "no-flag")
						}
						if profile.TCP.FinNoAck {
							checks = append(checks, "fin-no-ack")
						}
						if profile.TCP.WinNuke {
							checks = append(checks, "winnuke")
						}
						if profile.TCP.SynFrag {
							checks = append(checks, "syn-frag")
						}
						if profile.TCP.SynFlood != nil {
							checks = append(checks, fmt.Sprintf("syn-flood(threshold:%d)", profile.TCP.SynFlood.AttackThreshold))
						}
						if profile.ICMP.PingDeath {
							checks = append(checks, "ping-death")
						}
						if profile.ICMP.FloodThreshold > 0 {
							checks = append(checks, fmt.Sprintf("icmp-flood(threshold:%d)", profile.ICMP.FloodThreshold))
						}
						if profile.IP.SourceRouteOption {
							checks = append(checks, "source-route-option")
						}
						if profile.IP.TearDrop {
							checks = append(checks, "teardrop")
						}
						if profile.UDP.FloodThreshold > 0 {
							checks = append(checks, fmt.Sprintf("udp-flood(threshold:%d)", profile.UDP.FloodThreshold))
						}
						if len(checks) > 0 {
							fmt.Fprintf(&buf, "    Enabled checks: %s\n", strings.Join(checks, ", "))
						}
					}
				}
				// Policy detail breakdown
				buf.WriteString("  Policy summary:\n")
				totalPolicies := 0
				for _, zpp := range cfg.Security.Policies {
					if zpp.FromZone == name || zpp.ToZone == name {
						for _, pol := range zpp.Policies {
							action := "permit"
							switch pol.Action {
							case 1:
								action = "deny"
							case 2:
								action = "reject"
							}
							fmt.Fprintf(&buf, "    %s -> %s: %s (%s)\n",
								zpp.FromZone, zpp.ToZone, pol.Name, action)
							totalPolicies++
						}
					}
				}
				if totalPolicies == 0 {
					buf.WriteString("    (no policies)\n")
				}
				buf.WriteString("\n")
			}
		}

	case "ipsec-statistics":
		if s.ipsec == nil {
			buf.WriteString("IPsec manager not available\n")
		} else {
			sas, err := s.ipsec.GetSAStatus()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "IPsec statistics: %v", err)
			}
			activeTunnels := 0
			for _, sa := range sas {
				if sa.State == "ESTABLISHED" || sa.State == "INSTALLED" {
					activeTunnels++
				}
			}
			fmt.Fprintf(&buf, "IPsec statistics:\n")
			fmt.Fprintf(&buf, "  Active tunnels: %d\n", activeTunnels)
			fmt.Fprintf(&buf, "  Total SAs:      %d\n", len(sas))
			buf.WriteString("\n")
			if len(sas) > 0 {
				fmt.Fprintf(&buf, "  %-20s %-14s %-12s %-12s\n", "Name", "State", "Bytes In", "Bytes Out")
				for _, sa := range sas {
					inBytes := sa.InBytes
					if inBytes == "" {
						inBytes = "-"
					}
					outBytes := sa.OutBytes
					if outBytes == "" {
						outBytes = "-"
					}
					fmt.Fprintf(&buf, "  %-20s %-14s %-12s %-12s\n", sa.Name, sa.State, inBytes, outBytes)
				}
			}
			if cfg != nil && len(cfg.Security.IPsec.VPNs) > 0 {
				fmt.Fprintf(&buf, "\n  Configured VPNs: %d\n", len(cfg.Security.IPsec.VPNs))
			}
		}

	case "class-of-service":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			type ifBinding struct {
				name     string
				inputV4  string
				outputV4 string
				inputV6  string
				outputV6 string
			}
			var bindings []ifBinding
			for _, ifc := range cfg.Interfaces.Interfaces {
				for _, unit := range ifc.Units {
					b := ifBinding{name: ifc.Name}
					b.inputV4 = unit.FilterInputV4
					b.outputV4 = unit.FilterOutputV4
					b.inputV6 = unit.FilterInputV6
					b.outputV6 = unit.FilterOutputV6
					if b.inputV4 != "" || b.outputV4 != "" || b.inputV6 != "" || b.outputV6 != "" {
						bindings = append(bindings, b)
					}
				}
			}
			if len(bindings) == 0 {
				buf.WriteString("No interfaces with class-of-service configuration\n")
			} else {
				sort.Slice(bindings, func(i, j int) bool { return bindings[i].name < bindings[j].name })
				printBinding := func(dir, family, filterName string) {
					filters := cfg.Firewall.FiltersInet
					if family == "inet6" {
						filters = cfg.Firewall.FiltersInet6
					}
					f, ok := filters[filterName]
					if !ok {
						fmt.Fprintf(&buf, "  %s filter (%s): %s (not found)\n", dir, family, filterName)
						return
					}
					fmt.Fprintf(&buf, "  %s filter (%s): %s\n", dir, family, filterName)
					for _, term := range f.Terms {
						var matchParts []string
						if term.DSCP != "" {
							matchParts = append(matchParts, "dscp "+term.DSCP)
						}
						if term.Protocol != "" {
							matchParts = append(matchParts, "protocol "+term.Protocol)
						}
						if len(term.DestinationPorts) > 0 {
							matchParts = append(matchParts, "port "+strings.Join(term.DestinationPorts, ","))
						}
						if term.ICMPType >= 0 {
							matchParts = append(matchParts, fmt.Sprintf("icmp-type %d", term.ICMPType))
						}
						if term.ICMPCode >= 0 {
							matchParts = append(matchParts, fmt.Sprintf("icmp-code %d", term.ICMPCode))
						}
						matchStr := "any"
						if len(matchParts) > 0 {
							matchStr = strings.Join(matchParts, " ")
						}
						action := term.Action
						if action == "" {
							action = "accept"
						}
						extras := ""
						if term.ForwardingClass != "" {
							extras += " forwarding-class " + term.ForwardingClass
						}
						if term.DSCPRewrite != "" {
							extras += " dscp " + term.DSCPRewrite
						}
						if term.Log {
							extras += " log"
						}
						fmt.Fprintf(&buf, "    Term %s: match %s -> %s%s\n", term.Name, matchStr, action, extras)
					}
				}
				for _, b := range bindings {
					fmt.Fprintf(&buf, "Interface: %s\n", b.name)
					if b.inputV4 != "" {
						printBinding("Input", "inet", b.inputV4)
					}
					if b.outputV4 != "" {
						printBinding("Output", "inet", b.outputV4)
					}
					if b.inputV6 != "" {
						printBinding("Input", "inet6", b.inputV6)
					}
					if b.outputV6 != "" {
						printBinding("Output", "inet6", b.outputV6)
					}
					buf.WriteString("\n")
				}
			}
		}

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
			if len(snmpCfg.V3Users) > 0 {
				buf.WriteString("SNMPv3 USM users:\n")
				for name, u := range snmpCfg.V3Users {
					auth := u.AuthProtocol
					if auth == "" {
						auth = "none"
					}
					priv := u.PrivProtocol
					if priv == "" {
						priv = "none"
					}
					fmt.Fprintf(&buf, "  %s: auth=%s priv=%s\n", name, auth, priv)
				}
			}
		}

	case "snmp-v3":
		if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
			buf.WriteString("No SNMPv3 users configured\n")
		} else {
			buf.WriteString("SNMPv3 USM Users:\n")
			fmt.Fprintf(&buf, "  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
			for _, u := range cfg.System.SNMP.V3Users {
				auth := u.AuthProtocol
				if auth == "" {
					auth = "none"
				}
				priv := u.PrivProtocol
				if priv == "" {
					priv = "none"
				}
				fmt.Fprintf(&buf, "  %-20s %-12s %-12s\n", u.Name, auth, priv)
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

	case "dhcp-server-detail":
		if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
			buf.WriteString("No DHCP server configured\n")
		} else {
			// Pool configuration
			if srv := cfg.System.DHCPServer.DHCPLocalServer; srv != nil && len(srv.Groups) > 0 {
				buf.WriteString("DHCPv4 Server Configuration:\n")
				for name, group := range srv.Groups {
					fmt.Fprintf(&buf, "  Group: %s\n", name)
					if len(group.Interfaces) > 0 {
						fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
					}
					for _, pool := range group.Pools {
						fmt.Fprintf(&buf, "    Pool: %s\n", pool.Name)
						if pool.Subnet != "" {
							fmt.Fprintf(&buf, "      Subnet: %s\n", pool.Subnet)
						}
						if pool.RangeLow != "" {
							fmt.Fprintf(&buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
						}
						if pool.Router != "" {
							fmt.Fprintf(&buf, "      Router: %s\n", pool.Router)
						}
						if len(pool.DNSServers) > 0 {
							fmt.Fprintf(&buf, "      DNS: %s\n", strings.Join(pool.DNSServers, ", "))
						}
						if pool.LeaseTime > 0 {
							fmt.Fprintf(&buf, "      Lease time: %ds\n", pool.LeaseTime)
						}
					}
				}
				buf.WriteString("\n")
			}
			if srv := cfg.System.DHCPServer.DHCPv6LocalServer; srv != nil && len(srv.Groups) > 0 {
				buf.WriteString("DHCPv6 Server Configuration:\n")
				for name, group := range srv.Groups {
					fmt.Fprintf(&buf, "  Group: %s\n", name)
					if len(group.Interfaces) > 0 {
						fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
					}
					for _, pool := range group.Pools {
						fmt.Fprintf(&buf, "    Pool: %s\n", pool.Name)
						if pool.Subnet != "" {
							fmt.Fprintf(&buf, "      Subnet: %s\n", pool.Subnet)
						}
						if pool.RangeLow != "" {
							fmt.Fprintf(&buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
						}
					}
				}
				buf.WriteString("\n")
			}
			// Leases with subnet IDs
			if s.dhcpServer != nil && s.dhcpServer.IsRunning() {
				leases4, _ := s.dhcpServer.GetLeases4()
				leases6, _ := s.dhcpServer.GetLeases6()
				if len(leases4) == 0 && len(leases6) == 0 {
					buf.WriteString("Active leases: none\n")
				}
				if len(leases4) > 0 {
					fmt.Fprintf(&buf, "DHCPv4 Leases (%d active):\n", len(leases4))
					fmt.Fprintf(&buf, "  %-18s %-20s %-15s %-10s %-12s %s\n", "Address", "MAC", "Hostname", "Subnet", "Lifetime", "Expires")
					for _, l := range leases4 {
						fmt.Fprintf(&buf, "  %-18s %-20s %-15s %-10s %-12s %s\n",
							l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
					}
				}
				if len(leases6) > 0 {
					fmt.Fprintf(&buf, "DHCPv6 Leases (%d active):\n", len(leases6))
					fmt.Fprintf(&buf, "  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "DUID", "Hostname", "Subnet", "Lifetime", "Expires")
					for _, l := range leases6 {
						fmt.Fprintf(&buf, "  %-40s %-20s %-15s %-10s %-12s %s\n",
							l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
					}
				}
			} else {
				buf.WriteString("DHCP server not running (no lease data)\n")
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

	case "lldp":
		if cfg == nil || cfg.Protocols.LLDP == nil {
			buf.WriteString("LLDP not configured\n")
		} else {
			lldpCfg := cfg.Protocols.LLDP
			if lldpCfg.Disable {
				buf.WriteString("LLDP: disabled\n")
			} else {
				interval := lldpCfg.Interval
				if interval <= 0 {
					interval = 30
				}
				holdMult := lldpCfg.HoldMultiplier
				if holdMult <= 0 {
					holdMult = 4
				}
				buf.WriteString("LLDP:\n")
				fmt.Fprintf(&buf, "  Transmit interval: %ds\n", interval)
				fmt.Fprintf(&buf, "  Hold multiplier:   %d\n", holdMult)
				fmt.Fprintf(&buf, "  Hold time:         %ds\n", interval*holdMult)
				if len(lldpCfg.Interfaces) > 0 {
					fmt.Fprintf(&buf, "  Interfaces:        %s\n", strings.Join(lldpCfg.Interfaces, ", "))
				}
				if s.lldpNeighborsFn != nil {
					neighbors := s.lldpNeighborsFn()
					fmt.Fprintf(&buf, "  Neighbors:         %d\n", len(neighbors))
				}
			}
		}

	case "lldp-neighbors":
		if s.lldpNeighborsFn == nil {
			buf.WriteString("LLDP not running\n")
		} else {
			neighbors := s.lldpNeighborsFn()
			if len(neighbors) == 0 {
				buf.WriteString("No LLDP neighbors discovered\n")
			} else {
				fmt.Fprintf(&buf, "%-12s %-20s %-16s %-20s %-6s %s\n",
					"Interface", "Chassis ID", "Port ID", "System Name", "TTL", "Age")
				for _, n := range neighbors {
					age := time.Since(n.LastSeen).Truncate(time.Second)
					fmt.Fprintf(&buf, "%-12s %-20s %-16s %-20s %-6d %s\n",
						n.Interface, n.ChassisID, n.PortID, n.SystemName, n.TTL, age)
				}
			}
		}

	case "firewall":
		hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
		if !hasFilters {
			buf.WriteString("No firewall filters configured\n")
		} else {
			// Resolve filter IDs for counter display
			var filterIDs map[string]uint32
			if s.dp != nil && s.dp.IsLoaded() {
				if cr := s.dp.LastCompileResult(); cr != nil {
					filterIDs = cr.FilterIDs
				}
			}

			printFilters := func(family string, filters map[string]*config.FirewallFilter) {
				names := make([]string, 0, len(filters))
				for name := range filters {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					filter := filters[name]
					fmt.Fprintf(&buf, "Filter: %s (family %s)\n", name, family)

					// Get filter config for counter lookup
					var ruleStart uint32
					var hasCounters bool
					if filterIDs != nil {
						if fid, ok := filterIDs[family+":"+name]; ok {
							if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
								ruleStart = fcfg.RuleStart
								hasCounters = true
							}
						}
					}
					ruleOffset := ruleStart

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

						// Sum counters across all expanded BPF rules for this term
						if hasCounters {
							nSrc := len(term.SourceAddresses)
							for _, ref := range term.SourcePrefixLists {
								if !ref.Except {
									if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
										nSrc += len(pl.Prefixes)
									}
								}
							}
							if nSrc == 0 {
								nSrc = 1
							}
							nDst := len(term.DestAddresses)
							for _, ref := range term.DestPrefixLists {
								if !ref.Except {
									if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
										nDst += len(pl.Prefixes)
									}
								}
							}
							if nDst == 0 {
								nDst = 1
							}
							nDstPorts := len(term.DestinationPorts)
							if nDstPorts == 0 {
								nDstPorts = 1
							}
							nSrcPorts := len(term.SourcePorts)
							if nSrcPorts == 0 {
								nSrcPorts = 1
							}
							numRules := uint32(nSrc * nDst * nDstPorts * nSrcPorts)
							var totalPkts, totalBytes uint64
							for i := uint32(0); i < numRules; i++ {
								if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
									totalPkts += ctrs.Packets
									totalBytes += ctrs.Bytes
								}
							}
							fmt.Fprintf(&buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
							ruleOffset += numRules
						}
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
			var runtimeFeeds map[string]feeds.FeedInfo
			if s.feedsFn != nil {
				runtimeFeeds = s.feedsFn()
			}
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
				if fi, ok := runtimeFeeds[name]; ok {
					fmt.Fprintf(&buf, "  Prefixes: %d\n", fi.Prefixes)
					if !fi.LastFetch.IsZero() {
						age := time.Since(fi.LastFetch).Truncate(time.Second)
						fmt.Fprintf(&buf, "  Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
					} else {
						fmt.Fprintf(&buf, "  Last fetch: never\n")
					}
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
				names := make([]string, 0, len(cfg.Applications.Applications))
				for name := range cfg.Applications.Applications {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					app := cfg.Applications.Applications[name]
					fmt.Fprintf(&buf, "  %-24s proto=%-6s", name, app.Protocol)
					if app.DestinationPort != "" {
						fmt.Fprintf(&buf, " dst-port=%s", app.DestinationPort)
					}
					if app.SourcePort != "" {
						fmt.Fprintf(&buf, " src-port=%s", app.SourcePort)
					}
					if app.InactivityTimeout > 0 {
						fmt.Fprintf(&buf, " timeout=%ds", app.InactivityTimeout)
					}
					if app.ALG != "" {
						fmt.Fprintf(&buf, " alg=%s", app.ALG)
					}
					if app.Description != "" {
						fmt.Fprintf(&buf, " (%s)", app.Description)
					}
					buf.WriteString("\n")
				}
			}
			if len(cfg.Applications.ApplicationSets) > 0 {
				buf.WriteString("Application sets:\n")
				names := make([]string, 0, len(cfg.Applications.ApplicationSets))
				for name := range cfg.Applications.ApplicationSets {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					as := cfg.Applications.ApplicationSets[name]
					fmt.Fprintf(&buf, "  %-24s members: %s\n", name, strings.Join(as.Applications, ", "))
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
			if flow.TCPMSSGreIn > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE in):     %d\n", flow.TCPMSSGreIn)
			}
			if flow.TCPMSSGreOut > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE out):    %d\n", flow.TCPMSSGreOut)
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
			readCtr := func(idx uint32) uint64 {
				v, _ := s.dp.ReadGlobalCounter(idx)
				return v
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

	case "sessions-top:bytes", "sessions-top:packets":
		if s.dp == nil || !s.dp.IsLoaded() {
			buf.WriteString("Dataplane not loaded\n")
		} else {
			sortByBytes := req.Topic == "sessions-top:bytes"
			sortLabel := "bytes"
			if !sortByBytes {
				sortLabel = "packets"
			}

			type topEntry struct {
				src, dst, proto, zone, app string
				fwdPkts, revPkts           uint64
				fwdBytes, revBytes         uint64
				age                        int64
			}
			now := monotonicSeconds()
			zoneNames := make(map[uint16]string)
			if cr := s.dp.LastCompileResult(); cr != nil {
				for name, id := range cr.ZoneIDs {
					zoneNames[id] = name
				}
			}
			var entries []topEntry

			_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
				if val.IsReverse != 0 {
					return true
				}
				inZ := zoneNames[val.IngressZone]
				outZ := zoneNames[val.EgressZone]
				if inZ == "" {
					inZ = fmt.Sprintf("%d", val.IngressZone)
				}
				if outZ == "" {
					outZ = fmt.Sprintf("%d", val.EgressZone)
				}
				var age int64
				if now > val.Created {
					age = int64(now - val.Created)
				}
				entries = append(entries, topEntry{
					src:      fmt.Sprintf("%s:%d", net.IP(key.SrcIP[:]), ntohs(key.SrcPort)),
					dst:      fmt.Sprintf("%s:%d", net.IP(key.DstIP[:]), ntohs(key.DstPort)),
					proto:    protoName(key.Protocol),
					zone:     inZ + "->" + outZ,
					app:      resolveAppName(key.Protocol, ntohs(key.DstPort), cfg),
					fwdPkts:  val.FwdPackets,
					revPkts:  val.RevPackets,
					fwdBytes: val.FwdBytes,
					revBytes: val.RevBytes,
					age:      age,
				})
				return true
			})

			_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
				if val.IsReverse != 0 {
					return true
				}
				inZ := zoneNames[val.IngressZone]
				outZ := zoneNames[val.EgressZone]
				if inZ == "" {
					inZ = fmt.Sprintf("%d", val.IngressZone)
				}
				if outZ == "" {
					outZ = fmt.Sprintf("%d", val.EgressZone)
				}
				var age int64
				if now > val.Created {
					age = int64(now - val.Created)
				}
				entries = append(entries, topEntry{
					src:      fmt.Sprintf("[%s]:%d", net.IP(key.SrcIP[:]), ntohs(key.SrcPort)),
					dst:      fmt.Sprintf("[%s]:%d", net.IP(key.DstIP[:]), ntohs(key.DstPort)),
					proto:    protoName(key.Protocol),
					zone:     inZ + "->" + outZ,
					app:      resolveAppName(key.Protocol, ntohs(key.DstPort), cfg),
					fwdPkts:  val.FwdPackets,
					revPkts:  val.RevPackets,
					fwdBytes: val.FwdBytes,
					revBytes: val.RevBytes,
					age:      age,
				})
				return true
			})

			if sortByBytes {
				sort.Slice(entries, func(i, j int) bool {
					return (entries[i].fwdBytes + entries[i].revBytes) > (entries[j].fwdBytes + entries[j].revBytes)
				})
			} else {
				sort.Slice(entries, func(i, j int) bool {
					return (entries[i].fwdPkts + entries[i].revPkts) > (entries[j].fwdPkts + entries[j].revPkts)
				})
			}

			limit := 20
			if limit > len(entries) {
				limit = len(entries)
			}
			fmt.Fprintf(&buf, "Top %d sessions by %s (of %d total):\n", limit, sortLabel, len(entries))
			fmt.Fprintf(&buf, "%-5s %-22s %-22s %-5s %-20s %12s %12s %5s %s\n",
				"#", "Source", "Destination", "Proto", "Zone", "Bytes(f/r)", "Pkts(f/r)", "Age", "App")
			for i := 0; i < limit; i++ {
				e := entries[i]
				fmt.Fprintf(&buf, "%-5d %-22s %-22s %-5s %-20s %5d/%-6d %5d/%-6d %5d %s\n",
					i+1, e.src, e.dst, e.proto, e.zone,
					e.fwdBytes, e.revBytes, e.fwdPkts, e.revPkts, e.age, e.app)
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
		if s.dp == nil || s.dp.GetPersistentNAT() == nil {
			buf.WriteString("Persistent NAT table not available\n")
		} else {
			bindings := s.dp.GetPersistentNAT().All()
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

	case "nat-source-rule-detail":
		if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
			buf.WriteString("No source NAT rules configured\n")
		} else {
			// Count active SNAT sessions per rule-set
			type ruleSetKey struct{ from, to string }
			rsSessions := make(map[ruleSetKey]int)
			if s.dp != nil && s.dp.IsLoaded() && s.dp.LastCompileResult() != nil {
				cr := s.dp.LastCompileResult()
				zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
				for name, id := range cr.ZoneIDs {
					zoneByID[id] = name
				}
				_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
					if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
						rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
					}
					return true
				})
			}

			ruleIdx := 0
			for _, rs := range cfg.Security.NAT.Source {
				for _, rule := range rs.Rules {
					ruleIdx++
					action := "interface"
					if rule.Then.PoolName != "" {
						action = "pool " + rule.Then.PoolName
					} else if rule.Then.Off {
						action = "off"
					}
					srcMatch := "0.0.0.0/0"
					if rule.Match.SourceAddress != "" {
						srcMatch = rule.Match.SourceAddress
					}
					dstMatch := "0.0.0.0/0"
					if rule.Match.DestinationAddress != "" {
						dstMatch = rule.Match.DestinationAddress
					}
					fmt.Fprintf(&buf, "source NAT rule: %s\n", rule.Name)
					fmt.Fprintf(&buf, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
					fmt.Fprintf(&buf, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
					fmt.Fprintf(&buf, "    Match:\n")
					fmt.Fprintf(&buf, "      Source addresses:      %s\n", srcMatch)
					fmt.Fprintf(&buf, "      Destination addresses: %s\n", dstMatch)
					if rule.Match.Protocol != "" {
						fmt.Fprintf(&buf, "      IP protocol:           %s\n", rule.Match.Protocol)
					}
					fmt.Fprintf(&buf, "    Action:                  %s\n", action)

					if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
						if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
							if pool.PersistentNAT != nil {
								fmt.Fprintf(&buf, "    Persistent NAT:          enabled\n")
							}
							if len(pool.Addresses) > 0 {
								fmt.Fprintf(&buf, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
							}
							portLow, portHigh := pool.PortLow, pool.PortHigh
							if portLow == 0 {
								portLow = 1024
							}
							if portHigh == 0 {
								portHigh = 65535
							}
							fmt.Fprintf(&buf, "    Port range:              %d-%d\n", portLow, portHigh)
						}
					}

					if s.dp != nil && s.dp.LastCompileResult() != nil {
						ruleKey := rs.Name + "/" + rule.Name
						if cid, ok := s.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
							cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
							if err == nil {
								fmt.Fprintf(&buf, "    Translation hits:        %d packets  %d bytes\n",
									cnt.Packets, cnt.Bytes)
							}
						}
					}

					sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
					fmt.Fprintf(&buf, "    Number of sessions:      %d\n\n", sessions)
				}
			}
		}

	case "nat-dest-rule-detail":
		if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
			buf.WriteString("No destination NAT rules configured\n")
		} else {
			dnat := cfg.Security.NAT.Destination
			type ruleSetKey struct{ from, to string }
			rsSessions := make(map[ruleSetKey]int)
			if s.dp != nil && s.dp.IsLoaded() && s.dp.LastCompileResult() != nil {
				cr := s.dp.LastCompileResult()
				zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
				for name, id := range cr.ZoneIDs {
					zoneByID[id] = name
				}
				_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
					if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
						rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
					}
					return true
				})
			}

			ruleIdx := 0
			for _, rs := range dnat.RuleSets {
				for _, rule := range rs.Rules {
					ruleIdx++
					action := "off"
					if rule.Then.PoolName != "" {
						action = "pool " + rule.Then.PoolName
					}
					dstMatch := "0.0.0.0/0"
					if rule.Match.DestinationAddress != "" {
						dstMatch = rule.Match.DestinationAddress
					}
					fmt.Fprintf(&buf, "destination NAT rule: %s\n", rule.Name)
					fmt.Fprintf(&buf, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
					fmt.Fprintf(&buf, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
					fmt.Fprintf(&buf, "    Match:\n")
					fmt.Fprintf(&buf, "      Destination addresses: %s\n", dstMatch)
					if rule.Match.DestinationPort != 0 {
						fmt.Fprintf(&buf, "      Destination port:      %d\n", rule.Match.DestinationPort)
					}
					if rule.Match.Protocol != "" {
						fmt.Fprintf(&buf, "      IP protocol:           %s\n", rule.Match.Protocol)
					}
					if rule.Match.Application != "" {
						fmt.Fprintf(&buf, "      Application:           %s\n", rule.Match.Application)
					}
					fmt.Fprintf(&buf, "    Action:                  %s\n", action)

					if rule.Then.PoolName != "" && dnat.Pools != nil {
						if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
							fmt.Fprintf(&buf, "    Pool address:            %s\n", pool.Address)
							if pool.Port != 0 {
								fmt.Fprintf(&buf, "    Pool port:               %d\n", pool.Port)
							}
						}
					}

					if s.dp != nil && s.dp.LastCompileResult() != nil {
						ruleKey := rs.Name + "/" + rule.Name
						if cid, ok := s.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
							cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
							if err == nil {
								fmt.Fprintf(&buf, "    Translation hits:        %d packets  %d bytes\n",
									cnt.Packets, cnt.Bytes)
							}
						}
					}

					sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
					fmt.Fprintf(&buf, "    Number of sessions:      %d\n\n", sessions)
				}
			}
		}

	case "persistent-nat-detail":
		if s.dp == nil || s.dp.GetPersistentNAT() == nil {
			buf.WriteString("Persistent NAT table not available\n")
		} else {
			bindings := s.dp.GetPersistentNAT().All()
			if len(bindings) == 0 {
				buf.WriteString("No persistent NAT bindings\n")
			} else {
				type natKey struct {
					ip   uint32
					port uint16
				}
				sessionCounts := make(map[natKey]int)
				if s.dp.IsLoaded() {
					_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
						if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
							sessionCounts[natKey{val.NATSrcIP, val.NATSrcPort}]++
						}
						return true
					})
				}

				fmt.Fprintf(&buf, "Total persistent NAT bindings: %d\n\n", len(bindings))
				for i, b := range bindings {
					if i > 0 {
						buf.WriteString("\n")
					}
					remaining := time.Until(b.LastSeen.Add(b.Timeout))
					if remaining < 0 {
						remaining = 0
					}
					natIP := b.NatIP.As4()
					nk := natKey{
						ip:   binary.NativeEndian.Uint32(natIP[:]),
						port: b.NatPort,
					}
					sessions := sessionCounts[nk]

					fmt.Fprintf(&buf, "Persistent NAT binding:\n")
					fmt.Fprintf(&buf, "  Internal IP:        %s\n", b.SrcIP)
					fmt.Fprintf(&buf, "  Internal port:      %d\n", b.SrcPort)
					fmt.Fprintf(&buf, "  Reflexive IP:       %s\n", b.NatIP)
					fmt.Fprintf(&buf, "  Reflexive port:     %d\n", b.NatPort)
					fmt.Fprintf(&buf, "  Pool:               %s\n", b.PoolName)
					if b.PermitAnyRemoteHost {
						fmt.Fprintf(&buf, "  Any remote host:    yes\n")
					}
					fmt.Fprintf(&buf, "  Current sessions:   %d\n", sessions)
					fmt.Fprintf(&buf, "  Left time:          %s\n", remaining.Truncate(time.Second))
					fmt.Fprintf(&buf, "  Configured timeout: %ds\n", int(b.Timeout.Seconds()))
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
					if t.KeepaliveInfo != "" {
						fmt.Fprintf(&buf, "  Keepalive:   %s\n", t.KeepaliveInfo)
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
					if r.MinRTT > 0 {
						fmt.Fprintf(&buf, "    RTT: min %s, max %s, avg %s, jitter %s\n",
							r.MinRTT, r.MaxRTT, r.AvgRTT, r.Jitter)
					}
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

	case "commit-history":
		entries, err := s.store.ListCommitHistory(50)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "commit history: %v", err)
		}
		if len(entries) == 0 {
			buf.WriteString("No commit history available\n")
		} else {
			for i, e := range entries {
				fmt.Fprintf(&buf, "  %d  %s  %s\n", i, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action)
			}
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

	case "security-alarms", "security-alarms-detail":
		detail := req.Topic == "security-alarms-detail"
		var alarmCount int

		if cfg != nil {
			warnings := config.ValidateConfig(cfg)
			for _, w := range warnings {
				alarmCount++
				if detail {
					fmt.Fprintf(&buf, "Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
				}
			}
		}

		if s.dp != nil && s.dp.IsLoaded() {
			readCtr := func(idx uint32) uint64 {
				v, _ := s.dp.ReadGlobalCounter(idx)
				return v
			}
			screenNames := []struct {
				idx  uint32
				name string
			}{
				{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
				{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
				{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
				{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
				{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
				{dataplane.GlobalCtrScreenTearDrop, "Tear-drop"},
				{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
				{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no-flag"},
				{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN-no-ACK"},
				{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
				{dataplane.GlobalCtrScreenIPSrcRoute, "IP source-route"},
				{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
			}
			for _, sc := range screenNames {
				val := readCtr(sc.idx)
				if val > 0 {
					alarmCount++
					if detail {
						fmt.Fprintf(&buf, "Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, sc.name, val)
					}
				}
			}
		}

		if alarmCount == 0 {
			buf.WriteString("No security alarms currently active\n")
		} else if !detail {
			fmt.Fprintf(&buf, "%d security alarm(s) currently active\n", alarmCount)
			buf.WriteString("  run 'show security alarms detail' for details\n")
		}

	case "route-summary":
		if s.routing == nil {
			fmt.Fprintln(&buf, "Routing manager not available")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			// Determine router ID from config
			if cfg != nil {
				routerID := ""
				if cfg.Protocols.OSPF != nil && cfg.Protocols.OSPF.RouterID != "" {
					routerID = cfg.Protocols.OSPF.RouterID
				} else if cfg.Protocols.BGP != nil && cfg.Protocols.BGP.RouterID != "" {
					routerID = cfg.Protocols.BGP.RouterID
				}
				if routerID != "" {
					fmt.Fprintf(&buf, "Router ID: %s\n\n", routerID)
				}
			}
			v4ByProto := make(map[string]int)
			v6ByProto := make(map[string]int)
			var v4Count, v6Count int
			for _, e := range entries {
				if strings.Contains(e.Destination, ":") {
					v6Count++
					v6ByProto[e.Protocol]++
				} else {
					v4Count++
					v4ByProto[e.Protocol]++
				}
			}
			fmt.Fprintf(&buf, "inet.0: %d destinations, %d routes (%d active)\n", v4Count, v4Count, v4Count)
			v4Protos := make([]string, 0, len(v4ByProto))
			for p := range v4ByProto {
				v4Protos = append(v4Protos, p)
			}
			sort.Strings(v4Protos)
			for _, p := range v4Protos {
				fmt.Fprintf(&buf, "  %-14s %d routes, %d active\n", p+":", v4ByProto[p], v4ByProto[p])
			}
			if v6Count > 0 {
				fmt.Fprintln(&buf)
				fmt.Fprintf(&buf, "inet6.0: %d destinations, %d routes (%d active)\n", v6Count, v6Count, v6Count)
				v6Protos := make([]string, 0, len(v6ByProto))
				for p := range v6ByProto {
					v6Protos = append(v6Protos, p)
				}
				sort.Strings(v6Protos)
				for _, p := range v6Protos {
					fmt.Fprintf(&buf, "  %-14s %d routes, %d active\n", p+":", v6ByProto[p], v6ByProto[p])
				}
			}
		}

	case "route-terse":
		if s.routing == nil {
			fmt.Fprintln(&buf, "Routing manager not available")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			buf.WriteString(routing.FormatRouteTerse(entries))
		}

	case "route-detail":
		if s.frr == nil {
			fmt.Fprintln(&buf, "FRR manager not available")
		} else {
			routes, err := s.frr.GetRouteDetailJSON()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get route detail: %v", err)
			}
			if len(routes) == 0 {
				buf.WriteString("No routes\n")
			} else {
				buf.WriteString(frr.FormatRouteDetail(routes))
			}
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
			// Speed/duplex from sysfs
			var linkExtras []string
			if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/speed"); err == nil {
				if spd, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && spd > 0 {
					if spd >= 1000 {
						linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dGbps", spd/1000))
					} else {
						linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dMbps", spd))
					}
				}
			}
			duplexStr := "Full-duplex"
			if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/duplex"); err == nil {
				d := strings.TrimSpace(string(data))
				if d == "half" {
					duplexStr = "Half-duplex"
				}
			}
			linkExtras = append(linkExtras, "Link-mode: "+duplexStr)
			fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d, %s\n", attrs.EncapType, attrs.MTU, strings.Join(linkExtras, ", "))
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
			// BPF traffic counters (XDP/TC level)
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(attrs.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
					fmt.Fprintf(&buf, "  BPF statistics:\n")
					fmt.Fprintf(&buf, "    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
					fmt.Fprintf(&buf, "    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
				}
			}
			addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
			for _, a := range addrs {
				fmt.Fprintf(&buf, "  Address: %s\n", a.IPNet)
			}
			fmt.Fprintln(&buf)
		}

	case "interfaces-detail":
		linksList, err := netlink.LinkList()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing interfaces: %v", err)
		}
		sort.Slice(linksList, func(i, j int) bool {
			return linksList[i].Attrs().Name < linksList[j].Attrs().Name
		})
		ifZoneMap := make(map[string]string)
		ifDescMap := make(map[string]string)
		if cfg != nil {
			for _, z := range cfg.Security.Zones {
				for _, ifName := range z.Interfaces {
					ifZoneMap[ifName] = z.Name
				}
			}
			for _, ifc := range cfg.Interfaces.Interfaces {
				if ifc.Description != "" {
					ifDescMap[ifc.Name] = ifc.Description
				}
			}
		}
		for _, link := range linksList {
			attrs := link.Attrs()
			if attrs.Name == "lo" {
				continue
			}
			if req.Filter != "" && attrs.Name != req.Filter {
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
			if desc, ok := ifDescMap[attrs.Name]; ok {
				fmt.Fprintf(&buf, "  Description: %s\n", desc)
			}
			fmt.Fprintf(&buf, "  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)
			// Speed/duplex from sysfs
			linkType := attrs.EncapType
			if linkType == "" {
				linkType = "Ethernet"
			}
			speedStr := ""
			if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/speed"); err == nil {
				if spd, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && spd > 0 {
					if spd >= 1000 {
						speedStr = fmt.Sprintf(", Speed: %dGbps", spd/1000)
					} else {
						speedStr = fmt.Sprintf(", Speed: %dMbps", spd)
					}
				}
			}
			duplexStr := ""
			if data, err := os.ReadFile("/sys/class/net/" + attrs.Name + "/duplex"); err == nil {
				d := strings.TrimSpace(string(data))
				switch d {
				case "full":
					duplexStr = ", Duplex: Full-duplex"
				case "half":
					duplexStr = ", Duplex: Half-duplex"
				}
			}
			fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d%s%s\n", linkType, attrs.MTU, speedStr, duplexStr)
			if len(attrs.HardwareAddr) > 0 {
				fmt.Fprintf(&buf, "  Current address: %s\n", attrs.HardwareAddr)
			}
			if zone, ok := ifZoneMap[attrs.Name]; ok {
				fmt.Fprintf(&buf, "  Security zone: %s\n", zone)
			}
			fmt.Fprintf(&buf, "  Logical interface %s.0\n", attrs.Name)
			addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
			if len(addrs) > 0 {
				fmt.Fprintf(&buf, "    Addresses:\n")
				for _, a := range addrs {
					fmt.Fprintf(&buf, "      %s\n", a.IPNet)
				}
			}
			if st := attrs.Statistics; st != nil {
				fmt.Fprintf(&buf, "  Traffic statistics:\n")
				fmt.Fprintf(&buf, "    Input  packets:             %12d\n", st.RxPackets)
				fmt.Fprintf(&buf, "    Output packets:             %12d\n", st.TxPackets)
				fmt.Fprintf(&buf, "    Input  bytes:               %12d\n", st.RxBytes)
				fmt.Fprintf(&buf, "    Output bytes:               %12d\n", st.TxBytes)
				fmt.Fprintf(&buf, "    Input  errors:              %12d\n", st.RxErrors)
				fmt.Fprintf(&buf, "    Output errors:              %12d\n", st.TxErrors)
			}
			fmt.Fprintln(&buf)
		}

	case "policies-hit-count":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		// Parse optional zone filter from req.Filter: "from-zone X to-zone Y"
		var filterFrom, filterTo string
		if req.Filter != "" {
			parts := strings.Fields(req.Filter)
			for i := 0; i+1 < len(parts); i++ {
				switch parts[i] {
				case "from-zone":
					filterFrom = parts[i+1]
					i++
				case "to-zone":
					filterTo = parts[i+1]
					i++
				}
			}
		}
		fmt.Fprintf(&buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
			"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
		fmt.Fprintln(&buf, strings.Repeat("-", 88))
		policySetID := uint32(0)
		var totalPkts, totalBytes uint64
		for _, zpp := range cfg.Security.Policies {
			if (filterFrom != "" && zpp.FromZone != filterFrom) ||
				(filterTo != "" && zpp.ToZone != filterTo) {
				policySetID++
				continue
			}
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

	case "policies-detail":
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			fmt.Fprintln(&buf, "No active configuration")
			break
		}
		var filterFrom, filterTo string
		if req.Filter != "" {
			parts := strings.Fields(req.Filter)
			for i := 0; i+1 < len(parts); i++ {
				switch parts[i] {
				case "from-zone":
					filterFrom = parts[i+1]
					i++
				case "to-zone":
					filterTo = parts[i+1]
					i++
				}
			}
		}
		policySetID := uint32(0)
		for _, zpp := range cfg.Security.Policies {
			if (filterFrom != "" && zpp.FromZone != filterFrom) ||
				(filterTo != "" && zpp.ToZone != filterTo) {
				policySetID++
				continue
			}
			fmt.Fprintf(&buf, "Policy: %s -> %s, State: enabled\n", zpp.FromZone, zpp.ToZone)
			for i, pol := range zpp.Policies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				capAction := strings.ToUpper(action[:1]) + action[1:]
				ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				fmt.Fprintf(&buf, "\n  Policy: %s, action-type: %s\n", pol.Name, capAction)
				if pol.Description != "" {
					fmt.Fprintf(&buf, "    Description: %s\n", pol.Description)
				}
				fmt.Fprintf(&buf, "    Match:\n")
				fmt.Fprintf(&buf, "      Source zone: %s\n", zpp.FromZone)
				fmt.Fprintf(&buf, "      Destination zone: %s\n", zpp.ToZone)
				fmt.Fprintf(&buf, "      Source addresses:\n")
				for _, addr := range pol.Match.SourceAddresses {
					resolved := grpcResolveAddress(cfg, addr)
					fmt.Fprintf(&buf, "        %s%s\n", addr, resolved)
				}
				fmt.Fprintf(&buf, "      Destination addresses:\n")
				for _, addr := range pol.Match.DestinationAddresses {
					resolved := grpcResolveAddress(cfg, addr)
					fmt.Fprintf(&buf, "        %s%s\n", addr, resolved)
				}
				fmt.Fprintf(&buf, "      Applications:\n")
				for _, app := range pol.Match.Applications {
					fmt.Fprintf(&buf, "        %s\n", app)
				}
				fmt.Fprintf(&buf, "    Then:\n")
				fmt.Fprintf(&buf, "      %s\n", action)
				if pol.Log != nil {
					fmt.Fprintf(&buf, "      log\n")
				}
				if pol.Count {
					fmt.Fprintf(&buf, "      count\n")
				}
				if s.dp != nil && s.dp.IsLoaded() {
					if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
						fmt.Fprintf(&buf, "    Session statistics:\n")
						fmt.Fprintf(&buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
					}
				}
			}
			policySetID++
			fmt.Fprintln(&buf)
		}
		// Global policies
		if len(cfg.Security.GlobalPolicies) > 0 && filterFrom == "" && filterTo == "" {
			fmt.Fprintf(&buf, "Global policies:\n")
			for i, pol := range cfg.Security.GlobalPolicies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				capAction := strings.ToUpper(action[:1]) + action[1:]
				ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				fmt.Fprintf(&buf, "\n  Policy: %s, action-type: %s\n", pol.Name, capAction)
				if pol.Description != "" {
					fmt.Fprintf(&buf, "    Description: %s\n", pol.Description)
				}
				fmt.Fprintf(&buf, "    Match:\n")
				fmt.Fprintf(&buf, "      Source addresses:\n")
				for _, addr := range pol.Match.SourceAddresses {
					resolved := grpcResolveAddress(cfg, addr)
					fmt.Fprintf(&buf, "        %s%s\n", addr, resolved)
				}
				fmt.Fprintf(&buf, "      Destination addresses:\n")
				for _, addr := range pol.Match.DestinationAddresses {
					resolved := grpcResolveAddress(cfg, addr)
					fmt.Fprintf(&buf, "        %s%s\n", addr, resolved)
				}
				fmt.Fprintf(&buf, "      Applications:\n")
				for _, app := range pol.Match.Applications {
					fmt.Fprintf(&buf, "        %s\n", app)
				}
				fmt.Fprintf(&buf, "    Then:\n")
				fmt.Fprintf(&buf, "      %s\n", action)
				if pol.Log != nil {
					fmt.Fprintf(&buf, "      log\n")
				}
				if pol.Count {
					fmt.Fprintf(&buf, "      count\n")
				}
				if s.dp != nil && s.dp.IsLoaded() {
					if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
						fmt.Fprintf(&buf, "    Session statistics:\n")
						fmt.Fprintf(&buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
					}
				}
			}
			fmt.Fprintln(&buf)
		}

	case "chassis-hardware":
		// Alias: same output as "chassis" (CPU, memory, NICs)
		return s.ShowText(nil, &pb.ShowTextRequest{Topic: "chassis"})

	case "chassis-cluster":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.Chassis.Cluster == nil {
			fmt.Fprintln(&buf, "Cluster not configured")
			break
		}
		cluster := cfg.Chassis.Cluster
		fmt.Fprintf(&buf, "Chassis cluster status:\n")
		fmt.Fprintf(&buf, "  RETH count: %d\n", cluster.RethCount)
		// Show RETH interface names
		if s.routing != nil {
			rethNames := s.routing.RethNames()
			if len(rethNames) > 0 {
				fmt.Fprintf(&buf, "  RETH interfaces: %s\n", strings.Join(rethNames, ", "))
			}
		}
		fmt.Fprintln(&buf)

		// Get live monitor statuses
		var monStatuses map[int][]routing.InterfaceMonitorStatus
		if s.routing != nil {
			monStatuses = s.routing.InterfaceMonitorStatuses()
		}

		for _, rg := range cluster.RedundancyGroups {
			fmt.Fprintf(&buf, "Redundancy group: %d\n", rg.ID)
			for nodeID, priority := range rg.NodePriorities {
				fmt.Fprintf(&buf, "  Node %d priority: %d\n", nodeID, priority)
			}
			if rg.GratuitousARPCount > 0 {
				fmt.Fprintf(&buf, "  Gratuitous ARP count: %d\n", rg.GratuitousARPCount)
			}
			if statuses, ok := monStatuses[rg.ID]; ok && len(statuses) > 0 {
				fmt.Fprintln(&buf, "  Interface monitors:")
				for _, st := range statuses {
					state := "Up"
					if !st.Up {
						state = "Down"
					}
					fmt.Fprintf(&buf, "    %-20s weight %-4d status %s\n",
						st.Interface, st.Weight, state)
				}
			} else if len(rg.InterfaceMonitors) > 0 {
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
		if cfg.Security.Log.Mode != "" {
			fmt.Fprintf(&buf, "  Security log:   mode %s\n", cfg.Security.Log.Mode)
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
		if out, err := exec.Command("chronyc", "tracking").CombinedOutput(); err == nil {
			writeChronyTracking(&buf, string(out))
		} else if out, err := exec.Command("ntpq", "-pn").CombinedOutput(); err == nil {
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
						fmt.Fprintf(&buf, "    term %s:\n", t.Name)
						if t.FromProtocol != "" {
							fmt.Fprintf(&buf, "      from protocol %s\n", t.FromProtocol)
						}
						if t.PrefixList != "" {
							fmt.Fprintf(&buf, "      from prefix-list %s\n", t.PrefixList)
						}
						for _, rf := range t.RouteFilters {
							match := rf.MatchType
							if rf.MatchType == "upto" && rf.UptoLen > 0 {
								match = fmt.Sprintf("upto /%d", rf.UptoLen)
							}
							fmt.Fprintf(&buf, "      from route-filter %s %s\n", rf.Prefix, match)
						}
						if t.Action != "" {
							fmt.Fprintf(&buf, "      then %s\n", t.Action)
						}
						if t.NextHop != "" {
							fmt.Fprintf(&buf, "      then next-hop %s\n", t.NextHop)
						}
						if t.LoadBalance != "" {
							fmt.Fprintf(&buf, "      then load-balance %s\n", t.LoadBalance)
						}
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
					if sr.NextTable != "" {
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
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
					if sr.NextTable != "" {
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
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
			if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
				buf.WriteString("Port mirroring: (see 'show forwarding-options port-mirroring' for details)\n")
				hasContent = true
			}
			if !hasContent {
				buf.WriteString("No forwarding-options configured\n")
			}
		}

	case "forwarding-options-port-mirroring":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			pm := cfg.ForwardingOptions.PortMirroring
			if pm == nil || len(pm.Instances) == 0 {
				buf.WriteString("No port-mirroring instances configured\n")
			} else {
				for name, inst := range pm.Instances {
					fmt.Fprintf(&buf, "Instance: %s\n", name)
					if inst.InputRate > 0 {
						fmt.Fprintf(&buf, "  Input rate: 1/%d\n", inst.InputRate)
					} else {
						buf.WriteString("  Input rate: all packets\n")
					}
					if len(inst.Input) > 0 {
						fmt.Fprintf(&buf, "  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
					}
					if inst.Output != "" {
						fmt.Fprintf(&buf, "  Output interface: %s\n", inst.Output)
					}
					buf.WriteString("\n")
				}
			}
		}

	case "vlans":
		if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
			buf.WriteString("No VLANs configured\n")
		} else {
			ifZone := make(map[string]string)
			for zoneName, zone := range cfg.Security.Zones {
				for _, iface := range zone.Interfaces {
					ifZone[iface] = zoneName
				}
			}
			type vlanEntry struct {
				iface  string
				unit   int
				vlanID int
				zone   string
				trunk  bool
			}
			var entries []vlanEntry
			for _, ifc := range cfg.Interfaces.Interfaces {
				for unitNum, unit := range ifc.Units {
					if unit.VlanID > 0 || ifc.VlanTagging {
						entries = append(entries, vlanEntry{
							iface:  ifc.Name,
							unit:   unitNum,
							vlanID: unit.VlanID,
							zone:   ifZone[ifc.Name],
							trunk:  ifc.VlanTagging,
						})
					}
				}
			}
			if len(entries) == 0 {
				buf.WriteString("No VLANs configured\n")
			} else {
				sort.Slice(entries, func(i, j int) bool {
					if entries[i].iface != entries[j].iface {
						return entries[i].iface < entries[j].iface
					}
					return entries[i].unit < entries[j].unit
				})
				fmt.Fprintf(&buf, "%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
				for _, e := range entries {
					mode := "access"
					if e.trunk {
						mode = "trunk"
					}
					vid := fmt.Sprintf("%d", e.vlanID)
					if e.vlanID == 0 {
						vid = "native"
					}
					fmt.Fprintf(&buf, "%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
				}
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
				if ri.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", ri.Description)
				}
			}
		}

	case "routing-instances-detail":
		if cfg == nil || len(cfg.RoutingInstances) == 0 {
			buf.WriteString("No routing instances configured\n")
		} else {
			for _, ri := range cfg.RoutingInstances {
				fmt.Fprintf(&buf, "Instance: %s\n", ri.Name)
				if ri.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", ri.Description)
				}
				fmt.Fprintf(&buf, "  Type: %s\n", ri.InstanceType)
				if ri.TableID > 0 {
					fmt.Fprintf(&buf, "  Table ID: %d\n", ri.TableID)
				}
				if len(ri.Interfaces) > 0 {
					fmt.Fprintf(&buf, "  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
				}
				if ri.TableID > 0 && s.routing != nil {
					if routes, err := s.routing.GetRoutesForTable(ri.TableID); err == nil {
						fmt.Fprintf(&buf, "  Route count: %d\n", len(routes))
					}
				}
				var protos []string
				if ri.OSPF != nil {
					protos = append(protos, "OSPF")
				}
				if ri.BGP != nil {
					protos = append(protos, "BGP")
				}
				if ri.RIP != nil {
					protos = append(protos, "RIP")
				}
				if ri.ISIS != nil {
					protos = append(protos, "IS-IS")
				}
				if len(protos) > 0 {
					fmt.Fprintf(&buf, "  Protocols: %s\n", strings.Join(protos, ", "))
				}
				if len(ri.StaticRoutes) > 0 {
					fmt.Fprintf(&buf, "  Static routes: %d\n", len(ri.StaticRoutes))
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
				if ri.InterfaceRoutesRibGroup != "" {
					fmt.Fprintf(&buf, "  Interface routes rib-group: %s\n", ri.InterfaceRoutesRibGroup)
				}
				buf.WriteString("\n")
			}
		}

	case "route-instance":
		instanceName := req.Filter
		if instanceName == "" {
			buf.WriteString("Usage: show route instance <name>\n")
			break
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
			break
		}
		var tableID int
		found := false
		for _, ri := range cfg.RoutingInstances {
			if ri.Name == instanceName {
				tableID = ri.TableID
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(&buf, "Routing instance %q not found\n", instanceName)
			break
		}
		if s.routing != nil {
			entries, err := s.routing.GetRoutesForTable(tableID)
			if err != nil {
				fmt.Fprintf(&buf, "Error: %v\n", err)
				break
			}
			fmt.Fprintf(&buf, "Routing table for instance %s (table %d):\n", instanceName, tableID)
			fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n",
				"Destination", "Next-hop", "Interface", "Proto", "Pref")
			for _, e := range entries {
				fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
					e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
			}
		} else {
			buf.WriteString("Routing manager not available\n")
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
				readCtr := func(idx uint32) uint64 {
					v, _ := s.dp.ReadGlobalCounter(idx)
					return v
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

	case "buffers":
		if s.dp != nil {
			stats := s.dp.GetMapStats()
			if len(stats) == 0 {
				buf.WriteString("No BPF maps available\n")
			} else {
				fmt.Fprintf(&buf, "%-24s %-14s %10s %10s %8s %s\n", "Map", "Type", "Max", "Used", "Usage%", "Status")
				buf.WriteString(strings.Repeat("-", 78) + "\n")
				var warnings int
				for _, st := range stats {
					usage := "-"
					used := "-"
					sts := ""
					if st.Type != "Array" && st.Type != "PerCPUArray" {
						used = fmt.Sprintf("%d", st.UsedCount)
						if st.MaxEntries > 0 {
							pct := float64(st.UsedCount) / float64(st.MaxEntries) * 100
							usage = fmt.Sprintf("%.1f%%", pct)
							if pct >= 90 {
								sts = "CRITICAL"
								warnings++
							} else if pct >= 80 {
								sts = "WARNING"
								warnings++
							}
						}
					}
					fmt.Fprintf(&buf, "%-24s %-14s %10d %10s %8s %s\n", st.Name, st.Type, st.MaxEntries, used, usage, sts)
				}
				if warnings > 0 {
					fmt.Fprintf(&buf, "\n%d map(s) at high utilization — consider increasing max_entries\n", warnings)
				}
			}
			v4, v6 := s.dp.SessionCount()
			if v4 > 0 || v6 > 0 {
				fmt.Fprintf(&buf, "\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
			}
		} else {
			buf.WriteString("Dataplane not loaded\n")
		}

	case "bfd-peers":
		if s.frr == nil {
			buf.WriteString("FRR not available\n")
		} else {
			output, err := s.frr.GetBFDPeers()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "BFD peers: %v", err)
			}
			if output == "" {
				buf.WriteString("No BFD peers\n")
			} else {
				buf.WriteString(output)
			}
		}

	case "route-map":
		if s.frr == nil {
			buf.WriteString("FRR not available\n")
		} else {
			output, err := s.frr.GetRouteMapList()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "route-map: %v", err)
			}
			if output == "" {
				buf.WriteString("No route-maps configured\n")
			} else {
				buf.WriteString(output)
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

// writeChronyTracking parses chronyc tracking output and writes key fields.
func writeChronyTracking(buf *strings.Builder, output string) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, " : "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+3:])
			fields[key] = val
		}
	}

	fmt.Fprintln(buf, "\nNTP sync status:")
	for _, pair := range [][2]string{
		{"Reference ID", "Reference"},
		{"Stratum", "Stratum"},
		{"Ref time (UTC)", "Reference time"},
		{"System time", "System time offset"},
		{"Last offset", "Last offset"},
		{"RMS offset", "RMS offset"},
		{"Frequency", "Frequency"},
		{"Root delay", "Root delay"},
		{"Root dispersion", "Root dispersion"},
		{"Update interval", "Poll interval"},
		{"Leap status", "Leap status"},
	} {
		if v, ok := fields[pair[0]]; ok {
			fmt.Fprintf(buf, "  %s: %s\n", pair[1], v)
		}
	}
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
		writeNeighSummary(&buf, neighbors, neighStateStr)
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
		writeNeighSummary(&buf, neighbors, neighStateStr)
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

// writeNeighSummary writes a neighbor table summary (total + per-state + per-interface counts).
func writeNeighSummary(buf *strings.Builder, neighbors []netlink.Neigh, stateFn func(int) string) {
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		stateCounts[stateFn(n.State)]++
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifaceCounts[link.Attrs().Name]++
		}
	}
	fmt.Fprintf(buf, "Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete"} {
			if cnt := stateCounts[s]; cnt > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, cnt))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(buf, " (%s)", strings.Join(parts, ", "))
		}
	}
	fmt.Fprintln(buf)
	if len(ifaceCounts) > 1 {
		var ifNames []string
		for name := range ifaceCounts {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, name := range ifNames {
			fmt.Fprintf(buf, "  %-12s %d entries\n", name, ifaceCounts[name])
		}
	}
	fmt.Fprintln(buf)
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

	case "clear-arp":
		out, err := exec.Command("ip", "-4", "neigh", "flush", "all").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush ARP: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "ARP cache cleared"}, nil

	case "clear-ipv6-neighbors":
		out, err := exec.Command("ip", "-6", "neigh", "flush", "all").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "IPv6 neighbor cache cleared"}, nil

	case "clear-policy-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearPolicyCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "policy hit counters cleared"}, nil

	case "clear-firewall-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearFilterCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "Firewall filter counters cleared"}, nil

	case "clear-nat-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearNATRuleCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "NAT translation statistics cleared"}, nil

	case "clear-persistent-nat":
		if s.dp == nil || s.dp.GetPersistentNAT() == nil {
			return &pb.SystemActionResponse{Message: "Persistent NAT table not available"}, nil
		}
		count := s.dp.GetPersistentNAT().Len()
		s.dp.GetPersistentNAT().Clear()
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Cleared %d persistent NAT bindings", count),
		}, nil

	case "ospf-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh("clear ip ospf process"); err != nil {
			return nil, status.Errorf(codes.Internal, "clear OSPF: %v", err)
		}
		return &pb.SystemActionResponse{Message: "OSPF process cleared"}, nil

	case "bgp-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh("clear bgp * soft"); err != nil {
			return nil, status.Errorf(codes.Internal, "clear BGP: %v", err)
		}
		return &pb.SystemActionResponse{Message: "BGP sessions cleared (soft reset)"}, nil

	case "ipsec-sa-clear":
		if s.ipsec == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "IPsec manager not available")
		}
		count, err := s.ipsec.TerminateAllSAs()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Cleared %d IPsec SA(s)", count),
		}, nil

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

// routePrefixMatch checks if a route destination matches a filter prefix.
func routePrefixMatch(routeDst string, filterNet *net.IPNet, filterErr error) bool {
	if filterErr != nil {
		return routeDst == filterNet.String()
	}
	_, routeNet, err := net.ParseCIDR(routeDst)
	if err != nil {
		return false
	}
	filterOnes, _ := filterNet.Mask.Size()
	routeOnes, _ := routeNet.Mask.Size()
	if filterOnes <= routeOnes {
		return filterNet.Contains(routeNet.IP)
	}
	return routeNet.Contains(filterNet.IP)
}

// policyActionName returns a human-readable policy action name.
func policyActionName(a config.PolicyAction) string {
	switch a {
	case 1:
		return "deny"
	case 2:
		return "reject"
	default:
		return "permit"
	}
}

// matchShowPolicyAddr checks if an IP matches a list of address-book references.
func matchShowPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
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
		if matchShowPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchShowPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
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
		if matchShowPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchShowPolicyApp checks if a protocol/port matches a list of application references.
func matchShowPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchShowSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchShowSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchShowSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
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

// grpcResolveAddress looks up a named address in the global address book and returns its CIDR suffix.
func grpcResolveAddress(cfg *config.Config, name string) string {
	if name == "any" {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}
