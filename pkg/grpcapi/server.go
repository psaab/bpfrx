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
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/frr"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
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
	DHCP     *dhcp.Manager
	ApplyFn  func(*config.Config) // daemon's applyConfig callback
}

// Server implements the BpfrxService gRPC service.
type Server struct {
	pb.UnimplementedBpfrxServiceServer
	store     *configstore.Store
	dp        *dataplane.Manager
	eventBuf  *logging.EventBuffer
	gc        *conntrack.GC
	routing   *routing.Manager
	frr       *frr.Manager
	ipsec     *ipsec.Manager
	dhcp      *dhcp.Manager
	applyFn   func(*config.Config)
	startTime time.Time
	addr      string
}

// NewServer creates a new gRPC server.
func NewServer(addr string, cfg Config) *Server {
	return &Server{
		store:     cfg.Store,
		dp:        cfg.DP,
		eventBuf:  cfg.EventBuf,
		gc:        cfg.GC,
		routing:   cfg.Routing,
		frr:       cfg.FRR,
		ipsec:     cfg.IPsec,
		dhcp:      cfg.DHCP,
		applyFn:   cfg.ApplyFn,
		startTime: time.Now(),
		addr:      addr,
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
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowActiveSet()
	case req.Target == pb.ConfigTarget_ACTIVE:
		output = s.store.ShowActive()
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

	return &pb.GetGlobalStatsResponse{
		RxPackets:        readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:        readCounter(dataplane.GlobalCtrTxPackets),
		Drops:            readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated:  readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:   readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:      readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:     readCounter(dataplane.GlobalCtrPolicyDeny),
		NatAllocFailures: readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDenies: readCounter(dataplane.GlobalCtrHostInboundDeny),
		TcEgressPackets:  readCounter(dataplane.GlobalCtrTCEgressPackets),
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
			Name:       zoneName,
			Interfaces: zone.Interfaces,
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

	now := monotonicSeconds()
	var all []*pb.SessionEntry
	idx := 0

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
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV4(key, val, now))
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
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV6(key, val, now))
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

	resp := &pb.GetEventsResponse{}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.EventEntry{
			Time:           ev.Time.Format(time.RFC3339),
			Type:           ev.Type,
			SrcAddr:        ev.SrcAddr,
			DstAddr:        ev.DstAddr,
			Protocol:       ev.Protocol,
			Action:         ev.Action,
			PolicyId:       ev.PolicyID,
			IngressZone:    uint32(ev.InZone),
			EgressZone:     uint32(ev.OutZone),
			ScreenCheck:    ev.ScreenCheck,
			SessionPackets: ev.SessionPkts,
			SessionBytes:   ev.SessionBytes,
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
	return completeFromTree(operationalTree, words, partial)
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
		return completeFromTree(operationalTree, words[1:], partial)
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
	desc     string
	children map[string]*completionNode
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
		"route":      {desc: "Show routing table"},
		"schedulers": {desc: "Show policy schedulers"},
		"snmp":       {desc: "Show SNMP statistics"},
		"security": {desc: "Show security information", children: map[string]*completionNode{
			"zones":    {desc: "Show security zones"},
			"policies": {desc: "Show security policies"},
			"screen":   {desc: "Show screen/IDS profiles"},
			"flow": {desc: "Show flow information", children: map[string]*completionNode{
				"session": {desc: "Show active sessions"},
			}},
			"nat": {desc: "Show NAT information", children: map[string]*completionNode{
				"source":      {desc: "Show source NAT"},
				"destination": {desc: "Show destination NAT"},
				"static":      {desc: "Show static NAT"},
			}},
			"address-book": {desc: "Show address book entries"},
			"applications": {desc: "Show application definitions"},
			"log":          {desc: "Show recent security events"},
			"statistics":   {desc: "Show global statistics"},
			"ipsec": {desc: "Show IPsec status", children: map[string]*completionNode{
				"security-associations": {desc: "Show IPsec SAs"},
			}},
		}},
		"interfaces": {desc: "Show interface status", children: map[string]*completionNode{
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
		"system": {desc: "Show system information", children: map[string]*completionNode{
			"rollback": {desc: "Show rollback history"},
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

func completeFromTree(tree map[string]*completionNode, words []string, partial string) []string {
	current := tree
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil
		}
		if node.children == nil {
			return nil
		}
		current = node.children
	}
	return filterPrefix(keysOf(current), partial)
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

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64) *pb.SessionEntry {
	se := &pb.SessionEntry{
		SrcAddr:        net.IP(key.SrcIP[:]).String(),
		DstAddr:        net.IP(key.DstIP[:]).String(),
		SrcPort:        uint32(ntohs(key.SrcPort)),
		DstPort:        uint32(ntohs(key.DstPort)),
		Protocol:       protoName(key.Protocol),
		State:          sessionStateName(val.State),
		PolicyId:       val.PolicyID,
		IngressZone:    uint32(val.IngressZone),
		EgressZone:     uint32(val.EgressZone),
		FwdPackets:     val.FwdPackets,
		FwdBytes:       val.FwdBytes,
		RevPackets:     val.RevPackets,
		RevBytes:       val.RevBytes,
		TimeoutSeconds: val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.AgeSeconds = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.Nat = fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.Nat = fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort))
	}
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64) *pb.SessionEntry {
	se := &pb.SessionEntry{
		SrcAddr:        net.IP(key.SrcIP[:]).String(),
		DstAddr:        net.IP(key.DstIP[:]).String(),
		SrcPort:        uint32(ntohs(key.SrcPort)),
		DstPort:        uint32(ntohs(key.DstPort)),
		Protocol:       protoName(key.Protocol),
		State:          sessionStateName(val.State),
		PolicyId:       val.PolicyID,
		IngressZone:    uint32(val.IngressZone),
		EgressZone:     uint32(val.EgressZone),
		FwdPackets:     val.FwdPackets,
		FwdBytes:       val.FwdBytes,
		RevPackets:     val.RevPackets,
		RevBytes:       val.RevBytes,
		TimeoutSeconds: val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.AgeSeconds = int64(now - val.LastSeen)
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
		for _, inst := range instances {
			resp.Instances = append(resp.Instances, &pb.VRRPInstanceInfo{
				Interface:        inst.Interface,
				GroupId:          int32(inst.GroupID),
				State:            "BACKUP",
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
