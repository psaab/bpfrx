// Package grpcapi implements the gRPC API server for xpf.
package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Config configures the gRPC server.
type Config struct {
	Store         *configstore.Store
	DP            grpcRuntime
	EventBuf      *logging.EventBuffer
	GC            *conntrack.GC
	Routing       *routing.Manager
	FRR           *frr.Manager
	IPsec         *ipsec.Manager
	Cluster       *cluster.Manager
	DHCP          *dhcp.Manager
	DHCPServer    *dhcpserver.Manager
	RPMResultsFn  func() []*rpm.ProbeResult   // returns live RPM results
	IPMonStatusFn func() []ipmon.PolicyStatus // returns live ip-monitoring policy status (#1827)
	// NATPoolAlarmsFn returns the active NAT pool-utilization alarms for
	// `show security alarms` (#2079). nil when no monitor is wired.
	NATPoolAlarmsFn func() []natpoolalarm.ActiveAlarm
	FeedsFn         func() map[string]feeds.FeedInfo // returns live feed status
	// FeedOverlayFn returns the live dynamic-address feed-prefix overlay
	// (#2049) — an address-name -> union-of-feed-CIDRs map for the active
	// config — consulted by the `match-policies` simulator (#3042) so a
	// feed-backed policy address token resolves to its live feed prefixes.
	// Optional; if nil the simulator uses static address-book content only.
	FeedOverlayFn   func() map[string][]string
	LLDPNeighborsFn func() []*lldp.Neighbor // returns live LLDP neighbors
	// #1387 inc-2: DHCP dynamic-DNS status sources for
	// `show system services dhcp-server dynamic-dns [detail]`. nil when the
	// manager is absent (NoDataplane) — the show renders "not running".
	DDNSStatsFn        func() *dhcpserver.DDNSStats
	DDNSOwnedRecordsFn func() []dhcpserver.DDNSOwnedRecordView
	// #2691 P2: Surface A (router/interface-address) DDNS status sources for
	// `show system services dynamic-dns [detail]`. nil when the manager is
	// absent (NoDataplane).
	SurfaceADDNSStatsFn  func() *ddnspkg.SurfaceAStats
	SurfaceADDNSStatusFn func() []ddnspkg.SurfaceAStatusView
	// #3276: operator force-now / check-now verb for `request system
	// dynamic-dns update`. force=true arms the Surface A force-now latch +
	// nudges an immediate publish; force=false nudges a re-observe pass. Returns
	// (ok, message); honors the per-RG owner gate (no-op + clear message on the
	// backup). nil when the manager is absent (NoDataplane).
	SurfaceADDNSForceFn func(force bool) (bool, string)
	// #2464: per-collector NetFlow v9 / IPFIX write-health for
	// `show services flow-monitoring statistics`. nil when no flow export
	// is wired — the show renders "no flow export configured".
	FlowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
	// #846: atomic commit+apply callbacks. The daemon holds its
	// apply semaphore across configstore.Commit, applyConfig, and
	// (for gRPC) syncConfigToPeer, so two concurrent committers
	// can't interleave their commit→apply pairs. Returns ctx.Err()
	// if the request is canceled before the semaphore is acquired
	// (handlers translate to DeadlineExceeded/Canceled).
	CommitFn          func(ctx context.Context, comment string) (*config.Config, error)
	CommitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error)
	VRRPMgr           *vrrp.Manager      // native VRRP manager
	RAMgr             *ra.Manager        // embedded RA sender manager
	Version           string             // software version string
	FabricPeerAddrFn  func() []string    // returns peer fabric IPs (fab0, fab1; empty if standalone)
	FabricVRFDevice   string             // VRF for fabric interface (e.g. "vrf-mgmt")
	FwdSampler        *fwdstatus.Sampler // #881: 5s/1m/5m CPU windows for `show chassis forwarding`
}

// Server implements the BpfrxService gRPC service.
type Server struct {
	pb.UnimplementedBpfrxServiceServer
	store                 *configstore.Store
	dp                    grpcRuntime
	eventBuf              *logging.EventBuffer
	gc                    *conntrack.GC
	routing               *routing.Manager
	frr                   *frr.Manager
	ipsec                 *ipsec.Manager
	cluster               *cluster.Manager
	dhcp                  *dhcp.Manager
	dhcpServer            *dhcpserver.Manager
	rpmResultsFn          func() []*rpm.ProbeResult
	ipmonStatusFn         func() []ipmon.PolicyStatus
	natPoolAlarmsFn       func() []natpoolalarm.ActiveAlarm
	feedsFn               func() map[string]feeds.FeedInfo
	feedOverlayFn         func() map[string][]string
	lldpNeighborsFn       func() []*lldp.Neighbor
	ddnsStatsFn           func() *dhcpserver.DDNSStats
	ddnsOwnedRecordsFn    func() []dhcpserver.DDNSOwnedRecordView
	surfaceADDNSStatsFn   func() *ddnspkg.SurfaceAStats
	surfaceADDNSStatusFn  func() []ddnspkg.SurfaceAStatusView
	surfaceADDNSForceFn   func(force bool) (bool, string)
	flowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
	commitFn              func(ctx context.Context, comment string) (*config.Config, error)
	commitConfirmedFn     func(ctx context.Context, minutes int) (*config.Config, error)
	vrrpMgr               *vrrp.Manager
	raMgr                 *ra.Manager
	fwdSampler            *fwdstatus.Sampler
	startTime             time.Time
	addr                  string
	version               string
	fabricPeerAddrFn      func() []string
	fabricVRFDevice       string
	peerSystemActionFn    func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error)
	// peerZonePairSummaryFn is a test seam for the GetZonePairSummary peer
	// fan-out leg (#3592). Production leaves it nil and proxyPeerZonePairSummary
	// dials the real peer; a unit test wires it to observe the forwarded
	// request (x-peer-forwarded metadata) without a live peer.
	peerZonePairSummaryFn func(ctx context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error)
}

func (s *Server) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := s.dp.(userspaceStatusProvider)
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

func (s *Server) userspaceDataplaneControl() (userspaceControlProvider, error) {
	provider, ok := s.dp.(userspaceControlProvider)
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

// NewServer creates a new gRPC server.
// NOTE: gRPC is local-only (127.0.0.1) so all RPCs are inherently trusted.
// Login class RBAC enforcement could be added here via per-RPC interceptors if
// gRPC is ever exposed on non-loopback addresses.
func NewServer(addr string, cfg Config) *Server {
	return &Server{
		store:                 cfg.Store,
		dp:                    cfg.DP,
		eventBuf:              cfg.EventBuf,
		gc:                    cfg.GC,
		routing:               cfg.Routing,
		frr:                   cfg.FRR,
		ipsec:                 cfg.IPsec,
		cluster:               cfg.Cluster,
		dhcp:                  cfg.DHCP,
		dhcpServer:            cfg.DHCPServer,
		rpmResultsFn:          cfg.RPMResultsFn,
		ipmonStatusFn:         cfg.IPMonStatusFn,
		natPoolAlarmsFn:       cfg.NATPoolAlarmsFn,
		feedsFn:               cfg.FeedsFn,
		feedOverlayFn:         cfg.FeedOverlayFn,
		lldpNeighborsFn:       cfg.LLDPNeighborsFn,
		ddnsStatsFn:           cfg.DDNSStatsFn,
		ddnsOwnedRecordsFn:    cfg.DDNSOwnedRecordsFn,
		surfaceADDNSStatsFn:   cfg.SurfaceADDNSStatsFn,
		surfaceADDNSStatusFn:  cfg.SurfaceADDNSStatusFn,
		surfaceADDNSForceFn:   cfg.SurfaceADDNSForceFn,
		flowCollectorHealthFn: cfg.FlowCollectorHealthFn,
		commitFn:              cfg.CommitFn,
		commitConfirmedFn:     cfg.CommitConfirmedFn,
		vrrpMgr:               cfg.VRRPMgr,
		raMgr:                 cfg.RAMgr,
		fwdSampler:            cfg.FwdSampler,
		startTime:             time.Now(),
		addr:                  addr,
		version:               cfg.Version,
		fabricPeerAddrFn:      cfg.FabricPeerAddrFn,
		fabricVRFDevice:       cfg.FabricVRFDevice,
	}
}

// Run starts the gRPC server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(s.configLockInterceptor),
	)
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

// RunFabricListener starts an additional gRPC listener on the fabric IP
// so the cluster peer can proxy monitor requests. Blocks until ctx is cancelled.
// vrfDevice may be empty for default VRF, or e.g. "vrf-mgmt".
func (s *Server) RunFabricListener(ctx context.Context, addr, vrfDevice string) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if vrfDevice != "" {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfDevice)
				}
			})
			return err
		},
	}
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		slog.Warn("gRPC fabric listener failed", "addr", addr, "vrf", vrfDevice, "err", err)
		return
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(s.configLockInterceptor),
	)
	pb.RegisterBpfrxServiceServer(srv, s)

	go func() {
		slog.Info("gRPC fabric listener started", "addr", addr, "vrf", vrfDevice)
		if err := srv.Serve(lis); err != nil {
			slog.Warn("gRPC fabric listener error", "err", err)
		}
	}()

	<-ctx.Done()
	srv.GracefulStop()
}

// configLockInterceptor auto-releases stale config locks when a gRPC client
// disconnects (context cancelled) without calling ExitConfigure.
func (s *Server) configLockInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	resp, err := handler(ctx, req)

	// If the client's context was cancelled (disconnect, Ctrl-C), release any
	// config lock held by this connection.
	if ctx.Err() != nil {
		sessionID := peerSessionID(ctx)
		if sessionID != "" {
			if s.store.ExitConfigureSession(sessionID) {
				slog.Info("auto-released config lock on client disconnect", "session", sessionID)
			}
		}
	}
	return resp, err
}

// peerSessionID derives a stable session identifier from the gRPC peer address.
func peerSessionID(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	return p.Addr.String()
}
