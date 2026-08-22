// Package grpcapi implements the gRPC API server for xpf.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
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
	"github.com/psaab/xpf/pkg/sysservices"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/vrrp"
)

// maxRecvMsgSize caps an inbound gRPC message (fable-review-164 H-2). grpc-go
// defaults to 4 MiB, which is already enough to crash the pre-fix config
// parser; this explicit 16 MiB cap matches configstore.MaxConfigSize (the
// transport-independent parse ceiling) so an oversized Load/config-sync body
// is rejected at the transport with ResourceExhausted rather than buffered and
// fed to the parser.
const maxRecvMsgSize = 16 << 20 // 16 MiB

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
	// ZeroizeFn runs a factory-reset (zeroize) wipe under the daemon's apply
	// gate (#5281). It acquires the same apply semaphore commit/sync serialize
	// on, enters a TERMINAL reset generation so no concurrent or subsequent
	// config writer can re-create the erased .configdb SSOT or re-render the
	// wiped secrets, runs the passed wipe closure (the package performZeroizeWipe
	// primitive) while quiesced, and returns nil ONLY when the wipe fully
	// completed. On failure it fail-closes (the box stays recoverable) and
	// returns the error, and the SystemAction handler does NOT stop the daemon.
	// nil in NoDataplane / unit-test builds with no daemon, in which case the
	// handler falls back to an ungated direct wipe (the pre-#5281 behavior).
	ZeroizeFn        func(ctx context.Context, wipe func() error) error
	VRRPMgr          *vrrp.Manager      // native VRRP manager
	RAMgr            *ra.Manager        // embedded RA sender manager
	Version          string             // software version string
	FabricPeerAddrFn func() []string    // returns peer fabric IPs (fab0, fab1; empty if standalone)
	FabricVRFDevice  string             // VRF for fabric interface (e.g. "vrf-mgmt")
	FwdSampler       *fwdstatus.Sampler // #881: 5s/1m/5m CPU windows for `show chassis forwarding`
	// ListenersFn returns the EFFECTIVE (post-clamp, post-bind) management
	// listener addresses `show system services` reports (#6385). The daemon
	// wires it to Daemon.effectiveListeners so the remote gRPC renderer and the
	// local CLI read ONE daemon-owned snapshot and can never disagree. nil in a
	// unit-test / no-daemon build, where showSystemServices falls back to the
	// documented loopback defaults.
	ListenersFn func() sysservices.Listeners
	// KernelUpgradeStatusFn returns the #1930 kernel-channel state for
	// `show system kernel-upgrade` (#6495). Wired by the daemon, which reads
	// the durable journal + promotion marker + last-roll record and supplies
	// the cluster hold reason it alone knows. nil in a unit-test / no-daemon
	// build, where the topic reports an idle channel.
	KernelUpgradeStatusFn func() upgrade.ChannelStatus
	// PeerLookupFn overrides how the primary listener's #5278 authorization
	// gate learns which local account owns a connection. Production leaves it
	// nil and the gate calls authz.LookupPeer, which reads the kernel's socket
	// table. A test wires it so a case can state WHICH principal is calling
	// instead of testing whichever account runs the suite; the kernel lookup
	// itself is covered against live sockets in pkg/authz, and
	// TestProductionServerEnforcesRealPeerIdentity_5278 closes the loop here
	// with no injection at all.
	PeerLookupFn func(client, server net.Addr) authz.PeerIdentity
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
	zeroizeFn             func(ctx context.Context, wipe func() error) error
	vrrpMgr               *vrrp.Manager
	raMgr                 *ra.Manager
	fwdSampler            *fwdstatus.Sampler
	startTime             time.Time
	addr                  string
	version               string
	// listenersFn returns the effective management-listener snapshot for
	// `show system services` (#6385). Wired from Config.ListenersFn; nil in a
	// no-daemon unit-test build.
	listenersFn func() sysservices.Listeners
	// kernelUpgradeStatusFn backs the `kernel-upgrade` ShowText topic (#6495).
	// Wired from Config.KernelUpgradeStatusFn; nil in a no-daemon unit build.
	kernelUpgradeStatusFn func() upgrade.ChannelStatus
	// requestedAddr is the primary gRPC bind requested at construction
	// (--grpc-addr). Immutable, so it is read without effMu; it is the fallback
	// address reported while pre-bind and on a bind failure (#6385/#6401).
	requestedAddr string
	// ifindexByName resolves a netdev name to its kernel ifindex when
	// building the session {ifindex, VLAN} -> interface-name table. nil
	// means the real kernel lookup; tests inject a fixed table so the
	// session-identity paths are exercisable without real netdevs.
	ifindexByName func(string) (int, error)
	// effMu guards the primary gRPC listener state Run records for the
	// `show system services` effective-listener snapshot (#6385/#6401): effAddr
	// is the actual bound address (post-#5035 clamp, post-net.Listen), effState
	// tracks pre-bind → serving → failed. The daemon reads them via
	// EffectiveListener so the CLI reports what the listener is truly doing, not
	// the requested --grpc-addr.
	effMu              sync.Mutex
	effAddr            string
	effState           grpcListenState
	fabricPeerAddrFn   func() []string
	fabricVRFDevice    string
	peerSystemActionFn func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error)
	// peerZonePairSummaryFn is a test seam for the GetZonePairSummary peer
	// fan-out leg (#3592). Production leaves it nil and proxyPeerZonePairSummary
	// dials the real peer; a unit test wires it to observe the forwarded
	// request (x-peer-forwarded metadata) without a live peer.
	peerZonePairSummaryFn func(ctx context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error)
	// peerSessionSummaryFn is the GetSessionSummary analog of
	// peerZonePairSummaryFn (#5320). Production leaves it nil and
	// proxyPeerSessionSummary dials the real peer; a unit test wires it to
	// drive the peer_status classification (OK / UNREACHABLE / NOT_APPLICABLE)
	// without a live peer.
	peerSessionSummaryFn func(ctx context.Context) (*pb.GetSessionSummaryResponse, error)
	// peerLookupFn resolves a connection's peer identity for the #5278
	// authorization gate on the PRIMARY listener. Production leaves it nil and
	// lookupPeer falls back to authz.LookupPeer; wired from Config.PeerLookupFn.
	peerLookupFn func(client, server net.Addr) authz.PeerIdentity
	// fabricAuthKeyFn is a test seam for the #4107 fabric-listener PSK auth.
	// Production leaves it nil and fabricAuthKey() reads the live control-link
	// key from the cluster manager; a unit test wires it to inject a key
	// without building a full cluster.Manager.
	fabricAuthKeyFn func() []byte
	// heartbeatAuthSeenFn is a test seam for the #4107 fabric downgrade-guard
	// arming signal. Production leaves it nil and heartbeatPeerAuthSeen() reads
	// cluster.Manager.HeartbeatPeerAuthSeen(); a unit test wires it to drive the
	// heartbeat-armed state without a live heartbeat receiver.
	heartbeatAuthSeenFn func() bool
	// fabricPeerAuthSeen is the sticky #4107 downgrade guard: set true once a
	// valid PSK token has authenticated on the fabric listener. After that, a
	// tokenless fabric RPC is rejected (a downgrade to cleartext once both
	// nodes are keyed is an attack), not treated as a key-rollout grace case.
	fabricPeerAuthSeen atomic.Bool
	// fabricListenerMu guards fabricListenerUp (#5047). The fabric-listener
	// supervisor records per-address up/down health so a status surface (or the
	// caller) can observe whether the network-exposed peer-proxy gRPC surface is
	// currently serving. Keyed by bind address because a dual-fabric deployment
	// runs two supervisors (fab0 + fab1) against one Server.
	fabricListenerMu sync.Mutex
	fabricListenerUp map[string]bool
	// monitorStatus coalesces the userspace-dataplane Status() control-socket
	// query for the MonitorInterface streaming path (#5707). Every open stream
	// polls once per second and summary mode reads every configured interface
	// each tick, so without coalescing N interfaces across S concurrent streams
	// issue O(N*S) Status() calls per tick, contending on the shared helper
	// control socket and starving session installs. The cache serves one fetched
	// snapshot to every caller within monitorStatusTTL, collapsing the fan-out to
	// O(1) queries per tick regardless of interface or subscriber count. Lazily
	// built by monitorStatusReader; a test may pre-seed it with an injected clock.
	monitorStatusOnce  sync.Once
	monitorStatusCache *monitorStatusCache
}

func (s *Server) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := s.dpProbe().(userspaceStatusProvider)
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

func (s *Server) userspaceDataplaneControl() (userspaceControlProvider, error) {
	provider, ok := s.dpProbe().(userspaceControlProvider)
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

// NewServer creates a new gRPC server.
//
// The primary listener is loopback-only AND per-principal authorized (#5278).
// Loopback is a location, not an identity: the daemon provisions every `system
// login user` a real shell account, so a `read-only` class holder can dial
// 127.0.0.1:50051 directly, and pkg/cli's RBAC check runs in the CLI process
// where such a caller simply does not run it. Run therefore does BOTH — it
// clamps a non-loopback bind back to loopback (clampGRPCBindToLoopback, #5035)
// AND installs the login-class authorization chain (authz.go) that derives the
// caller's account from the kernel's socket table and denies any RPC the
// caller's class does not hold. Cross-node access still uses the separately
// authenticated fabric listener (RunFabricListener), not this one.
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
		zeroizeFn:             cfg.ZeroizeFn,
		vrrpMgr:               cfg.VRRPMgr,
		raMgr:                 cfg.RAMgr,
		fwdSampler:            cfg.FwdSampler,
		startTime:             time.Now(),
		addr:                  addr,
		requestedAddr:         addr,
		version:               cfg.Version,
		fabricPeerAddrFn:      cfg.FabricPeerAddrFn,
		fabricVRFDevice:       cfg.FabricVRFDevice,
		listenersFn:           cfg.ListenersFn,
		kernelUpgradeStatusFn: cfg.KernelUpgradeStatusFn,
		peerLookupFn:          cfg.PeerLookupFn,
	}
}

// grpcListenState tracks the primary gRPC listener lifecycle for the
// `show system services` effective-listener snapshot (#6385/#6401).
type grpcListenState int

const (
	// grpcPreBind: constructed, Run has not yet bound the listener (the brief
	// startup window). gRPC is loopback and essentially always binds, so this
	// renders as Listening on the requested address rather than flagging a
	// transient failure.
	grpcPreBind grpcListenState = iota
	// grpcListening: net.Listen succeeded and the serve loop is active.
	grpcListening
	// grpcFailed: net.Listen failed or the serve loop exited (Run returned) —
	// the control plane is no longer serving on this listener.
	grpcFailed
)

// EffectiveListener returns the effective state of the primary gRPC listener
// for the shared `show system services` snapshot (#6385/#6401): Listening with
// the actual bound address while serving, Failed on a bind failure / serve exit
// (with the requested/last-known address), or — in the brief pre-bind startup
// window — Listening on the requested address. gRPC is always configured, so it
// is never reported Disabled.
func (s *Server) EffectiveListener() sysservices.Listener {
	s.effMu.Lock()
	defer s.effMu.Unlock()
	switch s.effState {
	case grpcListening:
		return sysservices.Listener{Addr: s.effAddr, State: sysservices.StateListening}
	case grpcFailed:
		addr := s.effAddr
		if addr == "" {
			addr = s.requestedAddr
		}
		return sysservices.Listener{Addr: addr, State: sysservices.StateFailed}
	default: // grpcPreBind
		return sysservices.Listener{Addr: s.requestedAddr, State: sysservices.StateListening}
	}
}

func (s *Server) setListenState(addr string, state grpcListenState) {
	s.effMu.Lock()
	s.effAddr = addr
	s.effState = state
	s.effMu.Unlock()
}

// Run starts the gRPC server and blocks until ctx is cancelled.
// grpcStopTimeout bounds the graceful shutdown of a gRPC listener (#4910). On
// ctx cancellation a listener first tries GracefulStop so in-flight RPCs can
// finish, but the unbounded server-streaming MonitorInterface RPC only watches
// its client stream context — a client holding that stream open would
// otherwise block GracefulStop, and therefore Run / RunFabricListener, forever
// (a stuck daemon stop / failover / restart). After this grace period the
// server is force-Stop()'d so shutdown always completes.
const grpcStopTimeout = 2 * time.Second

// stopGRPCServer stops srv with a BOUNDED graceful shutdown (#4910):
// GracefulStop runs in a goroutine so active RPCs get a chance to finish, but
// if they have not within timeout, Stop() force-closes the connections —
// which cancels a stuck streaming handler's stream context so it returns and
// GracefulStop unblocks. A normal, RPC-idle shutdown (or one where every
// client has disconnected) returns as soon as GracefulStop completes, well
// before the timeout, so a clean disconnect drops nothing.
func stopGRPCServer(srv *grpc.Server, timeout time.Duration) {
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(timeout):
		srv.Stop()
		<-stopped
	}
}

// grpcHostIsLoopback reports whether a gRPC bind host is a loopback address.
// It mirrors the web-management / cluster bind doctrine (#4903/#4928): an EMPTY
// host is the Go wildcard spelling (`net.SplitHostPort(":50051")` yields host ""
// and listens on ALL interfaces) and is NOT loopback; the literal "localhost"
// is a legitimate loopback bind spelling; an unparseable, non-loopback host
// fails safe as NON-loopback so the bind is clamped rather than left exposed.
func grpcHostIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// clampGRPCBindToLoopback pulls a non-loopback PRIMARY gRPC bind back to a
// loopback of the same address family (#5035). The primary listener carries no
// TLS and no network-facing authentication: since #5278 it authorizes each
// caller by the LOCAL account that owns the peer socket, which is an answer the
// kernel can only give for a caller on this host. A non-loopback `--grpc-addr`
// (`0.0.0.0`, a routable address) would therefore expose the destructive
// surface (SystemAction zeroize/reboot/halt/power-off, Commit/Delete/Rollback,
// the whole config surface) to callers the gate can attribute to nobody.
//
// #5278 changes what that costs rather than making the clamp optional. Such a
// caller now has no socket row on this host, so authz.LookupPeer reports it
// unattributed and every RPC is DENIED — the exposure would be a reachable
// listener answering PermissionDenied, not an open control plane. The clamp
// stays because a listener that can only refuse is still a listener worth not
// publishing, and because the availability direction is the one that bites: a
// legitimate remote administrator cannot be served here at all. Unlike the
// web-management clamp there is NO auth mode that unlocks a non-loopback bind:
// the intentionally network-exposed gRPC surface is the SEPARATE fabric
// listener (RunFabricListener), which authenticates (#4107) and allowlists
// (#4122) every call. A genuine loopback bind (127.0.0.0/8, ::1, "localhost")
// is returned unchanged; a bind whose host part fails to split (no port to
// clamp) is also returned unchanged.
func clampGRPCBindToLoopback(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || grpcHostIsLoopback(host) {
		return addr, false
	}
	loopback := "127.0.0.1"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// An IPv6 (non-v4-mapped) bind clamps to the IPv6 loopback so the
		// listener stays same-family.
		loopback = "::1"
	}
	return net.JoinHostPort(loopback, port), true
}

func (s *Server) Run(ctx context.Context) error {
	// Fail-safe loopback clamp (#5035): the primary gRPC listener authorizes by
	// LOCAL peer credentials (#5278), which the kernel can only supply for a
	// caller on this host, so a non-loopback bind would publish the destructive
	// RPC surface to callers it can only refuse. Pull it back to a loopback of
	// the same family and WARN; the daemon still boots and gRPC stays reachable
	// on loopback (the console/SSH remain the lifeline). Cross-node access uses
	// the authenticated fabric listener, not this one.
	if clamped, ok := clampGRPCBindToLoopback(s.addr); ok {
		slog.Warn("gRPC bind is non-loopback but the primary gRPC listener authorizes by local peer credentials (loopback-only trust boundary); clamping to loopback — use the authenticated cluster fabric listener for cross-node access — #5035/#5278",
			"requested", s.addr, "clamped", clamped)
		s.addr = clamped
	}
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		// The bind failed — record Failed so `show system services` reports the
		// requested address as (bind failed), not as if it were serving
		// (#6385/#6401). The daemon logs the returned error non-fatally.
		s.setListenState("", grpcFailed)
		return fmt.Errorf("gRPC listen: %w", err)
	}
	// Record the effective serving address (post-clamp, post-bind) so
	// `show system services` reports what the primary gRPC listener actually
	// bound, not the requested --grpc-addr (#6385). lis.Addr() is authoritative
	// (e.g. a ":50051" wildcard clamp resolves to a concrete host:port).
	s.setListenState(lis.Addr().String(), grpcListening)

	srv := s.buildPrimaryServer()
	slog.Info("gRPC server listening", "addr", s.addr)
	// serveUntilDone returns when the serve loop exits (ctx cancel on a clean
	// shutdown, or a Serve error). Either way the listener is no longer serving,
	// so clear the bound address to Failed — a later local-console `show system
	// services` must not report a stale bound address for a dead server
	// (#6401). serveUntilDone is shared with the fabric listener, so the clear
	// lives HERE (Run) and never in the shared helper.
	runErr := s.serveUntilDone(ctx, srv, lis)
	s.setListenState("", grpcFailed)
	return runErr
}

// buildPrimaryServer constructs the primary (loopback) gRPC server with the
// #5278 login-class authorization chain. serveUntilDone registers the service,
// so this only builds the server — mirroring buildFabricServer, whose chain is
// deliberately DIFFERENT and must stay so:
//
//	primary (Run)                fabric (RunFabricListener)
//	principalUnary/Stream        fabricAuth* then fabricAllowlist*
//	  who is the local ACCOUNT     is this the peer NODE, and may it proxy this RPC
//
// A fabric peer has no uid on this host, so the principal gate would deny every
// cross-node call; a local login user holds no control-link PSK, so the fabric
// gate would deny every console call. Neither chain is a superset of the other
// and neither may be installed on the other listener.
func (s *Server) buildPrimaryServer() *grpc.Server {
	// #5883: no cluster peer ever dials this listener, so an inbound
	// x-peer-forwarded / xpf-no-peer marker here is forged by definition. Strip
	// both and promote NOTHING, so every handler on this listener sees the
	// markers absent and does the peer work it is supposed to do. The chain is
	// built by loopbackServerInterceptors so the WIRING is testable, not just
	// the interceptor.
	loopbackUnary, loopbackStream := loopbackServerInterceptors()
	// ORDER: the #5278 principal gate runs FIRST, so a caller whose login class
	// does not hold this RPC is refused before any request sanitisation runs on
	// its behalf. It mirrors the fabric chain's convention (authenticate, THEN
	// touch the markers) and is safe in the other direction too: the gate reads
	// the connection's accept-time identity, the method and the decoded
	// request — never metadata — so #5883's strip cannot change its verdict.
	unary := append([]grpc.UnaryServerInterceptor{s.principalUnaryInterceptor}, loopbackUnary...)
	stream := append([]grpc.StreamServerInterceptor{s.principalStreamInterceptor}, loopbackStream...)
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		// #5278: resolve the caller's identity ONCE per connection, at
		// connection setup, and authorize every RPC against it. TagConn runs on
		// grpc-go's per-connection goroutine, not its accept loop, so the
		// lookup is inline; see authz.go for why that differs from pkg/api.
		grpc.StatsHandler(&peerAuthStatsHandler{s: s}),
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(stream...),
		// #5849: the config-lock lifecycle is owned by a connection-scoped
		// stats.Handler (releases on ConnEnd), NOT a per-RPC interceptor that
		// tore the session down on any per-RPC cancellation.
		grpc.StatsHandler(&configLockStatsHandler{s: s}),
	)
}

// serveUntilDone registers the service on srv, serves lis, and on ctx
// cancellation stops srv with a bounded graceful shutdown (stopGRPCServer). It
// is split out of Run so the shutdown path can be exercised over an in-memory
// listener in tests. The caller logs the "listening" transition (Run for the
// loopback listener, superviseFabricListener for the fabric listener) so the
// logged address is accurate for each listener; serveUntilDone stays quiet.
func (s *Server) serveUntilDone(ctx context.Context, srv *grpc.Server, lis net.Listener) error {
	pb.RegisterBpfrxServiceServer(srv, s)

	errCh := make(chan error, 1)
	go func() {
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

	stopGRPCServer(srv, grpcStopTimeout)
	return nil
}

// Fabric-listener supervisor tuning (#5047). A transient bind or serve fault on
// the fabric listener used to be TERMINAL: a failed lc.Listen returned outright
// and the Serve goroutine only warned, so the caller (which starts the listener
// exactly once) permanently lost the network-exposed peer-proxy gRPC surface
// (monitor / peer-show / proxied-failover) until the whole cluster-comms
// lifecycle restarted. Single-fabric deployments had no fallback. The supervisor
// now retries a fault with a bounded exponential backoff while ctx is live.
const (
	// fabricListenerBackoffBase is the first retry delay after a fault.
	fabricListenerBackoffBase = 100 * time.Millisecond
	// fabricListenerBackoffMax caps the backoff so a persistent bind failure
	// keeps retrying at a bounded interval (no permanent give-up) without
	// spinning.
	fabricListenerBackoffMax = 5 * time.Second
	// fabricListenerHealthyServe is how long a Serve must stay up before the
	// supervisor treats it as a healthy session and resets the backoff to base.
	// A Serve that faults sooner keeps the backoff growing so a rapid
	// listen/serve flap does not reset to a tight retry.
	fabricListenerHealthyServe = 30 * time.Second
)

// fabricSupervisorConfig carries the fabric-listener supervisor seams (#5047).
// Production wires listen to the SO_REUSEADDR/REUSEPORT/SO_BINDTODEVICE
// ListenConfig and serve to buildFabricServer + serveUntilDone; tests inject a
// transient/persistent listen failure or a serve fault without a real socket.
type fabricSupervisorConfig struct {
	backoffBase  time.Duration
	backoffMax   time.Duration
	healthyServe time.Duration
	// listen creates a fresh listener bound to the fabric address.
	listen func(ctx context.Context) (net.Listener, error)
	// serve serves the fabric gRPC service on lis until it faults or ctx is
	// cancelled. It returns nil on a clean ctx-cancel shutdown and the serve
	// error otherwise (a genuine fault the supervisor should retry).
	serve func(ctx context.Context, lis net.Listener) error
}

// RunFabricListener supervises an additional gRPC listener on the fabric IP so
// the cluster peer can proxy monitor / show / failover requests. It blocks
// until ctx is cancelled; the caller starts it exactly once and the retry
// supervision is INTERNAL (#5047). vrfDevice may be empty for the default VRF,
// or e.g. "vrf-mgmt".
//
// #4122 + #4107: the fabric listener is the ONLY network-exposed gRPC surface
// (the loopback Run() listener binds 127.0.0.1). Two interceptor layers protect
// it, both absent from the loopback listener, which runs the DIFFERENT #5278
// login-class chain instead (a fabric peer is a node, not a local login user —
// see buildPrimaryServer):
//  1. fabricAuth* (#4107) AUTHENTICATES the caller with the control-link PSK
//     (HMAC token in metadata) so an unauthenticated host on the shared control
//     segment cannot invoke ANY fabric RPC. Runs FIRST.
//  2. fabricAllowlist* (#4122) AUTHORIZES only the read/monitor/failover RPCs
//     the peer legitimately proxies; destructive RPCs (Commit/Delete/Rollback,
//     SystemAction{zeroize,reboot,halt,power-off}) are rejected with
//     PermissionDenied and never reach a handler.
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
	s.superviseFabricListener(ctx, addr, vrfDevice, fabricSupervisorConfig{
		backoffBase:  fabricListenerBackoffBase,
		backoffMax:   fabricListenerBackoffMax,
		healthyServe: fabricListenerHealthyServe,
		listen: func(ctx context.Context) (net.Listener, error) {
			return lc.Listen(ctx, "tcp", addr)
		},
		serve: func(ctx context.Context, lis net.Listener) error {
			return s.serveUntilDone(ctx, s.buildFabricServer(), lis)
		},
	})
}

// buildFabricServer constructs the fabric gRPC server with the #4107 auth +
// #4122 allowlist interceptor chains. serveUntilDone registers the service, so
// this only builds the server (mirrors Run()'s split).
func (s *Server) buildFabricServer() *grpc.Server {
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		// #5883: peerMarker runs LAST in the chain on purpose —
		// ChainUnaryInterceptor invokes in order, so #4107 auth and the #4122
		// allowlist have both already accepted the call before the hop markers
		// are promoted to the in-process capability. An unauthenticated caller
		// on the fabric segment is rejected before anything is trusted.
		grpc.ChainUnaryInterceptor(s.fabricAuthUnaryInterceptor, s.fabricAllowlistUnaryInterceptor, peerMarkerUnaryInterceptor(true)),
		grpc.ChainStreamInterceptor(s.fabricAuthStreamInterceptor, s.fabricAllowlistStreamInterceptor, peerMarkerStreamInterceptor(true)),
		// #5849: same connection-scoped config-lock release contract as the
		// loopback server (a no-op for the fabric allowlist, which never admits
		// the config RPCs, but keeps the lifecycle uniform across both servers).
		grpc.StatsHandler(&configLockStatsHandler{s: s}),
	)
}

// superviseFabricListener is the fabric-listener supervision loop (#5047). It
// runs while ctx is live: bind a listener, serve it, and on a fault (bind
// failure OR a Serve error that is NOT the expected graceful shutdown) retry
// after a bounded exponential backoff. It resets the backoff to base after a
// Serve that stayed up at least cfg.healthyServe, so a persistent bind failure
// keeps retrying at cfg.backoffMax (no spin, no permanent give-up) while a rare
// one-off fault recovers quickly. It exits cleanly — no error-retry — on ctx
// cancellation or the expected grpc.ErrServerStopped. Per-address up/down
// health is published (setFabricListenerUp) and transitions are logged at
// Info/Warn; per-retry ticks stay at Debug.
func (s *Server) superviseFabricListener(ctx context.Context, addr, vrfDevice string, cfg fabricSupervisorConfig) {
	defer s.setFabricListenerUp(addr, false) // ensure health reads down once the supervisor exits
	backoff := cfg.backoffBase
	for {
		if ctx.Err() != nil {
			return
		}
		lis, err := cfg.listen(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("gRPC fabric listener bind failed; will retry",
				"addr", addr, "vrf", vrfDevice, "backoff", backoff, "err", err)
			if !sleepFabricBackoff(ctx, &backoff, cfg.backoffMax) {
				return
			}
			continue
		}

		if s.setFabricListenerUp(addr, true) {
			slog.Info("gRPC fabric listener up", "addr", addr, "vrf", vrfDevice)
		}
		start := time.Now()
		serveErr := cfg.serve(ctx, lis)
		s.setFabricListenerUp(addr, false)

		// Expected graceful shutdown: ctx cancelled (serveUntilDone returns nil)
		// or the server was intentionally stopped. Exit cleanly, no retry.
		if ctx.Err() != nil || serveErr == nil || errors.Is(serveErr, grpc.ErrServerStopped) {
			slog.Info("gRPC fabric listener stopped", "addr", addr, "vrf", vrfDevice)
			return
		}

		// Genuine serve fault. A session that stayed up long enough is treated
		// as healthy, so the next fault retries from base instead of the
		// grown-out cap.
		if time.Since(start) >= cfg.healthyServe {
			backoff = cfg.backoffBase
		}
		slog.Warn("gRPC fabric listener serve fault; will retry",
			"addr", addr, "vrf", vrfDevice, "backoff", backoff, "err", serveErr)
		if !sleepFabricBackoff(ctx, &backoff, cfg.backoffMax) {
			return
		}
	}
}

// sleepFabricBackoff waits out the current backoff (or ctx cancel), then doubles
// it up to backoffMax for the next fault. It returns false if ctx was cancelled
// during the wait (the caller must exit) and true if the wait elapsed. The
// per-tick wait is logged at Debug so a persistent bind failure does not flood
// Info (logging rules: transitions at Info/Warn, ticks at Debug).
func sleepFabricBackoff(ctx context.Context, backoff *time.Duration, backoffMax time.Duration) bool {
	d := *backoff
	next := d * 2
	if next > backoffMax {
		next = backoffMax
	}
	*backoff = next
	slog.Debug("gRPC fabric listener backoff wait", "delay", d)
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// setFabricListenerUp records the fabric listener's up/down health for addr and
// reports whether the state CHANGED, so the caller logs a transition exactly
// once (#5047). A status surface can read the published state via
// FabricListenerUp / FabricListenerHealth.
func (s *Server) setFabricListenerUp(addr string, up bool) (changed bool) {
	s.fabricListenerMu.Lock()
	defer s.fabricListenerMu.Unlock()
	if s.fabricListenerUp == nil {
		s.fabricListenerUp = make(map[string]bool)
	}
	prev, existed := s.fabricListenerUp[addr]
	changed = !existed || prev != up
	s.fabricListenerUp[addr] = up
	return changed
}

// FabricListenerUp reports whether the fabric listener bound to addr is
// currently serving (#5047). It returns false for an unknown address (never
// started, or torn down).
func (s *Server) FabricListenerUp(addr string) bool {
	s.fabricListenerMu.Lock()
	defer s.fabricListenerMu.Unlock()
	return s.fabricListenerUp[addr]
}

// FabricListenerHealth returns a snapshot of every supervised fabric listener's
// up/down state, keyed by bind address (#5047), for a status/CLI surface.
func (s *Server) FabricListenerHealth() map[string]bool {
	s.fabricListenerMu.Lock()
	defer s.fabricListenerMu.Unlock()
	out := make(map[string]bool, len(s.fabricListenerUp))
	for addr, up := range s.fabricListenerUp {
		out[addr] = up
	}
	return out
}

// fabricAllowedUnaryMethods is the fail-closed allowlist (#4122) of unary RPCs
// the cluster fabric listener serves. Every entry is a method the local node
// actually proxies to its peer over the fabric link — see the
// dialPeer()->NewBpfrxServiceClient call sites in server_show_forwarding.go
// (ShowText), server_sessions.go (GetSessions, GetSessionSummary,
// GetZonePairSummary, ClearSessions), and server_diag.go dialPeer() itself
// (GetStatus health probe). Any unary method NOT in this set is rejected with
// PermissionDenied — so Commit, Delete, Rollback, and the whole config-mode
// surface are unreachable on the network-exposed fabric IP.
//
// SystemAction is deliberately absent: it multiplexes fabric-safe cross-node
// cluster-failover with destructive node actions (zeroize/reboot/halt/
// power-off) under ONE gRPC method, so a method-name allowlist that included it
// would still expose zeroize. It is gated separately, by request-action, in
// isFabricSafeSystemAction.
var fabricAllowedUnaryMethods = map[string]bool{
	pb.BpfrxService_GetStatus_FullMethodName:          true,
	pb.BpfrxService_GetSessions_FullMethodName:        true,
	pb.BpfrxService_GetSessionSummary_FullMethodName:  true,
	pb.BpfrxService_GetZonePairSummary_FullMethodName: true,
	pb.BpfrxService_ShowText_FullMethodName:           true,
	pb.BpfrxService_ClearSessions_FullMethodName:      true,
}

// fabricAllowedStreamMethods is the fail-closed allowlist (#4122) of streaming
// RPCs the fabric listener serves. Only MonitorInterface is proxied
// (proxyMonitorInterface in server_diag.go).
var fabricAllowedStreamMethods = map[string]bool{
	pb.BpfrxService_MonitorInterface_FullMethodName: true,
}

// parseProxiedFailoverAction is the single source of truth for what a
// well-formed, peer-proxied cross-node cluster-failover SystemAction looks like.
// It parses the two — and only two — request-action forms that a node
// legitimately proxies to its peer over the fabric (the proxyPeerSystemAction
// call sites in server_diag.go):
//
//	"cluster-failover-data:node<N>"    -> (rgID=-1, nodeID=N, ok)  [all data RGs]
//	"cluster-failover:<rgID>:node<N>"  -> (rgID, nodeID=N, ok)
//
// It returns ok=false — fail-closed — for any other action, a missing/empty
// node target, a non-numeric rgID or nodeID, a trailing garbage suffix
// (e.g. "cluster-failover:1:node1:node2"), or a nodeID outside the supported
// cluster range (0/1). It delegates the parse to clusterfailover.ParseAction —
// the SAME grammar the loopback handler (server_diag_system_action.go) runs —
// so the fabric interceptor gate and the handler can never disagree on which
// failover actions are well-formed.
//
// Why the range check matters on the interceptor: the handler proxy-dials the
// peer whenever targetNode != local BEFORE rejecting an out-of-range/garbage
// node as forwarded-not-local / InvalidArgument. A loose HasPrefix/Contains
// gate would let a malformed action (e.g. "cluster-failover:1:node99") reach
// that outbound-dial path, letting an unauthenticated fabric client drive
// avoidable proxy dials + connection churn. Strict parsing here denies the
// malformed action at the interceptor (PermissionDenied) so it never reaches
// the handler.
func parseProxiedFailoverAction(action string) (rgID, nodeID int, ok bool) {
	// Delegate the parse to the SAME strict grammar the loopback handler uses
	// (pkg/clusterfailover) so the fabric interceptor gate and the handler can
	// never disagree about which failover action strings are well-formed
	// (#5810, #5851). Only the two node-targeted forms are proxyable over the
	// fabric; the plain RG failover and reset forms are valid but local-only.
	op, err := clusterfailover.ParseAction(action)
	if err != nil {
		return 0, 0, false
	}
	switch op.Kind {
	case clusterfailover.KindRGFailoverNode:
		return op.RG, op.Node, true
	case clusterfailover.KindDataFailover:
		// rgID = -1 sentinel: all data redundancy groups (the historical
		// contract this helper's callers depend on).
		return -1, op.Node, true
	default:
		return 0, 0, false
	}
}

// isFabricSafeSystemAction reports whether a SystemAction request carries a
// well-formed cross-node cluster-failover action the peer legitimately proxies
// over the fabric — delegating the strict parse to parseProxiedFailoverAction.
//
// These re-balance redundancy-group ownership — an operation squarely within the
// fabric peer's trust boundary (coordinating RG ownership is the fabric's job).
// Every other action — zeroize, reboot, halt, power-off, the local-only
// clear-* / cluster-failover-reset verbs, and any malformed failover suffix —
// is denied on the fabric listener. Node-local execution via the trusted
// loopback listener is unaffected: an operator SSHed into the target node still
// runs any action.
//
// This is the nested-action choice over a blanket SystemAction exclusion:
// excluding SystemAction entirely would make a cross-node `request chassis
// cluster failover ... node <peer>` return PermissionDenied when the initiating
// node proxies it, regressing a shipped HA operator workflow. Allowing ONLY the
// two well-formed failover forms preserves that flow while keeping
// node-lifecycle actions (zeroize/reboot/...) off the unauthenticated fabric
// surface.
func isFabricSafeSystemAction(req interface{}) bool {
	sa, ok := req.(*pb.SystemActionRequest)
	if !ok {
		return false
	}
	_, _, ok = parseProxiedFailoverAction(sa.GetAction())
	return ok
}

// fabricAllowlistUnaryInterceptor fail-closes unary RPCs on the cluster fabric
// listener (#4122): only the peer-proxied read/monitor RPCs
// (fabricAllowedUnaryMethods) plus the two cross-node cluster-failover
// SystemAction forms (isFabricSafeSystemAction) are served; every other method
// is rejected with PermissionDenied before the handler runs. The loopback
// listener does NOT install this interceptor and keeps the full service.
func (s *Server) fabricAllowlistUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if fabricAllowedUnaryMethods[info.FullMethod] {
		return handler(ctx, req)
	}
	if info.FullMethod == pb.BpfrxService_SystemAction_FullMethodName && isFabricSafeSystemAction(req) {
		return handler(ctx, req)
	}
	slog.Warn("fabric gRPC listener denied non-allowlisted method", "method", info.FullMethod)
	return nil, status.Errorf(codes.PermissionDenied, "method %s is not permitted on the cluster fabric listener", info.FullMethod)
}

// fabricAllowlistStreamInterceptor fail-closes streaming RPCs on the fabric
// listener (#4122): only MonitorInterface (fabricAllowedStreamMethods) is
// served; every other stream is rejected with PermissionDenied.
func (s *Server) fabricAllowlistStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if fabricAllowedStreamMethods[info.FullMethod] {
		return handler(srv, ss)
	}
	slog.Warn("fabric gRPC listener denied non-allowlisted stream method", "method", info.FullMethod)
	return status.Errorf(codes.PermissionDenied, "stream method %s is not permitted on the cluster fabric listener", info.FullMethod)
}

// peerSessionID derives a stable session identifier from the gRPC peer address.
// #5849: this is now only the FALLBACK identity (connSessionID) for a direct
// in-process call / unit test / the impossible crypto/rand-failure path — the
// config-session lifecycle is otherwise keyed by the connection-scoped id from
// configLockStatsHandler. It is NOT used as durable identity on its own: a
// reused peer address must not inherit or release an earlier connection's
// session.
func peerSessionID(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	return p.Addr.String()
}
