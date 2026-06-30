package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fsatomic"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
)

// ClusterSessionService is the HA-aware session surface the REST session
// handlers delegate to so REST and gRPC share ONE cross-node session path
// (#3423). The daemon wires the live *grpcapi.Server, which clears/queries
// the LOCAL node AND fans out to the cluster peer over the fabric gRPC
// link (clearPeerSessions / fetchPeerSessions). All three methods already
// exist on the gRPC server; REST builds the protobuf request and maps the
// response back to its JSON types. A nil service (standalone build, or a
// unit test that does not wire it) makes the REST handlers fall back to
// LOCAL-ONLY behavior — the pre-#3423 contract.
type ClusterSessionService interface {
	// ClearSessions clears all sessions on the local node and, in a
	// cluster, forwards the clear to the peer, returning per-family counts
	// plus a partial-failure summary (peer unreachable / peer clear failed).
	ClearSessions(context.Context, *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error)
	// GetSessions returns the HA-aware session list; with IncludePeer set it
	// stamps the peer node's sessions onto the response's Peer field.
	GetSessions(context.Context, *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error)
	// GetSessionSummary returns the HA-aware summary; with IncludePeer set it
	// stamps the peer node's summary onto the response's Peer field.
	GetSessionSummary(context.Context, *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error)
	// GetZonePairSummary returns the HA-aware zone-pair breakdown; with
	// IncludePeer set it stamps the peer node's breakdown onto the response's
	// Peer field (#3592).
	GetZonePairSummary(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error)
}

// CompileHealthSnapshot mirrors daemon.CompileHealth without the import.
// Keeping pkg/api -> pkg/daemon free of a back-edge preserves the layered
// build shape; the daemon injects a callback that returns this struct.
type CompileHealthSnapshot struct {
	EverSucceeded    bool
	FailureCount     uint64
	LastError        string
	LastErrorUnixSec int64
}

// Config configures the API server.
type Config struct {
	Addr      string
	HTTPSAddr string      // HTTPS listen address (empty = no HTTPS)
	TLS       bool        // enable HTTPS with auto-generated certificate
	Auth      *AuthConfig // nil = no authentication
	Store     *configstore.Store
	DP        apiRuntimeDataPlane
	EventBuf  *logging.EventBuffer
	GC        *conntrack.GC
	Routing   *routing.Manager
	FRR       *frr.Manager
	IPsec     *ipsec.Manager
	DHCP      *dhcp.Manager
	VRRPMgr   *vrrp.Manager // native VRRP manager
	// #846: atomic commit+apply callbacks. The daemon holds its
	// apply semaphore across configstore.Commit and applyConfig, so
	// two concurrent committers can't interleave their commit→apply
	// pairs. Returns ctx.Err() if the request is canceled before the
	// semaphore is acquired (handlers translate to 408/503).
	CommitFn          func(ctx context.Context, comment string) (*config.Config, error)
	CommitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error)
	// CompileHealthFn surfaces dataplane compile state via /health (#758).
	// Returning a snapshot with EverSucceeded=false and FailureCount>0
	// makes /health return 503 so operators see the degraded state
	// instead of reading "status: ok" alongside a one-shot WARN in the
	// journal. Optional; if nil, /health keeps the pre-#758 behaviour.
	CompileHealthFn func() CompileHealthSnapshot
	// ConfigPersistDegradedFn surfaces the configstore's persist-degraded
	// state via /health and the xpf_daemon_config_persist_degraded gauge
	// (#1799, mirrors the CompileHealthFn pattern). Returning true means
	// the RUNNING active config failed to persist to disk (HA SyncApply
	// or commit-confirmed auto-rollback hit a write error) and the
	// background retry has not yet succeeded — a daemon restart would
	// load a stale config. /health returns 503 while degraded. Optional;
	// if nil, the check and gauge are omitted.
	ConfigPersistDegradedFn func() bool
	// RollbackHistoryDegradedFn surfaces the configstore's
	// rollback-history-degraded state via /health and the
	// xpf_config_rollback_persist_degraded gauge (#3441, mirrors the
	// ConfigPersistDegradedFn pattern). Returning true means the most
	// recent commit failed to durably write its text rollback-history
	// files. UNLIKE ConfigPersistDegradedFn this does NOT make /health
	// return 503: the commit succeeded and the active config is durable
	// (the rollback files are a best-effort recovery aid), so it is
	// reported as a non-fatal field plus the gauge for alerting. Optional;
	// if nil, the field and gauge are omitted.
	RollbackHistoryDegradedFn func() bool
	// NeighborPhaseAgeFn surfaces the age (seconds) since each Go
	// periodic neighbor-maintenance phase last completed (#1780 Path A).
	// Keys: resolve/force_probe/clean_failed/warm. A monotonically
	// climbing age for any phase means that phase's guarded goroutine
	// is wedged (a stuck netlink/probe syscall), which is the signature
	// of the idle/overnight cold-connect hang. Optional; if nil, the
	// neighbor_periodic_last_success_age_seconds gauge is not emitted.
	NeighborPhaseAgeFn func() map[string]float64
	// IPMonStatusFn surfaces services ip-monitoring policy state for
	// the xpf_ipmon_* metrics (#1827). Optional; if nil, the family is
	// omitted.
	IPMonStatusFn func() []ipmon.PolicyStatus
	// EventActionStatsFn surfaces event-options remediation action
	// counters for the xpf_event_actions_* / xpf_event_action_queue_depth
	// metrics (#2157). Optional; if nil, the family is omitted.
	EventActionStatsFn func() eventengine.Stats
	// RPMPinFailedFn surfaces the count of RPM next-hop probe pins
	// whose kernel install (fwmark rule + pinned route) is currently
	// failed — the affected tests hold state instead of probing the
	// default path, so a nonzero value means those uplinks are not
	// being health-checked (#1895). Backs the
	// xpf_rpm_probe_pin_install_failures gauge. Optional; if nil, the
	// gauge is not emitted.
	RPMPinFailedFn func() float64
	// FRRReloadDegradedFn reports whether the last applied FRR reload
	// fell back to the additive vtysh -f path (full frr-reload.py diff
	// failed) and the in-manager retry has not yet converged —
	// stale-config removal is deferred while set (#1880). Backs the
	// xpf_frr_reload_degraded gauge (0/1, no labels). Optional; if nil,
	// the gauge is not emitted.
	FRRReloadDegradedFn func() bool
	// FeedsFn surfaces live dynamic-address feed status for the
	// xpf_feed_seconds_since_last_success / xpf_feed_stale gauges (#2050).
	// A feed that has never fetched successfully, or whose last-good
	// snapshot is being retained as stale, is the operator's signal that an
	// enforced address set is frozen (retain-forever default). Optional; if
	// nil, the feed gauges are omitted.
	FeedsFn func() map[string]feeds.FeedInfo
	// DDNSStatsFn surfaces the DHCP dynamic-DNS counter snapshot for the
	// xpf_dhcp_ddns_* metric family (#1387 inc-2). The daemon owns the
	// always-on DDNS manager; the API reads it through this function so the
	// api package does not import the manager type. Optional; if nil (or it
	// returns nil), the family is omitted.
	DDNSStatsFn func() *dhcpserver.DDNSStats
	// SurfaceAStatsFn surfaces the Surface A (router/interface-address) DDNS
	// counter snapshot for the xpf_ddns_surface_a_* metric family (#2691 P2).
	// Optional; if nil (or it returns nil), the family is omitted.
	SurfaceAStatsFn func() *ddns.SurfaceAStats
	// FlowCollectorHealthFn surfaces per-collector NetFlow v9 / IPFIX
	// write-health for the xpf_flow_export_collector_* metric family and
	// the /flow-exporters status endpoint (#2464). Flow export is
	// forensics/compliance data; a collector going silently unreachable
	// (every failed UDP write was debug-logged and dropped) is a
	// production concern, so the per-collector attempt/failure counters and
	// last-error/last-success state are surfaced here. Optional; if nil (or
	// it returns nil), the family is omitted.
	FlowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
	// FeedOverlayFn returns the live dynamic-address feed-prefix overlay
	// (#2049): an address-name -> union-of-feed-CIDRs map for the active
	// config, the same view the AF_XDP helper enforces. It is consulted by
	// the `match-policies` simulator (#3042) so a feed-backed policy address
	// token resolves to its live feed prefixes. Optional; if nil the
	// simulator resolves feed-backed names to their static content only.
	FeedOverlayFn func() map[string][]string
	// PolicySchedulerActiveStateFn returns the live daemon-local per-scheduler
	// active-state map (the same view Manager.PolicySchedulerActiveState
	// exposes to the CLI/gRPC show surfaces) plus whether it could be queried
	// (#3104). The `match-policies` simulator consults it so a scheduler-inactive
	// policy is skipped exactly like the runtime (policy.rs try_match_rule),
	// instead of reporting a definitive verdict the dataplane disagrees with.
	// Optional; if nil or it returns ok=false the simulator fails closed and
	// treats scheduled policies as inactive (#3414) — matching the snapshot
	// builder (nil scheduler state => dropped) rather than certifying an
	// as-if-active verdict the dataplane is skipping.
	PolicySchedulerActiveStateFn func() (map[string]bool, bool)
	// HAActiveFn reports whether THIS node is the active cluster member for
	// the default resource group, surfaced as the session ha_active field
	// (#3419 M6), mirroring the gRPC contract (server_sessions.go
	// IsLocalPrimary(0)). Optional; if nil the session view reports
	// ha_active=true (the standalone default).
	HAActiveFn func() bool
	// NodeIDFn returns this node's cluster id (0 standalone), stamped on the
	// REST session list/summary/clear responses so an operator knows WHICH
	// node a result came from (#3423 M5). Optional; if nil node_id reports 0.
	NodeIDFn func() int
	// ClusterSessionFn returns the HA-aware session service (the live gRPC
	// server) so the REST clear/list/summary handlers share the gRPC peer
	// fan-out path (#3423). It is resolved lazily, at request time, so the
	// daemon can wire a gRPC server constructed AFTER the REST server.
	// Optional; if nil (or it returns nil) the handlers stay local-only.
	ClusterSessionFn func() ClusterSessionService
}

// Server is the HTTP API server.
type Server struct {
	httpServer                *http.Server
	httpsServer               *http.Server
	store                     *configstore.Store
	dp                        apiRuntimeDataPlane
	eventBuf                  *logging.EventBuffer
	gc                        *conntrack.GC
	routing                   *routing.Manager
	frr                       *frr.Manager
	ipsec                     *ipsec.Manager
	dhcp                      *dhcp.Manager
	vrrpMgr                   *vrrp.Manager
	commitFn                  func(ctx context.Context, comment string) (*config.Config, error)
	commitConfirmedFn         func(ctx context.Context, minutes int) (*config.Config, error)
	compileHealthFn           func() CompileHealthSnapshot
	configPersistDegradedFn   func() bool
	rollbackHistoryDegradedFn func() bool
	neighborPhaseAgeFn        func() map[string]float64
	frrReloadDegradedFn       func() bool
	ipmonStatusFn             func() []ipmon.PolicyStatus
	eventActionStatsFn        func() eventengine.Stats
	rpmPinFailedFn            func() float64
	feedsFn                   func() map[string]feeds.FeedInfo
	ddnsStatsFn               func() *dhcpserver.DDNSStats
	surfaceAStatsFn           func() *ddns.SurfaceAStats
	flowCollectorHealthFn     func() []flowexport.ExporterCollectorHealth
	feedOverlayFn             func() map[string][]string
	policySchedActiveFn       func() (map[string]bool, bool)
	haActiveFn                func() bool
	nodeIDFn                  func() int
	clusterSessionFn          func() ClusterSessionService
	startTime                 time.Time
}

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	s := &Server{
		store:                     cfg.Store,
		dp:                        cfg.DP,
		eventBuf:                  cfg.EventBuf,
		gc:                        cfg.GC,
		routing:                   cfg.Routing,
		frr:                       cfg.FRR,
		ipsec:                     cfg.IPsec,
		dhcp:                      cfg.DHCP,
		vrrpMgr:                   cfg.VRRPMgr,
		commitFn:                  cfg.CommitFn,
		commitConfirmedFn:         cfg.CommitConfirmedFn,
		compileHealthFn:           cfg.CompileHealthFn,
		configPersistDegradedFn:   cfg.ConfigPersistDegradedFn,
		rollbackHistoryDegradedFn: cfg.RollbackHistoryDegradedFn,
		neighborPhaseAgeFn:        cfg.NeighborPhaseAgeFn,
		frrReloadDegradedFn:       cfg.FRRReloadDegradedFn,
		ipmonStatusFn:             cfg.IPMonStatusFn,
		eventActionStatsFn:        cfg.EventActionStatsFn,
		rpmPinFailedFn:            cfg.RPMPinFailedFn,
		feedsFn:                   cfg.FeedsFn,
		ddnsStatsFn:               cfg.DDNSStatsFn,
		surfaceAStatsFn:           cfg.SurfaceAStatsFn,
		flowCollectorHealthFn:     cfg.FlowCollectorHealthFn,
		feedOverlayFn:             cfg.FeedOverlayFn,
		policySchedActiveFn:       cfg.PolicySchedulerActiveStateFn,
		haActiveFn:                cfg.HAActiveFn,
		nodeIDFn:                  cfg.NodeIDFn,
		clusterSessionFn:          cfg.ClusterSessionFn,
		startTime:                 time.Now(),
	}

	mux := http.NewServeMux()

	// Health + metrics
	mux.HandleFunc("GET /health", s.healthHandler)

	// Prometheus metrics with isolated registry
	registry := prometheus.NewRegistry()
	registry.MustRegister(newCollector(s))
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	// REST API v1
	mux.HandleFunc("GET /api/v1/status", s.statusHandler)
	mux.HandleFunc("GET /api/v1/statistics/global", s.globalStatsHandler)
	mux.HandleFunc("GET /api/v1/statistics/interfaces", s.ifaceStatsHandler)
	mux.HandleFunc("GET /api/v1/statistics/zones", s.zoneStatsHandler)
	mux.HandleFunc("GET /api/v1/security/zones", s.zonesHandler)
	mux.HandleFunc("GET /api/v1/security/policies", s.policiesHandler)
	mux.HandleFunc("GET /api/v1/security/sessions", s.sessionsHandler)
	mux.HandleFunc("GET /api/v1/security/sessions/summary", s.sessionSummaryHandler)
	mux.HandleFunc("GET /api/v1/security/nat/source", s.natSourceHandler)
	mux.HandleFunc("GET /api/v1/security/nat/destination", s.natDestHandler)
	mux.HandleFunc("GET /api/v1/security/screen", s.screenHandler)
	mux.HandleFunc("GET /api/v1/security/events", s.eventsHandler)
	mux.HandleFunc("GET /api/v1/interfaces", s.interfacesHandler)
	mux.HandleFunc("GET /api/v1/dhcp/leases", s.dhcpLeasesHandler)
	mux.HandleFunc("GET /api/v1/dhcp/identifiers", s.dhcpIdentifiersHandler)
	mux.HandleFunc("GET /api/v1/routes", s.routesHandler)
	mux.HandleFunc("GET /api/v1/config", s.configHandler)

	// Routing protocols
	mux.HandleFunc("GET /api/v1/routing/ospf", s.ospfHandler)
	mux.HandleFunc("GET /api/v1/routing/bgp", s.bgpHandler)

	// IPsec
	mux.HandleFunc("GET /api/v1/security/ipsec/sa", s.ipsecSAHandler)

	// NAT stats
	mux.HandleFunc("GET /api/v1/security/nat/pools", s.natPoolStatsHandler)
	mux.HandleFunc("GET /api/v1/security/nat/rules", s.natRuleStatsHandler)

	// VRRP
	mux.HandleFunc("GET /api/v1/security/vrrp", s.vrrpHandler)

	// Policy match
	mux.HandleFunc("GET /api/v1/security/match", s.matchPoliciesHandler)

	// Interfaces detail
	mux.HandleFunc("GET /api/v1/interfaces/detail", s.interfacesDetailHandler)

	// Session zone-pair summary
	mux.HandleFunc("GET /api/v1/security/sessions/summary/zone-pairs", s.sessionZonePairHandler)

	// Flow-export collector health (#2464)
	mux.HandleFunc("GET /api/v1/services/flow-exporters", s.flowExportersHandler)

	// System info
	mux.HandleFunc("GET /api/v1/system/info", s.systemInfoHandler)
	mux.HandleFunc("GET /api/v1/system/buffers", s.systemBuffersHandler)

	// Mutations
	mux.HandleFunc("POST /api/v1/security/sessions/clear", s.clearSessionsHandler)
	mux.HandleFunc("POST /api/v1/security/counters/clear", s.clearCountersHandler)

	// Diagnostics
	mux.HandleFunc("POST /api/v1/diagnostics/ping", s.pingHandler)
	mux.HandleFunc("POST /api/v1/diagnostics/traceroute", s.tracerouteHandler)

	// Config management
	mux.HandleFunc("POST /api/v1/config/enter", s.configEnterHandler)
	mux.HandleFunc("POST /api/v1/config/exit", s.configExitHandler)
	mux.HandleFunc("GET /api/v1/config/status", s.configStatusHandler)
	mux.HandleFunc("POST /api/v1/config/set", s.configSetHandler)
	mux.HandleFunc("POST /api/v1/config/delete", s.configDeleteHandler)
	mux.HandleFunc("POST /api/v1/config/deactivate", s.configDeactivateHandler)
	mux.HandleFunc("POST /api/v1/config/activate", s.configActivateHandler)
	mux.HandleFunc("POST /api/v1/config/load", s.configLoadHandler)
	mux.HandleFunc("POST /api/v1/config/commit", s.configCommitHandler)
	mux.HandleFunc("POST /api/v1/config/commit-check", s.configCommitCheckHandler)
	mux.HandleFunc("POST /api/v1/config/commit-confirmed", s.configCommitConfirmedHandler)
	mux.HandleFunc("POST /api/v1/config/confirm", s.configConfirmHandler)
	mux.HandleFunc("POST /api/v1/config/rollback", s.configRollbackHandler)
	mux.HandleFunc("GET /api/v1/config/show", s.configShowHandler)
	mux.HandleFunc("GET /api/v1/config/export", s.configExportHandler)
	mux.HandleFunc("GET /api/v1/config/show-rollback", s.configShowRollbackHandler)
	mux.HandleFunc("GET /api/v1/config/compare", s.configCompareHandler)
	mux.HandleFunc("GET /api/v1/config/history", s.configHistoryHandler)
	mux.HandleFunc("GET /api/v1/config/search", s.configSearchHandler)
	mux.HandleFunc("POST /api/v1/config/annotate", s.configAnnotateHandler)

	// DHCP mutations
	mux.HandleFunc("POST /api/v1/dhcp/identifiers/clear", s.clearDHCPIdentifiersHandler)

	// SSE streaming
	mux.HandleFunc("GET /api/v1/events/stream", s.eventStreamHandler)
	mux.HandleFunc("GET /api/v1/logs/stream", s.logStreamHandler)

	// Generic text show
	mux.HandleFunc("GET /api/v1/show-text", s.showTextHandler)

	// System actions
	mux.HandleFunc("POST /api/v1/system/action", s.systemActionHandler)

	var handler http.Handler = mux
	if cfg.Auth != nil {
		handler = authMiddleware(*cfg.Auth, mux)
	}

	s.httpServer = &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}

	// Set up HTTPS server with auto-generated self-signed certificate
	if cfg.TLS && cfg.HTTPSAddr != "" {
		tlsCert, err := generateSelfSignedCert()
		if err != nil {
			slog.Warn("failed to generate self-signed certificate", "err", err)
		} else {
			s.httpsServer = &http.Server{
				Addr:    cfg.HTTPSAddr,
				Handler: handler,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					MinVersion:   tls.VersionTLS12,
				},
			}
		}
	}

	return s
}

// Run starts the HTTP (and optionally HTTPS) server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Start HTTPS server if configured
	if s.httpsServer != nil {
		go func() {
			slog.Info("HTTPS API server listening", "addr", s.httpsServer.Addr)
			if err := s.httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.httpsServer != nil {
		s.httpsServer.Shutdown(shutdownCtx)
	}
	return s.httpServer.Shutdown(shutdownCtx)
}

const (
	tlsDir   = "/etc/xpf/tls"
	certPath = "/etc/xpf/tls/cert.pem"
	keyPath  = "/etc/xpf/tls/key.pem"
)

// TLS persistence test seams (#1916 injected-failure tests). Production
// code must never mutate these.
var (
	tlsMkdirAllDurable  = fsatomic.MkdirAllDurable
	tlsRemove           = os.Remove
	tlsSyncDir          = fsatomic.SyncDir
	tlsWriteFileDurable = fsatomic.WriteFileDurable
)

// generateSelfSignedCert creates or loads a self-signed TLS certificate
// using the production /etc/xpf/tls paths. See generateSelfSignedCertAt.
func generateSelfSignedCert() (tls.Certificate, error) {
	return generateSelfSignedCertAt(tlsDir, certPath, keyPath)
}

// generateSelfSignedCertAt creates or loads a self-signed TLS certificate
// at the given paths.
//
// If a usable cert/key pair already exists on disk it is loaded and
// returned. Otherwise a new ECDSA P-256 certificate is generated and
// persisted (both cert and key are DurableState per #1916 D6: the HTTPS
// API can bind a non-loopback `web-management https interface` address,
// so cert churn after a power-cut loss would break remote clients' TOFU
// pins — the cert must survive power loss).
//
// Persistence follows the #1916 D5 STRICT sequence so a crash can never
// leave a MISMATCHED cert/key pair on disk:
//  1. MkdirAllDurable(dir).
//  2. Strict-remove any stale cert AND key (ignore ONLY os.IsNotExist;
//     ANY other remove error OR a SyncDir error aborts the write — the
//     {neither} start state is proven, not assumed), then SyncDir.
//  3. WriteFileDurable(key, 0600).
//  4. WriteFileDurable(cert, 0644).
//
// On ANY persistence error (steps 1-4) the function logs and returns the
// in-memory generated pair with a NIL error: the cert is usable this boot,
// only the disk write failed, so HTTPS still installs (the caller binds
// httpsServer on the nil-error path). A non-nil error is returned ONLY for
// a true generation failure (no usable cert at all).
func generateSelfSignedCertAt(dir, certPath, keyPath string) (tls.Certificate, error) {
	// Try loading an existing on-disk pair. LoadX509KeyPair reads the cert
	// first and errors on a key-only / mismatched state → falls through to
	// regen, which restores a matching pair.
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}

	// Generate new ECDSA key + self-signed cert (true generation failures
	// below return a non-nil error: there is no usable cert at all).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"xpf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	inMemory, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// The just-generated PEM does not parse — a true generation
		// failure, not a persistence one.
		return tls.Certificate{}, err
	}

	// From here, any failure is a PERSISTENCE failure: log it and return
	// the usable in-memory pair with a nil error so HTTPS still installs.
	if err := persistSelfSignedCert(dir, certPath, keyPath, certPEM, keyPEM); err != nil {
		slog.Error("failed to persist self-signed TLS certificate; serving in-memory cert this boot (will regenerate next boot)",
			"dir", dir, "err", err)
	}
	return inMemory, nil
}

// persistSelfSignedCert implements the #1916 D5 STRICT write sequence. Any
// returned error means the disk state is clean: either the directory could
// not be created, a strict-remove could not establish a provable {neither}
// start state (so no new write was attempted), a SyncDir failed to make the
// removes durable, or a durable write itself failed — in every case no
// mismatched pair is left visible on disk.
func persistSelfSignedCert(dir, certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := tlsMkdirAllDurable(dir, 0700); err != nil {
		return err
	}
	// Strict-remove the stale pair so the start state is provably {neither}.
	// Ignore ONLY os.IsNotExist; any other remove error aborts (do NOT
	// write) so we never leave a stale cert beside a fresh key.
	if err := tlsRemove(certPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := tlsRemove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Make the unlinks durable before writing the new pair; a SyncDir
	// failure also aborts (the {neither} start is not proven).
	if err := tlsSyncDir(dir); err != nil {
		return err
	}
	// Ordered durable writes: key first (DurableState 0600), then cert
	// (DurableState 0644). The only crash-visible states are {neither},
	// {key-only}, {both-matching}; LoadX509KeyPair rejects {key-only}.
	if err := tlsWriteFileDurable(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := tlsWriteFileDurable(certPath, certPEM, 0644); err != nil {
		return err
	}
	return nil
}
