package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
)

// Config configures the API server.
type Config struct {
	Addr     string
	Store    *configstore.Store
	DP       *dataplane.Manager
	EventBuf *logging.EventBuffer
	GC       *conntrack.GC
	Routing  *routing.Manager
	FRR      *frr.Manager
	IPsec    *ipsec.Manager
	DHCP     *dhcp.Manager
}

// Server is the HTTP API server.
type Server struct {
	httpServer *http.Server
	store      *configstore.Store
	dp         *dataplane.Manager
	eventBuf   *logging.EventBuffer
	gc         *conntrack.GC
	routing    *routing.Manager
	frr        *frr.Manager
	ipsec      *ipsec.Manager
	dhcp       *dhcp.Manager
	startTime  time.Time
}

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	s := &Server{
		store:     cfg.Store,
		dp:        cfg.DP,
		eventBuf:  cfg.EventBuf,
		gc:        cfg.GC,
		routing:   cfg.Routing,
		frr:       cfg.FRR,
		ipsec:     cfg.IPsec,
		dhcp:      cfg.DHCP,
		startTime: time.Now(),
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

	// System info
	mux.HandleFunc("GET /api/v1/system/info", s.systemInfoHandler)

	// Mutations
	mux.HandleFunc("POST /api/v1/security/sessions/clear", s.clearSessionsHandler)
	mux.HandleFunc("POST /api/v1/security/counters/clear", s.clearCountersHandler)

	// Diagnostics
	mux.HandleFunc("POST /api/v1/diagnostics/ping", s.pingHandler)
	mux.HandleFunc("POST /api/v1/diagnostics/traceroute", s.tracerouteHandler)

	s.httpServer = &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
	}

	return s
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(shutdownCtx)
}
