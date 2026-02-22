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

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/vrrp"
)

// Config configures the API server.
type Config struct {
	Addr      string
	HTTPSAddr string // HTTPS listen address (empty = no HTTPS)
	TLS       bool   // enable HTTPS with auto-generated certificate
	Auth      *AuthConfig // nil = no authentication
	Store     *configstore.Store
	DP        dataplane.DataPlane
	EventBuf  *logging.EventBuffer
	GC        *conntrack.GC
	Routing   *routing.Manager
	FRR       *frr.Manager
	IPsec     *ipsec.Manager
	DHCP      *dhcp.Manager
	VRRPMgr   *vrrp.Manager       // native VRRP manager
	ApplyFn   func(*config.Config) // daemon's applyConfig callback
}

// Server is the HTTP API server.
type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	store       *configstore.Store
	dp          dataplane.DataPlane
	eventBuf    *logging.EventBuffer
	gc          *conntrack.GC
	routing     *routing.Manager
	frr         *frr.Manager
	ipsec       *ipsec.Manager
	dhcp        *dhcp.Manager
	vrrpMgr     *vrrp.Manager
	applyFn     func(*config.Config)
	startTime   time.Time
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
		vrrpMgr:   cfg.VRRPMgr,
		applyFn:   cfg.ApplyFn,
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

	// Session zone-pair summary
	mux.HandleFunc("GET /api/v1/security/sessions/summary/zone-pairs", s.sessionZonePairHandler)

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
	certPath = "/etc/bpfrx/tls/cert.pem"
	keyPath  = "/etc/bpfrx/tls/key.pem"
)

// generateSelfSignedCert creates or loads a self-signed TLS certificate.
// If cert/key files exist on disk, they are loaded. Otherwise, a new
// ECDSA P-256 certificate is generated and persisted for reuse across restarts.
func generateSelfSignedCert() (tls.Certificate, error) {
	// Try loading existing cert
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}

	// Generate new ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"bpfrx"}},
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

	// Persist for reuse across restarts
	os.MkdirAll("/etc/bpfrx/tls", 0700)
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)

	return tls.X509KeyPair(certPEM, keyPEM)
}
