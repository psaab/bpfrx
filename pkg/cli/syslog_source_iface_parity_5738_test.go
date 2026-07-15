package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestBuildSyslogClientsGlobalSourceFallback_5738 is the fail-on-revert guard
// for #5738 gap 1: the in-process CLI commit path (reloadSyslog →
// buildSyslogClients) must apply the global `security log source-interface`
// fallback when a stream has no per-stream source-address, binding the same
// resolved interface IP the daemon's applySyslogConfig binds. Before the fix
// buildSyslogClients passed stream.SourceAddress unconditionally, so a stream
// configured with source-interface only got a kernel-chosen source on a
// local-console commit (which writes LAST) while daemon-apply bound the
// interface address.
//
// FAIL-ON-REVERT: dropping the `if srcAddr == "" { srcAddr = globalSourceAddr }`
// fallback makes the built client's SourceAddr() empty, so the assertion fires
// RED. TCP transport is used so an unreachable receiver yields a usable
// reconnecting client (#3351) whose stored source binding we can read.
func TestBuildSyslogClientsGlobalSourceFallback_5738(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {
			Name: "reth1",
			Units: map[int]*config.InterfaceUnit{
				100: {
					Number:         100,
					Addresses:      []string{"10.0.1.20/24"},
					PrimaryAddress: "10.0.1.20/24",
				},
			},
		},
	}
	cfg.Security.Log.SourceInterface = "reth1.100"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:      "audit",
			Host:      "127.0.0.1",
			Port:      1,
			Transport: config.SyslogTransport{Protocol: "tcp"},
			// NO per-stream SourceAddress — must inherit the global fallback.
		},
	}

	// Sanity: the shared resolver returns the interface's primary IP.
	if got := config.ResolveSyslogSourceAddr(cfg, "reth1.100"); got != "10.0.1.20" {
		t.Fatalf("ResolveSyslogSourceAddr = %q, want 10.0.1.20", got)
	}

	clients := buildSyslogClients(cfg)
	if len(clients) != 1 {
		t.Fatalf("expected 1 syslog client, got %d", len(clients))
	}
	if got := clients[0].SourceAddr(); got != "10.0.1.20" {
		t.Errorf("stream with source-interface but no source-address bound source %q, want 10.0.1.20 "+
			"(CLI in-process commit ignored the global source-interface fallback, #5738 gap 1)", got)
	}
}

// TestBuildSyslogClientsPerStreamSourceWins_5738 confirms a per-stream
// source-address still takes precedence over the global source-interface
// fallback, matching applySyslogConfig (the fallback only fills an EMPTY
// per-stream source).
func TestBuildSyslogClientsPerStreamSourceWins_5738(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {
			Name:  "reth1",
			Units: map[int]*config.InterfaceUnit{100: {Number: 100, PrimaryAddress: "10.0.1.20/24"}},
		},
	}
	cfg.Security.Log.SourceInterface = "reth1.100"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:          "audit",
			Host:          "127.0.0.1",
			Port:          1,
			Transport:     config.SyslogTransport{Protocol: "tcp"},
			SourceAddress: "192.0.2.7",
		},
	}
	clients := buildSyslogClients(cfg)
	if len(clients) != 1 {
		t.Fatalf("expected 1 syslog client, got %d", len(clients))
	}
	if got := clients[0].SourceAddr(); got != "192.0.2.7" {
		t.Errorf("per-stream source-address = %q, want 192.0.2.7 (global fallback must not override it)", got)
	}
}

// TestReloadSyslogEventModeClearsRemoteClients_5738 is the fail-on-revert guard
// for #5738 gap 2: in event mode the in-process CLI commit path must CLEAR
// remote syslog clients (and not rebuild them from Streams), matching the
// daemon's applySyslogConfig event-mode branch. Before the fix reloadSyslog
// unconditionally rebuilt remote clients from Streams, so a config with BOTH
// event-mode AND a remote stream re-installed the remote clients the daemon had
// cleared — because the CLI reload writes LAST on a local commit.
//
// FAIL-ON-REVERT: removing the `Mode == "event"` branch makes reloadSyslog build
// the stream's client, so SyslogClientCount() == 1 instead of 0. NewLocalLogWriter
// may fail to open /var/log/xpf on a bare test host; that is fine — the remote
// client clearing happens first and is what we assert (same posture as the
// daemon's TestApplySyslogConfigEventModeClosesStreamClients).
func TestReloadSyslogEventModeClearsRemoteClients_5738(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	// Seed a prior remote client, as the daemon reconcile would have installed
	// before an in-process commit runs.
	prior, _ := logging.NewSyslogClientTransport("127.0.0.1", 1, "", "tcp", nil)
	er.SetSyslogClients([]*logging.SyslogClient{prior})

	c := &CLI{eventReader: er}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "event"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {Name: "audit", Host: "127.0.0.1", Port: 1, Transport: config.SyslogTransport{Protocol: "tcp"}},
	}

	c.reloadSyslog(cfg)

	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("event mode must leave zero remote syslog clients, got %d "+
			"(CLI reload re-installed remote clients the daemon cleared, #5738 gap 2)", got)
	}
}

// TestReloadSyslogStreamModeClearsLocalWriters_5738 covers the other half of the
// event/stream parity: switching to stream mode must clear any local writer a
// prior event-mode apply installed, matching applySyslogConfig's stream-mode
// er.ReplaceLocalWriters(nil).
//
// FAIL-ON-REVERT: without the stream-mode ReplaceLocalWriters(nil), the seeded
// local writer survives and LocalWriterCount() stays 1.
func TestReloadSyslogStreamModeClearsLocalWriters_5738(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	// Seed a local writer (temp path so it opens on a bare host), as a prior
	// event-mode apply would have installed.
	lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{Path: filepath.Join(t.TempDir(), "security.log")})
	if err != nil {
		t.Fatalf("seed local writer: %v", err)
	}
	er.SetLocalWriters([]*logging.LocalLogWriter{lw})
	if er.LocalWriterCount() != 1 {
		t.Fatalf("precondition: expected 1 seeded local writer, got %d", er.LocalWriterCount())
	}

	c := &CLI{eventReader: er}
	cfg := &config.Config{}
	// Stream mode (default: Mode empty) with a single remote stream.
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {Name: "audit", Host: "127.0.0.1", Port: 1, Transport: config.SyslogTransport{Protocol: "tcp"}},
	}

	c.reloadSyslog(cfg)

	if got := er.LocalWriterCount(); got != 0 {
		t.Fatalf("stream mode must clear stale local writers, got %d (#5738 gap 2 stream-mode parity)", got)
	}
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("stream mode must install the remote stream client, got %d", got)
	}
}
