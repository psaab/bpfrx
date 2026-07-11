package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestApplySyslogConfigUnknownTransportInstallsNoClient is the daemon-side
// #5581 RED-on-revert proof. The strict commit schema rejects an unknown
// `transport protocol` (enum udp|tcp|tls), but the tolerant persisted /
// HA-synced load path does not — so applySyslogConfig can be handed a stream
// carrying a typo'd or unsupported transport token. Before the fix,
// NewSyslogClientTransport accepted the token and dial()'s default arm mapped
// it to UDP, so the daemon installed a live client shipping security/audit
// records as plaintext UDP while config/status still named a non-UDP transport.
//
// The fix makes the constructor return (nil, ErrUnsupportedTransport), so the
// daemon's `client == nil` guard skips the stream (a visible "failed to create
// syslog client" apply warning) and installs NO client — the records are not
// silently downgraded to plaintext. Reverting the fix installs one plaintext
// client here, so this test fails.
func TestApplySyslogConfigUnknownTransportInstallsNoClient(t *testing.T) {
	er := logging.NewEventReader(nil, nil)

	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"s1": {
			Name: "s1",
			Host: "127.0.0.1",
			Port: 514,
			Transport: config.SyslogTransport{
				Protocol: "tls-typo", // survives tolerant load; never passed a strict commit
			},
		},
	}

	d.applySyslogConfig(er, cfg)

	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("a stream with an unknown transport must install NO client "+
			"(fail closed), got %d — security records silently downgraded to "+
			"plaintext UDP (#5581)", got)
	}
}

// TestApplySyslogConfigKnownTransportInstallsClient guards against
// over-rejection: a stream with a valid (default UDP) transport must still
// install exactly one client, so the fail-closed guard does not break normal
// syslog forwarding.
func TestApplySyslogConfigKnownTransportInstallsClient(t *testing.T) {
	er := logging.NewEventReader(nil, nil)

	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"s1": {
			Name: "s1",
			Host: "127.0.0.1",
			Port: 514,
			// Transport.Protocol empty → UDP default (valid).
		},
	}

	d.applySyslogConfig(er, cfg)

	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("a stream with a valid transport must install one client, got %d", got)
	}
}
