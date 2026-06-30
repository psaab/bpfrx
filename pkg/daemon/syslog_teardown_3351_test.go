package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestApplySyslogConfigZeroStreamsTearsDownClients is the RED-on-revert proof
// for the #3351 follow-up: a day-2 commit that removes ALL security log streams
// must tear down previously-installed syslog clients, not leave them lingering
// on the EventReader. This matters most for the #3351 lazy-connect change — a
// down-at-apply TCP/TLS stream is now installed as a RECONNECTING client, so a
// lingering client would resume forwarding audit logs to a deleted receiver
// once that receiver recovered.
//
// Reverting the fix (removing er.SetSyslogClients(nil) from the zero-streams
// early return in applySyslogConfig) leaves the pre-installed client in place,
// so SyslogClientCount stays 1 and this test fails.
func TestApplySyslogConfigZeroStreamsTearsDownClients(t *testing.T) {
	er := logging.NewEventReader(nil, nil)

	// Simulate a prior config having installed a stream client. A UDP client
	// constructs successfully without a live peer, giving a real non-nil client.
	prior, err := logging.NewSyslogClient("127.0.0.1", 514)
	if err != nil {
		t.Fatalf("construct prior syslog client: %v", err)
	}
	er.SetSyslogClients([]*logging.SyslogClient{prior})
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("setup: expected 1 installed client, got %d", got)
	}

	// Day-2 commit: stream mode, ZERO streams (all removed). aggregation report
	// off so applyAggregator is a no-op on a bare daemon.
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = nil

	d.applySyslogConfig(er, cfg)

	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("removing all streams must tear down installed syslog clients; "+
			"got %d lingering client(s) (would forward audit logs to a deleted "+
			"receiver — #3351)", got)
	}
}

// TestApplySyslogConfigZeroStreamsNoClientsNoPanic guards the common path: zero
// streams with nothing previously installed simply leaves zero clients.
func TestApplySyslogConfigZeroStreamsNoClientsNoPanic(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"

	d.applySyslogConfig(er, cfg)

	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("expected 0 clients with no streams configured, got %d", got)
	}
}
