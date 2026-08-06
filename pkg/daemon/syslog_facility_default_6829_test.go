package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestApplySyslogConfigKeepsDefaultFacilityWhenUnset_6829 is the daemon-side
// twin of TestBuildSyslogClientsKeepsDefaultFacilityWhenUnset_6829 in pkg/cli.
//
// The compute/assign split for a stream's syslog facility is duplicated across
// two packages: buildSyslogClients (pkg/cli, the local-console commit mirror)
// and applySyslogConfig (here, the path the running daemon actually takes).
// Both carry their own `haveFacility` guard, so binding one leaves the other
// free to drift — and the one that ships records in production is this one.
//
// The guard keeps a stream that names NO facility on the constructor default
// FacilityLocal0 (16) rather than overwriting it with the zero value of the
// `facility` local (0 = FacilityKern). Measured: forcing the guard always-true
// at both sites left pkg/cli, pkg/daemon and pkg/logging green before this
// test and its pkg/cli twin existed.
func TestApplySyslogConfigKeepsDefaultFacilityWhenUnset_6829(t *testing.T) {
	// One stream per apply: SyslogClients() preserves install order, but with
	// two streams that order follows map iteration over cfg.Security.Log.Streams
	// and an index-keyed assertion would be nondeterministic.
	apply := func(t *testing.T, facility string) *logging.SyslogClient {
		t.Helper()
		er := logging.NewEventReader(nil, nil)
		d := &Daemon{}
		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"audit": {
				Name: "audit", Host: "127.0.0.1", Port: 514,
				Facility: facility, Severity: "info",
			},
		}
		d.applySyslogConfig(er, cfg)
		clients := er.SyslogClients()
		if len(clients) != 1 {
			t.Fatalf("want exactly one installed client for facility %q, got %d", facility, len(clients))
		}
		return clients[0]
	}

	t.Run("unset facility keeps the constructor default", func(t *testing.T) {
		got := apply(t, "").Facility
		if got == logging.FacilityKern {
			t.Fatalf("Facility = %d (FacilityKern) — the assign-half guard was dropped on the "+
				"DAEMON path, so a stream naming no facility got the zero value of the "+
				"`facility` local instead of the constructor default FacilityLocal0 (%d). "+
				"Every record from that stream would leave under kern",
				got, logging.FacilityLocal0)
		}
		if got != logging.FacilityLocal0 {
			t.Errorf("Facility = %d, want FacilityLocal0 (%d)", got, logging.FacilityLocal0)
		}
	})

	// Positive control — see the pkg/cli twin: without it, the subtest above is
	// satisfied by hardcoding local0 and dropping the configured value.
	t.Run("named facility still overrides the default", func(t *testing.T) {
		got := apply(t, "auth").Facility
		if got != logging.FacilityAuth {
			t.Fatalf("Facility = %d, want FacilityAuth (%d) — a named facility must still reach "+
				"the client on the daemon path", got, logging.FacilityAuth)
		}
	})
}
