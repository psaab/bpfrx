package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6875 + #5738: the per-stream `source-interface` must bind the same source on
// the CLI in-process commit path as on the daemon reconcile path.
//
// This exists because the precedence is implemented TWICE — daemon
// applySyslogConfig and cli buildSyslogClients — and #5738 is the issue that
// closed a divergence between exactly those two. A change to one and not the
// other is invisible to any test that only drives one of them, and the symptom
// is that an operator's audit stream sources differently depending on whether
// the config arrived by CLI commit or by reconcile.
func TestSyslogSourcePrecedenceMatchesDaemon_6875(t *testing.T) {
	// `primary` is what ResolveSyslogSourceAddr actually reads; a unit with
	// Addresses but no PrimaryAddress resolves to "" from config.
	base := func() *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, Addresses: []string{"10.0.1.20/24"}, PrimaryAddress: "10.0.1.20/24"},
			}},
			"reth2": {Name: "reth2", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.2.30/24"}, PrimaryAddress: "10.0.2.30/24"},
			}},
		}
		return cfg
	}

	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{
			// The new arm. Before #6875 this bound "" (or the global), because
			// the leaf compiled to nothing.
			name: "per-stream source-interface resolves",
			mutate: func(c *config.Config) {
				c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
			},
			want: "10.0.1.20",
		},
		{
			// Precedence rung 1: an explicit address beats a derived one.
			name: "source-address beats source-interface",
			mutate: func(c *config.Config) {
				c.Security.Log.Streams["audit"].SourceAddress = "192.0.2.7"
				c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
			},
			want: "192.0.2.7",
		},
		{
			// Precedence rung 3: the global still wins over nothing. Without
			// this cell, an implementation that ignored the global entirely
			// would pass the two above.
			name: "global remains the fallback",
			mutate: func(c *config.Config) {
				c.Security.Log.SourceInterface = "reth2.0"
			},
			want: "10.0.2.30",
		},
		{
			// Precedence rung 2 against rung 3 — the discriminating pair. Both
			// are set, and only a correct ranking produces reth1's address.
			name: "per-stream source-interface beats the global",
			mutate: func(c *config.Config) {
				c.Security.Log.SourceInterface = "reth2.0"
				c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
			},
			want: "10.0.1.20",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.Security.Log.Streams = map[string]*config.SyslogStream{
				"audit": {
					Name:      "audit",
					Host:      "127.0.0.1",
					Port:      1,
					Transport: config.SyslogTransport{Protocol: "tcp"},
				},
			}
			tc.mutate(cfg)

			clients := buildSyslogClients(cfg)
			if len(clients) != 1 {
				t.Fatalf("expected 1 syslog client, got %d — the assertion below "+
					"would otherwise read a client that was never built", len(clients))
			}
			if got := clients[0].SourceAddr(); got != tc.want {
				t.Errorf("CLI path bound source %q, want %q. The daemon path "+
					"(daemon_system.go) implements the same precedence; a divergence "+
					"here means an audit stream sources differently depending on "+
					"whether the config arrived by CLI commit or by reconcile (#5738)",
					got, tc.want)
			}
		})
	}
}
