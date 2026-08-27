package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #6875 WIRING, daemon side. The compiler storing a per-stream
// `source-interface` is worth nothing if the apply path does not consult it —
// which is precisely the defect this issue reports, a value carried to
// somewhere nothing reads.
//
// This drives the real `applySyslogConfig` and reads the source the constructed
// client actually bound. A mutation matrix showed the earlier cells, all of
// which lived in pkg/config and asserted compilation, left this hop free: a
// pre-existing spelling gate noticed the change incidentally, and no cell of
// mine did.
//
// The CLI half is pinned separately by TestSyslogSourcePrecedenceMatchesDaemon_6875;
// the two paths must agree (#5738) and each needs its own driver.
func TestApplySyslogConfigHonoursStreamSourceInterface_6875(t *testing.T) {
	ifaces := func() map[string]*config.InterfaceConfig {
		return map[string]*config.InterfaceConfig{
			"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, Addresses: []string{"10.0.1.20/24"}, PrimaryAddress: "10.0.1.20/24"},
			}},
			"reth2": {Name: "reth2", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.2.30/24"}, PrimaryAddress: "10.0.2.30/24"},
			}},
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"per-stream source-interface resolves", func(c *config.Config) {
			c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
		}, "10.0.1.20"},
		{"source-address beats source-interface", func(c *config.Config) {
			c.Security.Log.Streams["audit"].SourceAddress = "192.0.2.7"
			c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
		}, "192.0.2.7"},
		{"per-stream source-interface beats the global", func(c *config.Config) {
			c.Security.Log.SourceInterface = "reth2.0"
			c.Security.Log.Streams["audit"].SourceInterface = "reth1.100"
		}, "10.0.1.20"},
		{"global remains the fallback", func(c *config.Config) {
			c.Security.Log.SourceInterface = "reth2.0"
		}, "10.0.2.30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			er := logging.NewEventReader(nil, nil)
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = ifaces()
			cfg.Security.Log.Mode = "stream"
			cfg.Security.Log.Streams = map[string]*config.SyslogStream{
				"audit": {
					Name:      "audit",
					Host:      "127.0.0.1",
					Port:      1,
					Transport: config.SyslogTransport{Protocol: "tcp"},
				},
			}
			tc.mutate(cfg)

			d := &Daemon{}
			d.applySyslogConfig(er, cfg)

			clients := er.SyslogClients()
			if len(clients) != 1 {
				t.Fatalf("expected 1 syslog client after apply, got %d — the assertion "+
					"below would otherwise read a client that was never constructed",
					len(clients))
			}
			if got := clients[0].SourceAddr(); got != tc.want {
				t.Errorf("daemon apply bound source %q, want %q (#6875)", got, tc.want)
			}
		})
	}
}
