package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// #9165: the daemon-side reader for the remote-syslog drop counters.
func TestSyslogDropStatsReportsTheInstalledClients9165(t *testing.T) {
	er := &logging.EventReader{}
	c, err := logging.NewSyslogClientDeferred("203.0.113.7", 514, "", "tcp", nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	er.SetSyslogClients([]*logging.SyslogClient{c})

	d := &Daemon{eventReader: er}
	stats := d.syslogDropStats()
	if len(stats) != 1 {
		t.Fatalf("syslogDropStats returned %d rows, want 1", len(stats))
	}
	if stats[0].Protocol != "tcp" {
		t.Errorf("row protocol = %q, want tcp (%+v)", stats[0].Protocol, stats[0])
	}
}

// A metrics scrape races daemon startup and every commit that rebuilds the
// client set, so both nil hops must be no-ops rather than panics.
func TestSyslogDropStatsIsNilSafe9165(t *testing.T) {
	if got := (*Daemon)(nil).syslogDropStats(); got != nil {
		t.Errorf("nil daemon returned %v", got)
	}
	if got := (&Daemon{}).syslogDropStats(); got != nil {
		t.Errorf("daemon with no event reader returned %v", got)
	}
}
