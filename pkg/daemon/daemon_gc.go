package daemon

import (
	"time"

	"github.com/psaab/xpf/pkg/conntrack"
)

func (d *Daemon) newConntrackGC(interval time.Duration) *conntrack.GC {
	if d.dp == nil {
		return conntrack.NewGCWithDomains(nil, nil, nil, nil, interval)
	}

	sessions := d.dp.Sessions()
	telemetry := d.dp.Telemetry()
	if lp := d.legacyDP(); lp != nil {
		// Legacy eBPF keeps session-count publishing and persistent-NAT
		// ownership on the DataPlane surface while sessions/telemetry are
		// migrated to runtime domains.
		return conntrack.NewGCWithDomains(sessions, telemetry, lp, lp, interval)
	}
	return conntrack.NewGCWithDomains(sessions, telemetry, nil, nil, interval)
}
