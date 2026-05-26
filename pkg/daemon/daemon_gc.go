package daemon

import (
	"time"

	"github.com/psaab/xpf/pkg/conntrack"
)

// newConntrackGC wires d.dp into pkg/conntrack via the exported
// RuntimeDomainProvider (pkg/conntrack/gc.go:45 — a structural
// SessionStoreProvider + TelemetryProvider). NewGC internally
// type-asserts against package-private sessionCountPublisher /
// persistentNATProvider; missing assertions degrade to nil
// providers without touching the legacy DataPlane interface.
//
// Pre-#1519 this hand-rolled the providers via legacyDP() and
// passed them into NewGCWithDomains. Both *dataplane.Manager and
// *dataplane/userspace.LegacyDataPlaneAdapter satisfy
// RuntimeDomainProvider directly (Sessions()/Telemetry()), so the
// daemon no longer needs the BPF-shaped escape hatch here.
func (d *Daemon) newConntrackGC(interval time.Duration) *conntrack.GC {
	return conntrack.NewGC(d.dp, interval)
}
