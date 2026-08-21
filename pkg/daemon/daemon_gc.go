package daemon

import (
	"time"

	"github.com/psaab/xpf/pkg/conntrack"
)

// newConntrackGC wires the published dataplane into pkg/conntrack via the exported
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
//
// #2114 (Codex PR #6743 r3-7): the caller passes its pass snapshot —
// Run's phase-5 guard loaded the cell once, and the GC must be wired
// to THAT publication rather than re-loading (a clear landing between
// the two loads would construct the GC against a different backend
// than the guard validated). The parameter is the conntrack-facing
// interface (NOT dataplane.RuntimeDataPlane) so this file stays out
// of the #1451 legacy-import allowlist.
func (d *Daemon) newConntrackGC(rt conntrack.RuntimeDomainProvider, interval time.Duration) *conntrack.GC {
	return conntrack.NewGC(rt, interval)
}
