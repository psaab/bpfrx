package daemon

import (
	"errors"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

var _ fwdstatus.DataPlaneAccessor = forwardingStatusDaemonDataPlane{}

type forwardingStatusDaemonDataPlane struct {
	daemon *Daemon
}

// IsLoaded reads liveness off d.dp via the local dataplaneReadyProbe
// (runtime_probes.go). Both *dataplane.Manager and the userspace
// *LegacyDataPlaneAdapter satisfy the probe; the prior round-trip
// through legacyDP() was unnecessary.
func (a forwardingStatusDaemonDataPlane) IsLoaded() bool {
	if a.daemon == nil || a.daemon.dp == nil {
		return false
	}
	if ready, ok := a.daemon.dp.(dataplaneReadyProbe); ok {
		return ready.IsLoaded()
	}
	return false
}

// GetMapStats reads map stats via the runtime Telemetry domain
// (pkg/dataplane.Telemetry.MapStats — apply.go:154). The prior
// path went via legacyDP().GetMapStats(); the runtime domain
// already exposes the same map metadata, so the legacy bridge is
// no longer needed.
func (a forwardingStatusDaemonDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.daemon == nil || a.daemon.dp == nil {
		return nil
	}
	telemetry := a.daemon.dp.Telemetry()
	if telemetry == nil {
		return nil
	}
	stats := telemetry.MapStats()
	out := make([]fwdstatus.MapStats, 0, len(stats))
	for _, ms := range stats {
		out = append(out, fwdstatus.MapStats{
			Type:       ms.Type,
			MaxEntries: ms.MaxEntries,
			UsedCount:  ms.UsedCount,
		})
	}
	return out
}

type forwardingStatusDaemonUserspaceDataPlane struct {
	forwardingStatusDaemonDataPlane
}

func (a forwardingStatusDaemonUserspaceDataPlane) Status() (dpuserspace.ProcessStatus, error) {
	if a.daemon == nil {
		return dpuserspace.ProcessStatus{}, errors.New("userspace status unavailable")
	}
	return a.daemon.userspaceDataplaneStatus()
}

// userspaceStatusProbe matches the userspace adapter's Status()
// method without re-importing the dataplane.DataPlane interface.
// Satisfied by *dataplane/userspace.LegacyDataPlaneAdapter. The
// legacy eBPF Manager intentionally does not implement Status() —
// it carries no ProcessStatus snapshot — so the probe assertion
// fails on eBPF and forwardingStatusDataplane returns the base
// wrapper without Status().
type userspaceStatusProbe interface {
	Status() (dpuserspace.ProcessStatus, error)
}

func (d *Daemon) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	if d == nil || d.dp == nil {
		return dpuserspace.ProcessStatus{}, errors.New("userspace status unavailable")
	}
	provider, ok := d.dp.(userspaceStatusProbe)
	if !ok {
		return dpuserspace.ProcessStatus{}, errors.New("userspace status unavailable")
	}
	return provider.Status()
}

// forwardingStatusDataplane builds the fwdstatus accessor used by
// the gRPC + CLI forwarding-status sampler. Returns nil when the
// daemon has no dataplane (config-only mode); returns the
// userspace-specialized wrapper when d.dp is the AF_XDP helper
// adapter (so Status() works); returns the base wrapper otherwise.
func (d *Daemon) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if d == nil || d.dp == nil {
		return nil
	}
	base := forwardingStatusDaemonDataPlane{daemon: d}
	if _, ok := d.dp.(userspaceStatusProbe); ok {
		return forwardingStatusDaemonUserspaceDataPlane{forwardingStatusDaemonDataPlane: base}
	}
	return base
}
