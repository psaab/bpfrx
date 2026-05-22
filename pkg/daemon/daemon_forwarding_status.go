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

func (a forwardingStatusDaemonDataPlane) IsLoaded() bool {
	if a.daemon == nil {
		return false
	}
	dp := a.daemon.legacyDP()
	return dp != nil && dp.IsLoaded()
}

func (a forwardingStatusDaemonDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.daemon == nil {
		return nil
	}
	dp := a.daemon.legacyDP()
	if dp == nil {
		return nil
	}
	stats := dp.GetMapStats()
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

func (d *Daemon) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	dp := d.legacyDP()
	provider, ok := dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return dpuserspace.ProcessStatus{}, errors.New("userspace status unavailable")
	}
	return provider.Status()
}

func (d *Daemon) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if d == nil {
		return nil
	}
	dp := d.legacyDP()
	if dp == nil {
		return nil
	}
	base := forwardingStatusDaemonDataPlane{daemon: d}
	if _, ok := dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		return forwardingStatusDaemonUserspaceDataPlane{forwardingStatusDaemonDataPlane: base}
	}
	return base
}
