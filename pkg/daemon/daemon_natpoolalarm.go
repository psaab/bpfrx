package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/natpoolalarm"
)

// natPoolAlarmSampler returns a natpoolalarm.Sampler that reads the
// userspace helper's last-applied, generation-coherent NAT pool view from
// the manager's cached state (#2079). It performs NO control-socket I/O: the
// manager's AppliedNATView reads m.lastStatus (refreshed by the 1 Hz status
// loop) and m.appliedSnapshot (captured at each successful apply_snapshot).
//
// When d.dp is not the userspace adapter (e.g. NoDataplane), the sampler
// reports Available:false so the monitor HOLDs (makes no decision).
func (d *Daemon) natPoolAlarmSampler() natpoolalarm.Sampler {
	return func() natpoolalarm.View {
		if d == nil || d.dp == nil {
			return natpoolalarm.View{Available: false}
		}
		adapter, ok := d.dp.(interface {
			Manager() *dpuserspace.Manager
		})
		if !ok {
			return natpoolalarm.View{Available: false}
		}
		mgr := adapter.Manager()
		if mgr == nil {
			return natpoolalarm.View{Available: false}
		}
		v := mgr.AppliedNATView()
		if !v.Available {
			return natpoolalarm.View{Available: false}
		}
		pools := make(map[string]natpoolalarm.PoolStatus, len(v.Pools))
		for name, p := range v.Pools {
			pools[name] = natpoolalarm.PoolStatus{
				PoolName:     p.PoolName,
				AddressCount: p.AddressCount,
				PortLow:      p.PortLow,
				PortHigh:     p.PortHigh,
				UsedPorts:    p.UsedPorts,
			}
		}
		return natpoolalarm.View{
			Config:         v.Config,
			Pools:          pools,
			HelperCoherent: v.HelperCoherent,
			Available:      true,
		}
	}
}

// natPoolAlarmEmitter returns a natpoolalarm.Emitter that forwards one
// pre-formatted structured RT_NAT line to all configured syslog streams and
// local writers via the daemon's EventReader (#2079). It is gated entirely
// behind a raise/clear transition by the monitor, so it fires at most a
// couple of lines per pool per utilization excursion — never per tick.
func (d *Daemon) natPoolAlarmEmitter() natpoolalarm.Emitter {
	return func(severity int, msg string) {
		if d == nil || d.eventReader == nil {
			return
		}
		d.eventReader.ForwardLogMsg(severity, msg)
	}
}

// natPoolAlarms returns the active NAT pool-utilization alarms for the
// `show security alarms` render sites (#2079). Returns nil when the monitor
// is not running (NoDataplane).
func (d *Daemon) natPoolAlarms() []natpoolalarm.ActiveAlarm {
	if d == nil || d.natPoolAlarm == nil {
		return nil
	}
	return d.natPoolAlarm.ActiveAlarms()
}
