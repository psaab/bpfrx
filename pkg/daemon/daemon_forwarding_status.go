package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

// forwardingStatusDaemonDataPlane is the daemon's sampler-only dataplane
// adapter (#2114). It deliberately does NOT satisfy
// fwdstatus.DataPlaneAccessor and has no Status method: Build keys backend
// identity on Status() presence (pkg/fwdstatus/builder.go), so this type
// can never be misrouted into a Build path. The pre-#2114 wrapper pair
// (base + userspace-specialized) resolved capability at CONSTRUCTION time
// against the d.dp value then current, so a backend transition left a
// permanently wrong adapter behind; the single-method shape probes the
// currently published dataplane on every call instead.
type forwardingStatusDaemonDataPlane struct {
	daemon *Daemon
}

// CachedStatus returns the last control-socket-captured ProcessStatus
// without issuing a new request (#3970). The fwdstatus CPU sampler
// consumes this instead of Status() so it reads worker telemetry off
// the primary 1 Hz status poll rather than doubling the shared
// control-socket status rate.
func (a forwardingStatusDaemonDataPlane) CachedStatus() (dpuserspace.ProcessStatus, bool) {
	if a.daemon == nil {
		return dpuserspace.ProcessStatus{}, false
	}
	return a.daemon.userspaceDataplaneCachedStatus()
}

// userspaceCachedStatusProbe matches the userspace adapter's
// CachedStatus() method (#3970), which reads the last captured
// ProcessStatus without a control-socket request.
type userspaceCachedStatusProbe interface {
	CachedStatus() (dpuserspace.ProcessStatus, bool)
}

// userspaceDataplaneCachedStatus probes the CURRENTLY published dataplane
// (#2114: one dataplane() load per call) and returns its cached
// ProcessStatus, ok=false when no dataplane is published or the published
// backend is not the userspace adapter.
func (d *Daemon) userspaceDataplaneCachedStatus() (dpuserspace.ProcessStatus, bool) {
	if d == nil {
		return dpuserspace.ProcessStatus{}, false
	}
	rt := d.dataplane()
	if rt == nil {
		return dpuserspace.ProcessStatus{}, false
	}
	provider, ok := rt.(userspaceCachedStatusProbe)
	if !ok {
		return dpuserspace.ProcessStatus{}, false
	}
	return provider.CachedStatus()
}

// forwardingStatusDataplane builds the sampler's dataplane provider
// (#2114: narrowed to fwdstatus.CachedStatusProvider — the sampler only
// ever calls CachedStatus). Returns nil when the daemon has no dataplane
// at all (nil receiver, or config-only NoDataplane mode — the cell stays
// empty for the daemon lifetime there). A constructed-but-unarmed
// dataplane (bootstrap mode) still yields a non-nil provider whose
// per-call probe reports ok=false until a backend publishes status.
func (d *Daemon) forwardingStatusDataplane() fwdstatus.CachedStatusProvider {
	if d == nil || d.opts.NoDataplane {
		return nil
	}
	return forwardingStatusDaemonDataPlane{daemon: d}
}
