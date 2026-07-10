package upgrade

import (
	"fmt"
	"path/filepath"
	"time"
)

// HelperStatusFunc performs a one-shot status query against the RUNNING
// userspace dataplane helper on its control socket and reports the forwarding
// state plus the helper process PID. It is the existing control-socket "status"
// request (pkg/dataplane/userspace.ProbeStatus), adapted to primitives so
// pkg/upgrade need not import the dataplane package (and cannot cycle).
//
//   - enabled = ProcessStatus.Enabled, armed = ProcessStatus.ForwardingArmed:
//     the authoritative "forwarding is LIVE right now" pair the dataplane and
//     the #1993 boot probe already gate forwarding on.
//   - pid = ProcessStatus.PID: the helper process, used to tie the armed helper
//     to the freshly-cut target-version binary.
//
// A helper that is unreachable / not answering returns a non-nil err; a helper
// that answered but reports no live status returns enabled=armed=false.
type HelperStatusFunc func(controlSocket string, timeout time.Duration) (enabled, armed bool, pid int, err error)

// HelperExeFunc resolves the on-disk executable path a running PID is executing
// (production: os.Readlink("/proc/<pid>/exe")). It is the mechanism that ties an
// armed+forwarding helper to the version dir its binary physically lives under.
type HelperExeFunc func(pid int) (string, error)

// HelperHealthDeps are the injectable seams the post-cut helper-readiness probe
// consults (#5286). Keeping the probe LOGIC here — rather than inline in
// cmd/xpfd — makes the fail-closed armed+forwarding+target-version gate
// unit-testable in pkg/upgrade without a live host, and lets the RED-on-revert
// test contrast it against the pre-fix is-active-only fallback. cmd/xpfd wires
// the production adapters (userspace.ProbeStatus, /proc/<pid>/exe, systemctl
// is-active, the config-resolved control socket); tests inject fakes.
type HelperHealthDeps struct {
	// UnitActive reports whether the systemd unit is active (the process is
	// up). It is the NECESSARY-BUT-INSUFFICIENT precondition (#5286): the
	// pre-fix HelperHealthy treated is-active as SUFFICIENT, so a Type=simple
	// daemon that is up while its helper is down / crash-looping / not
	// forwarding reported "healthy" and the cut COMMITTED, clearing the
	// rollback journal (standalone) or returning the node to HA election while
	// it did not forward. Defaults to unitActiveProbe(DefaultUnit).
	UnitActive func() bool
	// Status performs the control-socket status query (armed+forwarding+pid).
	Status HelperStatusFunc
	// HelperExe resolves the armed helper PID's executable path (target-version
	// tie).
	HelperExe HelperExeFunc
	// ControlSocket is the helper control-socket path, resolved from the active
	// config (honoring an operator `system dataplane control-socket` override)
	// with a default fallback.
	ControlSocket string
	// VersionsDir is the runtime versioned root. The armed helper's binary must
	// live under VersionsDir/<expectVersion>/ for the target-version gate to
	// pass.
	VersionsDir string
	// PollInterval bounds the retry cadence while waiting for readiness
	// (default 500ms).
	PollInterval time.Duration
	// StatusTimeout bounds a single control-socket status query (default 2s).
	StatusTimeout time.Duration
}

// HelperHealthProbe builds the production post-cut helper-readiness probe wired
// into the upgrade System via NewSystemWithHelperHealth (#5286). It FAILS
// CLOSED: within `deadline` it must observe ALL of
//
//	(a) the unit ACTIVE (the process is up) — necessary but NOT sufficient;
//	(b) the helper reachable on its control socket reporting
//	    Enabled && ForwardingArmed — i.e. the dataplane is genuinely
//	    FORWARDING, not merely a live process; and
//	(c) the armed+forwarding helper EXECUTING the TARGET version's binary
//	    (VersionsDir/<expectVersion>/...), so a stale previous-version helper
//	    still armed on the socket is not mistaken for the new dataplane.
//
// If any condition is unmet within the deadline it returns a non-nil error, so
// cutover.go does NOT commit / clear the rollback journal — the standalone flow
// auto-rolls-back to the previous version, and the HA flow surfaces the failure
// (SkipStartHealthRollback) so the node is not returned to election while it is
// not forwarding.
//
// Per the eBPF-dataplane retirement (#1373) the userspace helper is the ONLY
// forwarding path, so a healthy post-upgrade node MUST have an armed forwarding
// helper — there is no legitimate no-helper configuration to exempt from the
// gate.
func HelperHealthProbe(deps HelperHealthDeps) func(expectVersion string, deadline time.Duration) error {
	unitActive := deps.UnitActive
	if unitActive == nil {
		unitActive = func() bool { return unitActiveProbe(DefaultUnit) }
	}
	poll := deps.PollInterval
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	statusTimeout := deps.StatusTimeout
	if statusTimeout <= 0 {
		statusTimeout = 2 * time.Second
	}
	return func(expectVersion string, deadline time.Duration) error {
		wantDir := filepath.Clean(filepath.Join(deps.VersionsDir, expectVersion))
		end := time.Now().Add(deadline)
		var last error
		for {
			last = checkHelperReady(deps, unitActive, statusTimeout, expectVersion, wantDir)
			if last == nil {
				return nil
			}
			if !time.Now().Before(end) {
				return fmt.Errorf("post-cut dataplane readiness gate failed for target %s "+
					"within %s (helper not confirmed armed+forwarding on the target "+
					"version): %w", expectVersion, deadline, last)
			}
			time.Sleep(poll)
		}
	}
}

// checkHelperReady performs ONE evaluation of the three-part readiness gate.
func checkHelperReady(deps HelperHealthDeps, unitActive func() bool, statusTimeout time.Duration, expectVersion, wantDir string) error {
	// (a) Precondition: the unit process must be up. Necessary but NOT
	// sufficient (#5286) — a Type=simple unit reports active immediately, before
	// the dataplane arms.
	if !unitActive() {
		return fmt.Errorf("unit not active (process not up)")
	}
	if deps.Status == nil {
		return fmt.Errorf("helper health probe misconfigured: no control-socket status query wired")
	}
	// (b) Positive dataplane readiness: the helper must be reachable AND report
	// Enabled && ForwardingArmed — the authoritative "forwarding is live"
	// signal. A down / stale / crash-looping helper fails here.
	enabled, armed, pid, err := deps.Status(deps.ControlSocket, statusTimeout)
	if err != nil {
		return fmt.Errorf("helper control-socket status query failed: %w", err)
	}
	if !enabled || !armed {
		return fmt.Errorf("helper not forwarding (enabled=%v forwarding_armed=%v)", enabled, armed)
	}
	// (c) Target-version tie: the armed+forwarding helper must be executing the
	// TARGET version's binary. This rejects a stale previous-version helper that
	// is still armed on the shared control socket while the freshly-started
	// target daemon has NOT actually armed its own dataplane.
	if deps.HelperExe == nil {
		return fmt.Errorf("helper health probe misconfigured: no exe resolver wired")
	}
	exe, err := deps.HelperExe(pid)
	if err != nil {
		return fmt.Errorf("resolve armed helper (pid %d) executable: %w", pid, err)
	}
	// filepath.Dir tolerates a trailing " (deleted)" suffix on /proc/<pid>/exe:
	// the suffix rides the basename, so the directory is unaffected.
	gotDir := filepath.Clean(filepath.Dir(exe))
	if gotDir != wantDir {
		return fmt.Errorf("armed helper executes %s (version dir %s), not the target version "+
			"%s (%s); the live dataplane is not the freshly-cut binary", exe, gotDir, expectVersion, wantDir)
	}
	return nil
}
