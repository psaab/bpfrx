package userspace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// helperEventSocketPath resolves the event-socket path for a helper config: the
// explicit `event-socket` when the operator set one, else the conventional name
// beside the control socket. The pre-stop preflight and the listener setup both
// resolve it through here, so they can never disagree about which path was
// validated (#5839).
func helperEventSocketPath(cfg config.UserspaceConfig) string {
	if cfg.EventSocket != "" {
		return cfg.EventSocket
	}
	return filepath.Join(filepath.Dir(cfg.ControlSocket), "userspace-dp-events.sock")
}

// preflightHelperPaths rejects a helper path set that bring-up would have to
// refuse anyway, while the RUNNING generation can still be spared (#5839).
//
// ensureProcessLocked stops generation N before it prepares generation N+1, so
// without a preflight every path fault is paid for with forwarding: the healthy
// helper is killed, socket preparation then fails, and the node is left with no
// dataplane at all. The two checks here are exactly the DETERMINISTIC faults —
// an aliased path, and a path that exists as something other than a Unix socket
// — neither of which stopping the helper can change. Everything conditional on
// the running helper is deliberately left to removeStaleUnixSocket after the
// stop; above all the liveness check, since the control socket is live PRECISELY
// UNTIL we stop the helper that owns it.
//
// It fails only on a certain fault. An Lstat error other than "does not exist"
// is inconclusive here and is left to the post-stop path rather than turned into
// a new bring-up failure on a code path that used to have none.
func preflightHelperPaths(cfg config.UserspaceConfig) error {
	evtPath := helperEventSocketPath(cfg)
	// The stale-socket primitive must never be pointed at the state file: a
	// REGULAR FILE is expected there, so aliasing it onto a socket path would
	// hand helper state to a socket unlink. Aliasing the two sockets onto each
	// other is equally unworkable — the daemon's event listener would occupy
	// the path the helper must bind.
	for _, pair := range []struct{ aName, a, bName, b string }{
		{"control-socket", cfg.ControlSocket, "event socket", evtPath},
		{"control-socket", cfg.ControlSocket, "state-file", cfg.StateFile},
		{"event socket", evtPath, "state-file", cfg.StateFile},
	} {
		if pair.a != "" && pair.a == pair.b {
			return fmt.Errorf("userspace dataplane %s and %s must name distinct paths (both are %s)",
				pair.aName, pair.bName, pair.a)
		}
	}
	for _, sock := range []struct{ kind, path string }{
		{socketKindControl, cfg.ControlSocket},
		{socketKindEventStream, evtPath},
	} {
		if sock.path == "" {
			continue
		}
		info, err := os.Lstat(sock.path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("userspace dataplane %s %s is a %s, not a Unix socket",
				sock.kind, sock.path, describeFileMode(info.Mode()))
		}
	}
	return nil
}

// stopForNewGenerationLocked preflights the incoming path set and tears the
// running helper down only once that preflight passes, so a config that cannot
// bring up a new generation leaves the previous one — and its forwarding —
// running (#5839).
func (m *Manager) stopForNewGenerationLocked(cfg config.UserspaceConfig) error {
	if err := preflightHelperPaths(cfg); err != nil {
		return fmt.Errorf("refusing to restart userspace dataplane helper, "+
			"previous generation left running: %w", err)
	}
	m.stopLocked()
	return nil
}

func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
	tuneSocketBuffers()
	if m.proc != nil && m.proc.Process != nil && configEqual(m.cfg, cfg) {
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{Type: "ping"}, &status); err == nil {
			if status.PID != 0 || status.ConfigSnapshotProtocolVersion != 0 {
				m.setLastStatusLocked(status)
			}
			return nil
		}
		slog.Warn("userspace dataplane helper unhealthy, restarting")
		if err := m.stopForNewGenerationLocked(cfg); err != nil {
			return err
		}
	}
	if m.proc != nil {
		if err := m.stopForNewGenerationLocked(cfg); err != nil {
			return err
		}
	}
	m.clearLastStatusLocked()
	binary, err := findBinary(cfg.Binary)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlSocket), 0755); err != nil {
		return fmt.Errorf("mkdir control socket dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	// The control socket is named by operator configuration and xpfd runs as
	// root, so the stale-socket unlink is guarded rather than fire-and-forget:
	// it refuses a path that is not a Unix socket, refuses one a live listener
	// still holds, and surfaces a removal failure instead of discarding it
	// (#5839). The helper has not been spawned yet, so failing here costs
	// nothing beyond the generation that was already stopped.
	if err := removeStaleUnixSocket(socketKindControl, cfg.ControlSocket); err != nil {
		return err
	}
	// Start the event stream listener before spawning the helper so it
	// can connect immediately.
	evtPath := helperEventSocketPath(cfg)
	es := NewEventStream(evtPath)
	esCtx, esCancel := context.WithCancel(context.Background())
	// The event socket is the primary push path for post-bootstrap session
	// deltas from the local helper to the daemon. If its listener fails to bind,
	// fail the whole bring-up here — BEFORE spawning the helper — rather than
	// silently starting in the slower DrainSessionDeltas polling fallback with a
	// non-nil-but-dead stream that takeoverReadyLocked would wave through as
	// healthy (#5273).
	if err := es.Start(esCtx); err != nil {
		esCancel()
		es.Close()
		return fmt.Errorf("start userspace dataplane event stream listener: %w", err)
	}
	m.eventStream = es
	m.eventStreamCancel = esCancel
	// Clear stale XSKMAP entries from previous helper instance.
	// Old entries point to dead socket fds; new helper will repopulate.
	if xskMap := m.bpfShim.Map(mapNameUserspaceXSK); xskMap != nil {
		for i := uint32(0); i < 4096; i++ {
			_ = xskMap.Delete(i)
		}
		slog.Debug("userspace: cleared stale XSKMAP entries")
	}
	pollMode := cfg.PollMode
	if pollMode == "" {
		pollMode = "busy-poll"
	}
	cmd := exec.Command(binary,
		"--control-socket", cfg.ControlSocket,
		"--state-file", cfg.StateFile,
		"--workers", fmt.Sprintf("%d", cfg.Workers),
		"--ring-entries", fmt.Sprintf("%d", cfg.RingEntries),
		"--poll-mode", pollMode,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		if m.eventStreamCancel != nil {
			m.eventStreamCancel()
		}
		if m.eventStream != nil {
			m.eventStream.Close()
		}
		m.eventStream = nil
		m.eventStreamCancel = nil
		return fmt.Errorf("start userspace dataplane helper: %w", err)
	}
	m.cfg = cfg
	m.proc = cmd
	// Bootstrap XSK fill ring on all queues: send broadcast pings
	// 3 seconds after helper start. During this window, ctrl is disabled;
	// the shim only passes proven local/control traffic and drops transit.
	// The broadcast pings generate hardware RX events on multiple queues,
	// triggering NAPI which consumes fill ring entries and posts WQEs for
	// zero-copy.
	go func() {
		time.Sleep(3 * time.Second)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil {
			return
		}
		m.bootstrapNAPIQueuesAsyncLocked("startup")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.ControlSocket); err == nil {
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "ping"}, &status); err == nil {
				if status.PID != 0 || status.ConfigSnapshotProtocolVersion != 0 {
					m.setLastStatusLocked(status)
				}
				slog.Info("userspace dataplane helper started", "pid", cmd.Process.Pid, "socket", cfg.ControlSocket)
				return nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("userspace dataplane helper did not become ready at %s", cfg.ControlSocket)
}

// tuneSocketBuffers raises the kernel socket buffer limits so AF_XDP copy-mode
// sockets can receive at line rate.  The default rmem_default (212992 = 208KB)
// is far too small — copy-mode XSK pushes each packet through the socket
// receive buffer and silently drops when it fills, causing throughput to stall
// after an initial burst.
func tuneSocketBuffers() {
	const desired = 67108864 // 64 MB
	paths := []string{
		"/proc/sys/net/core/rmem_default",
		"/proc/sys/net/core/rmem_max",
		"/proc/sys/net/core/wmem_default",
		"/proc/sys/net/core/wmem_max",
	}
	for _, path := range paths {
		cur, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var curVal int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(cur)), "%d", &curVal); err != nil {
			continue
		}
		if curVal >= desired {
			continue
		}
		val := fmt.Sprintf("%d", desired)
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to tune socket buffer", "path", path, "err", err)
		} else {
			slog.Info("tuned socket buffer for AF_XDP", "path", path, "from", curVal, "to", desired)
		}
	}
}

func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("userspace dataplane binary not found: %s", explicit)
	}
	candidates := []string{
		"./xpf-userspace-dp",
		filepath.Join("userspace-dp", "target", "release", "xpf-userspace-dp"),
		filepath.Join(filepath.Dir(os.Args[0]), "xpf-userspace-dp"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("xpf-userspace-dp"); err == nil {
		return p, nil
	}
	return "", errors.New("userspace dataplane helper binary not found; build make build-userspace-dp or configure system dataplane binary")
}

func (m *Manager) stopLocked() {
	if m.eventStreamCancel != nil {
		m.eventStreamCancel()
		m.eventStreamCancel = nil
	}
	if m.eventStream != nil {
		m.eventStream.Close()
		m.eventStream = nil
	}
	if m.syncCancel != nil {
		m.syncCancel()
		m.syncCancel = nil
	}
	if m.proc == nil {
		m.clearLastStatusLocked()
		m.bindingsBusySince = time.Time{}
		m.lastBindingsAutoRebind = time.Time{}
		m.sessionMirrorFailed = false
		m.sessionMirrorErr = ""
		return
	}
	// Disable userspace forwarding BEFORE stopping the helper. Without this,
	// the XDP shim continues redirecting to XSK after the helper exits,
	// sending packets to dead socket fds. Setting ctrl.enabled=0 makes the
	// shim pass only proven local/control traffic and drop transit. If the
	// disable cannot be verified, the wrapper clears all bindings fail-closed
	// before the helper shutdown below (#5486).
	_ = m.disableCtrlBeforeTeardownLocked()
	_ = m.requestLocked(ControlRequest{Type: "shutdown"}, nil)
	done := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(done)
	}(m.proc)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if m.proc.Process != nil {
			_ = m.proc.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if m.proc.Process != nil {
				_ = m.proc.Process.Kill()
			}
			<-done
		}
	}
	m.proc = nil
	m.clearLastStatusLocked()
	m.neighborsPrewarmed = false
	m.ctrlEnableAt = time.Time{}
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.initialCtrlCleanupDone = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	m.lastNAPIBootstrap = time.Time{}
	m.lastStandbyNeighResolve = time.Time{}
	m.bindingsBusySince = time.Time{}
	m.lastBindingsAutoRebind = time.Time{}
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""
	// #2079: forget the applied snapshot when the helper stops so a
	// restarted helper does not expose a stale applied config before its
	// first apply lands (AppliedNATView also guards on m.proc == nil).
	m.appliedSnapshot = appliedSnapshot{}
	m.sessionMirrorFailed = false
	m.sessionMirrorErr = ""
}

func configEqual(a, b config.UserspaceConfig) bool {
	return a.Binary == b.Binary &&
		a.ControlSocket == b.ControlSocket &&
		a.EventSocket == b.EventSocket &&
		a.StateFile == b.StateFile &&
		a.Workers == b.Workers &&
		a.RingEntries == b.RingEntries &&
		a.PollMode == b.PollMode
}

func (m *Manager) StartFIBSync(ctx context.Context) {
	m.bpfShim.StartFIBSync(ctx)
}
