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
		m.stopLocked()
	}
	if m.proc != nil {
		m.stopLocked()
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
	_ = os.Remove(cfg.ControlSocket)
	// Start the event stream listener before spawning the helper so it
	// can connect immediately.
	evtPath := cfg.EventSocket
	if evtPath == "" {
		evtPath = filepath.Join(filepath.Dir(cfg.ControlSocket), "userspace-dp-events.sock")
	}
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
