package userspace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// process_supervisor.go owns the lifetime of a spawned helper process (#5838).
//
// # What was missing
//
// ensureProcessLocked spawned `xpf-userspace-dp`, waited for control-socket
// readiness and returned. Nothing called cmd.Wait() for the RUNNING generation
// — the only Wait in the package was created inside stopLocked, i.e. only for
// an INTENTIONAL stop. A helper that died after reporting ready (OOM, assert,
// SIGKILL, panic) therefore:
//
//   - stayed a zombie, because nobody reaped it;
//   - left m.proc non-nil, so every `m.proc == nil` liveness test read TRUE;
//   - left m.lastStatus at its last-good values, because the 1 Hz status poll's
//     failure branch only logged;
//   - and was noticed only if some later compile/sync path happened to call
//     ensureProcessLocked. On a stable config and a stable FIB, nothing does,
//     so the state persisted indefinitely.
//
// cmd.ProcessState is not populated until Wait, so it was not a valid liveness
// detector either — which is why the pre-existing readiness loop's
// `cmd.ProcessState != nil` check could only ever fire for a child that died
// before becoming ready.
//
// # What this is NOT
//
// It is not a fix for "the box forwards without policy after a helper crash",
// because the box does not do that. The XDP shim stays attached and is owned by
// xpfd, not the helper, and it drops transit through THREE independent
// degraded-path gates, verified in userspace-xdp/src/lib.rs:
//
//   - a missing or not-ready binding row -> drop_degraded_transit;
//   - a missing or STALE heartbeat -> drop_degraded_transit
//     (USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS = 5000, and the dead helper stops
//     writing USERSPACE_HEARTBEAT immediately);
//   - a failed XSK redirect -> drop_degraded_transit.
//
// All three PASS proven local/control traffic (pass_local_control) so the node
// stays manageable, and DROP transit. The post-crash failure mode is therefore
// a transit blackhole, not unadjudicated kernel forwarding. That is the safer
// failure and it is why this file's job is availability and honesty rather than
// closing a forwarding hole.
//
// The honesty half is the security-relevant one: takeoverReadyLocked gates on
// `m.proc == nil` and on m.lastStatus, and BOTH were stale after a crash, so
// TakeoverReady() returned true — with no reasons — for a node whose dataplane
// was dead. In a chassis cluster the peer consults exactly that to decide
// whether an RG ownership move can rely on this node for forwarding, so a
// crashed node advertised itself as a valid failover target and would blackhole
// every flow handed to it.

// helperGeneration is one spawned helper process and the SINGLE Wait that owns
// it.
//
// exited is closed by the waiter goroutine BEFORE it acquires m.mu. That
// ordering is what lets stopLocked block on it while holding m.mu without
// deadlocking against the waiter's own bookkeeping.
type helperGeneration struct {
	gen    uint64
	cmd    *exec.Cmd
	exited chan struct{}
	// waitErr and state are written by the waiter before it closes exited, so
	// a reader that has observed the close may read them without a lock.
	waitErr error
	state   *os.ProcessState
}

// describeExit renders a reaped child's disposition for a log line and the
// operator-facing crash record. Read only after exited is closed.
func (g *helperGeneration) describeExit() string {
	if g.state == nil {
		if g.waitErr != nil {
			return "wait failed: " + g.waitErr.Error()
		}
		return "unknown"
	}
	if ws, ok := g.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("killed by signal %v", ws.Signal())
	}
	return fmt.Sprintf("exit status %d", g.state.ExitCode())
}

// helperCrashState is the operator-visible record of the last unexpected exit
// and the backoff it drives.
type helperCrashState struct {
	// Crashed is set while the manager is between an unexpected exit and a
	// successful restart. It is what makes the staleness observable instead of
	// having to be inferred from a nil pointer.
	Crashed bool
	// Detail is the reaped disposition ("exit status 101", "killed by signal
	// killed"). Never carries a secret.
	Detail string
	// PID is the dead child, kept so an operator can correlate with journald.
	PID int
	// At is when the exit was observed.
	At time.Time
	// Restarts counts consecutive restart ATTEMPTS since the last helper that
	// reached readiness. It drives the backoff and is reset on success.
	Restarts int
	// NextRestart is the deadline the pending restart is scheduled for.
	NextRestart time.Time
}

// Helper restart backoff. Bounded exponential from base to max, so a helper
// that cannot start (a corrupt binary, a NIC that will not bind) retries
// forever at a fixed low rate instead of fork-storming, and a one-off crash
// recovers in about a second.
//
// They are vars rather than consts purely so a test can drive many real
// restarts without spending wall-clock seconds; production never reassigns
// them. Same seam idiom as statusLoopInterval in process_status.go.
var (
	helperRestartBackoffBase = time.Second
	helperRestartBackoffMax  = 60 * time.Second
)

// helperRestartDelay is the backoff for attempt n (1-based).
func helperRestartDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := helperRestartBackoffBase
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= helperRestartBackoffMax {
			return helperRestartBackoffMax
		}
	}
	return d
}

// scheduleRestartTimer arms fn to run after d.
//
// It is a per-Manager field rather than a package var deliberately: a package
// var is shared by every Manager in the process, so a supervisor goroutine from
// one test can land on another test's seam after t.Cleanup restored it —
// appending a phantom restart to a slice that test is asserting on, from a
// goroutine that does not hold that test's lock. That is a cross-test mutation
// channel and a data race at the same time. Production leaves it nil.
func (m *Manager) scheduleRestartTimer(d time.Duration, fn func()) {
	if m.restartTimerFn != nil {
		m.restartTimerFn(d, fn)
		return
	}
	time.AfterFunc(d, fn)
}

// startHelperSupervisorLocked allocates the next process generation for cmd and
// starts the ONE goroutine that owns its Wait.
//
// Called with m.mu held, immediately after a successful cmd.Start().
func (m *Manager) startHelperSupervisorLocked(cmd *exec.Cmd) {
	m.procGen++
	g := &helperGeneration{gen: m.procGen, cmd: cmd, exited: make(chan struct{})}
	m.procSup = g
	go m.superviseHelper(g)
}

// superviseHelper is the single waiter for one generation.
//
// It reaps the child, publishes the result, and only THEN takes m.mu — so a
// stopLocked that is parked on g.exited while holding m.mu is released before
// this goroutine needs the lock.
func (m *Manager) superviseHelper(g *helperGeneration) {
	g.waitErr = g.cmd.Wait()
	g.state = g.cmd.ProcessState
	close(g.exited)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Generation fence, and the ONLY thing that distinguishes an expected exit
	// from a crash.
	//
	// An INTENTIONAL teardown clears procSup under m.mu before releasing it,
	// and this goroutine cannot acquire m.mu until that release — so a stop is
	// already `m.procSup != g` by the time we get here and takes the same exit
	// as a stale generation. An earlier draft also carried a `stoppingHelper`
	// flag for that case; it was removed because no input made it decide
	// anything the fence had not already decided, and a branch whose condition
	// never varies is untestable code pretending to be a safeguard.
	if m.procSup != g || m.procGen != g.gen {
		return
	}
	m.handleUnexpectedHelperExitLocked(g)
}

// handleUnexpectedHelperExitLocked fails the node closed after a crash and
// schedules a bounded restart.
//
// Order matters. The shim is disarmed FIRST, before any bookkeeping that could
// fail, because that is the step that stops the XDP program redirecting into a
// dead XSK; every later step is about not lying to an operator or to the
// cluster peer.
func (m *Manager) handleUnexpectedHelperExitLocked(g *helperGeneration) {
	detail := g.describeExit()
	pid := 0
	if g.cmd.Process != nil {
		pid = g.cmd.Process.Pid
	}
	slog.Error("userspace dataplane helper exited unexpectedly; failing closed and scheduling restart (#5838)",
		"pid", pid, "disposition", detail, "generation", g.gen)

	// Disarm the shim explicitly rather than relying on it noticing. The
	// degraded gates in userspace-xdp already drop transit for a dead helper —
	// stale heartbeat within 5s, and a failing XSK redirect immediately — but
	// this closes the window deterministically and clears the binding rows, so
	// the shim has nothing READY to redirect to at all. It is the same
	// primitive the intentional teardown uses (#5486).
	_ = m.disableCtrlBeforeTeardownLocked()

	// The child is reaped; drop the handle so every `m.proc == nil` liveness
	// test in the package — takeoverReadyLocked's first gate among them — reads
	// the truth.
	m.proc = nil
	m.resetAfterHelperGoneLocked()

	m.helperCrash = helperCrashState{
		Crashed:  true,
		Detail:   detail,
		PID:      pid,
		At:       time.Now(),
		Restarts: m.helperCrash.Restarts,
	}
	m.scheduleHelperRestartLocked(g.gen)
}

// scheduleHelperRestartLocked arms the next restart attempt for the generation
// that just died, fenced on gen so a later intentional Stop cancels it by
// simply advancing procGen.
func (m *Manager) scheduleHelperRestartLocked(gen uint64) {
	m.helperCrash.Restarts++
	delay := helperRestartDelay(m.helperCrash.Restarts)
	m.helperCrash.NextRestart = time.Now().Add(delay)
	slog.Warn("userspace dataplane helper restart scheduled",
		"attempt", m.helperCrash.Restarts, "delay", delay)
	m.scheduleRestartTimer(delay, func() { m.restartHelperAfterCrash(gen) })
}

// restartHelperAfterCrash re-runs the ORDINARY bring-up for the current desired
// config.
//
// It deliberately calls ensureProcessLocked rather than re-executing the dead
// generation's argv: bring-up is where the binding / XSK-liveness / capability /
// event-stream readiness gates live, and a restart that skipped them would
// re-arm forwarding on a helper that had not proved any of them. m.cfg is the
// CURRENT desired config, so a config replacement that landed while the helper
// was down is what gets started, not the stale generation's.
func (m *Manager) restartHelperAfterCrash(gen uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Fences: a newer generation exists (someone already restarted or Stop ran
	// and respawned), or a helper is running again, or the crash was cleared.
	if m.procGen != gen || m.proc != nil || !m.helperCrash.Crashed {
		return
	}
	if err := m.ensureProcessLocked(m.cfg); err != nil {
		slog.Error("userspace dataplane helper restart failed; will retry",
			"attempt", m.helperCrash.Restarts, "err", err)
		// ensureProcessLocked may have advanced procGen on a spawn that then
		// failed readiness; re-fence the retry on whatever is current so the
		// timer chain cannot fork.
		m.scheduleHelperRestartLocked(m.procGen)
		return
	}
	slog.Info("userspace dataplane helper restarted after unexpected exit",
		"attempts", m.helperCrash.Restarts)
	m.helperCrash = helperCrashState{}
	// The crash tore the 1 Hz reconcile loop down with the generation it was
	// polling; the replacement needs its own.
	m.ensureStatusLoopLocked()
}

// HelperCrashState returns the last unexpected-exit record, for status
// rendering and tests. The zero value means no crash is on record.
func (m *Manager) HelperCrashState() helperCrashState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.helperCrash
}
