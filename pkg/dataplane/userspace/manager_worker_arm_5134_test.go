package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestDeferredWorkerArmDebtRetainedWhileHelperDown is the #5134 core contract:
// a deferred-MAC re-apply that FAILS must NOT be swallowed into a
// success-with-workerless-snapshot. The daemon records generation debt
// (RecordDeferredWorkerArmDebt); until the publish lands, the reconcile retry
// MUST keep the debt set and MUST NOT flip the retained snapshot to
// DeferWorkers=false (which would falsely report armed) or advance
// publishedSnapshot.
//
// RED-on-revert: if the daemon reverts to swallowing the error (never records
// debt) or the retry mechanism is removed, a workerless snapshot stays the
// terminal published state while the commit reports success — the silent
// forwarding outage this test guards against.
func TestDeferredWorkerArmDebtRetainedWhileHelperDown(t *testing.T) {
	dir := t.TempDir()
	// A control socket with nothing listening: every apply_snapshot publish
	// fails at dial, modeling a helper that keeps rejecting the re-arm.
	controlSock := filepath.Join(dir, "no-listener.sock")

	cfg := &config.Config{}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Simulate the state left by the first (deferred) apply: a published
	// workerless snapshot. The failed re-apply never advanced past this.
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	snap.DeferWorkers = true
	m.lastSnapshot = snap
	m.generation = 7
	m.publishedSnapshot = 7

	// The daemon records debt instead of swallowing the failed re-apply.
	m.RecordDeferredWorkerArmDebt()
	if !m.pendingWorkerArm {
		t.Fatal("RecordDeferredWorkerArmDebt must set pendingWorkerArm (debt not recorded — daemon swallowed the failure)")
	}

	// Reconcile tick while the helper is still down: the publish fails, so
	// the debt must persist and the retained snapshot must stay workerless.
	m.mu.Lock()
	retryErr := m.retryDeferredWorkerArmLocked()
	m.mu.Unlock()
	if retryErr == nil {
		t.Fatal("retryDeferredWorkerArmLocked must return the publish error while the helper is down")
	}
	if !m.pendingWorkerArm {
		t.Fatal("debt must remain set after a failed re-arm publish so the next tick retries")
	}
	if !m.lastSnapshot.DeferWorkers {
		t.Fatal("retained snapshot must stay DeferWorkers=true after a failed re-arm (never falsely reported armed)")
	}
	if m.publishedSnapshot != 7 {
		t.Fatalf("publishedSnapshot = %d, want 7 retained after a failed re-arm publish", m.publishedSnapshot)
	}
}

// TestDeferredWorkerArmDebtArmsWorkersOnRecovery verifies the self-heal: once
// the helper accepts apply_snapshot again, the reconcile retry republishes the
// snapshot with DeferWorkers=false (arming the workers) and clears the debt.
func TestDeferredWorkerArmDebtArmsWorkersOnRecovery(t *testing.T) {
	controlSock := filepath.Join(t.TempDir(), "control.sock")

	cfg := &config.Config{}
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	snap.DeferWorkers = true
	m.lastSnapshot = snap
	m.generation = 7
	m.publishedSnapshot = 7
	m.RecordDeferredWorkerArmDebt()

	reqs := startArmControlServer(t, controlSock, 1)

	m.mu.Lock()
	// applyHelperStatusLocked writes BPF maps that are not loaded in this
	// unit test; it returns an error AFTER the snapshot has landed and the
	// arm bookkeeping has advanced. The publish itself (the re-arm) succeeds,
	// which is what this test asserts.
	_ = m.retryDeferredWorkerArmLocked()
	m.mu.Unlock()

	select {
	case req := <-reqs:
		if req.Type != "apply_snapshot" {
			t.Fatalf("re-arm request type = %q, want apply_snapshot", req.Type)
		}
		if req.Snapshot == nil {
			t.Fatal("re-arm request carried no snapshot")
		}
		if req.Snapshot.DeferWorkers {
			t.Fatal("re-arm must publish DeferWorkers=false to start the workers")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the re-arm apply_snapshot")
	}

	if m.pendingWorkerArm {
		t.Fatal("debt must be cleared once the re-arm publish succeeds")
	}
	if m.lastSnapshot.DeferWorkers {
		t.Fatal("armed snapshot must have DeferWorkers=false after a successful re-arm")
	}
	if m.publishedSnapshot <= 7 {
		t.Fatalf("publishedSnapshot = %d, want > 7 after the re-arm publish landed", m.publishedSnapshot)
	}
}

// startArmControlServer stands up a unix control socket that replies OK to the
// next `n` requests, returning each decoded request on the channel.
func startArmControlServer(t *testing.T, controlSock string, n int) <-chan ControlRequest {
	t.Helper()
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	reqs := make(chan ControlRequest, n)
	go func() {
		defer close(reqs)
		for i := 0; i < n; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				select {
				case reqs <- req:
				default:
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK:     true,
					Status: &ProcessStatus{PID: 4242},
				})
			}()
		}
	}()
	return reqs
}
