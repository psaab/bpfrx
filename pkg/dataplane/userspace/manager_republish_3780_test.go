package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestUpdatePolicyScheduleStateReturnsErrorOnPublishFailure is the core
// #3780 contract at the dataplane boundary: a failed apply_snapshot on a
// scheduler window flip must be REPORTED (non-nil error), not swallowed.
//
// RED-on-revert: reverting the userspace manager to `slog.Warn(...);
// return` (void) makes this return nil — the daemon never learns the
// republish failed, never retries, and the helper keeps the OLD inactive
// bits, so a scheduled permit stays live after its window closed.
func TestUpdatePolicyScheduleStateReturnsErrorOnPublishFailure(t *testing.T) {
	dir := t.TempDir()
	// A control-socket path with nothing listening: requestLocked cannot
	// connect, so the apply_snapshot publish fails.
	controlSock := filepath.Join(dir, "no-listener.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot, _ = buildSnapshot(cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("UpdatePolicyScheduleState must return an error when apply_snapshot fails (silent fail-open otherwise)")
	}

	// The prior snapshot generation must be RETAINED (not bumped) so the
	// retry republishes cleanly from a consistent baseline.
	if m.generation != 7 {
		t.Fatalf("generation = %d, want 7 retained after a failed publish", m.generation)
	}
}

// TestUpdatePolicyScheduleStateNoHelperReportsConverged verifies the
// no-op paths report success (nil): with no helper process there is no
// live enforcement to go stale, so the daemon self-heal must not spin.
func TestUpdatePolicyScheduleStateNoHelperReportsConverged(t *testing.T) {
	cfg := &config.Config{}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	// No m.proc, no m.lastSnapshot: nothing published, nothing to converge.
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("no-snapshot republish must report converged (nil), got %v", err)
	}

	// Snapshot present but helper not running: still a no-op success.
	m.lastSnapshot, _ = buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("helperless republish must report converged (nil), got %v", err)
	}
}
