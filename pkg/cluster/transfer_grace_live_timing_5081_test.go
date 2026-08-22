package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// hbTimingManager builds a manager whose RUNNING heartbeat uses
// liveInterval/liveThreshold while the committed configuration says
// desiredInterval/desiredThreshold — the state a `set chassis cluster
// heartbeat-interval` commit leaves behind, because nothing restarts the
// heartbeat for a timing change (#5081).
func hbTimingManager(t *testing.T, liveInterval time.Duration, liveThreshold int, desiredIntervalMS, desiredThreshold int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0"
	cfg.HeartbeatInterval = desiredIntervalMS
	cfg.HeartbeatThreshold = desiredThreshold
	m.UpdateConfig(cfg)
	if liveThreshold > 0 {
		// newHeartbeatReceiver is the production constructor; StartHeartbeat
		// calls it with the values read out of m at that instant.
		m.mu.Lock()
		m.hbReceiver = newHeartbeatReceiver(m, nil, liveThreshold, liveInterval)
		m.mu.Unlock()
	}
	return m
}

// A commit that SHORTENS the configured heartbeat timing must not shrink the
// transfer-commit grace below the window the RUNNING receiver still uses to
// declare the peer dead. Live 5x1000ms => dead peer at 5s, grace must be
// 2*5*1000ms+5s = 15s. Sizing from the desired 3x100ms yields 0.6s+5s = 5.6s,
// floored to the 10s minimum — which expires before a 5s-armed timeout can be
// re-armed by the next transfer step, so the peer-timeout suppression the
// grace exists for lapses mid-transfer.
func TestTransferCommitGrace_SizedFromLiveHeartbeatTiming_5081(t *testing.T) {
	m := hbTimingManager(t, time.Second, 5, 100, 3)

	m.mu.Lock()
	got := m.transferCommitGracePeriodLocked()
	m.mu.Unlock()

	want := 2*5*time.Second + transferCommitHeartbeatSlack
	if got != want {
		t.Fatalf("transfer-commit grace = %v, want %v (live 5x1s dead-peer window, NOT the desired 3x100ms)", got, want)
	}
	if got == minTransferCommitGracePeriod {
		t.Fatalf("grace collapsed to the %v floor — that is the desired-timing answer, not the live one", minTransferCommitGracePeriod)
	}
}

// With no heartbeat running there is no live cadence, so the desired values
// are the answer and the grace is unchanged from pre-#5081.
func TestTransferCommitGrace_NoHeartbeatFallsBackToDesired_5081(t *testing.T) {
	m := hbTimingManager(t, 0, 0, 1000, 5)

	m.mu.Lock()
	got := m.transferCommitGracePeriodLocked()
	m.mu.Unlock()

	want := 2*5*time.Second + transferCommitHeartbeatSlack
	if got != want {
		t.Fatalf("grace with no running heartbeat = %v, want the desired-sized %v", got, want)
	}
}

// FormatInformation must report the timing the wire is using, and must name
// the committed-but-unapplied values rather than passing them off as live.
func TestFormatInformation_ReportsLiveHeartbeatTiming_5081(t *testing.T) {
	m := hbTimingManager(t, time.Second, 5, 100, 3)

	out := m.FormatInformation()

	if !strings.Contains(out, "Heartbeat interval: 1000 ms") {
		t.Errorf("status does not report the LIVE interval (1000 ms):\n%s", out)
	}
	if !strings.Contains(out, "Heartbeat threshold: 5") {
		t.Errorf("status does not report the LIVE threshold (5):\n%s", out)
	}
	if strings.Contains(out, "Heartbeat interval: 100 ms") {
		t.Errorf("status reports the DESIRED interval as if it were live:\n%s", out)
	}
	if !strings.Contains(out, "Heartbeat pending restart: configured interval 100 ms, threshold 3") {
		t.Errorf("status does not disclose the committed-but-unapplied timing:\n%s", out)
	}
}

// When live and desired agree — every steady state, and every standalone or
// pre-bringup manager — the render must be byte-identical to pre-#5081: no
// pending line at all.
func TestFormatInformation_NoPendingLineWhenTimingApplied_5081(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *Manager
	}{
		{"heartbeat running with the committed timing", hbTimingManager(t, 200*time.Millisecond, 5, 200, 5)},
		{"no heartbeat running", hbTimingManager(t, 0, 0, 200, 5)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.m.FormatInformation()
			if strings.Contains(out, "Heartbeat pending restart") {
				t.Errorf("unexpected pending-restart line when live == desired:\n%s", out)
			}
			if !strings.Contains(out, "Heartbeat interval: 200 ms") || !strings.Contains(out, "Heartbeat threshold: 5") {
				t.Errorf("status lost the heartbeat timing lines:\n%s", out)
			}
		})
	}
}

var _ = config.ClusterConfig{}
