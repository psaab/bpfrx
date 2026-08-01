package cluster

import (
	"net"
	"strings"
	"testing"
)

// #6669 fold round 2 — HeartbeatStats must report the epoch state at its real
// SCOPE.
//
// The downgrade latch and its counters live on Manager.hbAuth so a heartbeat
// restart or a VRF rebind cannot reset them (#5086/#6642). HeartbeatStats read
// them through the installed receiver and gated them on `receiver != nil`, so
// during every window with no receiver — StopHeartbeat, and the whole bind-retry
// span of a failed RestartHeartbeat (up to ~5s) — it reported the latch CLEAR
// while the process-scoped state was in fact ARMED.
//
// RETAINED, not "armed and refusing", which an earlier revision of this header
// said: with no receiver installed nothing is reading frames, so nothing is
// being refused during the gap. What is asserted below is the retention and what
// status RENDERS off it, not enforcement. Enforcement while a receiver IS
// installed is TestHeartbeatEpochlessReplayRefusedOnceLatched_6169's job. The
// gap matters because the latch comes back armed the instant a receiver does,
// with no re-arming heartbeat needed.
//
// That is not cosmetic: epochlessExposureNote reads PeerEpochLatched, so status
// flipped back to telling the operator "replay protection is ring-only; rotate
// the control-link PSK" at a moment when the latch was in fact armed.

// TestEpochLatchSurvivesReceiverGapInStats_6669 is the fail-on-revert gate.
//
// RED-on-revert: move the three epoch assignments in Manager.HeartbeatStats
// back inside the `if receiver != nil` block and both halves fail.
func TestEpochLatchSurvivesReceiverGapInStats_6669(t *testing.T) {
	e := newLatchEnv(t)

	// A not-yet-upgraded peer first, so EpochlessAdmitted is non-zero and the
	// exposure note has something to describe.
	const epochless = 4
	e.liveRun(e.captureIncarnation(0xB001, 0, epochless), "not-yet-upgraded peer")
	// Then it upgrades: the latch arms off real traffic.
	e.liveRun(e.captureIncarnation(0xB002, 9_600_000_000_000_000, 2), "upgraded peer")
	// And one epoch-less frame is refused, so the rejection counter moves too.
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xB003, 1, 0)) {
		t.Fatal("setup: an epoch-less frame must be refused once the latch is armed")
	}

	before := e.m.HeartbeatStats()
	if !before.PeerEpochLatched {
		t.Fatal("setup: the latch must be armed while the receiver is installed")
	}
	if before.EpochlessAdmitted != epochless || before.EpochDowngradeRejected != 1 {
		t.Fatalf("setup: counters = %d admitted / %d rejected, want %d / 1",
			before.EpochlessAdmitted, before.EpochDowngradeRejected, epochless)
	}

	// THE GAP. StopHeartbeat is the production path; a failed RestartHeartbeat
	// bind-retry leaves the same state (hbReceiver nil, hbAuth untouched) for up
	// to ~5s.
	//
	// The shared env builds receivers with a nil conn because it drives the read
	// path directly; heartbeatReceiver.stop closes the conn, so give this one a
	// real socket and take the production path rather than reaching into
	// Manager.hbReceiver by hand.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e.r.conn = conn
	e.m.StopHeartbeat()
	if e.m.HeartbeatRunning() {
		t.Fatal("setup: StopHeartbeat must clear the installed receiver")
	}
	if !e.m.hbAuth.peerEpochLatched() {
		t.Fatal("setup: stopping the heartbeat must NOT disarm the Manager-owned latch (#5086/#6642)")
	}

	during := e.m.HeartbeatStats()
	if !during.PeerEpochLatched {
		t.Fatal("HeartbeatStats reports PeerEpochLatched=false with no receiver installed, but " +
			"the latch lives on Manager.hbAuth and is still armed. The report must track the " +
			"process state, not whether a receiver goroutine happens to be installed — a failed " +
			"RestartHeartbeat holds this window open for ~5s of bind retries.")
	}
	if during.EpochlessAdmitted != epochless {
		t.Fatalf("EpochlessAdmitted = %d during the receiver gap, want %d — the counter is on "+
			"Manager.hbAuth and does not reset with the receiver", during.EpochlessAdmitted, epochless)
	}
	if during.EpochDowngradeRejected != 1 {
		t.Fatalf("EpochDowngradeRejected = %d during the receiver gap, want 1", during.EpochDowngradeRejected)
	}

	// The OPERATOR-facing consequence, on every rendered surface: with the latch
	// misreported as clear, status re-ran the "you are exposed, rotate the PSK"
	// advice about a node whose latch was in fact armed.
	for name, render := range map[string]func() string{
		"FormatInformation":            e.m.FormatInformation,
		"FormatStatistics":             e.m.FormatStatistics,
		"FormatControlPlaneStatistics": e.m.FormatControlPlaneStatistics,
	} {
		t.Run(name+"_during_receiver_gap", func(t *testing.T) {
			out := render()
			if strings.Contains(out, "rotate the control-link PSK") {
				t.Fatalf("%s reports LIVE epoch-less exposure during a heartbeat restart gap, "+
					"though the downgrade latch is still armed and comes back with the next "+
					"receiver\n--- output ---\n%s", name, out)
			}
			if !strings.Contains(out, "count is historical") {
				t.Fatalf("%s does not mark the epoch-less count historical during the gap\n"+
					"--- output ---\n%s", name, out)
			}
		})
	}

	// Reinstalling a receiver (what RestartHeartbeat does once the bind
	// succeeds) changes nothing, which is the point: the state never moved.
	e.restartHeartbeat()
	after := e.m.HeartbeatStats()
	if !after.PeerEpochLatched || after.EpochlessAdmitted != epochless || after.EpochDowngradeRejected != 1 {
		t.Fatalf("after reinstalling a receiver: latched=%v admitted=%d rejected=%d, "+
			"want true / %d / 1", after.PeerEpochLatched, after.EpochlessAdmitted,
			after.EpochDowngradeRejected, epochless)
	}
}
