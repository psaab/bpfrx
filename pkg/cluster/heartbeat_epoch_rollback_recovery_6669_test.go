package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// #6669 fold — what the documented rollback recovery actually recovers from.
//
// pkg/cluster/README.md told operators that `systemctl restart xpfd` on the
// refusing node recovers from a peer rollback, unqualified. It does not, and
// the gap matters precisely against the attacker #6169 exists to stop.

// TestArchivedEpochReplayReArmsLatchAfterRestart_6169 is the executable
// statement of residual 5.
//
// The restart clears the floor, the latch and the ring TOGETHER, and arming the
// latch needs only an authenticated, orderable, ring-fresh epoch frame. Against
// that empty state a single ARCHIVED frame — captured while the peer still ran
// an epoch-capable build — satisfies all three: highEpoch is 0 so nothing is
// below the floor, and an empty ring calls its session never-seen. It re-arms
// the latch and the legitimately rolled-back peer is refused again.
//
// This is a CHARACTERIZATION test: it pins behaviour the code deliberately does
// not change (see the arming site in admitAuthedLocked for why a durable latch
// and a freshness test were both rejected), so that the documentation and the
// operator warning cannot drift back to claiming a bare restart is enough.
func TestArchivedEpochReplayReArmsLatchAfterRestart_6169(t *testing.T) {
	e := newLatchEnv(t)

	// 1. The peer runs an epoch-capable build. The attacker records it.
	const peerEpoch = uint64(9_500_000_000_000_000)
	archived := e.captureIncarnation(0x6690, peerEpoch, epochFramesPerIncarnation)
	e.liveRun(archived, "peer on an epoch-capable build")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	// 2. The peer is legitimately rolled back to a pre-#6169 build: fresh
	//    session, fresh counter, no epoch. Refused, as designed.
	rolledBack := e.captureIncarnation(0x66FF, 0, epochFramesPerIncarnation)
	for i, f := range rolledBack {
		if e.feed(f) {
			t.Fatalf("setup: rolled-back frame %d admitted; the latch is not engaging", i)
		}
	}

	// 3. The operator performs the documented recovery: restart xpfd here.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart must disarm the latch")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor after a daemon restart = %d, want 0", got)
	}

	// 4. The attacker replays ONE archived frame into that empty state.
	if !e.feed(archived[0]) {
		t.Fatal("an archived epoch frame was refused by a freshly restarted receiver; if this " +
			"now fails, the re-arm is closed and README residual 5 plus the arming-site comment " +
			"in admitAuthedLocked are stale")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the replayed archived frame did not re-arm the latch; README residual 5 and the " +
			"arming-site comment in admitAuthedLocked are stale and must be updated")
	}

	// 5. So the restart did NOT recover: the genuine rolled-back peer is refused
	//    again, and one replay per restart sustains that indefinitely.
	for i, f := range e.captureIncarnation(0x6701, 0, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("rolled-back frame %d admitted after the re-arm (frame %d)", i, i)
		}
	}

	// 6. The complete recovery is a PSK ROTATION FIRST: with a new key the
	//    archived frame no longer verifies, so it cannot reach the latch at all,
	//    and the restart then sticks.
	e.restartDaemon()
	e.key = []byte("rotated-cluster-shared-secret")
	if e.feed(archived[0]) {
		t.Fatal("an archived frame still verified after a PSK rotation — rotation is the only " +
			"thing that retires the attacker's capture, so this must fail")
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a frame that failed MAC verification must not arm the latch")
	}
	// The rolled-back peer, re-keyed with the operator, is accepted again.
	e.liveRun(e.captureIncarnation(0x6702, 0, epochFramesPerIncarnation),
		"rolled-back peer after rotating the PSK and restarting")
}

// TestEpochDowngradeWarningNamesTheCompleteRecovery_6169 is the fail-on-revert
// gate for the OPERATOR-facing half.
//
// The warning is the only place an operator learns what to do, and it used to
// say "restart xpfd on THIS node to clear the latch" — advice that loops
// forever while an archived frame is being replayed. It must name the PSK
// rotation, and name it FIRST.
//
// RED-on-revert: restore the old single-sentence recovery in
// Manager.NoteEpochDowngradeHeartbeat and this fails.
func TestEpochDowngradeWarningNamesTheCompleteRecovery_6169(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })

	NewManager(0, 42).NoteEpochDowngradeHeartbeat()

	out := buf.String()
	if out == "" {
		t.Fatal("NoteEpochDowngradeHeartbeat logged nothing; the refusal must be operator-visible")
	}
	for _, want := range []string{
		"rotate the control-link PSK",
		"BOTH nodes",
		"restart",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the epoch-downgrade warning does not mention %q.\n"+
				"An operator told only to restart will loop: a replayed archived epoch frame "+
				"re-arms the latch against the empty post-restart state, and only rotating the "+
				"PSK retires that capture.\n--- log ---\n%s", want, out)
		}
	}
	// The ORDER is the load-bearing part: rotate, then restart.
	if strings.Index(out, "rotate the control-link PSK") > strings.Index(out, "then restart") {
		t.Fatalf("the warning puts the restart before the rotation; restarting first leaves a "+
			"window for the replay to land\n--- log ---\n%s", out)
	}
}
