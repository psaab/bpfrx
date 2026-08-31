package cluster

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// #7501: the older of two overlapping incarnations must not raise the boot
// epoch above a value a LIVE sibling wrote.
//
// WHY THIS NEEDS A REAL SECOND PROCESS. The existing characterization,
// TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669, drives both
// "incarnations" inside ONE test process, so they share a pid and a start time
// — sameEpochOwner is true and this guard correctly does not fire. That test
// therefore still passes unchanged and proves nothing about the fix. A guard
// keyed on process identity can only be exercised by a second process.
//
// `sleep` is used rather than a fork of the test binary because the guard reads
// nothing but /proc/<pid>/stat: any live pid that is not us is a faithful stand
// -in for a sibling xpfd, and spawning the test binary again would drag its
// TestMain and its flags into the fixture for no added fidelity.
func liveSiblingOwner7501(t *testing.T) (epochOwner, func()) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a helper process: %v", err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	tick, ok := processStartTick(cmd.Process.Pid)
	if !ok {
		stop()
		t.Skip("cannot read /proc/<pid>/stat for the helper; /proc is not available here")
	}
	boot := localBootIncarnation()
	if !boot.known() {
		stop()
		t.Skip("no boot id available; the identity this guard keys on cannot be formed")
	}
	return epochOwner{pid: cmd.Process.Pid, startTick: tick, boot: boot}, stop
}

// THE SCHEDULE FROM THE ISSUE, asserted end to end: B (newer) persists `b`; A
// (older) reaches the lock second and must NOT raise itself above it; the peer
// then admits B, the survivor.
func TestOlderIncarnationDoesNotRaiseAboveALiveSibling_7501(t *testing.T) {
	sibling, stop := liveSiblingOwner7501(t)
	defer stop()

	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")

	// B, the NEWER incarnation, has persisted its epoch and is still running.
	b := uint64(time.Now().UnixNano())
	if err := os.WriteFile(path, []byte(formatEpoch7501(b)), 0o644); err != nil {
		t.Fatalf("seed epoch file: %v", err)
	}
	if err := writeEpochOwner(path, sibling); err != nil {
		t.Fatalf("seed owner sidecar: %v", err)
	}

	// A, the OLDER incarnation, published a lower seed and only now refines.
	var pubA atomic.Uint64
	pubA.Store(b - uint64(time.Second))
	before := pubA.Load()
	refineBootEpoch(path, &pubA, 0)

	if got := pubA.Load(); got != before {
		t.Fatalf("the older incarnation raised itself to %d over a LIVE sibling's %d. "+
			"That makes the exiting process the peer's floor and gets the survivor "+
			"refused for the life of its process (#7501).", got, b)
	}
	if got := readPersistedEpoch(t, path); got != b {
		t.Fatalf("the file moved to %d; the live sibling's value must be left alone", got)
	}

	// CRITERION 1: the survivor is admissible. Asserted on the peer's own
	// admission path rather than on the epoch numbers, because "below the
	// floor" is a statement about what admitAuthed does.
	var peer heartbeatAuthState
	// A's frame first, and NOT redundant: it is what SETS the peer's floor. B
	// clearing a floor that nothing established would be vacuous — the
	// assertion below has to mean "B is admitted over a floor A already put
	// there", which is the shape of the lockout. Do not delete this as setup
	// noise.
	if ok, _ := peer.admitAuthed(true, pubA.Load(), 0xA501, 1); !ok {
		t.Fatal("the peer refused the older incarnation's frame, so no floor was " +
			"established and the assertion below would prove nothing")
	}
	if ok, _ := peer.admitAuthed(true, b, 0xB501, 1); !ok {
		t.Fatalf("the peer refused the SURVIVOR at %d under floor %d — the #7501 lockout "+
			"is still reachable", b, peer.peerEpochFloor())
	}
}

// THE CONTROL, and the cell that makes the one above mean something: with the
// sibling DEAD the same file is a predecessor's, and refinement must raise
// exactly as it always did. Without this, a guard that simply never raised
// would pass the test above — and never raising is the #6711 lockout.
func TestDeadPredecessorStillRaises_7501(t *testing.T) {
	sibling, stop := liveSiblingOwner7501(t)
	stop() // it is a PREDECESSOR now, not a sibling.
	// Give the kernel a moment to reap, so /proc/<pid> is gone rather than a
	// zombie whose stat still reads.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := processStartTick(sibling.pid); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, stillThere := processStartTick(sibling.pid); stillThere {
		t.Skip("the helper pid is still readable in /proc; cannot stage a dead predecessor")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")
	prev := uint64(time.Now().UnixNano())
	if err := os.WriteFile(path, []byte(formatEpoch7501(prev)), 0o644); err != nil {
		t.Fatalf("seed epoch file: %v", err)
	}
	if err := writeEpochOwner(path, sibling); err != nil {
		t.Fatalf("seed owner sidecar: %v", err)
	}

	var pub atomic.Uint64
	pub.Store(prev - uint64(time.Second))
	refineBootEpoch(path, &pub, 0)

	if got := pub.Load(); got <= prev {
		t.Fatalf("published %d after refining against a DEAD predecessor's %d — refinement "+
			"must still chain above it, or a backward clock step is no longer carried "+
			"across a restart (#6711)", got, prev)
	}
}

// CRITERION 2, and the reason a sidecar was chosen over a lock: a node that
// cannot form or read the identity still refines exactly as before. The guard
// may only ever SUBTRACT a raise, so being unable to evaluate it costs the
// existing semantics and nothing more.
func TestUnknownOwnerFallsBackToRaising_7501(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sidecar string
		write   bool
	}{
		{"no sidecar at all (a file from an older binary)", "", false},
		{"unparseable sidecar", "garbage\n", true},
		{"sidecar with a bad boot id", "1 2 nothex\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ha-boot-epoch")
			prev := uint64(time.Now().UnixNano())
			if err := os.WriteFile(path, []byte(formatEpoch7501(prev)), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if tc.write {
				if err := os.WriteFile(epochOwnerSidecarPath(path), []byte(tc.sidecar), 0o644); err != nil {
					t.Fatalf("seed sidecar: %v", err)
				}
			}
			var pub atomic.Uint64
			pub.Store(prev - uint64(time.Second))
			refineBootEpoch(path, &pub, 0)
			if got := pub.Load(); got <= prev {
				t.Errorf("published %d against persisted %d — an unknown owner must fall "+
					"back to the pre-#7501 behaviour of raising, not to declining", got, prev)
			}
		})
	}
}

func formatEpoch7501(v uint64) string {
	return string(append([]byte(uint64String7501(v)), '\n'))
}

func uint64String7501(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
