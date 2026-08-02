package cluster

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// #6669 fold round 8 — the boot-epoch state lock does NOT order incarnations,
// and the recoverable half of that.
//
// withEpochFileLock serializes read-modify-write across processes, and its
// rationale used to claim that this stops two overlapping incarnations
// publishing epochs "that are not strictly ordered". It does not: it serializes
// by LOCK ACQUISITION, and heartbeatBootEpoch deliberately publishes the
// wall-clock seed and starts emitting BEFORE its worker reaches the lock, so the
// two orders are independent.
//
// These pin both halves — the mis-ordering itself (characterization, so the
// comment cannot drift back), and the recovery that keeps it from lasting for
// the life of the process.

// waitBootEpochIdle joins whatever refine worker is in flight. startBootEpochRefine
// takes bootEpochRefining on the CALLER's goroutine before spawning the worker,
// so a caller that has just requested a refine cannot observe idle too early.
//
// It waits on the PENDING bit too. A coalesced request normally runs with
// bootEpochRefining still held, but the worker's hand-back path releases the
// flag and re-claims it, so there is an instant where the flag is clear and a
// pass is still owed. Polling only the flag could observe idle inside it.
func waitBootEpochIdle(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for m.bootEpochRefining.Load() || m.bootEpochRefinePending.Load() {
		if time.Now().After(deadline) {
			t.Fatal("a boot-epoch refine worker never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

// readPersistedEpoch reads the boot-epoch state file.
func readPersistedEpoch(t *testing.T, path string) uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted epoch: %v", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatalf("parse persisted epoch %q: %v", data, err)
	}
	return n
}

// keyedManagerAt installs a control-link PSK so the epoch path engages, and
// points the package path var at a per-test file.
func keyedEpochManager(t *testing.T, path string) *Manager {
	t.Helper()
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = []byte("cluster-shared-secret")
	m.mu.Unlock()
	return m
}

// TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669 is the executable
// statement of what the lock does and does not buy.
//
// The schedule is the one SO_REUSEPORT makes reachable — two overlapping xpfd
// instances, no pidfile — with the OLDER incarnation's refine worker delayed
// past the newer one's:
//
//   - B (newer, higher seed) publishes, locks first, persists `b`;
//   - A (older, lower seed) locks second, reads `b`, and raises ITSELF to `b+1`,
//     because from inside refineBootEpoch a concurrent incarnation's value and a
//     predecessor's value after a backward clock step are the same file;
//   - the peer latches `b+1` from the OLDER incarnation and refuses the NEWER
//     one, which is the survivor.
//
// The first half is a CHARACTERIZATION: it is not fixed here, and cannot be with
// this file alone (see withEpochFileLock). The second half IS the fix — B can
// re-refine at its next heartbeat start and climb back above the file, instead
// of being pinned below the peer's floor for the life of the process by a
// one-shot sync.Once.
//
// RED-on-revert: drop the `m.bootEpoch.Load() != 0 -> m.refreshBootEpoch()`
// branch in initHeartbeatEpochState (so every call funnels back through
// heartbeatBootEpoch's sync.Once) and the recovery assertion below fails with
// B still parked at its original epoch.
func TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	mB := keyedEpochManager(t, path)

	// --- B: the NEWER incarnation. It reaches the lock first and persists.
	mB.initHeartbeatEpochState()
	select {
	case <-mB.bootEpochReady:
	case <-time.After(5 * time.Second):
		t.Fatal("B's first refine never completed")
	}
	b := mB.heartbeatBootEpoch()
	if b == 0 {
		t.Fatal("B published no epoch")
	}
	if got := readPersistedEpoch(t, path); got != b {
		t.Fatalf("persisted %d after B's first refine, want %d", got, b)
	}

	// --- A: an OLDER incarnation (seed one second behind B's) whose worker was
	// delayed and only now reaches the lock.
	var pubA atomic.Uint64
	pubA.Store(b - uint64(time.Second))
	refineBootEpoch(path, &pubA, 0)

	epochA := pubA.Load()
	if epochA <= b {
		t.Fatalf("A published %d, which does not exceed B's %d — the schedule this test "+
			"describes did not happen, so the assertions below prove nothing", epochA, b)
	}

	// --- The peer orders them by epoch alone, so the OLDER one wins and the
	// survivor is refused.
	var peer heartbeatAuthState
	if !peer.admitAuthed(true, epochA, 0xA669, 1) {
		t.Fatal("the peer refused A's frame")
	}
	if peer.admitAuthed(true, b, 0xB669, 1) {
		t.Fatalf("the peer admitted B at %d under a floor of %d; the mis-ordering this test "+
			"characterizes is not reachable and withEpochFileLock's ordering note is stale",
			b, peer.peerEpochFloor())
	}

	// --- A exits. B's next heartbeat start (a VRF rebind, an HA comms restart,
	// or any StartHeartbeat) re-runs refinement and lifts it back above the file.
	mB.initHeartbeatEpochState()
	waitBootEpochIdle(t, mB)

	recovered := mB.heartbeatBootEpoch()
	if recovered <= epochA {
		t.Fatalf("B is still at %d after a heartbeat restart, at or below the %d the older "+
			"incarnation left in the file. Refinement behind sync.Once alone never re-reads, "+
			"so the peer refuses this node until a full daemon restart.", recovered, epochA)
	}
	if !peer.admitAuthed(true, recovered, 0xB66A, 1) {
		t.Fatalf("B at %d is still refused under floor %d after re-refinement",
			recovered, peer.peerEpochFloor())
	}
	if got := readPersistedEpoch(t, path); got != recovered {
		t.Fatalf("persisted %d after B's re-refine, want %d", got, recovered)
	}
}

// TestBootEpochRefreshIsIdempotent_6669 is the other half of making refinement
// re-runnable: on a healthy node it must be a no-op.
//
// Refinement raises whenever the persisted value is at or above what we
// published — that is how a backward clock step is carried across a restart —
// and after a successful persist the file holds OUR OWN value. So a re-run meets
// that condition trivially and would ratchet the epoch by one on every heartbeat
// start, rewriting the file each time, if nothing distinguished "the file moved
// under me" from "the file holds what I wrote".
//
// RED-on-revert: delete the `prev == lastWrote` early return in refineBootEpoch
// and the epoch climbs by one per restart here.
func TestBootEpochRefreshIsIdempotent_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	m.initHeartbeatEpochState()
	select {
	case <-m.bootEpochReady:
	case <-time.After(5 * time.Second):
		t.Fatal("the first refine never completed")
	}
	first := m.heartbeatBootEpoch()
	firstFile := readPersistedEpoch(t, path)

	for i := 0; i < 5; i++ {
		m.initHeartbeatEpochState()
		waitBootEpochIdle(t, m)
		if got := m.heartbeatBootEpoch(); got != first {
			t.Fatalf("restart %d moved the published epoch from %d to %d; a healthy node's "+
				"routine heartbeat restarts must not ratchet it", i, first, got)
		}
		if got := readPersistedEpoch(t, path); got != firstFile {
			t.Fatalf("restart %d rewrote the state file from %d to %d", i, firstFile, got)
		}
	}
}

// TestBootEpochSeedResolutionIsFinerThanARestart_6669 pins the seed's own
// granularity, which nothing else in the package did.
//
// pkg/cluster/README.md states the resolution as a design property ("Resolution
// is NANOSECONDS deliberately: a coarser seed hands two incarnations starting in
// the same interval identical values"), and it carries real weight in exactly
// the case persistence cannot help: two back-to-back incarnations whose writes
// do not land — a wedged or read-only store — are ordered by the seed alone.
// TestBootEpochMonotonic_6169/restarts_strictly_increase looks like the guard
// for it and is not: every iteration there persists, so `persisted+1` supplies
// strictness whenever the seed does not. Verified by rounding bootEpochSeed up
// to whole seconds — the whole package stayed green.
//
// The bar is a granularity FINER THAN A MILLISECOND rather than exactly one
// nanosecond, because that is what can be measured without flaking: consecutive
// time.Now() calls are tens of nanoseconds apart, so the smallest positive gap
// over many samples lands far below a millisecond, while any seed quantised to
// milliseconds or coarser can only produce gaps of 0 or >= 1ms. A millisecond is
// also the operationally meaningful line — two daemon starts inside one
// millisecond is a supervisor restart loop, not a contrived case.
//
// RED-on-revert: quantise bootEpochSeed to any unit >= 1ms.
func TestBootEpochSeedResolutionIsFinerThanARestart_6669(t *testing.T) {
	const samples = 2000
	seeds := make([]uint64, 0, samples)
	for i := 0; i < samples; i++ {
		seeds = append(seeds, bootEpochSeed())
	}

	smallest := uint64(0)
	for i := 1; i < len(seeds); i++ {
		if seeds[i] < seeds[i-1] {
			t.Fatalf("bootEpochSeed went BACKWARDS between samples %d and %d (%d -> %d)",
				i-1, i, seeds[i-1], seeds[i])
		}
		gap := seeds[i] - seeds[i-1]
		if gap == 0 {
			continue
		}
		if smallest == 0 || gap < smallest {
			smallest = gap
		}
	}
	if smallest == 0 {
		t.Fatalf("all %d seeds were identical — bootEpochSeed cannot distinguish two "+
			"incarnations at all", samples)
	}
	if smallest >= uint64(time.Millisecond) {
		t.Fatalf("the smallest positive gap between %d consecutive bootEpochSeed values is %v. "+
			"The seed is quantised at or above a millisecond, so two incarnations starting in "+
			"the same tick get the SAME epoch — and when persistence is unavailable that is the "+
			"only term ordering them.", samples, time.Duration(smallest))
	}
}

// TestBootEpochRefreshCarriesABackwardClockStep_6669 guards the property the
// idempotence rule must NOT break: a genuine predecessor value in the file is
// still chained from on a first pass.
//
// The `prev == lastWrote` early return keys on this incarnation's OWN persist
// watermark, which is 0 until it writes. A rule that keyed on "the file equals
// what I published" instead would skip exactly the backward-clock-step case
// persistence exists for.
func TestBootEpochRefreshCarriesABackwardClockStep_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	ahead := uint64(time.Now().Add(30 * time.Minute).UnixNano())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(ahead, 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var published atomic.Uint64
	published.Store(uint64(time.Now().UnixNano()))

	wrote := refineBootEpoch(path, &published, 0)
	if got := published.Load(); got != ahead+1 {
		t.Fatalf("refined epoch = %d, want %d (persisted+1 must dominate a backward clock step)",
			got, ahead+1)
	}
	if wrote != ahead+1 {
		t.Fatalf("returned watermark = %d, want %d — the caller would re-chain from its own "+
			"write on the next pass", wrote, ahead+1)
	}
	// And a second pass with that watermark leaves everything alone.
	if got := refineBootEpoch(path, &published, wrote); got != wrote {
		t.Fatalf("second pass returned watermark %d, want %d", got, wrote)
	}
	if got := published.Load(); got != ahead+1 {
		t.Fatalf("second pass moved the epoch to %d, want %d", got, ahead+1)
	}
}
