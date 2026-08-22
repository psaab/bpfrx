package cluster

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6724: a refine pass that could not PERSIST used to have no retry at all.
// The only re-run was at the next heartbeat (re)start, which is event-driven
// and unbounded — a daemon can run for days without one. Meanwhile a peer that
// latched a raise this node emitted but could not write refuses a concurrent
// incarnation, which has no other channel to learn of it.
//
// These pin the trigger and, just as importantly, WHEN IT MUST NOT FIRE.

// TestPersistOwedIsSetOnlyByFAULTS_6724 is the discriminator the whole trigger
// rests on: a pass that DECLINED to write on purpose must not be retried.
//
// The #6711 preserve branch is the case that makes a cheaper design wrong. It
// ends with the published epoch (this incarnation's wall-clock seed) different
// from what this incarnation has written (nothing), and it ends that way
// FOREVER, deliberately — so a trigger keyed on `published != wrote` would spin
// on a preserved file for the life of the process, re-reading state #7499 went
// out of its way to leave alone.
//
// FAIL-ON-REVERT: making refineBootEpochReporting return `persistOwed = true`
// from the preserve or heal branch reds the "declined" rows; dropping it from
// the write-failure branch reds the "faulted" rows.
func TestPersistOwedIsSetOnlyByFAULTS_6724(t *testing.T) {
	now := uint64(time.Now().UnixNano())

	cases := []struct {
		name string
		// prep returns the state-file path to refine against.
		prep     func(t *testing.T) string
		wantOwed bool
		why      string
	}{
		{
			name: "clean first write",
			prep: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "ha-boot-epoch")
			},
			wantOwed: false,
			why:      "the write succeeded; there is nothing to retry",
		},
		{
			name: "preserve branch (#6711)",
			prep: func(t *testing.T) string {
				// A value far enough ahead that this node declines to chain,
				// but inside the preserve band, so #7499 leaves it alone.
				ahead := now + bootEpochPreserveMaxSkew/2
				return writeEpochFile6724(t, ahead)
			},
			wantOwed: false,
			why: "the pass DECIDED not to write — retrying would spin on a file " +
				"#7499 preserves on purpose",
		},
		{
			name: "heal branch (value beyond the preserve band)",
			prep: func(t *testing.T) string {
				// Beyond the preserve band: garbage, healed by the ordinary
				// write below it.
				return writeEpochFile6724(t, now+bootEpochPreserveMaxSkew*4)
			},
			wantOwed: false,
			why:      "the heal path WRITES, so the persist is not owed",
		},
		{
			name: "unparseable file",
			prep: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "ha-boot-epoch")
				if err := os.WriteFile(p, []byte("not-a-number\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantOwed: false,
			why:      "a parse failure falls through to the write, which succeeds",
		},
		{
			name: "write fails (read-only directory)",
			prep: func(t *testing.T) string {
				dir := t.TempDir()
				sub := filepath.Join(dir, "state")
				if err := os.Mkdir(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				// Seed a value so the pass gets past the read and reaches the
				// write, then make the directory unwritable so the atomic
				// rename cannot land.
				p := filepath.Join(sub, "ha-boot-epoch")
				if err := os.WriteFile(p, []byte(strconv.FormatUint(now-1000, 10)+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(sub, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
				return p
			},
			wantOwed: true,
			why:      "the epoch is on the wire but not on disk — the case the trigger exists for",
		},
		{
			name: "lock unavailable",
			prep: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "ha-boot-epoch")
				orig := epochFlock
				epochFlock = func(int, int) error { return unix.EWOULDBLOCK }
				t.Cleanup(func() { epochFlock = orig })
				return p
			},
			wantOwed: true,
			why:      "the read-modify-write was SKIPPED entirely; nothing was decided",
		},
	}

	sawOwed, sawNotOwed := false, false
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.prep(t)
			var published atomic.Uint64
			published.Store(now)

			_, owed := refineBootEpochReporting(path, &published, 0)
			if owed != tc.wantOwed {
				t.Fatalf("persistOwed = %v, want %v — %s", owed, tc.wantOwed, tc.why)
			}
			if owed {
				sawOwed = true
			} else {
				sawNotOwed = true
			}
		})
	}
	// Both kinds must be present, or the table cannot tell a signal from a
	// constant.
	if !sawOwed || !sawNotOwed {
		t.Fatalf("the table produced owed=%v and not-owed=%v: it must contain BOTH to "+
			"show persistOwed is a discriminator and not a constant", sawOwed, sawNotOwed)
	}
}

// TestRetryIsANoOpWhenNothingIsOwed_6724 binds the GATE, which is the part that
// keeps this trigger from making the two-incarnation case worse.
//
// An unconditional periodic refine would make the leapfrog described in
// withEpochFileLock continuous: while two incarnations overlap, each pass
// raises above the other and rewrites the file, so both nodes would be refused
// by the peer for part of every period instead of one being refused until its
// next heartbeat restart. Alternating refusal is worse for HA than a stable
// one. The gate makes the trigger a no-op for two healthy incarnations, because
// neither ever owes a persist.
//
// FAIL-ON-REVERT: delete the `if !m.bootEpochPersistOwed.Load() { return }`
// guard and the file moves under a manager that owes nothing.
func TestRetryIsANoOpWhenNothingIsOwed_6724(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	m.initHeartbeatEpochState()
	awaitFirstRefine(t, m, "first refine")
	waitBootEpochIdle(t, m)

	settled := readPersistedEpoch(t, path)
	if settled == 0 {
		t.Fatal("nothing persisted after the first refine")
	}
	if m.bootEpochPersistOwed.Load() {
		t.Fatal("a clean first refine reported an owed persist")
	}

	// Every retry the sender loop would make in a minute of ticks.
	for i := 0; i < 8; i++ {
		m.retryOwedBootEpochPersist()
	}
	waitBootEpochIdle(t, m)

	if got := readPersistedEpoch(t, path); got != settled {
		t.Fatalf("the epoch file moved from %d to %d while nothing was owed — the "+
			"retry gate is not holding, so two overlapping incarnations would "+
			"leapfrog on every period (#6724)", settled, got)
	}
	if got := m.bootEpoch.Load(); got != settled {
		t.Fatalf("the published epoch moved from %d to %d while nothing was owed", settled, got)
	}
}

// TestRetryPersistsWhatTheFailedPassCouldNot_6724 is the trigger doing its job:
// a pass that could not write is retried, and once the write lands the value is
// the one that was already on the wire — not a ratchet.
//
// The "not a ratchet" half matters as much as the persist. The peer latched
// what this node EMITTED; a retry that wrote something higher would leave the
// file describing an epoch no peer ever saw.
func TestRetryPersistsWhatTheFailedPassCouldNot_6724(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "state")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	// Fail the write: an unwritable directory cannot take the atomic rename.
	if err := os.Chmod(sub, 0o555); err != nil {
		t.Fatal(err)
	}
	m.initHeartbeatEpochState()
	awaitFirstRefine(t, m, "the failing refine")
	waitBootEpochIdle(t, m)

	published := m.bootEpoch.Load()
	if published == 0 {
		t.Fatal("no epoch published")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the epoch file exists after a write that could not land: %v", err)
	}
	if !m.bootEpochPersistOwed.Load() {
		t.Fatal("a failed persist did not set the retry trigger — nothing would ever " +
			"re-attempt it, which is the #6724 gap")
	}

	// The fault clears (the operator frees the filesystem, remounts rw, ...).
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	m.retryOwedBootEpochPersist()
	waitBootEpochIdle(t, m)

	got := readPersistedEpoch(t, path)
	if got == 0 {
		t.Fatal("the retry did not persist anything")
	}
	if got != published {
		t.Fatalf("the retry persisted %d but this node had already emitted %d — a retry "+
			"must land the value the peer may have latched, not a new one", got, published)
	}
	if m.bootEpochPersistOwed.Load() {
		t.Fatal("the trigger is still armed after a successful retry; it would re-run forever")
	}
}

// TestPersistRetryTicksTracksTheInterval_6724 pins the tick derivation.
//
// It is a TICK count rather than a deadline on purpose: every clock available
// here is the wall clock, and a backward step in it is precisely the fault the
// boot epoch exists to survive — a deadline would suspend retries for the
// duration of the step that makes them matter.
func TestPersistRetryTicksTracksTheInterval_6724(t *testing.T) {
	cases := []struct {
		interval time.Duration
		want     int
	}{
		{200 * time.Millisecond, 150}, // the RETH default
		{30 * time.Second, 1},
		{time.Minute, 1}, // longer than the retry interval: every tick
		{0, 1},           // degenerate
		{-1 * time.Second, 1},
	}
	for _, tc := range cases {
		if got := bootEpochPersistRetryTicks(tc.interval); got != tc.want {
			t.Errorf("bootEpochPersistRetryTicks(%v) = %d, want %d", tc.interval, got, tc.want)
		}
		// The property behind the table: whatever the interval, the retry
		// cadence must never be zero (a zero would mean "never retry", which is
		// the pre-#6724 behaviour) and never exceed the configured interval.
		got := bootEpochPersistRetryTicks(tc.interval)
		if got < 1 {
			t.Errorf("bootEpochPersistRetryTicks(%v) = %d: a cadence below one tick "+
				"never fires", tc.interval, got)
		}
		if tc.interval > 0 && time.Duration(got)*tc.interval > bootEpochPersistRetryInterval+tc.interval {
			t.Errorf("bootEpochPersistRetryTicks(%v) = %d ticks = %v, which overshoots the "+
				"configured %v retry interval", tc.interval, got,
				time.Duration(got)*tc.interval, bootEpochPersistRetryInterval)
		}
	}
}

func writeEpochFile6724(t *testing.T, epoch uint64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ha-boot-epoch")
	if err := os.WriteFile(p, []byte(strconv.FormatUint(epoch, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
