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

// #6669 fold — boundary and precondition tests for the #6169 boot epoch.
//
// These cover two findings an independent correctness review raised against
// heartbeat_epoch.go: refinement validated the value it READ but published the
// value + 1 without re-checking it, and the README claimed a bad persisted
// epoch "heals" without stating the clock precondition that makes that true.

// withPinnedEpochClock pins the instant refineBootEpoch validates against.
// Both boundaries below exist only for one specific `now`, so the real clock
// cannot hit them reliably.
func withPinnedEpochClock(t *testing.T, now int64) {
	t.Helper()
	orig := epochNowNanos
	epochNowNanos = func() int64 { return now }
	t.Cleanup(func() { epochNowNanos = orig })
}

// writeEpochFile seeds the persisted boot epoch.
func writeEpochFile(t *testing.T, path string, v uint64) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strconv.FormatUint(v, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readEpochFile reads it back.
func readEpochFile(t *testing.T, path string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file unreadable: %v", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		t.Fatalf("state file unparseable (%q): %v", raw, err)
	}
	return n
}

// TestRefinementValidatesThePublishedEpochNotJustThePersistedOne_6169 is the
// fail-on-revert gate for the validate-before-increment ordering defect.
//
// refineBootEpoch chains `prev+1`, but it used to validate only `prev`. A
// persisted value one below a bound therefore passed the load check and then
// published a candidate the receiver refuses — the sender emits an epoch that
// is, by construction, unusable, and every frame it signs is dropped. Not
// overflow: ordering.
//
// Both bounds are exercised, because they escape differently.
//
// RED-on-revert: drop the `|| !epochOrderable(n+1, now)` disjunct in
// refineBootEpoch and both subtests fail — the published epoch becomes exactly
// epochPlausibleMax / one nanosecond past the forward bound.
func TestRefinementValidatesThePublishedEpochNotJustThePersistedOne_6169(t *testing.T) {
	// The receiver's own clock, used to judge what it would accept from us.
	const receiverNow = int64(1_800_000_000_000_000_000) // ~2027, credible

	t.Run("absolute_band", func(t *testing.T) {
		// A pre-2020 local clock skips the forward bound entirely, so only the
		// absolute year-2200 band applies — and epochPlausibleMax-1 is inside
		// it. Chaining publishes exactly epochPlausibleMax, which
		// epochUsableAsFloor refuses on a strict `<`.
		withPinnedEpochClock(t, 1_000_000_000) // 1970: not credible
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		prev := epochPlausibleMax - 1
		writeEpochFile(t, path, prev)

		var published atomic.Uint64
		seed := uint64(1_700_000_000_000_000_000)
		published.Store(seed)
		refineBootEpoch(path, &published)

		got := published.Load()
		if got == epochPlausibleMax {
			t.Fatalf("published epoch = %d == epochPlausibleMax: refinement chained to a value "+
				"epochUsableAsFloor refuses on a strict `<`, so EVERY frame this node signs is "+
				"dropped by the peer. prev was validated; prev+1 was not", got)
		}
		if !epochUsableAsFloor(got) {
			t.Fatalf("published epoch %d is not usable as a peer floor at all", got)
		}
		// Declining to chain keeps the wall-clock seed, exactly as an
		// out-of-range `prev` already did, and heals the file.
		if got != seed {
			t.Fatalf("published epoch = %d, want the wall-clock seed %d", got, seed)
		}
		if onDisk := readEpochFile(t, path); onDisk != seed {
			t.Fatalf("persisted %d, want the healed wall-clock seed %d", onDisk, seed)
		}
	})

	t.Run("forward_bound", func(t *testing.T) {
		// A credible local clock with `prev` sitting EXACTLY on the forward
		// bound: `prev` passes (the bound is `>`), `prev+1` does not.
		const localNow = receiverNow
		withPinnedEpochClock(t, localNow)
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		prev := uint64(localNow) + bootEpochMaxSkew
		writeEpochFile(t, path, prev)

		// Pre-condition on the fixture itself: prev is admissible, prev+1 is not.
		if !epochOrderable(prev, localNow) {
			t.Fatalf("fixture broken: prev %d must be orderable at now %d", prev, localNow)
		}
		if epochOrderable(prev+1, localNow) {
			t.Fatalf("fixture broken: prev+1 %d must NOT be orderable at now %d", prev+1, localNow)
		}

		var published atomic.Uint64
		seed := uint64(localNow)
		published.Store(seed)
		refineBootEpoch(path, &published)

		got := published.Load()
		if got == prev+1 {
			t.Fatalf("published epoch = %d, one nanosecond past the forward bound a receiver at "+
				"the same instant applies: the raise path refuses it, so this node cannot "+
				"establish a floor at all", got)
		}
		if !epochOrderable(got, receiverNow) {
			t.Fatalf("published epoch %d is not orderable by a receiver at %d", got, receiverNow)
		}
		if got != seed {
			t.Fatalf("published epoch = %d, want the wall-clock seed %d", got, seed)
		}
	})

	t.Run("in_range_predecessor_still_chains", func(t *testing.T) {
		// NEGATIVE CONTROL. The candidate check must not break the case
		// persistence exists for: a value comfortably inside both bounds is
		// still chained from after a backward clock step.
		const localNow = receiverNow
		withPinnedEpochClock(t, localNow)
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		prev := uint64(localNow) + bootEpochMaxSkew/2
		writeEpochFile(t, path, prev)

		var published atomic.Uint64
		published.Store(uint64(localNow)) // the clock stepped back below prev
		refineBootEpoch(path, &published)

		if got := published.Load(); got != prev+1 {
			t.Fatalf("published epoch = %d, want %d — a value inside both bounds must still "+
				"dominate a backward clock step", got, prev+1)
		}
		if onDisk := readEpochFile(t, path); onDisk != prev+1 {
			t.Fatalf("persisted %d, want %d", onDisk, prev+1)
		}
	})
}

// TestPersistedEpochHealsOnlyWhenClockCredible_6169 pins the PRECONDITION on
// the self-healing claim, in both directions.
//
// pkg/cluster/README.md used to say a node written under a bad clock "heals
// instead of being stranded", unqualified. It heals only when the LOCAL clock
// is credible at the moment refinement loads the file: below
// epochClockSaneFloor the forward bound is skipped, so a wrong-but-below-2200
// value passes and is chained from. That skip is deliberate — under a dead RTC
// a legitimate previous epoch and a corrupt future one are indistinguishable,
// both ~56 years "ahead" of a 1970 clock — so this test documents a residual
// rather than a bug to fix. Refinement runs once per Manager, so a later NTP
// correction does not re-validate the value.
//
// RED-on-revert for the DOCUMENTATION: if the healing precondition is ever
// removed from epochWithinForwardBound / the README, this test still pins the
// behaviour those texts must describe.
func TestPersistedEpochHealsOnlyWhenClockCredible_6169(t *testing.T) {
	// Year ~2191: wrong by any measure, but below the absolute year-2200 band,
	// so only the forward bound can catch it.
	const bad = uint64(7_000_000_000_000_000_000)
	if !epochUsableAsFloor(bad) {
		t.Fatalf("fixture broken: %d must be inside the absolute plausibility band", bad)
	}

	t.Run("credible_clock_heals", func(t *testing.T) {
		const localNow = int64(1_800_000_000_000_000_000) // ~2027
		withPinnedEpochClock(t, localNow)
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		writeEpochFile(t, path, bad)

		var published atomic.Uint64
		seed := uint64(localNow)
		published.Store(seed)
		refineBootEpoch(path, &published)

		if got := published.Load(); got != seed {
			t.Fatalf("published epoch = %d, want the wall-clock seed %d — a credible clock must "+
				"reject the bad persisted value", got, seed)
		}
		if onDisk := readEpochFile(t, path); onDisk != seed {
			t.Fatalf("state file still holds %d, want the healed %d", onDisk, seed)
		}
	})

	t.Run("uncredible_clock_does_not_heal", func(t *testing.T) {
		// A dead RTC: xpfd starts before NTP, near the Unix epoch.
		const localNow = int64(1_000_000_000) // 1970
		if uint64(localNow) >= epochClockSaneFloor {
			t.Fatalf("fixture broken: %d must be below epochClockSaneFloor", localNow)
		}
		withPinnedEpochClock(t, localNow)
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		writeEpochFile(t, path, bad)

		var published atomic.Uint64
		published.Store(uint64(localNow))
		refineBootEpoch(path, &published)

		got := published.Load()
		if got != bad+1 {
			t.Fatalf("published epoch = %d, want %d.\nThis test documents the RESIDUAL: below "+
				"epochClockSaneFloor the forward bound is skipped, so the bad value IS chained "+
				"from. If this now heals, the precondition text in epochWithinForwardBound and "+
				"pkg/cluster/README.md residual 6 is stale and must be updated.", got, bad+1)
		}
		// And the consequence, which is the half that matters operationally: a
		// correctly clocked peer refuses the epoch this node now advertises, on
		// its raise path. That is ASYMMETRIC — this node keeps accepting the
		// peer, so it does not know it is invisible.
		var peer heartbeatAuthState
		if peer.admitAuthed(true, got, 0x6669, 1) {
			t.Fatalf("a correctly clocked peer admitted epoch %d; it is far beyond that peer's "+
				"forward bound and must be refused", got)
		}
		// The same peer accepts an ordinary epoch, so the refusal is about this
		// value and not a wedged receiver.
		if !peer.admitAuthed(true, uint64(time.Now().UnixNano()), 0x666A, 1) {
			t.Fatal("control: a peer that refuses the stranded epoch must still accept a normal one")
		}
	})
}

// TestEpochClockPinIsTestOnly_6169 guards the seam itself: production must use
// the real clock, so a test that forgets to restore the hook cannot silently
// pin every later test to a fixed instant.
func TestEpochClockPinIsTestOnly_6169(t *testing.T) {
	got := epochNowNanos()
	now := time.Now().UnixNano()
	if delta := now - got; delta < 0 || delta > int64(time.Minute) {
		t.Fatalf("epochNowNanos() = %d but time.Now() = %d — the default clock hook is not the "+
			"real clock (a test leaked its pin?)", got, now)
	}
}
