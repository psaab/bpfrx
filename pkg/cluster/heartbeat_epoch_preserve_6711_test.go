package cluster

import (
	"path/filepath"
	"sync/atomic"
	"testing"
)

// #6711: a SINGLE backward wall-clock step larger than bootEpochMaxSkew, with
// persisted state perfectly intact, regressed this node's boot epoch AND
// durably overwrote the higher persisted value with the lower one. The peer,
// holding the higher floor, then refused this node — and because the good
// predecessor was gone, every later boot re-published from the same bad clock
// instead of chaining back above the floor. The lockout survived restarts.
//
// The documented safety margin said this needed TWO simultaneous faults
// ("Both terms must fail together"). It needs one. Those doc sites were already
// corrected in the tree; what was left was the persistence semantics, which is
// what this file pins.
//
// THE FIX IS NOT "chain from it anyway". Chaining from a value further ahead
// than bootEpochMaxSkew is the unrecoverable direction — it strands this node
// permanently ABOVE the range its peer will ever accept, which refineBootEpoch's
// own comment spells out. The fix is narrower: decline to chain exactly as
// before, but decline to OVERWRITE as well, so the value that keeps this node
// acceptable survives for the next boot.
//
// The band matters as much as the rule. epochUsableAsFloor admits anything
// before year 2200, so preserving on that alone would keep a year-2191 value
// forever and destroy the self-healing property #6669 relies on.
// bootEpochPreserveMaxSkew is the "could a real backward step explain this"
// window instead.

// refinedEpochFile runs one refinement pass against a pinned clock and returns
// the published epoch and what the file holds afterwards.
func refinedEpochFile(t *testing.T, persisted uint64, seed uint64, now int64) (published uint64, onDisk uint64, exists bool) {
	t.Helper()
	withPinnedEpochClock(t, now)
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	writeEpochFile(t, path, persisted)

	var pub atomic.Uint64
	pub.Store(seed)
	refineBootEpoch(path, &pub, 0)
	return pub.Load(), readEpochFile(t, path), true
}

// TestBackwardClockStepDoesNotDestroyTheEpochFile6711 is the fix.
//
// Both halves are asserted because only the pair distinguishes this from
// "chain from anything": the published epoch must be UNCHANGED (this node still
// declines to chain, so nothing about what it puts on the wire moves), while
// the FILE must be untouched (so a corrected clock can chain from it later).
func TestBackwardClockStepDoesNotDestroyTheEpochFile6711(t *testing.T) {
	// A credible present-day clock for the incarnation that wrote the file.
	const goodNow = int64(1_800_000_000_000_000_000) // ~2027

	cases := []struct {
		name         string
		stepBack     uint64 // how far this incarnation's clock has stepped back
		wantPreserve bool
		why          string
	}{
		{
			name:         "two_hour_step_back_preserves",
			stepBack:     2 * 60 * 60 * 1_000_000_000,
			wantPreserve: true,
			why: "just past bootEpochMaxSkew — the smallest step that reproduces #6711, " +
				"and the one an ordinary NTP correction produces",
		},
		{
			name:         "one_week_step_back_preserves",
			stepBack:     7 * 24 * 60 * 60 * 1_000_000_000,
			wantPreserve: true,
			why:          "a VM restored from a week-old snapshot",
		},
		{
			name:         "one_year_step_back_is_garbage_and_heals",
			stepBack:     365 * 24 * 60 * 60 * 1_000_000_000,
			wantPreserve: false,
			why: "beyond bootEpochPreserveMaxSkew: no real backward step explains it, so the " +
				"self-healing property #6669 depends on must still apply",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The file was written by a correctly-clocked earlier incarnation.
			persisted := uint64(goodNow)
			// This incarnation's clock has stepped back, so its wall-clock seed
			// is LOWER than the persisted value.
			now := goodNow - int64(tc.stepBack)
			seed := uint64(now)

			// Premise: the fixture really does construct the #6711 shape — the
			// persisted value is intact and orderable at the time it was
			// written, but not chainable from the stepped-back clock.
			if !epochOrderable(persisted, goodNow) {
				t.Fatalf("fixture: persisted %d is not orderable even at the good time %d; "+
					"this is not an intact predecessor", persisted, goodNow)
			}
			if epochOrderable(persisted, now) {
				t.Fatalf("fixture: persisted %d is still chainable at the stepped-back time %d, "+
					"so this cell does not reach the #6711 branch at all", persisted, now)
			}

			published, onDisk, _ := refinedEpochFile(t, persisted, seed, now)

			// UNCHANGED IN BOTH CASES: declining to chain must keep the value
			// already on the wire. If this moved, the fix would be changing what
			// the peer sees, which is a different and much riskier change.
			if published != seed {
				t.Fatalf("published epoch = %d, want the wall-clock seed %d — the fix must not "+
					"alter what this node puts on the wire, only what it leaves on disk",
					published, seed)
			}

			if tc.wantPreserve {
				if onDisk != persisted {
					t.Fatalf("persisted value was overwritten: file holds %d, want the intact "+
						"predecessor %d.\nA single backward clock step (%s) then destroys the only "+
						"value that keeps this node acceptable to its peer, so the lockout survives "+
						"every restart instead of ending when the clock is fixed (#6711).",
						onDisk, persisted, tc.why)
				}
				return
			}
			if onDisk != seed {
				t.Fatalf("file holds %d, want the healed wall-clock seed %d — %s",
					onDisk, seed, tc.why)
			}
		})
	}
}

// TestPreservedEpochLetsACorrectedClockChainAgain6711 is the PAIRED proof: the
// fix is only worth anything if the preserved value is actually usable later.
//
// Pass 1 runs with the stepped-back clock (preserve). Pass 2 runs with the clock
// corrected, and must chain from the value pass 1 left behind — which is
// precisely the recovery the overwrite used to make impossible.
func TestPreservedEpochLetsACorrectedClockChainAgain6711(t *testing.T) {
	const goodNow = int64(1_800_000_000_000_000_000)
	const stepBack = int64(2 * 60 * 60 * 1_000_000_000)

	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	persisted := uint64(goodNow)
	writeEpochFile(t, path, persisted)

	// Pass 1: clock stepped back.
	func() {
		withPinnedEpochClock(t, goodNow-stepBack)
		var pub atomic.Uint64
		pub.Store(uint64(goodNow - stepBack))
		refineBootEpoch(path, &pub, 0)
	}()
	if got := readEpochFile(t, path); got != persisted {
		t.Fatalf("pass 1 left %d on disk, want the preserved %d; the rest of this cell is vacuous",
			got, persisted)
	}

	// Pass 2: clock corrected (a later boot, or NTP catching up).
	withPinnedEpochClock(t, goodNow)
	var pub atomic.Uint64
	pub.Store(uint64(goodNow))
	refineBootEpoch(path, &pub, 0)

	if got := pub.Load(); got <= persisted {
		t.Fatalf("after the clock was corrected the node published %d, which is NOT above the "+
			"peer's latched floor %d. Recovery from a backward clock step depends on chaining "+
			"from the preserved predecessor; without it the node stays refused (#6711).",
			got, persisted)
	}
	if got := readEpochFile(t, path); got <= persisted {
		t.Fatalf("the corrected pass left %d on disk, want a value above %d so the NEXT boot "+
			"keeps climbing", got, persisted)
	}
}

// TestGarbageEpochStillHeals6711 is the negative control for the whole change:
// the values that were always garbage must still be overwritten, or #6669's
// self-healing property is silently retired by this fix.
func TestGarbageEpochStillHeals6711(t *testing.T) {
	const now = int64(1_800_000_000_000_000_000)

	cases := []struct {
		name      string
		persisted uint64
	}{
		{"zero_is_not_usable_as_a_floor", 0},
		{"beyond_year_2200", epochPlausibleMax},
		{"one_below_the_absolute_max_still_publishes_out_of_range", epochPlausibleMax - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed := uint64(now)
			published, onDisk, _ := refinedEpochFile(t, tc.persisted, seed, now)
			if published != seed {
				t.Fatalf("published %d, want the wall-clock seed %d", published, seed)
			}
			if onDisk != seed {
				t.Fatalf("garbage value %d was PRESERVED (file holds %d, want the healed seed %d). "+
					"The #6711 preserve band must not swallow the values #6669 relies on being "+
					"healed, or a corrupt file becomes permanent.",
					tc.persisted, onDisk, seed)
			}
		})
	}
}
