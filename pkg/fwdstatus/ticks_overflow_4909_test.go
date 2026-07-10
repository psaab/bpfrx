package fwdstatus

import (
	"math/big"
	"testing"
)

// TestTicksToNanosNoOverflow pins #4909: converting a large scheduler-tick
// count to nanoseconds must not overflow. The pre-fix `ticks * 1e9 / userHZ`
// wraps uint64 once `ticks * 1e9` exceeds 2^64 — at ~1.845e10 ticks (~33 days
// of busy CPU summed across 64 cores at 100 Hz) — corrupting the CPU windows
// used to diagnose saturation. The divide-before-multiply form is exact.
//
// RED on revert: restore `ticks * 1e9 / userHZ` and the wrap/near-wrap cases
// below produce a wrong (wrapped) value, mismatching the big.Int oracle.
func TestTicksToNanosNoOverflow(t *testing.T) {
	// Old intermediate wrap point: 2^64 / 1e9 ≈ 1.8446744073e10 ticks.
	const wrap = ^uint64(0) / 1_000_000_000

	// Upper bound of the inputs: the true result must still fit uint64 (the
	// function returns uint64 nanoseconds). 1<<40 ticks ≈ 1.1e19 ns fits;
	// anything much larger is unphysical (centuries of CPU at 100 Hz).
	cases := []uint64{
		0, 1, 99, 100, 101, 12_345,
		wrap - 1, wrap, wrap + 1, wrap + 1000,
		1 << 40,
	}

	bilNano := big.NewInt(1_000_000_000)
	bilHZ := big.NewInt(userHZ)
	for _, ticks := range cases {
		got := ticksToNanos(ticks)

		// Exact expected value via big.Int (no intermediate overflow).
		want := new(big.Int).SetUint64(ticks)
		want.Mul(want, bilNano)
		want.Div(want, bilHZ)
		if !want.IsUint64() {
			// Result itself does not fit uint64 — not exercised by these inputs.
			t.Fatalf("test oracle overflow for ticks=%d", ticks)
		}
		if want.Uint64() != got {
			t.Errorf("ticksToNanos(%d) = %d, want %d (overflow/wrap)", ticks, got, want.Uint64())
		}
	}
}
