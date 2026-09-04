package config

import "time"

// #8642: the one place a config seconds/milliseconds knob becomes a Duration.
//
// THE FAMILY. A config knob is stored by the compiler as a plain `int` from
// `strconv.Atoi` with no range check, and a consumer computes
// `time.Duration(n) * time.Second`. Past MaxDurationSeconds the multiply
// overflows int64 nanoseconds and WRAPS.
//
// THE PART THAT DEFEATS THE GUARDS ACTUALLY PRESENT. The residue can be small
// and POSITIVE. `gcd(1e9, 2^64) = 512`, so second-denominated residues are
// 512ns multiples and the smallest is exactly 512ns; `gcd(1e6, 2^64) = 64`, so
// millisecond residues bottom out at 64ns. Every site this replaced guarded with
// `<= 0` or `> 0`, which is blind to that by construction — and so is a
// post-multiply sanity check like `if d > someMax`, because a wrapped value
// lands INSIDE the plausible range. **A guard written as "is it nonsense in the
// obvious direction" cannot see wrap, because wrap is not nonsense.**
//
// WHY A SCHEMA CEILING IS NOT THE FIX. `Store.compileTreeLenient` downgrades a
// typed-leaf violation to a warning on the tolerant Store.Load / Store.SyncApply
// ingress — configs the operator did not just author. So a schema bound stops an
// operator's `commit` and does not stop a persisted config from an older binary,
// or one pushed by an un-upgraded cluster primary. The bound has to be at the
// conversion.
//
// THE FALLBACK DIRECTION IS ARGUED, NOT DEFAULTED. Both helpers return the
// caller's fallback rather than clamping to the maximum, following #6769 and
// #8597: a value this far out of range is a typo or a hostile config, not an
// operator asking for the largest window the type allows. #8597 showed it
// mattering — clamping to the maximum would have kept a DENY feed on a
// drop-to-empty refresh schedule, where falling back keeps it enforced.
//
// The four prior fixes (#5705 routing, #5723 rpm, #6769 flowexport, #8597
// feeds/eventengine) each carried a private copy of this clamp. Five copies of
// one three-line predicate is how the sixth site gets missed, which is what
// #8642 measured.

// SecondsToDuration converts a second-denominated config knob to a Duration,
// returning fallback when the value is non-positive or would overflow.
//
// The comparison is against MaxDurationSeconds — the overflow point of the
// arithmetic itself, not a number chosen for looking reasonable. A tighter
// ceiling would silently rewrite a legitimately large but working configuration,
// which is a behaviour change wearing the shape of a safety fix.
func SecondsToDuration(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 || int64(seconds) > MaxDurationSeconds {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// MillisToDuration is the millisecond analogue. The ceiling differs by three
// orders of magnitude (MaxDurationMillis vs MaxDurationSeconds) and so does the
// residue floor (64ns vs 512ns), which is why this is a separate function
// rather than a unit parameter: a caller that passed the wrong unit would get a
// bound that is wrong by 1000x in the permissive direction, and nothing would
// say so.
func MillisToDuration(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 || int64(ms) > MaxDurationMillis {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

// MinutesToDuration is the minutes analogue, for completeness of the three units
// the tree actually uses (MaxDurationMinutes already exists for #5784).
func MinutesToDuration(minutes int, fallback time.Duration) time.Duration {
	if minutes <= 0 || int64(minutes) > MaxDurationMinutes {
		return fallback
	}
	return time.Duration(minutes) * time.Minute
}
