//! TAI64N timestamp for the WireGuard handshake initiation.
//!
//! WireGuard carries a 12-byte TAI64N timestamp as the encrypted Noise
//! payload of message type 1. A compliant responder (kernel WireGuard,
//! wireguard-go, UniFi) uses it for handshake anti-replay: it rejects an
//! initiation whose timestamp is `<=` the last one it accepted from that
//! peer. So xpf MUST emit a strictly increasing timestamp or it DoSes its
//! own re-handshakes.
//!
//! ## Wire encoding (12 bytes, big-endian)
//!
//! ```text
//!   bytes [0..8]   = 0x400000000000000a + unix_seconds   (BE u64)
//!   bytes [8..12]  = nanoseconds & 0xFF00_0000           (BE u32, whitened)
//! ```
//!
//! - The seconds base is `0x400000000000000a` = `2^62 + 10`. The `2^62`
//!   is the TAI64 epoch label; the `+ 10` is the TAI−UTC leap-second
//!   offset at the 1970 Unix epoch. Both the Linux kernel
//!   (`drivers/net/wireguard/noise.c`: `ktime_get_real_seconds() +
//!   0x400000000000000aULL`) and wireguard-go (`tai64n/tai64n.go`:
//!   `base = uint64(0x400000000000000a)`) use this exact base. Omitting
//!   the `+ 10` makes every timestamp 10 s in the past, which a strict
//!   peer can drop as stale.
//! - The nanoseconds field is **whitened**: the low 24 bits are cleared
//!   (`nanos & 0xFF00_0000`, i.e. `nanos &^ (0x0100_0000 - 1)`), matching
//!   the reference's `nano = uint32(t.Nanosecond()) &^ (0x1000000 - 1)`.
//!   This coarsens the sub-~16 ms component so the timestamp does not leak
//!   a fine-grained local clock.
//!
//! Because the 8-byte seconds field is the most significant part and both
//! fields are big-endian, lexicographic byte comparison of the 12-byte
//! value equals numeric comparison — the same property wireguard-go relies
//! on with `bytes.Compare`. The monotonic clock exploits this.
//!
//! ## Monotonicity (in-process)
//!
//! [`Tai64nClock`] returns a value strictly greater than every prior
//! return from the same clock. It is derived from `SystemTime::now()`, but
//! if the freshly-computed (whitened) value is `<=` the last returned one
//! (a backwards wall-clock step, or two calls inside one whitened tick),
//! it returns `last + one whitened tick` instead. On nanos overflow the
//! carry rolls into the seconds field — and crucially the carry triggers
//! when the advanced nanos reach `1_000_000_000`, NOT at the `0xFF00_0000`
//! whitening boundary: a TAI64N nanos field must be a valid sub-second
//! value `< 10^9` or a strict peer rejects the datagram as malformed.
//!
//! Cross-restart persistence (so the clock never regresses after an xpf
//! restart with a skewed wall clock) is the control plane's job and is
//! deferred to the config-integration step (#1703 S6). This module exposes
//! [`Tai64nClock::seed_high_water`] / [`Tai64nClock::high_water`] hooks for
//! it; S1 has no daemon to persist from, so in-process monotonicity is the
//! S1 contract.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// TAI64N wire length: 8-byte seconds + 4-byte nanoseconds.
pub(crate) const TAI64N_LEN: usize = 12;

/// TAI64 seconds base: `2^62` epoch label + 10 s TAI−UTC leap offset at
/// the 1970 epoch. See the module docs.
const TAI64_BASE: u64 = 0x4000_0000_0000_000a;

/// Whitening mask applied to the nanoseconds field: clear the low 24
/// bits (keep `0xFF00_0000`). One whitened tick is therefore
/// `0x0100_0000` ns (~16.78 ms).
const NANOS_WHITEN_MASK: u32 = 0xFF00_0000;
const WHITENED_TICK: u32 = 0x0100_0000;
const NANOS_PER_SEC: u32 = 1_000_000_000;

/// Encode `(unix_secs, nanos)` into a 12-byte big-endian TAI64N with the
/// canonical base offset and nanos whitening.
///
/// `nanos` from `SystemTime::subsec_nanos()` is always `< 1_000_000_000`,
/// and whitening only clears low bits, so the live path stays in range.
/// We still defensively clamp a whitened value `>= 1_000_000_000` down to
/// the largest valid whitened tick (`< 10^9`) so a hand-constructed /
/// seeded out-of-range nanos can never produce a malformed TAI64N that a
/// strict peer would reject. (A whitened nanos can never exceed
/// `0xFF00_0000`; clamping keeps it a valid sub-second value.)
#[inline]
fn encode(unix_secs: u64, nanos: u32) -> [u8; TAI64N_LEN] {
    let secs = TAI64_BASE.wrapping_add(unix_secs);
    let mut whitened = nanos & NANOS_WHITEN_MASK;
    if whitened >= NANOS_PER_SEC {
        // Largest whitened multiple strictly below 10^9.
        whitened = (NANOS_PER_SEC - 1) & NANOS_WHITEN_MASK;
    }
    let mut out = [0u8; TAI64N_LEN];
    out[0..8].copy_from_slice(&secs.to_be_bytes());
    out[8..12].copy_from_slice(&whitened.to_be_bytes());
    out
}

/// Decode the seconds and nanoseconds fields from a 12-byte TAI64N. Used
/// only by tests and the monotonic-advance path.
#[inline]
fn decode(ts: &[u8; TAI64N_LEN]) -> (u64, u32) {
    let secs = u64::from_be_bytes([
        ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], ts[6], ts[7],
    ]);
    let nanos = u32::from_be_bytes([ts[8], ts[9], ts[10], ts[11]]);
    (secs, nanos)
}

/// Advance a TAI64N value by exactly one whitened tick, carrying into the
/// seconds field when the nanos would reach a full second.
///
/// The carry MUST trigger at `nanos >= 1_000_000_000`, not at the
/// `0xFF00_0000` whitening boundary: the maximum whitened nanos is
/// `0x3B00_0000` (989_855_744 — the largest multiple of the tick below
/// 10^9), and `0x3B00_0000 + 0x0100_0000 = 0x3C00_0000` (1_006_632_960)
/// which is `> 10^9`. A peer rejects a nanos field `>= 10^9` as malformed,
/// so we roll over to `secs + 1, nanos = 0` there.
#[inline]
fn advance_one_tick(ts: &[u8; TAI64N_LEN]) -> [u8; TAI64N_LEN] {
    let (secs, raw_nanos) = decode(ts);
    // Defensive: a value reaching here normally comes from `encode()` or a
    // prior `advance` (so nanos < 10^9), but `seed_high_water` accepts a raw
    // 12-byte value that could carry an out-of-range nanos. Clamp to a valid
    // sub-second whitened value before adding a tick so the `+ WHITENED_TICK`
    // cannot wrap u32 and so the result is always a valid TAI64N.
    let nanos = if raw_nanos >= NANOS_PER_SEC {
        (NANOS_PER_SEC - 1) & NANOS_WHITEN_MASK
    } else {
        raw_nanos & NANOS_WHITEN_MASK
    };
    let next = nanos.wrapping_add(WHITENED_TICK);
    if next >= NANOS_PER_SEC {
        // Carry: the seconds field is the raw TAI64 value (already includes
        // the base), so increment it directly and reset nanos.
        let mut out = [0u8; TAI64N_LEN];
        out[0..8].copy_from_slice(&secs.wrapping_add(1).to_be_bytes());
        // nanos = 0
        out
    } else {
        let mut out = *ts;
        out[8..12].copy_from_slice(&next.to_be_bytes());
        out
    }
}

/// In-process strictly-monotonic TAI64N clock.
///
/// `now()` is the only value source on the handshake-build path. The
/// `Mutex` is taken only on the slow handshake path (never per-packet), so
/// contention is irrelevant.
#[derive(Debug)]
pub(crate) struct Tai64nClock {
    /// The most recent value returned. `None` until the first `now()`.
    last: Mutex<Option<[u8; TAI64N_LEN]>>,
}

impl Default for Tai64nClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Tai64nClock {
    pub(crate) fn new() -> Self {
        Self {
            last: Mutex::new(None),
        }
    }

    /// Return a TAI64N strictly greater than every prior return from this
    /// clock. Derived from `SystemTime::now()`, clamped up to
    /// `last + one whitened tick` if the wall clock did not advance past
    /// `last`.
    pub(crate) fn now(&self) -> [u8; TAI64N_LEN] {
        let candidate = Self::wall_clock_now();
        let mut guard = self.last.lock().unwrap();
        let next = match *guard {
            // Strictly greater (big-endian byte compare == numeric): take
            // the fresh wall-clock value.
            Some(prev) if candidate <= prev => advance_one_tick(&prev),
            _ => candidate,
        };
        *guard = Some(next);
        next
    }

    /// Compute the whitened TAI64N for the current wall clock. Pre-1970
    /// clocks (`SystemTime` before `UNIX_EPOCH`) collapse to unix_secs = 0;
    /// monotonicity still holds because `now()` clamps against `last`.
    fn wall_clock_now() -> [u8; TAI64N_LEN] {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => encode(d.as_secs(), d.subsec_nanos()),
            Err(_) => encode(0, 0),
        }
    }

    /// Seed the clock's high-water mark from a persisted value so a future
    /// control plane (#1703 S6) can prevent cross-restart regression. The
    /// next `now()` will return strictly greater than `hw`. Slow path only.
    pub(crate) fn seed_high_water(&self, hw: [u8; TAI64N_LEN]) {
        let mut guard = self.last.lock().unwrap();
        // Only move the high-water mark forward; never let a stale seed
        // pull it backwards.
        match *guard {
            Some(prev) if hw <= prev => {}
            _ => *guard = Some(hw),
        }
    }

    /// Snapshot the current high-water mark for persistence (#1703 S6).
    /// Returns `None` if `now()` has never been called and no seed applied.
    pub(crate) fn high_water(&self) -> Option<[u8; TAI64N_LEN]> {
        *self.last.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn tai64n_encoding_kat() {
        // Fixed (secs, nanos) -> exact 12-byte wire image with the +10
        // epoch offset and the low-24-bit whitening applied.
        //
        // secs field = 0x400000000000000a + 1 = 0x400000000000000b
        // nanos      = 0x12345678 & 0xFF000000 = 0x12000000
        let ts = encode(1, 0x1234_5678);
        assert_eq!(
            ts,
            [
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, // secs BE
                0x12, 0x00, 0x00, 0x00, // whitened nanos BE
            ]
        );

        // Re-derive the seconds base independently of the constant to catch
        // a transcription typo: 2^62 + 10.
        let base = (1u64 << 62) + 10;
        assert_eq!(base, TAI64_BASE);
        assert_eq!(&ts[0..8], &base.wrapping_add(1).to_be_bytes());

        // unix_secs = 0 yields the bare base in the seconds field.
        let z = encode(0, 0);
        assert_eq!(&z[0..8], &TAI64_BASE.to_be_bytes());
        assert_eq!(&z[8..12], &[0u8; 4]);
    }

    #[test]
    fn nanos_are_whitened_low_24_bits() {
        // Any value in [0, 0x00FF_FFFF] whitens to zero.
        assert_eq!(&encode(0, 0x00FF_FFFF)[8..12], &[0u8; 4]);
        // The high byte survives for an in-range (< 10^9) nanos. 0.5 s =
        // 500_000_000 = 0x1DCD6500; whitened (clear low 24 bits) = 0x1D000000.
        assert_eq!(&encode(0, 500_000_000)[8..12], &0x1D00_0000u32.to_be_bytes());
        // An out-of-range nanos (>= 10^9) is clamped to a valid whitened
        // sub-second value rather than emitted as a malformed TAI64N.
        let clamped = u32::from_be_bytes([
            encode(0, 0xAB_FF_FF_FF)[8],
            encode(0, 0xAB_FF_FF_FF)[9],
            encode(0, 0xAB_FF_FF_FF)[10],
            encode(0, 0xAB_FF_FF_FF)[11],
        ]);
        assert!(clamped < NANOS_PER_SEC, "out-of-range nanos must clamp below 10^9");
        assert_eq!(clamped & !NANOS_WHITEN_MASK, 0, "clamped value stays whitened");
    }

    #[test]
    fn tai64n_strictly_monotonic() {
        // Even when the wall clock never advances (we cannot control it in
        // a unit test, but rapid successive calls land in the same whitened
        // tick), each call must be strictly greater than the previous.
        let clk = Tai64nClock::new();
        let mut prev = clk.now();
        for _ in 0..10_000 {
            let cur = clk.now();
            assert!(
                cur > prev,
                "TAI64N must be strictly increasing: prev={prev:02x?} cur={cur:02x?}"
            );
            prev = cur;
        }
    }

    #[test]
    fn tai64n_monotonic_after_backwards_seed() {
        // Seed a far-future high-water mark (with a VALID sub-second nanos);
        // the next now() must still be strictly greater (clamps up via
        // advance_one_tick), proving the backwards-wall-clock case.
        let clk = Tai64nClock::new();
        let future = encode(4_000_000_000, 0x3A00_0000); // valid whitened nanos < 10^9
        clk.seed_high_water(future);
        let n = clk.now();
        assert!(n > future, "now() after future seed must exceed the seed");
    }

    #[test]
    fn advance_is_robust_to_out_of_range_seed() {
        // A raw seed whose nanos field is >= 10^9 (malformed) must not panic
        // or wrap when advanced; the result is a valid TAI64N (nanos < 10^9)
        // strictly greater than nothing-was-clamped-to-zero would give.
        let mut bad = encode(100, 0);
        bad[8..12].copy_from_slice(&0xFF00_0000u32.to_be_bytes()); // 4.27e9 ns
        let adv = advance_one_tick(&bad);
        let (_secs, nanos) = decode(&adv);
        assert!(nanos < NANOS_PER_SEC, "advanced nanos must be a valid sub-second value");
    }

    #[test]
    fn tai64n_carry_at_1e9() {
        // The carry into seconds MUST trigger at nanos >= 1_000_000_000,
        // not at the 0xFF000000 whitening boundary. Start one whitened tick
        // below a full second and advance: it must roll to secs+1, nanos=0,
        // and the resulting nanos must be a valid sub-second value.
        //
        // 0x3B000000 = 989_855_744 is the largest whitened nanos < 10^9.
        let at_edge = {
            let mut t = encode(100, 0);
            t[8..12].copy_from_slice(&0x3B00_0000u32.to_be_bytes());
            t
        };
        let (secs_before, nanos_before) = decode(&at_edge);
        assert!(nanos_before < NANOS_PER_SEC);
        assert!(nanos_before + WHITENED_TICK >= NANOS_PER_SEC, "test setup: must be the last tick");

        let advanced = advance_one_tick(&at_edge);
        let (secs_after, nanos_after) = decode(&advanced);
        assert_eq!(secs_after, secs_before + 1, "carry must increment seconds");
        assert_eq!(nanos_after, 0, "carry must reset nanos to 0");
        assert!(nanos_after < NANOS_PER_SEC, "nanos must stay a valid sub-second value");

        // A mid-range advance must NOT carry.
        let mid = encode(100, 0x1000_0000);
        let mid_adv = advance_one_tick(&mid);
        let (s, ns) = decode(&mid_adv);
        assert_eq!(s, 100 + TAI64_BASE, "mid-range advance must not touch seconds");
        assert_eq!(ns, 0x1100_0000, "mid-range advance adds one whitened tick");
    }

    #[test]
    fn tai64n_concurrent_monotonic() {
        // N threads hammering now() must collectively produce N distinct,
        // strictly-orderable values — no duplicates, no regressions.
        let clk = Arc::new(Tai64nClock::new());
        let threads = 8;
        let per = 2_000;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let clk = clk.clone();
            handles.push(thread::spawn(move || {
                let mut v = Vec::with_capacity(per);
                for _ in 0..per {
                    v.push(clk.now());
                }
                v
            }));
        }
        let mut all: Vec<[u8; TAI64N_LEN]> = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        all.sort();
        let total = all.len();
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "concurrent now() produced {} duplicate TAI64N values",
            total - all.len()
        );
    }

    #[test]
    fn high_water_round_trips() {
        let clk = Tai64nClock::new();
        assert_eq!(clk.high_water(), None);
        let n = clk.now();
        assert_eq!(clk.high_water(), Some(n));
        // A seed below the current mark is ignored.
        clk.seed_high_water(encode(0, 0));
        assert_eq!(clk.high_water(), Some(n));
    }
}
