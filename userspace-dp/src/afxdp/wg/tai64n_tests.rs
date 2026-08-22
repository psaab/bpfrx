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
    assert_eq!(
        &encode(0, 500_000_000)[8..12],
        &0x1D00_0000u32.to_be_bytes()
    );
    // An out-of-range nanos (>= 10^9) is clamped to a valid whitened
    // sub-second value rather than emitted as a malformed TAI64N.
    let clamped = u32::from_be_bytes([
        encode(0, 0xAB_FF_FF_FF)[8],
        encode(0, 0xAB_FF_FF_FF)[9],
        encode(0, 0xAB_FF_FF_FF)[10],
        encode(0, 0xAB_FF_FF_FF)[11],
    ]);
    assert!(
        clamped < NANOS_PER_SEC,
        "out-of-range nanos must clamp below 10^9"
    );
    assert_eq!(
        clamped & !NANOS_WHITEN_MASK,
        0,
        "clamped value stays whitened"
    );
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
    assert!(
        nanos < NANOS_PER_SEC,
        "advanced nanos must be a valid sub-second value"
    );
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
    assert!(
        nanos_before + WHITENED_TICK >= NANOS_PER_SEC,
        "test setup: must be the last tick"
    );

    let advanced = advance_one_tick(&at_edge);
    let (secs_after, nanos_after) = decode(&advanced);
    assert_eq!(secs_after, secs_before + 1, "carry must increment seconds");
    assert_eq!(nanos_after, 0, "carry must reset nanos to 0");
    assert!(
        nanos_after < NANOS_PER_SEC,
        "nanos must stay a valid sub-second value"
    );

    // A mid-range advance must NOT carry.
    let mid = encode(100, 0x1000_0000);
    let mid_adv = advance_one_tick(&mid);
    let (s, ns) = decode(&mid_adv);
    assert_eq!(
        s,
        100 + TAI64_BASE,
        "mid-range advance must not touch seconds"
    );
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

/// #6422: the initiator's monotonic TAI64N clock. Every outbound
/// handshake initiation calls `now()`; with `.lock().unwrap()` a single
/// poisoning panic stopped the tunnel from ever initiating again.
/// Recovery preserves the high-water mark, so strict monotonicity — the
/// property the clock exists for — survives the panic.
#[test]
fn clock_now_recovers_poisoned_lock_6422() {
    use crate::afxdp::wg::poison_tests::poison_mutex;
    let clock = Tai64nClock::new();
    let first = clock.now();

    poison_mutex(&clock.last);

    let second = clock.now();
    assert!(
        second > first,
        "recovery must keep the committed high-water mark so `now()` \
         stays strictly monotonic (got {second:?} after {first:?})"
    );
    assert_eq!(clock.high_water(), Some(second));
}
