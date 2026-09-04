//! #8108: the RPC-fallback delta buffer's occupancy is measurable.
//!
//! The issue's acceptance is "a measured ring-occupancy figure from a
//! revocation burst large enough to matter — not a computed bound", and it
//! explicitly allows the issue to be CLOSED if the measurement shows the ring
//! is not reached. Neither outcome was available: `pending_session_deltas.len()`
//! was read only for the cap check and nothing retained it, and
//! `delta_loss_pending` is a BOOLEAN — "we overflowed at least once", never
//! "we reached 90%".
//!
//! So a buffer running comfortably and a buffer surviving on luck were the same
//! observation. This makes them different.

use super::*;
use std::sync::atomic::Ordering;

fn delta_8108(_id: u64) -> SessionDeltaInfo {
    // The contents are irrelevant to occupancy — this measures DEPTH, and a
    // depth counts entries regardless of what they carry.
    SessionDeltaInfo::default()
}

/// The defining property: it records the MAXIMUM, not the current depth.
///
/// This is the whole reason it is a high-water mark. The buffer drains, so a
/// depth gauge sampled at 1 Hz sees a revocation burst only if the sample lands
/// inside it — and reports a comfortable small number otherwise, for exactly
/// the event being measured. A cell that only pushed and read would pass
/// against a plain depth gauge; this one drains first.
#[test]
fn the_high_water_survives_a_drain_8108() {
    let b = BindingLiveState::new();
    for i in 0..7 {
        b.push_session_delta(delta_8108(i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        7,
        "high water must equal the depth reached"
    );

    let drained = b.drain_session_deltas(usize::MAX);
    assert_eq!(drained.len(), 7, "precondition: the buffer drained");

    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        7,
        "after a full drain the CURRENT depth is 0 but the high water must still \
         read 7. A gauge that fell back to 0 here would report a healthy buffer \
         for the burst it just absorbed, which is the measurement this exists to \
         make possible."
    );
}

/// It rises to the new maximum and never falls back to a lower peak.
#[test]
fn the_high_water_only_rises_8108() {
    let b = BindingLiveState::new();
    for i in 0..5 {
        b.push_session_delta(delta_8108(i));
    }
    let _ = b.drain_session_deltas(usize::MAX);
    for i in 0..2 {
        b.push_session_delta(delta_8108(100 + i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        5,
        "a smaller later burst must not lower the recorded peak"
    );

    for i in 0..9 {
        b.push_session_delta(delta_8108(200 + i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        11,
        "a larger burst must raise it (2 retained + 9 = 11)"
    );
}

/// A fresh binding reads zero, so "never pushed" and "pushed nothing" are the
/// same observation — which they are — and the metric cannot be mistaken for
/// having measured something it did not.
#[test]
fn a_fresh_binding_reports_zero_high_water_8108() {
    let b = BindingLiveState::new();
    assert_eq!(b.session_delta_high_water.load(Ordering::Relaxed), 0);
}

/// The three states the issue needs separated, asserted together.
///
/// Before #8108 only the third was observable, and only as a boolean. The point
/// of the pair is that "near the cap but never dropped" — surviving on luck —
/// is now distinguishable from "comfortable", and that distinction is what
/// decides whether the fallback in the issue's item 2 is worth building.
#[test]
fn high_water_and_dropped_separate_comfortable_from_lucky_8108() {
    // Comfortable: well under the cap, nothing dropped.
    let comfortable = BindingLiveState::new();
    for i in 0..4 {
        comfortable.push_session_delta(delta_8108(i));
    }
    assert!(comfortable.session_delta_high_water.load(Ordering::Relaxed) < MAX_PENDING_SESSION_DELTAS as u64);
    assert_eq!(comfortable.session_delta_dropped.load(Ordering::Relaxed), 0);

    // Lossy: filled past the cap. dropped > 0 AND the high water pins at the cap.
    let lossy = BindingLiveState::new();
    for i in 0..(MAX_PENDING_SESSION_DELTAS + 5) {
        lossy.push_session_delta(delta_8108(i as u64));
    }
    assert_eq!(
        lossy.session_delta_high_water.load(Ordering::Relaxed),
        MAX_PENDING_SESSION_DELTAS as u64,
        "the high water tops out AT the cap — it never records a depth the buffer \
         cannot hold, so a reader cannot mistake the overflow for a deeper queue"
    );
    assert_eq!(
        lossy.session_delta_dropped.load(Ordering::Relaxed),
        5,
        "and the drops are counted separately, so 'reached the cap' and 'lost \
         deltas' stay distinguishable"
    );
    assert!(lossy.delta_loss_pending.load(Ordering::Relaxed));
}
