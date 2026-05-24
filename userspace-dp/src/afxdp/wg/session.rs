//! WG transport session: snow `StatelessTransportState` plus a
//! sliding-window replay tracker.
//!
//! The transport state is derived from a completed Noise IK
//! handshake. snow's `StatelessTransportState` is `Sync` because
//! it holds no mutable per-message state — the counter and the
//! replay window are entirely the caller's responsibility, which is
//! exactly what we want for AF_XDP worker integration.
//!
//! Replay window: RFC 6479-style 64-bit sliding bitmap. Single
//! `Mutex` covers `(highest, bitmap)` — contention is bounded
//! because we only ever decap from the worker that owns the binding
//! the session was demuxed onto. Encap uses a separate `AtomicU64`
//! counter because we are the sole producer.

use snow::StatelessTransportState;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Width of the replay window in packets. 64 is a tight fit for a
/// single u64 bitmap; if we widen to 128 in the future we can swap
/// the type without touching the API.
pub(crate) const REPLAY_WINDOW: u64 = 64;
/// WireGuard reject-after-messages limit.
///
/// Per the protocol, a session must stop encrypting after this many
/// transport messages and rekey.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1u64 << 13);

#[inline]
fn reserve_next_counter(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            if current >= REJECT_AFTER_MESSAGES {
                None
            } else {
                Some(current + 1)
            }
        })
        .ok()
}

/// Which side of the handshake produced this session. Determines the
/// initial value of `confirmed` (initiator-side sessions are confirmed
/// at install because the initiator is the side that sends first;
/// responder-side sessions start unconfirmed and must observe a valid
/// inbound data record before egress is allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRole {
    Initiator,
    Responder,
}

/// A live, post-handshake WG transport session.
///
/// Debug-impl is hand-rolled because snow's `StatelessTransportState`
/// doesn't expose useful Debug (it would leak keys anyway).
pub(crate) struct WgSession {
    /// snow transport state. Stateless w.r.t. nonce — we drive the
    /// counter ourselves on both directions.
    pub(crate) transport: StatelessTransportState,
    /// Receiver index that the *peer* will put in the WG data
    /// header when sending to us. Locally chosen at handshake time.
    /// Used for inbound demux: the engine's
    /// `sessions_by_local_index: RwLock<FxHashMap<u32, Arc<WgSession>>>`
    /// is keyed by `local_index` alone, not by `(listen_port,
    /// local_index)`. Listen-port selection happens one layer up in
    /// the integration PR's UDP-socket dispatch, before the record
    /// reaches the engine.
    pub(crate) local_index: u32,
    /// Receiver index that *we* put in the WG data header when
    /// sending to the peer. Peer-chosen at handshake time.
    pub(crate) peer_index: u32,
    /// Monotonic outbound counter.
    pub(crate) tx_counter: AtomicU64,
    /// Replay tracker for inbound packets.
    pub(crate) replay: Mutex<ReplayState>,
    /// Identifier of the peer this session belongs to (peer pubkey).
    /// Stored so the engine can route demuxed packets back through
    /// the peer's AllowedIPs gate.
    pub(crate) peer_pubkey: [u8; 32],
    /// WireGuard key-confirmation flag. WG spec: the responder MUST
    /// NOT send encrypted transport data on a fresh session until it
    /// has authenticated the initiator's first transport packet. This
    /// is the anti-reflection / key-confirmation invariant that
    /// prevents the responder from acting as a one-shot amplifier
    /// against a forged handshake response. Initiator-role sessions
    /// are installed with `confirmed = true` (the initiator is the
    /// side that sends first by definition). Responder-role sessions
    /// are installed with `confirmed = false`; egress through such a
    /// session is treated as no-usable-session until a successful
    /// inbound `read_message` flips the flag.
    pub(crate) confirmed: AtomicBool,
}

impl std::fmt::Debug for WgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgSession")
            .field("local_index", &self.local_index)
            .field("peer_index", &self.peer_index)
            .field("tx_counter", &self.tx_counter)
            .field("peer_pubkey_first4", &&self.peer_pubkey[..4])
            .finish_non_exhaustive()
    }
}

impl WgSession {
    /// Create a session in initiator role — confirmed at install
    /// (the initiator is the side that sends first per the WG spec).
    /// Existing callers used `WgSession::new`; that constructor maps
    /// to this initiator behavior to preserve backward compatibility
    /// for the in-tree tests that drive both sides through the
    /// engine's slow path. Callers that handle a responder session
    /// (after reading the initiator's first handshake message) MUST
    /// use `new_with_role(SessionRole::Responder, ...)`.
    pub(crate) fn new(
        transport: StatelessTransportState,
        local_index: u32,
        peer_index: u32,
        peer_pubkey: [u8; 32],
    ) -> Self {
        Self::new_with_role(
            transport,
            local_index,
            peer_index,
            peer_pubkey,
            SessionRole::Initiator,
        )
    }

    /// Create a session and record its role for key-confirmation
    /// gating. See the `confirmed` field doc on `WgSession` for the
    /// initiator-vs-responder contract.
    pub(crate) fn new_with_role(
        transport: StatelessTransportState,
        local_index: u32,
        peer_index: u32,
        peer_pubkey: [u8; 32],
        role: SessionRole,
    ) -> Self {
        let confirmed = matches!(role, SessionRole::Initiator);
        Self {
            transport,
            local_index,
            peer_index,
            tx_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayState::default()),
            peer_pubkey,
            confirmed: AtomicBool::new(confirmed),
        }
    }

    /// Atomically reserve the next outbound counter value.
    #[inline]
    pub(crate) fn next_tx_counter(&self) -> Option<u64> {
        reserve_next_counter(&self.tx_counter)
    }

    /// Returns true once the session has authenticated at least one
    /// inbound transport packet. Initiator-role sessions return true
    /// from install onward.
    #[inline]
    pub(crate) fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }

    /// Mark the session as confirmed. Called from `try_decap` after a
    /// successful AEAD authentication of an inbound transport record.
    /// `Release` pairs with the `Acquire` load in `is_confirmed` so
    /// any subsequent egress reader sees a `true` flag.
    #[inline]
    pub(crate) fn mark_confirmed(&self) {
        self.confirmed.store(true, Ordering::Release);
    }
}

/// Sliding-window replay tracker. Tracks the most recent 64
/// counters seen, anchored at `highest`.
///
/// State invariant after the first accepted counter: `bitmap` bit 0
/// always corresponds to `highest`. A counter `c` is fresh iff
///   - `c > highest`, OR
///   - `highest - c < REPLAY_WINDOW` AND the corresponding bit is
///     unset.
///
/// `started == false` means no counters have been seen yet, which
/// is distinguishable from "the all-zero state happens to be the
/// post-first-accept state for counter 0". Without this flag the
/// `c == highest` arm would incorrectly accept the duplicate of
/// counter 0 immediately after the first accept.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ReplayState {
    pub(crate) highest: u64,
    pub(crate) bitmap: u64,
    pub(crate) started: bool,
}

impl ReplayState {
    /// Cheap pre-crypto reject for trivially stale counters.
    ///
    /// This never rejects in-window candidates for the current replay
    /// state snapshot, so it is safe to run before AEAD without
    /// creating false drops. Under concurrent decap another packet may
    /// advance `highest` between this check and post-decrypt update,
    /// so this is a best-effort CPU guard rather than a hard guarantee.
    #[inline]
    pub(crate) fn definitely_out_of_window(&self, c: u64) -> bool {
        self.started && c.saturating_add(REPLAY_WINDOW) <= self.highest
    }

    /// Check-and-update for inbound counter `c`. Returns
    /// `ReplayDecision::Accept` if the counter is fresh (and the
    /// window is updated atomically with the accept), or one of
    /// the reject variants otherwise.
    ///
    /// Algorithm: RFC 6479 (anti-replay window). Worth reading the
    /// RFC if you're changing this — the test suite covers the
    /// in-order / repeat / out-of-window / gap-fill arms explicitly.
    pub(crate) fn check_and_update(&mut self, c: u64) -> ReplayDecision {
        if !self.started {
            self.started = true;
            self.highest = c;
            self.bitmap = 1;
            return ReplayDecision::Accept;
        }
        if c > self.highest {
            // New high water mark — shift the bitmap left by the
            // gap and set bit 0 for the newly-accepted counter.
            let gap = c - self.highest;
            if gap >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << gap) | 1;
            }
            self.highest = c;
            ReplayDecision::Accept
        } else {
            // c <= highest: this is either a repeat of `highest`
            // (which post-init is always already-seen because we
            // marked bit 0 on accept) or a strictly older counter.
            let age = self.highest - c;
            if age >= REPLAY_WINDOW {
                ReplayDecision::OutOfWindow
            } else {
                let mask = 1u64 << age;
                if self.bitmap & mask != 0 {
                    ReplayDecision::Repeat
                } else {
                    // In-window gap fill: accept and mark the bit.
                    self.bitmap |= mask;
                    ReplayDecision::Accept
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
    Accept,
    Repeat,
    OutOfWindow,
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn in_order_accepts() {
        let mut r = ReplayState::default();
        for c in 0u64..200 {
            assert_eq!(r.check_and_update(c), ReplayDecision::Accept, "c={}", c);
        }
    }

    #[test]
    fn exact_repeat_rejects() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10), ReplayDecision::Accept);
        // Replay of the same counter must be rejected as Repeat,
        // not silently accepted as a no-op.
        assert_eq!(r.check_and_update(10), ReplayDecision::Repeat);
    }

    #[test]
    fn out_of_window_rejects() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(1000), ReplayDecision::Accept);
        // Counter 1000 - 64 = 936 is exactly at the window edge;
        // anything <= that is out-of-window.
        assert_eq!(r.check_and_update(936), ReplayDecision::OutOfWindow);
        assert_eq!(r.check_and_update(0), ReplayDecision::OutOfWindow);
    }

    #[test]
    fn gap_fill_in_window_accepts() {
        let mut r = ReplayState::default();
        // Receive 0, 2, 4 — accept all. Then receive the gap-filled
        // 1 and 3. WG explicitly allows in-window gap fill; this
        // is the whole point of the sliding bitmap (NAT/reorder).
        assert_eq!(r.check_and_update(0), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(2), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(4), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(1), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(3), ReplayDecision::Accept);
        // But the gap fills themselves now repeat.
        assert_eq!(r.check_and_update(1), ReplayDecision::Repeat);
        assert_eq!(r.check_and_update(3), ReplayDecision::Repeat);
    }

    #[test]
    fn jump_ahead_resets_bitmap() {
        // Counter jumping forward by more than the window width
        // resets the bitmap to "only the new counter seen".
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(1000), ReplayDecision::Accept);
        // The old counter 10 is now far out of window.
        assert_eq!(r.check_and_update(10), ReplayDecision::OutOfWindow);
        // The new counter 1000 is at the head and must repeat-fail.
        assert_eq!(r.check_and_update(1000), ReplayDecision::Repeat);
    }

    #[test]
    fn window_edge_repeat() {
        // The bit at the trailing edge of the window must reject a
        // repeat. This is the most common off-by-one in replay
        // window code.
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(0), ReplayDecision::Accept);
        // Move the window so 0 is at the trailing edge but still
        // in-window: highest = 63, age = 63 < 64.
        assert_eq!(r.check_and_update(63), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(0), ReplayDecision::Repeat);
        // One more step pushes 0 out: highest = 64, age = 64 = REPLAY_WINDOW.
        assert_eq!(r.check_and_update(64), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(0), ReplayDecision::OutOfWindow);
    }

    #[test]
    fn precheck_out_of_window_matches_window_width() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(1000), ReplayDecision::Accept);
        assert!(!r.definitely_out_of_window(937));
        assert!(r.definitely_out_of_window(936));
    }

    #[test]
    fn reject_after_messages_constant_matches_wireguard_spec() {
        assert_eq!(REJECT_AFTER_MESSAGES, 0xffff_ffff_ffff_dfff);
    }

    #[test]
    fn tx_counter_stops_at_reject_after_messages_without_advancing() {
        let counter = AtomicU64::new(REJECT_AFTER_MESSAGES - 1);
        assert_eq!(
            reserve_next_counter(&counter),
            Some(REJECT_AFTER_MESSAGES - 1)
        );
        assert_eq!(counter.load(Ordering::Relaxed), REJECT_AFTER_MESSAGES);
        assert_eq!(reserve_next_counter(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), REJECT_AFTER_MESSAGES);
    }
}
