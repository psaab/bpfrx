//! #1865: operator-visible WireGuard telemetry counters.
//!
//! One `WgCounters` per `WgEngine` (== per tunnel in S2a). All fields
//! are relaxed `AtomicU64`s: increment sites are either the per-tunnel
//! control thread (slow path) or the rarely-hit transit encap path in
//! `frame/wg.rs` (which already heap-allocates per packet), and the
//! single reader is the 1/s status poll. Multi-counter snapshots are
//! NOT transactional — the poll reads each atomic independently while
//! the control thread increments, so e.g. `decap_packets` may be one
//! ahead of `decap_bytes` within one snapshot. Fine for observability.
//!
//! Counter lifetime follows the engine `Arc`:
//!   - survives control-thread tombstone/respawn cycles (#1872) and
//!     unrelated commits (engine reuse via `wg_identity_unchanged`);
//!   - resets to zero when a commit CHANGES the crypto identity and
//!     `populate_wg_engines` rebuilds the engine. Deliberate: under
//!     #1873's positional id renumbering, inheriting the same-id
//!     previous engine's counters would attribute a DIFFERENT
//!     tunnel's history to this one. Prometheus `rate()` tolerates
//!     monotonic resets, and the reset is itself a faithful signal
//!     that every session was rebuilt.
//!
//! Reason mapping is consolidated here (`count_decap_err`,
//! `count_encap_err`, `count_handshake_rx_err`) so the engine return
//! sites stay one-liners and a future error-variant addition fails
//! compilation here rather than silently going uncounted.
//!
//! Reserved reason names with NO increment site today (do not invent
//! counters for them): TAI64N-replay rejects and under-load rate-limit
//! rejects — S1 explicitly defers per-peer TAI64N anti-replay and
//! cookie/MAC2 (S7) to responder hardening (handshake_session.rs,
//! "does not yet enforce per-peer TAI64N anti-replay").

use super::engine::{DecapError, EncapError};
use super::handshake::FramingError;
use super::handshake_session::HandshakeError;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub(crate) struct WgCounters {
    // --- handshake ---
    /// `create_initiation` Ok — msg1 BUILT (not necessarily sent; a
    /// failed send shows in `hs_send_errors`, so the #1736 EINVAL
    /// fingerprint is `created↑ + send_errors↑ + completions flat`).
    pub(crate) hs_initiations_created: AtomicU64,
    /// `create_initiation` Err, all variants folded (previously
    /// discarded by the `if let Ok` at the drive_initiation call site).
    pub(crate) hs_initiation_build_failures: AtomicU64,
    /// `consume_initiation_create_response` Ok — responder accepted
    /// msg1, built msg2, installed the (unconfirmed) session. This is
    /// ALSO the responder-completion event (single increment site; the
    /// Prometheus completions metric emits it under role="responder").
    pub(crate) hs_responses_created: AtomicU64,
    /// `consume_response` Ok — initiator-side handshake completion.
    pub(crate) hs_completions_initiator: AtomicU64,
    /// Inbound handshake-message drops by reason (msg1 + msg2 paths).
    pub(crate) hs_rx_drops_mac1_mismatch: AtomicU64,
    pub(crate) hs_rx_drops_malformed: AtomicU64,
    pub(crate) hs_rx_drops_crypto: AtomicU64,
    pub(crate) hs_rx_drops_unknown_peer: AtomicU64,
    pub(crate) hs_rx_drops_stale_response: AtomicU64,
    pub(crate) hs_rx_drops_index_exhausted: AtomicU64,
    /// Type-3 (cookie) datagrams — S7 placeholder, dropped today.
    pub(crate) hs_rx_cookie_unsupported: AtomicU64,
    /// Type byte ∉ {1,2,3,4}. Zero-length UDP datagrams never reach
    /// type dispatch (consumed by the `Ok(_) => break` recv arm in
    /// wg_control), so runts are deliberately NOT counted here.
    pub(crate) rx_unknown_type: AtomicU64,
    /// `wg_send_to` failures for handshake messages — BOTH the
    /// initiation send and the (previously `let _ =`-discarded)
    /// response send.
    pub(crate) hs_send_errors: AtomicU64,
    /// `request_handshake` accepted a NoSession edge (rate-limited
    /// worker→control "please initiate"). Ties an encap-drop burst to
    /// the re-initiation it triggered.
    pub(crate) hs_requests_armed: AtomicU64,

    // --- transport decap (inbound) ---
    pub(crate) decap_packets: AtomicU64,
    /// Inner-IP bytes (un-padded), symmetric with `encap_bytes`. These
    /// are logical tunnel payload bytes — they will NOT match a kernel
    /// peer's `wg show` transfer numbers (which include WG overhead).
    pub(crate) decap_bytes: AtomicU64,
    /// Authenticated ZERO-length transport records (WG persistent
    /// keepalives: pad_to_16(0) == 0 ⇒ snow yields n == 0). Counted
    /// after the replay gate, before the inner parse — withOUT this
    /// class peel a keepalive peer would emit steady
    /// `decap_drops_malformed_inner` false alarms. NOT a drop counter.
    pub(crate) decap_keepalives: AtomicU64,
    pub(crate) decap_drops_malformed_header: AtomicU64,
    pub(crate) decap_drops_unknown_session: AtomicU64,
    pub(crate) decap_drops_counter_ceiling: AtomicU64,
    pub(crate) decap_drops_crypto: AtomicU64,
    pub(crate) decap_drops_replay: AtomicU64,
    pub(crate) decap_drops_allowed_ips: AtomicU64,
    /// MalformedInner with n > 0 only — the n == 0 keepalive class is
    /// peeled off into `decap_keepalives` above.
    pub(crate) decap_drops_malformed_inner: AtomicU64,
    pub(crate) decap_drops_buffer: AtomicU64,

    // --- transport encap (egress) ---
    pub(crate) encap_packets: AtomicU64,
    pub(crate) encap_bytes: AtomicU64,
    /// `EncapError::NoSession` from the no-current-session arm ONLY.
    pub(crate) encap_drops_no_session: AtomicU64,
    /// `EncapError::NoSession` from the `is_confirmed()` gate arm —
    /// the responder key-confirmation window. Distinguishable so an
    /// operator does not tcpdump a transient rekey blip (#1736 AGY
    /// r2). Counter-only split: the returned error stays `NoSession`
    /// and every caller contract is untouched.
    pub(crate) encap_drops_unconfirmed: AtomicU64,
    pub(crate) encap_drops_rekey_required: AtomicU64,
    /// UnknownPeer | CryptoFailed | BufferTooSmall — all
    /// "structurally impossible unless bug" classes, folded. Split if
    /// ever nonzero in the field.
    pub(crate) encap_drops_other: AtomicU64,
    /// Exact pad-aware MTU-guard drops, BOTH egress sites (control
    /// thread TUN-read + frame/wg.rs transit). The #1736 v4-mapped
    /// blackhole counter.
    pub(crate) encap_mtu_drops: AtomicU64,
    /// `wg_send_to` failures for encap'd transport datagrams.
    pub(crate) transport_send_errors: AtomicU64,
    /// `tun.write_all` failures delivering decap'd inner packets.
    pub(crate) tun_write_errors: AtomicU64,
    /// Inner packets drained (and dropped) off the TUN while a
    /// responder-only peer has no learned endpoint to send to.
    pub(crate) tun_rx_drops_no_endpoint: AtomicU64,

    // --- state (not a counter) ---
    /// Monotonic (CLOCK_MONOTONIC ns) stamp of the most recent
    /// handshake completion, either role. 0 = never. Converted to
    /// wall-clock epoch seconds at status-snapshot time; the stored
    /// stamp stays monotonic so an NTP step fences nothing (#1792).
    pub(crate) last_handshake_complete_ns: AtomicU64,
}

impl WgCounters {
    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a decap failure by reason and hand the error back, so the
    /// engine's return sites stay `Err(self.counters.count_decap_err(e))`
    /// one-liners. The keepalive class never routes through here (it is
    /// counted at its dedicated site inside `try_decap`).
    pub(crate) fn count_decap_err(&self, e: DecapError) -> DecapError {
        let c = match e {
            DecapError::MalformedHeader | DecapError::ShortRecord => {
                &self.decap_drops_malformed_header
            }
            DecapError::UnknownSession => &self.decap_drops_unknown_session,
            DecapError::CounterRejectAfterMessages => &self.decap_drops_counter_ceiling,
            DecapError::CryptoFailed => &self.decap_drops_crypto,
            DecapError::ReplayDuplicate | DecapError::ReplayOutOfWindow => {
                &self.decap_drops_replay
            }
            DecapError::AllowedIpsViolation => &self.decap_drops_allowed_ips,
            DecapError::MalformedInner => &self.decap_drops_malformed_inner,
            DecapError::BufferTooSmall => &self.decap_drops_buffer,
        };
        Self::bump(c);
        e
    }

    /// Count an encap failure by reason and hand the error back. The
    /// two `NoSession` arms inside `try_encap` do NOT route through
    /// here — they bump `encap_drops_no_session` /
    /// `encap_drops_unconfirmed` directly at their distinct sites (the
    /// returned variant is the same `NoSession`, so this mapper cannot
    /// tell them apart).
    pub(crate) fn count_encap_err(&self, e: EncapError) -> EncapError {
        let c = match e {
            EncapError::RekeyRequired => &self.encap_drops_rekey_required,
            // Defensive: NoSession should never reach this mapper (see
            // doc above); attribute to no_session rather than lose it.
            EncapError::NoSession => &self.encap_drops_no_session,
            EncapError::UnknownPeer
            | EncapError::CryptoFailed
            | EncapError::BufferTooSmall => &self.encap_drops_other,
        };
        Self::bump(c);
        e
    }

    /// Count an inbound handshake-message drop by reason (msg1 + msg2
    /// consume paths) and hand the error back.
    pub(crate) fn count_handshake_rx_err(&self, e: HandshakeError) -> HandshakeError {
        let c = match &e {
            HandshakeError::Framing(FramingError::Mac1Mismatch) => {
                &self.hs_rx_drops_mac1_mismatch
            }
            HandshakeError::Framing(_) | HandshakeError::OutputTooSmall => {
                &self.hs_rx_drops_malformed
            }
            HandshakeError::Crypto | HandshakeError::Internal => &self.hs_rx_drops_crypto,
            HandshakeError::UnknownInitiator | HandshakeError::UnknownPeer => {
                &self.hs_rx_drops_unknown_peer
            }
            HandshakeError::NoPendingHandshake | HandshakeError::ReceiverIndexMismatch => {
                &self.hs_rx_drops_stale_response
            }
            HandshakeError::IndexExhausted => &self.hs_rx_drops_index_exhausted,
        };
        Self::bump(c);
        e
    }

    /// Stamp a handshake completion (either role) at `now_ns`
    /// (CLOCK_MONOTONIC). `max(1)` keeps a (test-clock) completion at
    /// t=0 distinguishable from "never".
    pub(crate) fn record_handshake_complete(&self, now_ns: u64) {
        self.last_handshake_complete_ns
            .store(now_ns.max(1), Ordering::Relaxed);
    }
}

/// CLOCK_MONOTONIC nanoseconds. Same clock domain (and same
/// implementation) as `crate::afxdp::neighbor::monotonic_nanos` — the
/// status snapshot converts stamps recorded here using that helper's
/// `now_mono`, so the domains MUST match. Duplicated (6 lines) rather
/// than imported to preserve the wg module's documented isolation from
/// the wider afxdp web (wg/mod.rs "Why this module exists in
/// isolation").
pub(crate) fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod counters_tests {
    use super::*;

    #[test]
    fn decap_err_mapping_covers_every_variant() {
        let c = WgCounters::default();
        for e in [
            DecapError::MalformedHeader,
            DecapError::ShortRecord,
            DecapError::UnknownSession,
            DecapError::CounterRejectAfterMessages,
            DecapError::CryptoFailed,
            DecapError::ReplayDuplicate,
            DecapError::ReplayOutOfWindow,
            DecapError::AllowedIpsViolation,
            DecapError::MalformedInner,
            DecapError::BufferTooSmall,
        ] {
            let back = c.count_decap_err(e.clone());
            assert_eq!(back, e, "mapper must hand the error back unchanged");
        }
        assert_eq!(c.decap_drops_malformed_header.load(Ordering::Relaxed), 2);
        assert_eq!(c.decap_drops_replay.load(Ordering::Relaxed), 2);
        assert_eq!(c.decap_drops_unknown_session.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_counter_ceiling.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_crypto.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_allowed_ips.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_malformed_inner.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_buffer.load(Ordering::Relaxed), 1);
        // The keepalive class never routes through the mapper.
        assert_eq!(c.decap_keepalives.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handshake_rx_err_mapping_distinguishes_mac1() {
        let c = WgCounters::default();
        c.count_handshake_rx_err(HandshakeError::Framing(FramingError::Mac1Mismatch));
        c.count_handshake_rx_err(HandshakeError::Framing(FramingError::WrongLength));
        c.count_handshake_rx_err(HandshakeError::OutputTooSmall);
        c.count_handshake_rx_err(HandshakeError::NoPendingHandshake);
        assert_eq!(c.hs_rx_drops_mac1_mismatch.load(Ordering::Relaxed), 1);
        assert_eq!(c.hs_rx_drops_malformed.load(Ordering::Relaxed), 2);
        assert_eq!(c.hs_rx_drops_stale_response.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handshake_complete_stamp_never_zero() {
        let c = WgCounters::default();
        assert_eq!(c.last_handshake_complete_ns.load(Ordering::Relaxed), 0);
        c.record_handshake_complete(0);
        assert_eq!(
            c.last_handshake_complete_ns.load(Ordering::Relaxed),
            1,
            "a t=0 completion must remain distinguishable from never"
        );
    }
}
