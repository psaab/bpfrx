//! WireGuard responder-side cookie-reply / MAC2 under-load DoS mitigation
//! (#4094 PR-A, WG whitepaper §5.4.7 / wireguard-go `device/cookie.go`).
//!
//! ## The attack this defends against
//!
//! MAC1 keys on the responder's *static public* key — which is not secret
//! and does not bind an initiation to its source address. A flood attacker
//! who knows our public key can forge valid-MAC1 initiations with spoofed
//! sources and force one Noise handshake (an X25519 DH + AEAD) per packet:
//! a CPU-exhaustion DoS. MAC2 is the anti-flood layer: when the responder
//! is under load it answers a valid-MAC1 initiation with a *cookie reply*
//! (type-3) instead of running the handshake. The cookie is a keyed MAC
//! over the initiator's REAL source address, so only a peer that actually
//! received the reply at that source can echo a valid MAC2 in its next
//! initiation. Spoofed sources never receive the reply, so their MAC2
//! never validates and the expensive handshake is never spent on them.
//!
//! ## Construction (§5.4.7)
//!
//! - `cookie = MAC(Rm, A_r)` where `MAC = keyed-BLAKE2s-128`, `Rm` is a
//!   random per-responder secret rotated every [`COOKIE_ROTATION_TIME_NS`],
//!   and `A_r` is the initiator's source IP + UDP port (the ACTUAL
//!   datagram source, never a claimed one).
//! - `mac2 = keyed-BLAKE2s-128(cookie, msg[0..offsetof(mac2)])`. The
//!   responder recomputes `cookie` from `Rm` + the current source and
//!   accepts the initiation only if the carried MAC2 matches. When NOT
//!   under load the responder keeps today's spec-correct skip-verify.
//! - The cookie reply carries `cookie` XChaCha20-Poly1305-encrypted under
//!   `key = BLAKE2s-256("cookie--" || responder_static_pub)`, with a
//!   random 24-byte nonce and the triggering initiation's MAC1 as AEAD
//!   associated data. This keeps the cookie opaque on the wire (only a
//!   holder of the responder's public key — i.e. a real configured peer —
//!   can decrypt it and derive a valid MAC2). Decrypting the reply is
//!   PR-B (the xpf-as-initiator interop half); this module is responder-
//!   only, plus a `#[cfg(test)]` decrypt mirror that doubles as the PR-B
//!   reference.
//!
//! ## Secret rotation window
//!
//! wireguard-go holds a single secret and re-challenges across a rotation
//! boundary; the #4094 plan keeps the PREVIOUS secret for one rotation
//! window so a cookie issued just before a rotation still validates its
//! MAC2 (avoids dropping a just-challenged peer that happened to straddle
//! the boundary). A gap of two or more full windows with no activity
//! starts fresh with no previous, bounding any secret's validity to under
//! `2 * COOKIE_ROTATION_TIME_NS`.
//!
//! ## Isolation
//!
//! Like the rest of `wg/`, this module stays free of the wider `afxdp`
//! type web (only `std` + the crypto crates). The load gate, secret
//! rotation, and reply budget are all `std::sync::Mutex`-guarded; the sole
//! caller is the per-tunnel control thread (`dispatch_inbound`), so the
//! locks are effectively uncontended — they exist for `&self` interior
//! mutability, not cross-thread contention. NEVER log a secret, a cookie,
//! or the encryption key.

use std::net::SocketAddr;
use std::sync::Mutex;

use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{Digest, FixedOutput, KeyInit, Update};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Key, KeyInit as AeadKeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::{WG_KEY_LEN, WG_LABEL_COOKIE, WG_MAC_LEN, WG_MSG_INIT_LEN, WG_TYPE_COOKIE};

/// Responder cookie secret (`Rm`) rotation period. Mirrors wireguard-go
/// `CookieRefreshTime` / kernel `COOKIE_SECRET_MAX_AGE` (2 minutes).
pub(crate) const COOKIE_ROTATION_TIME_NS: u64 = 120 * 1_000_000_000;

/// Fixed-window width for the inbound-initiation rate gate.
const UNDER_LOAD_WINDOW_NS: u64 = 1_000_000_000;

/// Once the initiation rate trips the threshold, stay "under load" for
/// this grace period even if the rate falls back — mirrors wireguard-go's
/// `UnderLoadAfterTime` (1 s). Prevents flapping in and out of the cookie
/// path at the threshold boundary.
const UNDER_LOAD_GRACE_NS: u64 = 1_000_000_000;

/// Inbound type-1 initiations per [`UNDER_LOAD_WINDOW_NS`] window above
/// which the responder declares itself "under load" and starts issuing
/// cookie challenges. wireguard-go's analog is a handshake-queue depth of
/// `QueueHandshakeSize/8 == 128`; we process initiations inline (no
/// queue), so a per-second arrival rate is the natural equivalent. 25/s
/// to a single tunnel is far above any legitimate rekey pattern (WG rekeys
/// every ~2 min per peer) yet well below a flood — a conservative floor.
/// Tripping it only adds one cookie round-trip to an honest peer's
/// handshake (self-healing), so a false positive degrades latency, never
/// connectivity. Tunable named constant, not a magic number.
pub(crate) const INITIATIONS_UNDER_LOAD_THRESHOLD: u64 = 25;

/// Cap on cookie replies *emitted* per [`UNDER_LOAD_WINDOW_NS`] window.
/// A valid-MAC1 flood (attacker knows our public key) would otherwise draw
/// one 64-byte reply per initiation; the reply is far cheaper than a
/// handshake (one keyed-BLAKE2s + one XChaCha of 16 bytes) and is
/// de-amplifying (64 B out per 148 B in), but this budget still bounds the
/// CPU/socket cost of the generated-reply burst so it cannot itself become
/// a sink — the WG analog of the syn-cookie reply-budget discipline
/// (#4094 plan item 6). Over budget → the initiation is dropped WITHOUT a
/// reply (`hs_cookie_reply_budget_drops`); an honest peer retries and is
/// challenged in the next window. WG cookie replies leave via the tunnel's
/// UDP socket (not the AF_XDP TX ring), so this bounds CPU/socket load
/// rather than TX-ring descriptors.
pub(crate) const COOKIE_REPLY_BUDGET_PER_WINDOW: u64 = 40;

/// Cookie MAC length (keyed-BLAKE2s-128 output).
pub(crate) const WG_COOKIE_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length carried in the cookie reply.
pub(crate) const WG_COOKIE_NONCE_LEN: usize = 24;

/// WG type-3 CookieReply wire length:
///   type(1) + reserved(3) + receiver_index(4) + nonce(24)
///   + encrypted_cookie(16 + 16 tag) = 64.
pub(crate) const WG_MSG_COOKIE_LEN: usize = 1 + 3 + 4 + WG_COOKIE_NONCE_LEN + WG_COOKIE_LEN + 16;

// Type-3 field offsets.
const M3_RECEIVER: usize = 4;
const M3_NONCE: usize = 8;
const M3_COOKIE: usize = M3_NONCE + WG_COOKIE_NONCE_LEN; // 32
const _: () = assert!(M3_COOKIE + WG_COOKIE_LEN + 16 == WG_MSG_COOKIE_LEN);

// MAC2 lives at msg[132..148]; the MAC covers msg[0..132] (through MAC1).
const M1_MAC2: usize = WG_MSG_INIT_LEN - WG_MAC_LEN; // 132
const M1_MAC1: usize = M1_MAC2 - WG_MAC_LEN; // 116

/// Cookie-reply build failures. All non-fatal at the call site (the init
/// is simply dropped without a reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieError {
    /// Output buffer smaller than [`WG_MSG_COOKIE_LEN`].
    OutputTooSmall,
    /// The triggering initiation was not exactly [`WG_MSG_INIT_LEN`].
    WrongInitLength,
    /// XChaCha20-Poly1305 sealing failed (structurally impossible for a
    /// 16-byte plaintext; folded rather than panicked).
    Crypto,
}

/// Keyed-BLAKE2s with 16-byte output — the WG `MAC()` primitive. `key` may
/// be up to 32 bytes (BLAKE2s keyed-hash bound); the cookie secret is 32,
/// the cookie itself is 16. NOT HMAC.
fn keyed_blake2s_128(key: &[u8], data: &[u8]) -> [u8; WG_COOKIE_LEN] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("BLAKE2s keyed-hash key length <= 32");
    Update::update(&mut mac, data);
    let mut out = [0u8; WG_COOKIE_LEN];
    FixedOutput::finalize_into(mac, (&mut out).into());
    out
}

/// The cookie-reply AEAD key: `BLAKE2s-256("cookie--" || responder_pub)`.
fn cookie_encryption_key(our_static_pub: &[u8; WG_KEY_LEN]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    Digest::update(&mut h, WG_LABEL_COOKIE);
    Digest::update(&mut h, our_static_pub);
    h.finalize().into()
}

/// Serialize a datagram source into the bytes the cookie MAC covers:
/// canonical IP octets (4 for v4, 16 for v6) followed by the 2-byte
/// big-endian UDP port. Returns a fixed 18-byte buffer plus the used
/// length. This binding is an internal responder detail — the cookie is
/// opaque to the initiator (which only echoes it via MAC2), so the format
/// need only be self-consistent between [`build_cookie_reply`] and
/// [`verify_initiation_mac2`]. A v4-mapped v6 source is canonicalized to
/// v4 first so a peer seen once as `a.b.c.d` and once as `::ffff:a.b.c.d`
/// gets the same cookie.
fn endpoint_cookie_bytes(addr: SocketAddr) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    let n = match super::canonicalize_endpoint(addr) {
        SocketAddr::V4(v4) => {
            buf[0..4].copy_from_slice(&v4.ip().octets());
            buf[4..6].copy_from_slice(&v4.port().to_be_bytes());
            6
        }
        SocketAddr::V6(v6) => {
            buf[0..16].copy_from_slice(&v6.ip().octets());
            buf[16..18].copy_from_slice(&v6.port().to_be_bytes());
            18
        }
    };
    (buf, n)
}

/// Constant-time-ish 16-byte MAC comparison (fold, no short-circuit).
#[inline]
fn macs_equal(a: &[u8; WG_COOKIE_LEN], b: &[u8]) -> bool {
    if b.len() != WG_COOKIE_LEN {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..WG_COOKIE_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Two-slot responder secret with lazy first-use init and a one-window
/// carry of the previous secret.
struct SecretState {
    current: Zeroizing<[u8; 32]>,
    previous: Zeroizing<[u8; 32]>,
    has_previous: bool,
    /// Monotonic ns the `current` secret was generated. 0 = never
    /// initialized (lazy: the first observer stamps it without rotating,
    /// so a large monotonic clock does not force an immediate rotation).
    generated_at_ns: u64,
}

/// Fixed-window inbound-initiation rate gate plus a sticky under-load
/// grace window.
struct LoadState {
    window_start_ns: u64,
    count: u64,
    under_load_until_ns: u64,
}

/// Fixed-window cookie-reply emission budget.
struct BudgetState {
    window_start_ns: u64,
    emitted: u64,
}

/// Responder cookie checker: secret rotation + load detection + reply
/// budget + MAC2 verification, all keyed to one tunnel's responder static
/// key. One per [`super::WgEngine`].
pub(crate) struct CookieChecker {
    /// `BLAKE2s-256("cookie--" || our_pub)`. Public-key-derived, not
    /// secret, but never logged for hygiene.
    enc_key: [u8; 32],
    secret: Mutex<SecretState>,
    load: Mutex<LoadState>,
    budget: Mutex<BudgetState>,
}

impl CookieChecker {
    pub(crate) fn new(our_static_pub: &[u8; WG_KEY_LEN]) -> Self {
        let mut current = [0u8; 32];
        fill_random(&mut current);
        Self {
            enc_key: cookie_encryption_key(our_static_pub),
            secret: Mutex::new(SecretState {
                current: Zeroizing::new(current),
                previous: Zeroizing::new([0u8; 32]),
                has_previous: false,
                generated_at_ns: 0,
            }),
            load: Mutex::new(LoadState {
                window_start_ns: 0,
                count: 0,
                under_load_until_ns: 0,
            }),
            budget: Mutex::new(BudgetState {
                window_start_ns: 0,
                emitted: 0,
            }),
        }
    }

    /// Record one inbound initiation arrival at `now_ns` and return whether
    /// the responder is currently under load. Fixed-window count with a
    /// sticky grace: crossing the threshold arms the under-load state for
    /// [`UNDER_LOAD_GRACE_NS`].
    pub(crate) fn note_initiation(&self, now_ns: u64) -> bool {
        let mut s = self.load.lock().unwrap();
        if s.window_start_ns == 0
            || now_ns.saturating_sub(s.window_start_ns) >= UNDER_LOAD_WINDOW_NS
        {
            s.window_start_ns = now_ns;
            s.count = 1;
        } else {
            s.count = s.count.saturating_add(1);
        }
        if s.count > INITIATIONS_UNDER_LOAD_THRESHOLD {
            s.under_load_until_ns = now_ns.saturating_add(UNDER_LOAD_GRACE_NS);
        }
        now_ns < s.under_load_until_ns
    }

    /// True iff a cookie reply may still be emitted in the current window
    /// (and reserves one slot). Fixed-window budget mirroring the load gate.
    pub(crate) fn reply_budget_available(&self, now_ns: u64) -> bool {
        let mut b = self.budget.lock().unwrap();
        if b.window_start_ns == 0
            || now_ns.saturating_sub(b.window_start_ns) >= UNDER_LOAD_WINDOW_NS
        {
            b.window_start_ns = now_ns;
            b.emitted = 0;
        }
        if b.emitted >= COOKIE_REPLY_BUDGET_PER_WINDOW {
            return false;
        }
        b.emitted += 1;
        true
    }

    /// Rotate the secret if `current` is older than one rotation window,
    /// then return `(current, previous_if_still_valid)`. Lazy first-use
    /// init stamps `generated_at_ns` without rotating. A gap of two or more
    /// full windows starts fresh with no previous (bounds any secret's
    /// validity to `< 2 * COOKIE_ROTATION_TIME_NS`).
    fn secrets(&self, now_ns: u64) -> ([u8; 32], Option<[u8; 32]>) {
        let mut s = self.secret.lock().unwrap();
        if s.generated_at_ns == 0 {
            s.generated_at_ns = now_ns;
        } else {
            let gap = now_ns.saturating_sub(s.generated_at_ns);
            if gap >= 2 * COOKIE_ROTATION_TIME_NS {
                // Both slots would be stale; discard the previous.
                let mut fresh = [0u8; 32];
                fill_random(&mut fresh);
                *s.current = fresh;
                *s.previous = [0u8; 32];
                s.has_previous = false;
                s.generated_at_ns = now_ns;
            } else if gap >= COOKIE_ROTATION_TIME_NS {
                *s.previous = *s.current;
                let mut fresh = [0u8; 32];
                fill_random(&mut fresh);
                *s.current = fresh;
                s.has_previous = true;
                s.generated_at_ns = now_ns;
            }
        }
        let prev = if s.has_previous {
            Some(*s.previous)
        } else {
            None
        };
        (*s.current, prev)
    }

    /// Verify the MAC2 carried in an inbound type-1 initiation `msg`
    /// against the cookie the responder would have issued to this exact
    /// datagram source (`from`), under the current secret and — within the
    /// carry window — the previous one. Returns false for a wrong-length
    /// message or a zero/absent MAC2 (the cookie is non-zero). Slow path.
    pub(crate) fn verify_initiation_mac2(&self, msg: &[u8], from: SocketAddr, now_ns: u64) -> bool {
        if msg.len() != WG_MSG_INIT_LEN {
            return false;
        }
        let got = &msg[M1_MAC2..WG_MSG_INIT_LEN];
        let (src, n) = endpoint_cookie_bytes(from);
        let src = &src[..n];
        let (cur, prev) = self.secrets(now_ns);
        let cookie_cur = keyed_blake2s_128(&cur, src);
        let expect_cur = keyed_blake2s_128(&cookie_cur, &msg[..M1_MAC2]);
        if macs_equal(&expect_cur, got) {
            return true;
        }
        if let Some(prev) = prev {
            let cookie_prev = keyed_blake2s_128(&prev, src);
            let expect_prev = keyed_blake2s_128(&cookie_prev, &msg[..M1_MAC2]);
            if macs_equal(&expect_prev, got) {
                return true;
            }
        }
        false
    }

    /// Build a WG type-3 CookieReply for the initiation `init_msg` that
    /// arrived from `from`, writing it at `out[0..WG_MSG_COOKIE_LEN]`. The
    /// cookie binds to `from` (the ACTUAL datagram source); it is sealed
    /// under XChaCha20-Poly1305 with a fresh random nonce and the
    /// initiation's MAC1 as AEAD associated data. Echoes the initiator's
    /// sender_index as the reply's receiver_index. Slow path.
    pub(crate) fn build_cookie_reply(
        &self,
        init_msg: &[u8],
        from: SocketAddr,
        now_ns: u64,
        out: &mut [u8],
    ) -> Result<usize, CookieError> {
        if out.len() < WG_MSG_COOKIE_LEN {
            return Err(CookieError::OutputTooSmall);
        }
        if init_msg.len() != WG_MSG_INIT_LEN {
            return Err(CookieError::WrongInitLength);
        }
        let (src, n) = endpoint_cookie_bytes(from);
        let (cur, _) = self.secrets(now_ns);
        let cookie = keyed_blake2s_128(&cur, &src[..n]);

        let mut nonce = [0u8; WG_COOKIE_NONCE_LEN];
        fill_random(&mut nonce);

        // AEAD associated data = the triggering initiation's MAC1.
        let aad = &init_msg[M1_MAC1..M1_MAC2];
        let mut sealed = cookie; // 16-byte plaintext, encrypted in place.
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.enc_key));
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut sealed)
            .map_err(|_| CookieError::Crypto)?;

        let msg = &mut out[..WG_MSG_COOKIE_LEN];
        msg[0] = WG_TYPE_COOKIE;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 0;
        // receiver_index echoes the initiator's sender_index (LE).
        msg[M3_RECEIVER..M3_RECEIVER + 4].copy_from_slice(&init_msg[4..8]);
        msg[M3_NONCE..M3_COOKIE].copy_from_slice(&nonce);
        msg[M3_COOKIE..M3_COOKIE + WG_COOKIE_LEN].copy_from_slice(&sealed);
        msg[M3_COOKIE + WG_COOKIE_LEN..WG_MSG_COOKIE_LEN].copy_from_slice(tag.as_slice());
        Ok(WG_MSG_COOKIE_LEN)
    }

    // --- test-only mirrors of the PR-B initiator decrypt + secret peek ---

    /// Decrypt a type-3 CookieReply the way the xpf-as-initiator half
    /// (PR-B) will: recover the 16-byte cookie with the responder's
    /// public-key-derived AEAD key, the reply's nonce, and the AAD MAC1 of
    /// the initiation that triggered it. `#[cfg(test)]` reference until
    /// PR-B wires it into the initiator path.
    #[cfg(test)]
    pub(crate) fn decrypt_cookie_reply(
        reply: &[u8],
        our_static_pub: &[u8; WG_KEY_LEN],
        aad_mac1: &[u8],
    ) -> Option<[u8; WG_COOKIE_LEN]> {
        if reply.len() != WG_MSG_COOKIE_LEN || reply[0] != WG_TYPE_COOKIE {
            return None;
        }
        let key = cookie_encryption_key(our_static_pub);
        let nonce = &reply[M3_NONCE..M3_COOKIE];
        let mut buf = [0u8; WG_COOKIE_LEN];
        buf.copy_from_slice(&reply[M3_COOKIE..M3_COOKIE + WG_COOKIE_LEN]);
        let tag = &reply[M3_COOKIE + WG_COOKIE_LEN..WG_MSG_COOKIE_LEN];
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                aad_mac1,
                &mut buf,
                chacha20poly1305::Tag::from_slice(tag),
            )
            .ok()?;
        Some(buf)
    }

    /// The cookie the responder would issue for `from` under the CURRENT
    /// secret at `now_ns` (rotating first if due). Test hook for the
    /// rotation-window vectors.
    #[cfg(test)]
    pub(crate) fn cookie_for_test(&self, from: SocketAddr, now_ns: u64) -> [u8; WG_COOKIE_LEN] {
        let (src, n) = endpoint_cookie_bytes(from);
        let (cur, _) = self.secrets(now_ns);
        keyed_blake2s_128(&cur, &src[..n])
    }
}

/// Fill `buf` with OS randomness; fall back to a time-seeded xorshift only
/// if `getrandom` fails (never expected on Linux). A weak fallback secret
/// still binds a cookie to a source for the window — degraded, not broken.
fn fill_random(buf: &mut [u8]) {
    if getrandom::getrandom(buf).is_ok() {
        return;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    for b in buf.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed >> 24) as u8;
    }
}

/// Stamp `mac2` (keyed-BLAKE2s-128 over `msg[0..132]` with `cookie` as the
/// key) into a type-1 initiation's MAC2 slot. This is what a real
/// initiator does with a decrypted cookie; used by tests and, later, PR-B.
#[cfg(test)]
pub(crate) fn stamp_initiation_mac2(msg: &mut [u8; WG_MSG_INIT_LEN], cookie: &[u8; WG_COOKIE_LEN]) {
    let mac2 = keyed_blake2s_128(cookie, &msg[..M1_MAC2]);
    msg[M1_MAC2..WG_MSG_INIT_LEN].copy_from_slice(&mac2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::wg::handshake::{self, MSG_INIT_NOISE_LEN};

    fn src(port: u16) -> SocketAddr {
        format!("203.0.113.7:{port}").parse().unwrap()
    }

    fn valid_mac1_init(our_pub: &[u8; 32], sender_index: u32) -> [u8; WG_MSG_INIT_LEN] {
        let noise = [0x5Au8; MSG_INIT_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        handshake::build_initiation(&mut buf, sender_index, &noise, our_pub).unwrap();
        buf
    }

    #[test]
    fn cookie_reply_length_and_type() {
        assert_eq!(WG_MSG_COOKIE_LEN, 64);
        let our_pub = [0x11u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let init = valid_mac1_init(&our_pub, 0xABCD);
        let mut out = [0u8; 128];
        let len = cc
            .build_cookie_reply(&init, src(51820), 10_000_000_000, &mut out)
            .unwrap();
        assert_eq!(len, WG_MSG_COOKIE_LEN);
        assert_eq!(out[0], WG_TYPE_COOKIE);
        assert_eq!(&out[1..4], &[0, 0, 0], "reserved zero");
        // receiver_index echoes the initiator's sender_index.
        assert_eq!(&out[M3_RECEIVER..M3_RECEIVER + 4], &init[4..8]);
    }

    /// End-to-end: a cookie reply decrypts (PR-B mirror) to the cookie the
    /// responder would recompute, and a MAC2 stamped from that cookie
    /// verifies. A DIFFERENT source (spoofed) does NOT verify.
    #[test]
    fn cookie_reply_roundtrip_and_source_binding() {
        let our_pub = [0x22u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let now = 10_000_000_000;
        let real = src(51820);
        let init = valid_mac1_init(&our_pub, 7);
        let mut reply = [0u8; 64];
        cc.build_cookie_reply(&init, real, now, &mut reply).unwrap();

        // Initiator (PR-B) decrypts using the responder pubkey + the
        // initiation's MAC1 as AAD.
        let aad = &init[M1_MAC1..M1_MAC2];
        let cookie = CookieChecker::decrypt_cookie_reply(&reply, &our_pub, aad).expect("decrypts");

        // Stamp MAC2 and verify from the SAME source → accepted.
        let mut init2 = init;
        stamp_initiation_mac2(&mut init2, &cookie);
        assert!(
            cc.verify_initiation_mac2(&init2, real, now),
            "same-source MAC2 verifies"
        );

        // The same MAC2 replayed from a DIFFERENT source → rejected (the
        // cookie is bound to the source that received the reply).
        let spoof = src(51821);
        assert!(
            !cc.verify_initiation_mac2(&init2, spoof, now),
            "MAC2 must not verify from a different source"
        );

        // Wrong AAD MAC1 fails the AEAD entirely.
        let bad_aad = [0u8; WG_MAC_LEN];
        assert!(CookieChecker::decrypt_cookie_reply(&reply, &our_pub, &bad_aad).is_none());
    }

    /// A zero / absent MAC2 (a normal not-yet-challenged initiation) never
    /// verifies — the cookie is non-zero.
    #[test]
    fn zero_mac2_never_verifies() {
        let our_pub = [0x33u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let init = valid_mac1_init(&our_pub, 1); // build_initiation zeroes MAC2
        assert_eq!(&init[M1_MAC2..], &[0u8; 16]);
        assert!(!cc.verify_initiation_mac2(&init, src(1), 10_000_000_000));
    }

    /// Secret rotation with the one-window previous-secret carry: a cookie
    /// issued under the original secret still validates after ONE rotation
    /// (previous window) but NOT after two (secret aged out).
    #[test]
    fn secret_rotation_previous_window() {
        let our_pub = [0x44u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let peer = src(51820);
        let t0 = 10_000_000_000; // 10 s (nonzero → lazy init stamps here)

        // Cookie + MAC2 minted under the original secret at t0.
        let cookie0 = cc.cookie_for_test(peer, t0);
        let mut init = valid_mac1_init(&our_pub, 9);
        stamp_initiation_mac2(&mut init, &cookie0);
        assert!(
            cc.verify_initiation_mac2(&init, peer, t0),
            "current secret validates"
        );

        // One rotation later (t0 + 130 s > 120 s): current rotates, the
        // original becomes `previous` → the old MAC2 STILL validates.
        let t1 = t0 + 130 * 1_000_000_000;
        assert!(
            cc.verify_initiation_mac2(&init, peer, t1),
            "previous-secret window keeps a just-challenged peer valid across a rotation"
        );

        // A second rotation later (another +130 s): the original has aged
        // out of both slots → the old MAC2 no longer validates.
        let t2 = t1 + 130 * 1_000_000_000;
        assert!(
            !cc.verify_initiation_mac2(&init, peer, t2),
            "secret aged past the previous window no longer validates"
        );
    }

    #[test]
    fn load_gate_trips_over_threshold_and_grace_holds() {
        let our_pub = [0x55u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let base = 10_000_000_000;
        // First arrival: not under load.
        assert!(!cc.note_initiation(base));
        // Drive past the threshold within the same 1 s window.
        let mut under = false;
        for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 2) {
            under = cc.note_initiation(base);
        }
        assert!(
            under,
            "crossing the per-window threshold declares under-load"
        );
        // Grace holds for ~1 s even with no further arrivals accounted.
        assert!(
            cc.note_initiation(base + 500_000_000),
            "grace still under load"
        );
        // Well past the grace window with a fresh (low-rate) window → clear.
        assert!(!cc.note_initiation(base + 3_000_000_000));
    }

    #[test]
    fn reply_budget_caps_per_window() {
        let our_pub = [0x66u8; 32];
        let cc = CookieChecker::new(&our_pub);
        let base = 10_000_000_000;
        let mut granted = 0u64;
        for _ in 0..(COOKIE_REPLY_BUDGET_PER_WINDOW + 10) {
            if cc.reply_budget_available(base) {
                granted += 1;
            }
        }
        assert_eq!(
            granted, COOKIE_REPLY_BUDGET_PER_WINDOW,
            "budget caps emission per window"
        );
        // A new window refills.
        assert!(cc.reply_budget_available(base + UNDER_LOAD_WINDOW_NS));
    }
}
