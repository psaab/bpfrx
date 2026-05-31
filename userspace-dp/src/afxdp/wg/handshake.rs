//! WireGuard on-wire handshake-message framing (message types 1 and 2).
//!
//! The engine ([`super::engine`]) drives the Noise IKpsk2 handshake through
//! `snow`, which emits only the raw Noise message body. This module wraps
//! that body in the WireGuard outer framing so the bytes are byte-identical
//! to what kernel WireGuard / wireguard-go / UniFi put on the wire:
//!
//! ## Message 1 — Handshake Initiation (148 bytes)
//!
//! ```text
//!   off  size  field
//!    0    1    message_type = 1
//!    1    3    reserved_zero = {0,0,0}
//!    4    4    sender_index            (LE u32, initiator-chosen)
//!    8   32    unencrypted_ephemeral   ─┐
//!   40   48    encrypted_static (32+16) ├─ snow IK msg1 body (108 bytes)
//!   88   28    encrypted_timestamp(12+16)┘  Noise payload = 12-byte TAI64N
//!  116   16    mac1
//!  132   16    mac2
//! ```
//!
//! ## Message 2 — Handshake Response (92 bytes)
//!
//! ```text
//!   off  size  field
//!    0    1    message_type = 2
//!    1    3    reserved_zero = {0,0,0}
//!    4    4    sender_index            (LE u32, responder-chosen)
//!    8    4    receiver_index          (LE u32, echoes msg1.sender_index)
//!   12   32    unencrypted_ephemeral   ─┐ snow IK msg2 body (48 bytes)
//!   44   16    encrypted_nothing (0+16) ┘  Noise payload = empty
//!   60   16    mac1
//!   76   16    mac2
//! ```
//!
//! ## MAC1
//!
//! `mac1 = keyed-BLAKE2s-128(key, msg[0 .. offsetof(mac1)])` where
//! `key = BLAKE2s-256(LABEL_MAC1 || recipient_static_public)` and
//! `LABEL_MAC1 = b"mac1----"`. The MAC keys on the RECIPIENT's static
//! public key: for msg1 the recipient is the responder, for msg2 the
//! recipient is the initiator. This is keyed-BLAKE2s, NOT HMAC — the KAT
//! tests pin the distinction (an HMAC over the same key/message yields a
//! different value).
//!
//! ## MAC2
//!
//! `mac2 = keyed-BLAKE2s-128(last_received_cookie, msg[0 .. offsetof(mac2)])`
//! or all-zeros when no cookie has been received. S1 only ever emits zeros
//! (cookie/type-3 handling is #1703 S7) and SKIP-verifies inbound mac2 (a
//! peer holding our cookie sets it; treating non-zero as malformed would
//! wrongly drop such a peer). mac2 generation/verification lands in S7.

use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::digest::Digest;

use super::{
    WG_KEY_LEN, WG_LABEL_MAC1, WG_MAC_LEN, WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN,
    WG_TYPE_INITIATION, WG_TYPE_RESPONSE,
};

/// snow IK message-1 Noise body length:
///   ephemeral(32) + encrypted_static(32+16) + encrypted_timestamp(12+16).
pub(crate) const MSG_INIT_NOISE_LEN: usize = 32 + (32 + 16) + (12 + 16); // 108

/// snow IK message-2 Noise body length:
///   ephemeral(32) + encrypted_nothing(0+16).
pub(crate) const MSG_RESPONSE_NOISE_LEN: usize = 32 + 16; // 48

// Message-1 field offsets.
const M1_TYPE: usize = 0;
const M1_SENDER: usize = 4;
const M1_NOISE: usize = 8;
const M1_MAC1: usize = M1_NOISE + MSG_INIT_NOISE_LEN; // 116
const M1_MAC2: usize = M1_MAC1 + WG_MAC_LEN; // 132

// Message-2 field offsets.
const M2_TYPE: usize = 0;
const M2_SENDER: usize = 4;
const M2_RECEIVER: usize = 8;
const M2_NOISE: usize = 12;
const M2_MAC1: usize = M2_NOISE + MSG_RESPONSE_NOISE_LEN; // 60
const M2_MAC2: usize = M2_MAC1 + WG_MAC_LEN; // 76

// Compile-time invariants: the offset arithmetic must agree with the
// published wire lengths.
const _: () = assert!(M1_MAC2 + WG_MAC_LEN == WG_MSG_INIT_LEN);
const _: () = assert!(M2_MAC2 + WG_MAC_LEN == WG_MSG_RESPONSE_LEN);

/// Framing errors. All variants are non-fatal at the call site (the slow
/// path counts them); a malformed or unauthenticated message is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// The datagram length is not EXACTLY the fixed message size. WG
    /// handshake messages are fixed-length (148 / 92 bytes); kernel WG and
    /// wireguard-go reject `len != MessageInitiationSize` / `MessageResponseSize`
    /// outright. We reject both too-short AND too-long (a trailing-garbage
    /// datagram whose 148/92-byte prefix happens to verify must not parse).
    WrongLength,
    /// Output buffer too small to hold the framed message.
    OutputTooSmall,
    /// `message_type` byte is not the expected 1 (init) or 2 (response).
    BadType,
    /// The supplied Noise body length does not match the message type.
    BadNoiseLen,
    /// mac1 did not verify against `BLAKE2s-256(LABEL_MAC1 || our_pub)`.
    /// A compliant peer (and kernel WG) drops the datagram here, before
    /// any Noise crypto.
    Mac1Mismatch,
}

/// Compute the keyed-BLAKE2s-128 MAC1 over `data` using the recipient's
/// static public key.
///
/// `key = BLAKE2s-256(LABEL_MAC1 || recipient_static_pub)`,
/// `mac1 = keyed-BLAKE2s-128(key, data)`.
///
/// Slow path only (handshake build/parse), never per-packet.
pub(crate) fn compute_mac1(recipient_static_pub: &[u8; WG_KEY_LEN], data: &[u8]) -> [u8; WG_MAC_LEN] {
    // key = BLAKE2s-256("mac1----" || recipient_pub)
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, WG_LABEL_MAC1);
    Digest::update(&mut hasher, recipient_static_pub);
    let key = hasher.finalize();

    // mac1 = keyed-BLAKE2s with 16-byte output. NOT HMAC.
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key)
        .expect("BLAKE2s-256 digest is a valid 32-byte BLAKE2s key");
    Update::update(&mut mac, data);
    let mut out = [0u8; WG_MAC_LEN];
    FixedOutput::finalize_into(mac, (&mut out).into());
    out
}

/// Constant-time-ish comparison of two 16-byte MACs. MAC1 is computed over
/// public inputs (the message + a public key + a public label), so it is
/// not a secret-key comparison in the AEAD sense; nonetheless we avoid an
/// early-return byte loop to keep the habit. (`subtle` is not a dep here;
/// the fold avoids the short-circuit.)
#[inline]
fn macs_equal(a: &[u8; WG_MAC_LEN], b: &[u8; WG_MAC_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..WG_MAC_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// A WG type-1 initiation produced by [`build_initiation`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BuiltInitiation {
    pub len: usize,
}

/// Frame a WG type-1 initiation around a snow msg1 Noise body.
///
/// - `out` must be at least [`WG_MSG_INIT_LEN`] (148) bytes; the framed
///   message is written at `out[0..148]`.
/// - `sender_index` is the initiator's locally-chosen index (LE on wire).
/// - `noise_body` is exactly what snow `write_message(tai64n, ..)` produced
///   — must be [`MSG_INIT_NOISE_LEN`] (108) bytes.
/// - `responder_static_pub` keys mac1 (the recipient of msg1).
/// - mac2 is all-zeros in S1.
pub(crate) fn build_initiation(
    out: &mut [u8],
    sender_index: u32,
    noise_body: &[u8],
    responder_static_pub: &[u8; WG_KEY_LEN],
) -> Result<BuiltInitiation, FramingError> {
    if noise_body.len() != MSG_INIT_NOISE_LEN {
        return Err(FramingError::BadNoiseLen);
    }
    let msg = out.get_mut(..WG_MSG_INIT_LEN).ok_or(FramingError::OutputTooSmall)?;
    msg[M1_TYPE] = WG_TYPE_INITIATION;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[M1_SENDER..M1_SENDER + 4].copy_from_slice(&sender_index.to_le_bytes());
    msg[M1_NOISE..M1_MAC1].copy_from_slice(noise_body);
    // mac1 over msg[0..116].
    let mac1 = compute_mac1(responder_static_pub, &msg[..M1_MAC1]);
    msg[M1_MAC1..M1_MAC2].copy_from_slice(&mac1);
    // mac2 = zeros (S1).
    msg[M1_MAC2..WG_MSG_INIT_LEN].fill(0);
    Ok(BuiltInitiation {
        len: WG_MSG_INIT_LEN,
    })
}

/// A parsed WG type-1 initiation. Borrows the Noise body from the input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedInitiation<'a> {
    pub sender_index: u32,
    pub noise_body: &'a [u8],
}

/// Parse + authenticate a WG type-1 initiation.
///
/// `our_static_pub` is xpf's own static public key — the recipient key for
/// an inbound initiation; mac1 is verified against
/// `BLAKE2s-256(LABEL_MAC1 || our_static_pub)`. mac2 is NOT verified in S1
/// (skip-verify; a peer holding our cookie legitimately sets it). The
/// returned `noise_body` (108 bytes) is fed to snow `read_message`.
pub(crate) fn parse_initiation<'a>(
    msg: &'a [u8],
    our_static_pub: &[u8; WG_KEY_LEN],
) -> Result<ParsedInitiation<'a>, FramingError> {
    // WG handshake messages are fixed-length; require EXACTLY 148 bytes
    // (kernel WG / wireguard-go reject any other length).
    if msg.len() != WG_MSG_INIT_LEN {
        return Err(FramingError::WrongLength);
    }
    // WG's message_type is a 32-bit little-endian word: a canonical
    // initiation is exactly 0x00000001, i.e. type byte = 1 AND the three
    // reserved bytes = 0. wireguard-go / kernel WG read the full u32 and
    // reject a non-canonical high byte, so we do too (strict parse). This is
    // also belt-and-suspenders: mac1 already covers bytes [0..116] including
    // the reserved bytes, so a forged non-zero-reserved datagram would fail
    // mac1 regardless — but rejecting it up front keeps us byte-strict.
    if !is_canonical_type(msg, WG_TYPE_INITIATION) {
        return Err(FramingError::BadType);
    }
    // Verify mac1 over msg[0..116] BEFORE handing the body to snow — kernel
    // WG drops on a bad mac1 before any crypto, and so do we.
    let expect = compute_mac1(our_static_pub, &msg[..M1_MAC1]);
    let got = {
        let mut m = [0u8; WG_MAC_LEN];
        m.copy_from_slice(&msg[M1_MAC1..M1_MAC2]);
        m
    };
    if !macs_equal(&expect, &got) {
        return Err(FramingError::Mac1Mismatch);
    }
    // mac2 (msg[132..148]) is skip-verified in S1 (cookie handling is S7).
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    Ok(ParsedInitiation {
        sender_index,
        noise_body: &msg[M1_NOISE..M1_MAC1],
    })
}

/// True iff `msg`'s leading 4 bytes are exactly the little-endian u32
/// `expected_type` — i.e. the type byte matches AND the three reserved bytes
/// are zero. WG transmits `message_type` as a u32; a compliant peer's
/// initiation/response always has zero reserved bytes.
#[inline]
fn is_canonical_type(msg: &[u8], expected_type: u8) -> bool {
    let word = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
    word == expected_type as u32
}

/// A WG type-2 response produced by [`build_response`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BuiltResponse {
    pub len: usize,
}

/// Frame a WG type-2 response around a snow msg2 Noise body.
///
/// - `out` must be at least [`WG_MSG_RESPONSE_LEN`] (92) bytes.
/// - `sender_index` is the responder's locally-chosen index.
/// - `receiver_index` MUST echo the initiator's msg1 sender_index.
/// - `noise_body` is snow `write_message(&[], ..)` output — must be
///   [`MSG_RESPONSE_NOISE_LEN`] (48) bytes.
/// - `initiator_static_pub` keys mac1 (the recipient of msg2).
pub(crate) fn build_response(
    out: &mut [u8],
    sender_index: u32,
    receiver_index: u32,
    noise_body: &[u8],
    initiator_static_pub: &[u8; WG_KEY_LEN],
) -> Result<BuiltResponse, FramingError> {
    if noise_body.len() != MSG_RESPONSE_NOISE_LEN {
        return Err(FramingError::BadNoiseLen);
    }
    let msg = out.get_mut(..WG_MSG_RESPONSE_LEN).ok_or(FramingError::OutputTooSmall)?;
    msg[M2_TYPE] = WG_TYPE_RESPONSE;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[M2_SENDER..M2_SENDER + 4].copy_from_slice(&sender_index.to_le_bytes());
    msg[M2_RECEIVER..M2_RECEIVER + 4].copy_from_slice(&receiver_index.to_le_bytes());
    msg[M2_NOISE..M2_MAC1].copy_from_slice(noise_body);
    let mac1 = compute_mac1(initiator_static_pub, &msg[..M2_MAC1]);
    msg[M2_MAC1..M2_MAC2].copy_from_slice(&mac1);
    msg[M2_MAC2..WG_MSG_RESPONSE_LEN].fill(0);
    Ok(BuiltResponse {
        len: WG_MSG_RESPONSE_LEN,
    })
}

/// A parsed WG type-2 response. Borrows the Noise body from the input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedResponse<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub noise_body: &'a [u8],
}

/// Parse + authenticate a WG type-2 response. `our_static_pub` is xpf's own
/// static public key (the recipient of a response is the initiator = us).
/// mac1 verified; mac2 skipped (S1).
pub(crate) fn parse_response<'a>(
    msg: &'a [u8],
    our_static_pub: &[u8; WG_KEY_LEN],
) -> Result<ParsedResponse<'a>, FramingError> {
    if msg.len() != WG_MSG_RESPONSE_LEN {
        return Err(FramingError::WrongLength);
    }
    // Strict 32-bit LE type word (type byte 2 + zero reserved). See
    // `parse_initiation` / `is_canonical_type`.
    if !is_canonical_type(msg, WG_TYPE_RESPONSE) {
        return Err(FramingError::BadType);
    }
    let expect = compute_mac1(our_static_pub, &msg[..M2_MAC1]);
    let got = {
        let mut m = [0u8; WG_MAC_LEN];
        m.copy_from_slice(&msg[M2_MAC1..M2_MAC2]);
        m
    };
    if !macs_equal(&expect, &got) {
        return Err(FramingError::Mac1Mismatch);
    }
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let receiver_index = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    Ok(ParsedResponse {
        sender_index,
        receiver_index,
        noise_body: &msg[M2_NOISE..M2_MAC1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independently re-derive the WG construction hashes the same way the
    /// reference does (`InitialChainKey = BLAKE2s-256(NoiseConstruction)`,
    /// `InitialHash = BLAKE2s-256(InitialChainKey || WGIdentifier)`), and
    /// pin them to the canonical hex. Dual-source: a transcription typo
    /// fails the hex, an impl/primitive bug fails the re-derivation. This
    /// proves the `blake2` crate computes the WG hashes correctly even
    /// though snow's prologue (not this module) is what mixes them at
    /// runtime — it is the foundation the MAC1 KAT builds on.
    #[test]
    fn construction_hashes_match_spec() {
        let ick = {
            let mut h = Blake2s256::new();
            Digest::update(&mut h, b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
            h.finalize()
        };
        let ih = {
            let mut h = Blake2s256::new();
            Digest::update(&mut h, &ick);
            Digest::update(&mut h, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
            h.finalize()
        };
        // Canonical values (computed offline from the WG construction; also
        // reproduced here from first principles above).
        let ick_hex = "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36";
        let ih_hex = "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3";
        assert_eq!(hex(&ick), ick_hex);
        assert_eq!(hex(&ih), ih_hex);
    }

    /// MAC1 KAT: keyed-BLAKE2s-128, NOT HMAC. Dual-source — assert the baked
    /// hex AND re-derive `compute_mac1`'s key independently. The baked value
    /// `78df3b0a...` is the keyed-BLAKE2s-128 output; an HMAC-BLAKE2s
    /// implementation over the same key + message would instead produce
    /// `778123b8eb3dffafb3cc980b88b84bbc` (independently computed by Codex in
    /// the plan-review), so pinning the keyed value to this exact hex would
    /// fail loudly if `compute_mac1` were ever switched to HMAC — locking the
    /// keyed-vs-HMAC distinction without taking an `hmac` dependency.
    #[test]
    fn mac1_keyed_blake2s_128_kat() {
        let pk = [0x42u8; 32];
        // compute_mac1 over message "abc" — the keyed-BLAKE2s-128 value.
        let mac = compute_mac1(&pk, b"abc");
        assert_eq!(hex(&mac), "78df3b0a90577688ce9d272d04a8fb90");
        // The HMAC-BLAKE2s value over the same inputs is documented-different;
        // this is NOT it, confirming compute_mac1 is keyed-BLAKE2s.
        assert_ne!(hex(&mac), "778123b8eb3dffafb3cc980b88b84bbc");

        // Independently re-derive the MAC1 key and confirm.
        let key = {
            let mut h = Blake2s256::new();
            Digest::update(&mut h, b"mac1----");
            Digest::update(&mut h, &pk);
            h.finalize()
        };
        assert_eq!(
            hex(&key),
            "172c34d6807bd7acef1a2471f20e928626c23ce0b9f90b326cf5f82d12480a4e"
        );
    }

    /// mac1 keys on the RECIPIENT's static pub: a msg1 built toward
    /// responder R verifies under R's pubkey and FAILS under any other.
    #[test]
    fn mac1_keys_on_recipient_static_pub() {
        let resp_pub = [0x11u8; 32];
        let other_pub = [0x22u8; 32];
        let noise = [0xABu8; MSG_INIT_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        build_initiation(&mut buf, 0xDEADBEEF, &noise, &resp_pub).unwrap();

        // Verifies under the responder pubkey it was built for.
        assert!(parse_initiation(&buf, &resp_pub).is_ok());
        // Fails under a different recipient pubkey.
        assert_eq!(
            parse_initiation(&buf, &other_pub).unwrap_err(),
            FramingError::Mac1Mismatch
        );
    }

    #[test]
    fn msg1_layout_byte_offsets() {
        let resp_pub = [0x33u8; 32];
        let mut noise = [0u8; MSG_INIT_NOISE_LEN];
        for (i, b) in noise.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut buf = [0xFFu8; WG_MSG_INIT_LEN];
        let built = build_initiation(&mut buf, 0x01020304, &noise, &resp_pub).unwrap();
        assert_eq!(built.len, 148);
        assert_eq!(buf[0], WG_TYPE_INITIATION);
        assert_eq!(&buf[1..4], &[0, 0, 0], "reserved must be zero");
        // sender_index is little-endian.
        assert_eq!(&buf[4..8], &0x01020304u32.to_le_bytes());
        assert_eq!(&buf[8..116], &noise, "noise body at offset 8..116");
        // mac2 zeros.
        assert_eq!(&buf[132..148], &[0u8; 16]);
    }

    #[test]
    fn msg2_layout_byte_offsets() {
        let init_pub = [0x44u8; 32];
        let mut noise = [0u8; MSG_RESPONSE_NOISE_LEN];
        for (i, b) in noise.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let mut buf = [0xFFu8; WG_MSG_RESPONSE_LEN];
        let built = build_response(&mut buf, 0x0A0B0C0D, 0x01020304, &noise, &init_pub).unwrap();
        assert_eq!(built.len, 92);
        assert_eq!(buf[0], WG_TYPE_RESPONSE);
        assert_eq!(&buf[1..4], &[0, 0, 0]);
        assert_eq!(&buf[4..8], &0x0A0B0C0Du32.to_le_bytes(), "sender LE");
        assert_eq!(&buf[8..12], &0x01020304u32.to_le_bytes(), "receiver LE");
        assert_eq!(&buf[12..60], &noise, "noise body at offset 12..60");
        assert_eq!(&buf[76..92], &[0u8; 16], "mac2 zeros");
    }

    /// Full byte-exact msg1 KAT with a fixed responder pubkey and a fixed
    /// (deterministic) Noise body. This pins the entire framing assembly —
    /// type byte, reserved, LE sender, body placement, and the mac1 over
    /// msg[0..116] — so an offset or endianness bug in the assembly fails
    /// here even when the per-field KATs pass. (The Noise body is a fixed
    /// pattern rather than a real snow output: this module's job is the
    /// framing assembly + mac1; the snow body byte-exactness is covered by
    /// the engine self-handshake test and the S2 live kernel-WG interop.)
    #[test]
    fn msg1_full_kat_fixed_body() {
        let resp_pub = [0x42u8; 32];
        let mut noise = [0u8; MSG_INIT_NOISE_LEN];
        for (i, b) in noise.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        build_initiation(&mut buf, 0x11223344, &noise, &resp_pub).unwrap();

        // Re-derive the expected mac1 independently of build_initiation's
        // own path: assemble the prefix by hand and keyed-BLAKE2s it.
        let mut prefix = Vec::with_capacity(116);
        prefix.push(1u8);
        prefix.extend_from_slice(&[0, 0, 0]);
        prefix.extend_from_slice(&0x11223344u32.to_le_bytes());
        prefix.extend_from_slice(&noise);
        assert_eq!(prefix.len(), 116);
        let expect_mac1 = compute_mac1(&resp_pub, &prefix);
        assert_eq!(&buf[116..132], &expect_mac1, "mac1 over msg[0..116]");
        assert_eq!(&buf[0..116], &prefix[..], "framed prefix byte-exact");
        assert_eq!(&buf[132..148], &[0u8; 16], "mac2 zeros");
    }

    /// Full byte-exact msg2 KAT (mirror of msg1).
    #[test]
    fn msg2_full_kat_fixed_body() {
        let init_pub = [0x42u8; 32];
        let mut noise = [0u8; MSG_RESPONSE_NOISE_LEN];
        for (i, b) in noise.iter_mut().enumerate() {
            *b = (200 - i) as u8;
        }
        let mut buf = [0u8; WG_MSG_RESPONSE_LEN];
        build_response(&mut buf, 0xAABBCCDD, 0x11223344, &noise, &init_pub).unwrap();

        let mut prefix = Vec::with_capacity(60);
        prefix.push(2u8);
        prefix.extend_from_slice(&[0, 0, 0]);
        prefix.extend_from_slice(&0xAABBCCDDu32.to_le_bytes());
        prefix.extend_from_slice(&0x11223344u32.to_le_bytes());
        prefix.extend_from_slice(&noise);
        assert_eq!(prefix.len(), 60);
        let expect_mac1 = compute_mac1(&init_pub, &prefix);
        assert_eq!(&buf[60..76], &expect_mac1, "mac1 over msg[0..60]");
        assert_eq!(&buf[0..60], &prefix[..], "framed prefix byte-exact");
        assert_eq!(&buf[76..92], &[0u8; 16], "mac2 zeros");
    }

    #[test]
    fn framing_roundtrip_initiation() {
        let resp_pub = [0x55u8; 32];
        let noise = [0x77u8; MSG_INIT_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        build_initiation(&mut buf, 0xCAFEF00D, &noise, &resp_pub).unwrap();
        let parsed = parse_initiation(&buf, &resp_pub).unwrap();
        assert_eq!(parsed.sender_index, 0xCAFEF00D);
        assert_eq!(parsed.noise_body, &noise);
    }

    #[test]
    fn framing_roundtrip_response() {
        let init_pub = [0x66u8; 32];
        let noise = [0x88u8; MSG_RESPONSE_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_RESPONSE_LEN];
        build_response(&mut buf, 0x12345678, 0x9ABCDEF0, &noise, &init_pub).unwrap();
        let parsed = parse_response(&buf, &init_pub).unwrap();
        assert_eq!(parsed.sender_index, 0x12345678);
        assert_eq!(parsed.receiver_index, 0x9ABCDEF0);
        assert_eq!(parsed.noise_body, &noise);
    }

    #[test]
    fn parse_rejects_wrong_length_and_bad_type() {
        let pub_k = [0x99u8; 32];
        // Too short.
        assert_eq!(
            parse_initiation(&[0u8; 100], &pub_k).unwrap_err(),
            FramingError::WrongLength
        );
        // Too LONG: a valid 148-byte msg1 with trailing garbage must be
        // rejected (Copilot finding — fixed-length messages, no truncation).
        let resp_pub = [0x5Bu8; 32];
        let noise = [0x2Du8; MSG_INIT_NOISE_LEN];
        let mut over = vec![0u8; WG_MSG_INIT_LEN + 8];
        build_initiation(&mut over[..WG_MSG_INIT_LEN], 9, &noise, &resp_pub).unwrap();
        assert_eq!(
            parse_initiation(&over, &resp_pub).unwrap_err(),
            FramingError::WrongLength,
            "an oversized datagram must NOT parse by truncation"
        );
        // The exact-length prefix still parses on its own.
        assert!(parse_initiation(&over[..WG_MSG_INIT_LEN], &resp_pub).is_ok());

        // Same for the response: too-long is rejected.
        let init_pub = [0x6Cu8; 32];
        let rnoise = [0x3Eu8; MSG_RESPONSE_NOISE_LEN];
        let mut rover = vec![0u8; WG_MSG_RESPONSE_LEN + 4];
        build_response(&mut rover[..WG_MSG_RESPONSE_LEN], 1, 2, &rnoise, &init_pub).unwrap();
        assert_eq!(
            parse_response(&rover, &init_pub).unwrap_err(),
            FramingError::WrongLength
        );

        // Wrong type byte (response bytes parsed as initiation).
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        buf[0] = WG_TYPE_RESPONSE;
        assert_eq!(parse_initiation(&buf, &pub_k).unwrap_err(), FramingError::BadType);
    }

    /// Strict 32-bit-LE type word: a correct type byte but a NON-ZERO
    /// reserved byte must be rejected (the type is the u32 `0x00000001`, not
    /// just byte 0). A real WG peer always sends zero reserved bytes; this
    /// rejects non-canonical datagrams up front (Codex code-review finding 3).
    #[test]
    fn parse_rejects_nonzero_reserved_bytes() {
        let resp_pub = [0x5Au8; 32];
        let noise = [0x3Cu8; MSG_INIT_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        build_initiation(&mut buf, 0x1234, &noise, &resp_pub).unwrap();
        // Sanity: canonical build parses.
        assert!(parse_initiation(&buf, &resp_pub).is_ok());
        // Flip a reserved byte — must be rejected as BadType (the high bytes
        // of the type word are non-zero), regardless of mac1.
        buf[2] = 0x01;
        assert_eq!(
            parse_initiation(&buf, &resp_pub).unwrap_err(),
            FramingError::BadType
        );

        // Same for the response.
        let init_pub = [0xA5u8; 32];
        let rnoise = [0xC3u8; MSG_RESPONSE_NOISE_LEN];
        let mut rbuf = [0u8; WG_MSG_RESPONSE_LEN];
        build_response(&mut rbuf, 1, 2, &rnoise, &init_pub).unwrap();
        assert!(parse_response(&rbuf, &init_pub).is_ok());
        rbuf[1] = 0xFF;
        assert_eq!(
            parse_response(&rbuf, &init_pub).unwrap_err(),
            FramingError::BadType
        );
    }

    /// S1 must SKIP-verify mac2: a peer that holds our cookie sets a
    /// non-zero mac2; treating it as malformed would wrongly drop the
    /// initiation. mac1 still authenticates the message.
    #[test]
    fn parse_initiation_accepts_nonzero_mac2() {
        let resp_pub = [0xAAu8; 32];
        let noise = [0xBBu8; MSG_INIT_NOISE_LEN];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        build_initiation(&mut buf, 7, &noise, &resp_pub).unwrap();
        // Stamp a non-zero mac2 (last 16 bytes) — must NOT affect parse,
        // because mac1 (which covers only msg[0..116]) is unchanged.
        buf[132..148].copy_from_slice(&[0xCD; 16]);
        let parsed = parse_initiation(&buf, &resp_pub).expect("non-zero mac2 must parse");
        assert_eq!(parsed.sender_index, 7);
    }

    #[test]
    fn build_rejects_wrong_noise_len() {
        let pub_k = [0u8; 32];
        let mut buf = [0u8; WG_MSG_INIT_LEN];
        assert_eq!(
            build_initiation(&mut buf, 0, &[0u8; 10], &pub_k).unwrap_err(),
            FramingError::BadNoiseLen
        );
        let mut buf2 = [0u8; WG_MSG_RESPONSE_LEN];
        assert_eq!(
            build_response(&mut buf2, 0, 0, &[0u8; 10], &pub_k).unwrap_err(),
            FramingError::BadNoiseLen
        );
    }

    #[test]
    fn build_rejects_small_output() {
        let pub_k = [0u8; 32];
        let noise = [0u8; MSG_INIT_NOISE_LEN];
        let mut small = [0u8; 100];
        assert_eq!(
            build_initiation(&mut small, 0, &noise, &pub_k).unwrap_err(),
            FramingError::OutputTooSmall
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
