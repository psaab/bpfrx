//! Clean-room WireGuard tunnel termination for the userspace AF_XDP
//! dataplane. See `docs/pr/wireguard-clean/plan.md` for the design
//! and the explicit list of architectural choices that diverge from
//! the prior attempt in PR #1492.
//!
//! Scope of this PR: engine, framing, allowed-IPs trie, helpers,
//! and unit tests. Hot-path activation in `tx/dispatch.rs` and
//! `poll_descriptor.rs` is intentionally deferred — see the plan
//! doc for the rationale.
//!
//! ### Why this module exists in isolation
//!
//! The WireGuard surface area is small and self-contained — handshake,
//! framing, encap, decap, AllowedIPs LPM, replay window, MSS math.
//! Keeping the engine free of `pub(in crate::afxdp)` types from the
//! rest of `afxdp/` means we can unit-test it end-to-end and audit
//! its security-critical paths without dragging in the dataplane's
//! global type web. The integration PR will add a thin adapter
//! layer that bridges the engine API to the dispatch/poll types.

#![allow(dead_code)] // Most of this module is not yet wired into the hot path.

pub(crate) mod allowed_ips;
pub(crate) mod dscp;
pub(crate) mod engine;
pub(crate) mod framing;
pub(crate) mod mss;
pub(crate) mod outer;
pub(crate) mod peer;
pub(crate) mod scratch;
pub(crate) mod session;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use engine::{
    DecapError, DecapOutcome, EncapError, EncapOutcome, WgEngine, WgEngineConfig, WgPeerConfig,
};
pub(crate) use scratch::WgWorkerScratch;

/// X25519 public/private key length (bytes).
pub(crate) const WG_KEY_LEN: usize = 32;

/// Noise IKpsk2 pattern with WG primitives.
///
/// WireGuard always uses IKpsk2. When no explicit PSK is configured,
/// the protocol still mixes an all-zero 32-byte PSK in the `psk2`
/// step.
pub(crate) const WG_NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// All-zero PSK used for the standard "no explicit PSK configured"
/// WG handshake behavior.
pub(crate) const WG_ZERO_PSK: [u8; WG_KEY_LEN] = [0u8; WG_KEY_LEN];

/// WireGuard packet type codes (over UDP outer).
pub(crate) const WG_TYPE_INITIATION: u8 = 1;
pub(crate) const WG_TYPE_RESPONSE: u8 = 2;
pub(crate) const WG_TYPE_COOKIE: u8 = 3;
pub(crate) const WG_TYPE_DATA: u8 = 4;

/// Poly1305 authentication tag length.
pub(crate) const POLY1305_TAG_LEN: usize = 16;

/// Transport data header on the wire:
///   - type        u8  = 4
///   - reserved    [u8; 3]
///   - receiver_id u32 (little-endian)
///   - counter     u64 (little-endian)
pub(crate) const WG_DATA_HEADER_LEN: usize = 1 + 3 + 4 + 8;

/// Total per-packet WG overhead for IPv4 outer:
///   outer IP (20) + UDP (8) + WG data header (16) + Poly1305 tag (16).
pub(crate) const WG_OVERHEAD_V4: usize = 20 + 8 + WG_DATA_HEADER_LEN + POLY1305_TAG_LEN;

/// Total per-packet WG overhead for IPv6 outer.
pub(crate) const WG_OVERHEAD_V6: usize = 40 + 8 + WG_DATA_HEADER_LEN + POLY1305_TAG_LEN;
